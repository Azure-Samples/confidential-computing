# Generates sustained HTTP load against the Confidential VMSS demo app so that the CPU autoscale
# rules created by BuildRandomCVMSS.ps1 trigger a scale-out, then a scale-in once the load stops.
#
# Run this from your own machine - it only needs outbound HTTP to the Application Gateway public IP.
# If you also pass the subscription/resource group/scale set names it will poll and print the live
# instance count so you can watch the scale set grow and shrink.
#
# Usage: ./Start-VmssLoad.ps1 -Target http://<APPGW-IP> [-Concurrency 16] [-DurationMinutes 15]
#        [-BurnSeconds 20] [-subsID <SUB>] [-ResourceGroup <RG>] [-VmssName <VMSS>] [-CooldownMinutes 15]
#
# Concurrency      number of parallel workers hammering /burn - raise it if CPU does not reach the threshold
# DurationMinutes  how long to keep the load on. Autoscale averages CPU over 5 minutes, so use 10+ minutes
# BurnSeconds      CPU seconds consumed by each request
# CooldownMinutes  keep watching (with no load) after the run to observe the scale-in

param (
    [Parameter(Mandatory)]$Target,
    [Parameter(Mandatory=$false)][int]$Concurrency = 16,
    [Parameter(Mandatory=$false)][int]$DurationMinutes = 15,
    [Parameter(Mandatory=$false)][int]$BurnSeconds = 20,
    [Parameter(Mandatory=$false)]$subsID = "",
    [Parameter(Mandatory=$false)]$ResourceGroup = "",
    [Parameter(Mandatory=$false)]$VmssName = "",
    [Parameter(Mandatory=$false)][int]$CooldownMinutes = 0
)

if ($Concurrency -lt 1 -or $DurationMinutes -lt 1 -or $BurnSeconds -lt 1) {
    write-host "Concurrency, DurationMinutes and BurnSeconds must all be at least 1" -ForegroundColor Red
    exit 1
}

if ($Target -notmatch '^https?://') { $Target = "http://$Target" }
$Target = $Target.TrimEnd('/')

# Only track the scale set capacity if we were given everything needed to query it
$trackVmss = ($subsID -ne "" -and $ResourceGroup -ne "" -and $VmssName -ne "")
if ($trackVmss) {
    if (-not (Get-Module -Name Az.Compute -ListAvailable -ErrorAction SilentlyContinue)) {
        write-host "Az.Compute is not installed, so instance counts will not be shown." -ForegroundColor Yellow
        $trackVmss = $false
    } else {
        Set-AzContext -SubscriptionId $subsID | Out-Null
    }
}

function Get-VmssCapacity {
    if (-not $trackVmss) { return $null }
    try {
        $vmss = Get-AzVmss -ResourceGroupName $ResourceGroup -VMScaleSetName $VmssName -ErrorAction Stop
        return [int]$vmss.Sku.Capacity
    } catch {
        return $null
    }
}

write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Confidential VMSS load generator"
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Target      : $Target"
write-host "Concurrency : $Concurrency workers"
write-host "Duration    : $DurationMinutes minutes ($BurnSeconds CPU-seconds per request)"
if ($trackVmss) { write-host "Watching    : $VmssName in $ResourceGroup" }
write-host "----------------------------------------------------------------------------------------------------------------"

# Fail fast if the app is not reachable rather than burning minutes on a dead endpoint
try {
    Invoke-WebRequest -Uri "$Target/health" -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop | Out-Null
    write-host "Health check passed." -ForegroundColor Green
} catch {
    write-host "ERROR: cannot reach $Target/health - $($_.Exception.Message)" -ForegroundColor Red
    write-host "Check the Application Gateway backend health and that the app finished installing." -ForegroundColor Yellow
    exit 1
}

$startCapacity = Get-VmssCapacity
if ($null -ne $startCapacity) { write-host "Starting instance count: $startCapacity" -ForegroundColor Cyan }

# Each worker writes only its own key, so a concurrent dictionary is enough - no locking needed.
$stats = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$endTime = (Get-Date).AddMinutes($DurationMinutes)

$worker = {
    param($url, $burnSeconds, $endTimeTicks, $workerId, $stats)

    $requests = 0
    $errors = 0
    $hosts = @{}
    $deadline = [datetime]::new($endTimeTicks)

    while ((Get-Date) -lt $deadline) {
        try {
            $result = Invoke-RestMethod -Uri "$url/burn?seconds=$burnSeconds" -TimeoutSec ($burnSeconds + 120) -ErrorAction Stop
            $requests++
            if ($result.host) {
                if ($hosts.ContainsKey($result.host)) { $hosts[$result.host]++ } else { $hosts[$result.host] = 1 }
            }
        } catch {
            $errors++
            Start-Sleep -Seconds 2
        }
        $stats[$workerId] = @{ Requests = $requests; Errors = $errors; Hosts = $hosts.Clone() }
    }
    $stats[$workerId] = @{ Requests = $requests; Errors = $errors; Hosts = $hosts.Clone() }
}

$pool = [runspacefactory]::CreateRunspacePool(1, $Concurrency)
$pool.Open()
$jobs = @()

for ($i = 1; $i -le $Concurrency; $i++) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($worker).AddArgument($Target).AddArgument($BurnSeconds).AddArgument($endTime.Ticks).AddArgument("worker$i").AddArgument($stats)
    $jobs += [pscustomobject]@{ Shell = $ps; Handle = $ps.BeginInvoke() }
}

write-host ""
write-host "Load started - autoscale evaluates a 5 minute average, so expect the first scale-out after roughly 5-10 minutes." -ForegroundColor Cyan
write-host "Press Ctrl+C to stop early (the workers stop on their own at the end of the run)." -ForegroundColor DarkGray
write-host ""

function Show-Progress($label) {
    $snapshot = @($stats.Values)
    $totalRequests = ($snapshot | ForEach-Object { $_.Requests } | Measure-Object -Sum).Sum
    $totalErrors = ($snapshot | ForEach-Object { $_.Errors } | Measure-Object -Sum).Sum
    $instancesSeen = @{}
    foreach ($entry in $snapshot) {
        foreach ($key in $entry.Hosts.Keys) { $instancesSeen[$key] = $true }
    }
    $capacity = Get-VmssCapacity
    $capacityText = if ($null -ne $capacity) { "capacity $capacity" } else { "capacity n/a" }
    write-host ("[{0}] {1} | requests {2} | errors {3} | instances answering {4} | {5}" -f `
        (Get-Date -Format 'HH:mm:ss'), $label, ($totalRequests ?? 0), ($totalErrors ?? 0), $instancesSeen.Count, $capacityText)
}

while ((Get-Date) -lt $endTime) {
    Start-Sleep -Seconds 30
    Show-Progress "load on "
}

foreach ($job in $jobs) {
    try { $job.Shell.EndInvoke($job.Handle) | Out-Null } catch { }
    $job.Shell.Dispose()
}
$pool.Close()
$pool.Dispose()

write-host ""
write-host "Load stopped." -ForegroundColor Green
Show-Progress "final   "

$finalSnapshot = @($stats.Values)
$instanceCounts = @{}
foreach ($entry in $finalSnapshot) {
    foreach ($key in $entry.Hosts.Keys) {
        if ($instanceCounts.ContainsKey($key)) { $instanceCounts[$key] += $entry.Hosts[$key] } else { $instanceCounts[$key] = $entry.Hosts[$key] }
    }
}

write-host ""
write-host "Requests served per instance:" -ForegroundColor Cyan
$instanceCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { write-host ("  {0,-20} {1}" -f $_.Key, $_.Value) }

if ($CooldownMinutes -gt 0) {
    write-host ""
    write-host "Watching for scale-in for $CooldownMinutes minutes (no load is being generated now)..." -ForegroundColor Cyan
    $cooldownEnd = (Get-Date).AddMinutes($CooldownMinutes)
    while ((Get-Date) -lt $cooldownEnd) {
        Start-Sleep -Seconds 60
        $capacity = Get-VmssCapacity
        $capacityText = if ($null -ne $capacity) { $capacity } else { "n/a" }
        write-host ("[{0}] cooling down | capacity {1}" -f (Get-Date -Format 'HH:mm:ss'), $capacityText)
    }
}

$endCapacity = Get-VmssCapacity
write-host ""
write-host "----------------------------------------------------------------------------------------------------------------"
if ($null -ne $startCapacity -and $null -ne $endCapacity) {
    write-host "Instance count went from $startCapacity to $endCapacity"
}
write-host "Scale-in happens on the same 5 minute average, so the scale set takes a while to return to its minimum." -ForegroundColor Gray
write-host "----------------------------------------------------------------------------------------------------------------"
