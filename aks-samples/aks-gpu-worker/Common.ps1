#Requires -Version 7.2
. (Join-Path $PSScriptRoot 'Infrastructure.ps1')
. (Join-Path $PSScriptRoot 'Preflight.ps1')

function New-SampleSshKey {
    param([Parameter(Mandatory)][string]$Path)
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source
    $start.UseShellExecute = $false
    $start.RedirectStandardError = $true
    # ArgumentList preserves an empty passphrase, including on PowerShell 7.2.
    foreach ($argument in @('-t', 'rsa', '-b', '3072', '-N', '', '-f', $Path, '-q')) {
        $start.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "ssh-keygen failed with exit code $($process.ExitCode): $errorText" }
        if (-not (Test-Path $Path) -or -not (Test-Path "$Path.pub")) { throw 'ssh-keygen did not create the key pair.' }
    }
    finally { $process.Dispose() }
}

function Assert-MinimumKernel {
    param([string]$Kernel, [string]$Minimum = '6.8.0-1071-azure-fde')
    $pattern = '^(\d+)\.(\d+)\.(\d+)-(\d+)-azure-fde$'
    if ($Kernel -notmatch $pattern) { throw "Not an Azure FDE kernel: $Kernel" }
    $actual = [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    if ($Minimum -notmatch $pattern) { throw "Invalid minimum FDE kernel: $Minimum" }
    $floor = [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    if ($actual -lt $floor) { throw "Kernel $Kernel is older than $Minimum." }
}

function Get-LatestKubernetesPatch {
    param([object]$Versions)
    $patches = @($Versions.values | Where-Object { $_.isPreview -ne $true } |
        ForEach-Object { $_.patchVersions.PSObject.Properties.Name } |
        Where-Object { $_ -match '^\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_ } -Descending)
    if (-not $patches.Count) { throw 'No stable regional Kubernetes patch was returned.' }
    return $patches[0]
}

function Wait-SampleAksReady {
    param(
        [string]$Az, [string]$Subscription, [string]$ResourceGroup, [string]$ClusterName,
        [int]$TimeoutSeconds = 1200, [int]$PollSeconds = 15
    )
    $scope = @('--subscription', $Subscription, '--only-show-errors')
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $cluster = Invoke-CheckedCommand $Az (@('aks', 'show', '-g', $ResourceGroup,
            '-n', $ClusterName, '-o', 'json') + $scope) | ConvertFrom-Json
        $pools = @(Invoke-CheckedCommand $Az (@('aks', 'nodepool', 'list', '-g', $ResourceGroup,
            '--cluster-name', $ClusterName, '-o', 'json') + $scope) | ConvertFrom-Json)
        $states = @($cluster.provisioningState) + @($pools | ForEach-Object provisioningState)
        if (@($states | Where-Object { $_ -in @('Failed', 'Canceled') }).Count) {
            throw "AKS provisioning failed: $($states -join ', ')."
        }
        if ($pools.Count -gt 0 -and -not @($states | Where-Object { $_ -ne 'Succeeded' }).Count) { return }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
    throw "AKS operations did not settle within $TimeoutSeconds seconds: $($states -join ', ')."
}

function Stop-SampleAks {
    param(
        [string]$Az, [string]$Subscription, [string]$ResourceGroup, [string]$ClusterName,
        [int]$TimeoutSeconds = 1200, [int]$PollSeconds = 15
    )
    $arguments = @('aks', 'stop', '-g', $ResourceGroup, '-n', $ClusterName,
        '-o', 'none', '--subscription', $Subscription, '--only-show-errors')
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $PSNativeCommandUseErrorActionPreference = $false
    do {
        $output = & $Az @arguments 2>&1
        if ($LASTEXITCODE -eq 0) { return }
        $message = $output -join "`n"
        # AKS can report Succeeded while an addon handler still holds its lock.
        if ($message -notmatch 'OperationNotAllowed' -or $message -notmatch "in-progress .* operation") {
            throw "AKS stop failed: $message"
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw "AKS stop remained blocked for $TimeoutSeconds seconds: $message" }
        Write-Warning 'AKS stop is blocked by an in-progress operation; retrying within the shutdown deadline.'
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
}

function Get-ExactDriverImages {
    param([string]$Kernel, [string[]]$Branches)
    Assert-MinimumKernel $Kernel
    $token = Invoke-RestMethod 'https://nvcr.io/token?service=registry&scope=repository:nvidia/driver:pull'
    foreach ($branch in ($Branches | Sort-Object { [int]$_ } -Descending -Unique)) {
        if ($branch -notmatch '^\d+$') { throw "Invalid driver branch: $branch" }
        $tag = "$branch-$Kernel-ubuntu24.04"
        $response = Invoke-WebRequest "https://nvcr.io/v2/nvidia/driver/manifests/$tag" -Headers @{
            Authorization = "Bearer $($token.token)"
            Accept = 'application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json'
        } -SkipHttpErrorCheck
        $available = [int]$response.StatusCode -eq 200
        $digest = $null
        if ($available) {
            $digest = @($response.Headers['Docker-Content-Digest'])[0]
            if ($digest -notmatch '^sha256:[0-9a-f]{64}$') { throw "Missing registry digest for $tag." }
        }
        elseif ([int]$response.StatusCode -eq 404) {
            $body = $response.Content | ConvertFrom-Json
            if ($body.errors[0].code -ne 'MANIFEST_UNKNOWN' -or $body.errors[0].message -ne 'manifest unknown') {
                throw "Unexpected registry 404 for $tag."
            }
        }
        else { throw "Registry HTTP $($response.StatusCode) for $tag; not a missing-image result." }
        [pscustomobject]@{ Tag = $tag; Available = $available; Digest = $digest; HttpStatus = [int]$response.StatusCode }
    }
}

function Get-GuideOperatorValues {
    param([string]$Kernel)
    Assert-MinimumKernel $Kernel
    @"
driver:
  version: 580-$Kernel
  kernelModuleType: open
daemonsets:
  tolerations:
    - key: sku
      operator: Equal
      value: gpu
      effect: NoSchedule
node-feature-discovery:
  worker:
    tolerations:
      - key: sku
        operator: Equal
        value: gpu
        effect: NoSchedule
"@
}

function Get-GuideWorkloadManifest {
    param([Parameter(Mandatory)][string]$Manifest)
    $Manifest = $Manifest.Replace("`r`n", "`n")
    foreach ($required in @('name: tf-matmul-demo', 'image: tensorflow/tensorflow:2.15.0-gpu',
            "spec:`n  template:", '      restartPolicy: OnFailure', '          c = tf.matmul(a, b)')) {
        if (-not $Manifest.Contains($required)) { throw "Upstream workload manifest changed: missing $required." }
    }
    $Manifest = $Manifest.Replace("spec:`n  template:", "spec:`n  backoffLimit: 0`n  activeDeadlineSeconds: 900`n  template:")
    $Manifest = $Manifest.Replace('      restartPolicy: OnFailure', @'
      restartPolicy: Never
      runtimeClassName: nvidia
      nodeSelector:
        agentpool: gpunp
'@)
    $Manifest = $Manifest.Replace('          c = tf.matmul(a, b)', @'
          tf.config.set_soft_device_placement(False)
          assert tf.config.list_physical_devices('GPU'), "No GPU available"
          with tf.device('/GPU:0'):
              c = tf.matmul(a, b)
          assert 'GPU:0' in c.device, "Matmul did not execute on GPU"
          print("GPU matmul device:", c.device)
'@)
    return $Manifest
}

function Stop-ExistingNccCompute {
    param([string]$Az, [string]$Subscription, [string]$Location, [switch]$Stop)
    $scope = @('--subscription', $Subscription, '--only-show-errors')
    $clusters = @(Invoke-CheckedCommand $Az (@('aks', 'list', '-o', 'json') + $scope) | ConvertFrom-Json)
    $sets = @(Invoke-CheckedCommand $Az (@('vmss', 'list', '-o', 'json') + $scope) | ConvertFrom-Json)
    $vms = @(Invoke-CheckedCommand $Az (@('vm', 'list', '--show-details', '-o', 'json') + $scope) | ConvertFrom-Json)
    foreach ($set in @($sets | Where-Object { $_.location -eq $Location -and $_.sku.name -like 'Standard_NCC*' })) {
        $owner = @($clusters | Where-Object { $_.nodeResourceGroup -eq $set.resourceGroup })
        if ($owner.Count -gt 1) { throw "Ambiguous AKS owner for $($set.name)." }
        if ($owner.Count -eq 1) {
            $cluster = $owner[0]
            Write-Host "Existing NCC: $($cluster.name), power $($cluster.powerState.code), capacity $($set.sku.capacity)."
            if ($cluster.powerState.code -ne 'Stopped') {
                if (-not $Stop) { throw 'Running NCC AKS found. Pass -StopExistingNcc to authorize shutdown.' }
                Stop-SampleAks $Az $Subscription $cluster.resourceGroup $cluster.name
                $state = Invoke-CheckedCommand $Az (@('aks', 'show', '-g', $cluster.resourceGroup, '-n', $cluster.name,
                    '--query', 'powerState.code', '-o', 'tsv') + $scope)
                if ($state -ne 'Stopped') { throw "AKS $($cluster.name) did not stop." }
            }
            $instances = @(Invoke-CheckedCommand $Az (@('vmss', 'list-instances', '-g', $set.resourceGroup,
                '-n', $set.name, '--expand', 'instanceView', '-o', 'json') + $scope) | ConvertFrom-Json)
            foreach ($instance in $instances) {
                $power = @($instance.instanceView.statuses | Where-Object code -Like 'PowerState/*')
                if ($power.Count -ne 1 -or $power[0].code -ne 'PowerState/deallocated') {
                    throw "Existing AKS NCC instance $($instance.name) is not deallocated."
                }
            }
        }
        else {
            $instances = @(Invoke-CheckedCommand $Az (@('vmss', 'list-instances', '-g', $set.resourceGroup,
                '-n', $set.name, '--expand', 'instanceView', '-o', 'json') + $scope) | ConvertFrom-Json)
            $active = @($instances | Where-Object {
                'PowerState/deallocated' -notin @($_.instanceView.statuses.code)
            })
            if ($active.Count) {
                if (-not $Stop) { throw "Running standalone NCC scale set $($set.name). Pass -StopExistingNcc." }
                Invoke-CheckedCommand $Az (@('vmss', 'deallocate', '-g', $set.resourceGroup, '-n', $set.name, '-o', 'none') + $scope)
                $verified = @(Invoke-CheckedCommand $Az (@('vmss', 'list-instances', '-g', $set.resourceGroup,
                    '-n', $set.name, '--expand', 'instanceView', '-o', 'json') + $scope) | ConvertFrom-Json)
                if (@($verified | Where-Object { 'PowerState/deallocated' -notin @($_.instanceView.statuses.code) }).Count) {
                    throw "Standalone NCC scale set $($set.name) did not deallocate."
                }
            }
        }
    }
    foreach ($vm in @($vms | Where-Object { $_.location -eq $Location -and $_.hardwareProfile.vmSize -like 'Standard_NCC*' })) {
        Write-Host "Existing NCC VM: $($vm.name), $($vm.powerState)."
        if ($vm.powerState -ne 'VM deallocated') {
            if (-not $Stop) { throw "Existing NCC VM $($vm.name) needs -StopExistingNcc." }
            Invoke-CheckedCommand $Az (@('vm', 'deallocate', '--ids', $vm.id, '-o', 'none') + $scope)
            $state = Invoke-CheckedCommand $Az (@('vm', 'get-instance-view', '--ids', $vm.id,
                '--query', "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]", '-o', 'tsv') + $scope)
            if ($state -ne 'PowerState/deallocated') { throw "VM $($vm.name) did not deallocate." }
        }
    }
}
