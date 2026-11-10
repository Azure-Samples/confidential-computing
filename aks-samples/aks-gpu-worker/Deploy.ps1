#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$ResourceGroup,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]+$')][string]$ClusterName,
    [string]$Location = 'westeurope',
    [string]$KubernetesVersion = '1.36.5',
    [string]$SystemVmSize = 'Standard_D4ds_v6',
    [ValidateSet('Ubuntu2404')][string]$SystemOsSku = 'Ubuntu2404',
    [string]$GpuZone,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '.local'),
    [switch]$PreflightOnly,
    [switch]$RegisterPreview,
    [switch]$UseCoreCli,
    [switch]$Resume
)
. (Join-Path $PSScriptRoot 'Common.ps1')
$previousExtensionDirectory = $env:AZURE_EXTENSION_DIR
$previousDynamicInstall = $env:AZURE_EXTENSION_USE_DYNAMIC_INSTALL
try {
$az = Resolve-AzureCli
$scope = @('--subscription', $SubscriptionId.ToString(), '--only-show-errors')
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
if ($UseCoreCli) {
    $env:AZURE_EXTENSION_DIR = Join-Path $OutputDirectory 'cli-extensions-core'
    New-Item -ItemType Directory -Path $env:AZURE_EXTENSION_DIR -Force | Out-Null
    if (@(Get-ChildItem -LiteralPath $env:AZURE_EXTENSION_DIR -Force).Count) {
        throw 'Core CLI extension directory must be empty; inspect it before continuing.'
    }
    $env:AZURE_EXTENSION_USE_DYNAMIC_INSTALL = 'no'
}

$account = Invoke-CheckedCommand $az (@('account', 'show', '-o', 'json') + $scope) | ConvertFrom-Json
if ($account.state -ne 'Enabled') { throw 'The target subscription is not enabled.' }
if ($UseCoreCli) {
    $cliVersion = (Invoke-CheckedCommand $az @('version', '-o', 'json') | ConvertFrom-Json).'azure-cli'
    Write-Host "Using built-in Azure CLI $cliVersion AKS commands in $Location (extensions isolated)."
}
else {
    $extension = Invoke-CheckedCommand $az @('extension', 'show', '--name', 'aks-preview', '-o', 'json') | ConvertFrom-Json
    Write-Host "Using Azure CLI aks-preview $($extension.version) in $Location."
}
$versions = Invoke-CheckedCommand $az (@('aks', 'get-versions', '--location', $Location, '-o', 'json') + $scope) | ConvertFrom-Json
$patches = @($versions.values | ForEach-Object { $_.patchVersions.PSObject.Properties.Name })
if ($KubernetesVersion -notin $patches) { throw "Kubernetes $KubernetesVersion is not offered in $Location." }

$exists = Invoke-CheckedCommand $az (@('group', 'exists', '--name', $ResourceGroup, '-o', 'tsv') + $scope)
$existingPools = @()
$cluster = @()
if ($exists -eq 'true') {
    if (-not $Resume) { throw 'Resource group already exists. Use a new name, or -Resume for this sample.' }
    $group = Invoke-CheckedCommand $az (@('group', 'show', '--name', $ResourceGroup, '-o', 'json') + $scope) | ConvertFrom-Json -AsHashtable
    if ($group.tags.sample -ne 'aks-gpu-worker' -or $group.location -ne $Location) {
        throw 'Existing resource group is not a matching sample group; nothing was modified.'
    }
    $clusters = @(Invoke-CheckedCommand $az (@('aks', 'list', '--resource-group', $ResourceGroup, '-o', 'json') + $scope) | ConvertFrom-Json -AsHashtable)
    if (@($clusters | Where-Object name -NE $ClusterName).Count) { throw 'Resource group contains a different cluster.' }
    $cluster = @($clusters | Where-Object name -EQ $ClusterName)
    if ($cluster.Count) {
        if ($cluster[0].tags.sample -ne 'aks-gpu-worker' -or $cluster[0].location -ne $Location -or
            $cluster[0].kubernetesVersion -ne $KubernetesVersion -or $cluster[0].provisioningState -ne 'Succeeded' -or
            $cluster[0].autoUpgradeProfile.upgradeChannel -ne 'none' -or
            $cluster[0].autoUpgradeProfile.nodeOsUpgradeChannel -ne 'None') {
            throw 'Existing cluster is not a successful matching sample cluster; inspect it before continuing.'
        }
        $existingPools = @(Invoke-CheckedCommand $az (@('aks', 'nodepool', 'list', '--resource-group', $ResourceGroup,
            '--cluster-name', $ClusterName, '-o', 'json') + $scope) | ConvertFrom-Json -AsHashtable)
        Assert-SamplePools -Pools $existingPools -SystemVmSize $SystemVmSize -AllowMissingGpu
    }
}

$skus = @(Invoke-CheckedCommand $az (@('vm', 'list-skus', '--location', $Location,
    '--resource-type', 'virtualMachines', '--all', '-o', 'json') + $scope) | ConvertFrom-Json)
$usage = @(Invoke-CheckedCommand $az (@('vm', 'list-usage', '--location', $Location, '-o', 'json') + $scope) | ConvertFrom-Json)
$required = @{}
$skuEvidence = @(foreach ($size in @($SystemVmSize, 'Standard_NCC40ads_H100_v5')) {
    $sku = @($skus | Where-Object name -EQ $size)
    if ($sku.Count -ne 1) { throw "SKU $size was not found in $Location." }
    $sku = $sku[0]
    $regionBlocks = @($sku.restrictions | Where-Object type -EQ 'Location')
    if ($regionBlocks.Count) { throw "SKU $size has a regional subscription restriction: $($regionBlocks | ConvertTo-Json -Depth 10 -Compress)" }
    if ($size -eq 'Standard_NCC40ads_H100_v5' -and $GpuZone) {
        if ($GpuZone -notin @($sku.locationInfo | ForEach-Object zones)) { throw "GPU zone $GpuZone is not offered." }
        $zoneBlocks = @($sku.restrictions | Where-Object {
            $_.type -eq 'Zone' -and $GpuZone -in $_.restrictionInfo.zones
        })
        if ($zoneBlocks.Count) { throw "GPU zone $GpuZone is restricted for this subscription." }
    }
    $cores = [int]($sku.capabilities | Where-Object name -EQ 'vCPUs').value
    if (-not $required.ContainsKey($sku.family)) { $required[$sku.family] = 0 }
    $poolName = if ($size -eq 'Standard_NCC40ads_H100_v5') { 'gpunp' } else { 'sysnp' }
    if (-not @($existingPools | Where-Object name -EQ $poolName).Count) {
        $required[$sku.family] += $cores
    }
    $sku
})
$total = 0
foreach ($family in $required.Keys) {
    $quota = @($usage | Where-Object { $_.name.value -eq $family })
    if ($quota.Count -ne 1 -or ([int]$quota[0].limit - [int]$quota[0].currentValue) -lt $required[$family]) {
        throw "Insufficient $family quota for $($required[$family]) new vCPUs."
    }
    $total += $required[$family]
}
$regional = $usage | Where-Object { $_.name.value -eq 'cores' }
if (([int]$regional.limit - [int]$regional.currentValue) -lt $total) { throw "Insufficient regional vCPU quota for $total cores." }

$featureArgs = @('feature', 'show', '--namespace', 'Microsoft.ContainerService', '--name', 'Ubuntu2404Preview')
$feature = Invoke-CheckedCommand $az ($featureArgs + @('--query', 'properties.state', '-o', 'tsv') + $scope)
if ($feature -ne 'Registered' -and $RegisterPreview -and -not $PreflightOnly) {
    Invoke-CheckedCommand $az (@('feature', 'register', '--namespace', 'Microsoft.ContainerService',
        '--name', 'Ubuntu2404Preview', '-o', 'none') + $scope)
    $deadline = [DateTime]::UtcNow.AddMinutes(20)
    do {
        Start-Sleep -Seconds 20
        $feature = Invoke-CheckedCommand $az ($featureArgs + @('--query', 'properties.state', '-o', 'tsv') + $scope)
    } while ($feature -ne 'Registered' -and [DateTime]::UtcNow -lt $deadline)
    if ($feature -eq 'Registered') {
        Invoke-CheckedCommand $az (@('provider', 'register', '--namespace', 'Microsoft.ContainerService',
            '--wait', '-o', 'none') + $scope)
    }
}
$preflight = [ordered]@{
    CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
    Location = $Location
    KubernetesVersion = $KubernetesVersion
    PreviewState = "$feature"
    Skus = $skuEvidence
    Quota = @($usage | Where-Object { $_.name.value -in @($required.Keys) + @('cores') })
}
$preflight | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $OutputDirectory 'preflight.json')
if ($feature -ne 'Registered') { throw "Ubuntu2404Preview is $feature. Rerun with -RegisterPreview or arrange subscription registration." }
if ($PreflightOnly) { Write-Host 'Preflight passed; no Azure resources were changed.'; return }

if ($exists -ne 'true') {
    Invoke-CheckedCommand $az (@('group', 'create', '--name', $ResourceGroup, '--location', $Location,
        '--tags', 'sample=aks-gpu-worker', '-o', 'none') + $scope)
}
if ($cluster.Count -eq 0) {
    Invoke-CheckedCommand $az (@('aks', 'create', '--resource-group', $ResourceGroup, '--name', $ClusterName,
        '--location', $Location, '--kubernetes-version', $KubernetesVersion, '--tier', 'free',
        '--nodepool-name', 'sysnp', '--node-count', '1', '--node-vm-size', $SystemVmSize,
        '--os-sku', $SystemOsSku, '--node-osdisk-type', 'Managed', '--node-osdisk-size', '128',
        '--enable-managed-identity', '--generate-ssh-keys', '--auto-upgrade-channel', 'none',
        '--node-os-upgrade-channel', 'None', '--tags', 'sample=aks-gpu-worker', '-o', 'none') + $scope)
}
$pools = @(Invoke-CheckedCommand $az (@('aks', 'nodepool', 'list', '--resource-group', $ResourceGroup,
    '--cluster-name', $ClusterName, '-o', 'json') + $scope) | ConvertFrom-Json -AsHashtable)
Assert-SamplePools -Pools $pools -SystemVmSize $SystemVmSize -AllowMissingGpu
$gpu = @($pools | Where-Object name -EQ 'gpunp')
if ($gpu.Count -eq 0) {
    $arguments = @('aks', 'nodepool', 'add', '--resource-group', $ResourceGroup, '--cluster-name', $ClusterName,
        '--name', 'gpunp', '--mode', 'User', '--node-count', '1', '--node-vm-size', 'Standard_NCC40ads_H100_v5',
        '--os-sku', 'Ubuntu2404', '--gpu-driver', 'None', '--node-osdisk-type', 'Managed',
        '--node-osdisk-size', '128', '--node-taints', 'sku=gpu:NoSchedule', '-o', 'none')
    if ($GpuZone) { $arguments += @('--zones', $GpuZone) }
    Invoke-CheckedCommand $az ($arguments + $scope)
}
$pools = Invoke-CheckedCommand $az (@('aks', 'nodepool', 'list', '--resource-group', $ResourceGroup,
    '--cluster-name', $ClusterName, '-o', 'json') + $scope)
$pools | Set-Content (Join-Path $OutputDirectory 'nodepools.json')
Assert-SamplePools -Pools @($pools | ConvertFrom-Json -AsHashtable) -SystemVmSize $SystemVmSize
$nodeGroup = Invoke-CheckedCommand $az (@('aks', 'show', '--resource-group', $ResourceGroup,
    '--name', $ClusterName, '--query', 'nodeResourceGroup', '-o', 'tsv') + $scope)
$scaleSets = Invoke-CheckedCommand $az (@('vmss', 'list', '--resource-group', "$nodeGroup", '-o', 'json') + $scope)
$scaleSets | Set-Content (Join-Path $OutputDirectory 'scalesets.json')
Assert-ConfidentialGpuScaleSet -ScaleSets @($scaleSets | ConvertFrom-Json -AsHashtable)
$kubeconfig = Join-Path $OutputDirectory 'kubeconfig'
Invoke-CheckedCommand $az (@('aks', 'get-credentials', '--resource-group', $ResourceGroup,
    '--name', $ClusterName, '--file', $kubeconfig, '--overwrite-existing') + $scope)
Invoke-CheckedCommand kubectl @('--kubeconfig', $kubeconfig, 'wait', '--for=condition=Ready',
    'nodes', '-l', 'agentpool=gpunp', '--timeout=600s')
$node = Get-GpuNode -KubeConfig $kubeconfig
$node | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $OutputDirectory 'gpu-node.json')
& (Join-Path $PSScriptRoot 'Test-DriverCompatibility.ps1') -KubeConfig $kubeconfig `
    -OutputPath (Join-Path $OutputDirectory 'driver-compatibility.json') -RequireAvailable
}
finally {
    $env:AZURE_EXTENSION_DIR = $previousExtensionDirectory
    $env:AZURE_EXTENSION_USE_DYNAMIC_INSTALL = $previousDynamicInstall
}
