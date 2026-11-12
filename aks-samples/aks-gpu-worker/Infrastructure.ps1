#Requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-AzureCli {
    $commands = @(Get-Command az -CommandType Application -ErrorAction SilentlyContinue)
    if ($commands.Count) { return $commands[0].Source }
    if ($IsWindows) {
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if ($root) {
                $candidate = Join-Path $root 'Microsoft SDKs\Azure\CLI2\wbin\az.cmd'
                if (Test-Path $candidate) { return $candidate }
            }
        }
    }
    throw 'Azure CLI is required. Install it and run az login before retrying.'
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    $output = & $Command @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($ArgumentList -join ' ') failed with exit code $LASTEXITCODE."
    }
    return $output
}

function Get-GpuNode {
    param(
        [Parameter(Mandatory)][string]$KubeConfig,
        [string]$PoolName = 'gpunp'
    )
    $nodes = Invoke-CheckedCommand kubectl @('--kubeconfig', $KubeConfig, 'get', 'nodes',
        '-l', "agentpool=$PoolName", '-o', 'json') | ConvertFrom-Json
    if (@($nodes.items).Count -ne 1) {
        throw "Expected exactly one node in pool $PoolName; found $(@($nodes.items).Count)."
    }
    return $nodes.items[0]
}

function Assert-SamplePools {
    param(
        [Parameter(Mandatory)][object[]]$Pools,
        [Parameter(Mandatory)][string]$SystemVmSize,
        [switch]$AllowMissingGpu
    )
    $system = @($Pools | Where-Object name -EQ 'sysnp')
    $gpu = @($Pools | Where-Object name -EQ 'gpunp')
    if ($system.Count -ne 1 -or @($Pools | Where-Object { $_.name -notin @('sysnp', 'gpunp') }).Count -or
        $gpu.Count -gt 1 -or (-not $AllowMissingGpu -and $gpu.Count -ne 1)) {
        throw 'Expected one system pool and one GPU pool, with no additional pools.'
    }

    foreach ($pool in $Pools) {
        $size = if ($pool.name -eq 'sysnp') { $SystemVmSize } else { 'Standard_NCC40ads_H100_v5' }
        $mode = if ($pool.name -eq 'sysnp') { 'System' } else { 'User' }
        if ($pool.vmSize -ne $size -or $pool.count -ne 1 -or $pool.osSku -ne 'Ubuntu2404' -or
            $pool.mode -ne $mode -or $pool.enableAutoScaling -eq $true -or $pool.provisioningState -ne 'Succeeded') {
            throw "Pool $($pool.name) does not match the single-node sample configuration; it was not modified."
        }
        if ($pool.name -eq 'gpunp' -and
            ($pool.gpuProfile.driver -ne 'None' -or 'sku=gpu:NoSchedule' -notin $pool.nodeTaints)) {
            throw 'GPU pool must disable automatic drivers and retain the GPU scheduling taint.'
        }
    }
}

function Assert-ConfidentialGpuScaleSet {
    param([Parameter(Mandatory)][object[]]$ScaleSets)
    $gpu = @($ScaleSets | Where-Object { $_.sku.name -eq 'Standard_NCC40ads_H100_v5' })
    if ($gpu.Count -ne 1) { throw 'Expected exactly one H100 scale set.' }
    $security = $gpu[0].virtualMachineProfile.securityProfile
    if ($gpu[0].sku.capacity -ne 1 -or $security.securityType -ne 'ConfidentialVM' -or
        $security.uefiSettings.secureBootEnabled -ne $true -or $security.uefiSettings.vTpmEnabled -ne $true) {
        throw 'H100 scale set must have one ConfidentialVM instance with Secure Boot and vTPM enabled.'
    }
}
