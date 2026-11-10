#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'Common.ps1')
$script:passed = 0
$state = @{}

function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Expect-Failure([scriptblock]$Action, [string]$Pattern) {
    try { & $Action | Out-Null }
    catch {
        Assert ($_.Exception.Message -match $Pattern) "Unexpected error: $_"
        return
    }
    throw "Expected a failure matching '$Pattern'."
}
function Case([string]$Name, [scriptblock]$Action) {
    $state.status = 200
    $state.digest = 'sha256:' + ('a' * 64)
    $state.content = '{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}'
    $state.networkError = $false
    & $Action
    $script:passed++
    Write-Host "PASS $Name"
}
function Invoke-RestMethod { @{ token = 'offline-token' } }
function Invoke-WebRequest {
    param($Uri, $Headers, [switch]$SkipHttpErrorCheck)
    Assert ($Headers.Authorization -eq 'Bearer offline-token') 'Anonymous registry token not supplied.'
    foreach ($type in @('oci.image.manifest', 'oci.image.index', 'distribution.manifest.v2', 'distribution.manifest.list.v2')) {
        Assert ($Headers.Accept.Contains($type)) "Missing manifest media type: $type"
    }
    Assert $SkipHttpErrorCheck 'HTTP errors must be inspected explicitly.'
    if ($state.networkError) { throw 'Mock network failure' }
    @{
        StatusCode = $state.status
        Headers = @{ 'Docker-Content-Digest' = @($state.digest) }
        Content = $state.content
    }
}
function New-Pools {
    @(
        @{ name = 'sysnp'; vmSize = 'Standard_D4ds_v6'; count = 1; osSku = 'Ubuntu2404'
            mode = 'System'; enableAutoScaling = $false; provisioningState = 'Succeeded' }
        @{ name = 'gpunp'; vmSize = 'Standard_NCC40ads_H100_v5'; count = 1; osSku = 'Ubuntu2404'
            mode = 'User'; enableAutoScaling = $false; provisioningState = 'Succeeded'
            gpuProfile = @{ driver = 'None' }; nodeTaints = @('sku=gpu:NoSchedule') }
    )
}
$tag = '580-6.8.0-1071-azure-fde-ubuntu24.04'
Case 'available manifests require OCI/Docker Accept headers and a digest' {
    $result = Get-DriverManifest $tag
    Assert ($result.Available -and $result.Digest -eq $state.digest) 'Incorrect available-image result.'
}
Case 'genuine absent tag is reported, not thrown' {
    $state.status = 404
    $result = Get-DriverManifest $tag
    Assert (-not $result.Available -and $result.ErrorCode -eq 'MANIFEST_UNKNOWN') 'Missing tag not identified.'
}
Case 'misleading OCI 404 is not a missing tag' {
    $state.status = 404
    $state.content = '{"errors":[{"code":"MANIFEST_UNKNOWN","message":"OCI manifest found, but accept header does not support OCI manifests"}]}'
    Expect-Failure { Get-DriverManifest $tag } 'unexpected 404'
}
foreach ($status in @(401, 403, 429, 500, 503)) {
    Case "HTTP $status throws rather than reporting missing image" {
        $state.status = $status
        Expect-Failure { Get-DriverManifest $tag } "HTTP $status"
    }
}
Case 'network failure propagates' {
    $state.networkError = $true
    Expect-Failure { Get-DriverManifest $tag } 'network failure'
}
Case 'invalid digest is rejected' {
    $state.digest = 'invalid'
    Expect-Failure { Get-DriverManifest $tag } 'valid digest'
}
Case 'invalid registry tag is rejected' {
    Expect-Failure { Get-DriverManifest '../invalid' } 'pattern'
}
Case 'compatibility report retains shape and does not claim support' {
    $report = & (Join-Path $root 'Test-DriverCompatibility.ps1') -KernelVersion '6.8.0-1071-azure-fde' | ConvertFrom-Json
    Assert ($report.Manifests.Count -eq 2 -and $report.MatchingImageAvailable -and -not $report.SupportValidated) 'Incorrect report shape.'
}
Case 'missing images fail the required-availability gate' {
    $state.status = 404
    Expect-Failure {
        & (Join-Path $root 'Test-DriverCompatibility.ps1') -KernelVersion '6.8.0-1071-azure-fde' -RequireAvailable
    } 'BLOCKED: no exact-kernel'
}
Case 'invalid kernel and branch are rejected' {
    Expect-Failure { & (Join-Path $root 'Test-DriverCompatibility.ps1') -KernelVersion '6.8.0-generic' } 'pattern'
    Expect-Failure {
        & (Join-Path $root 'Test-DriverCompatibility.ps1') -KernelVersion '6.8.0-1071-azure-fde' -DriverBranches '580/invalid'
    } 'Invalid driver branch'
}
Case 'exact topology and partial system-only topology pass' {
    $pools = New-Pools
    Assert-SamplePools $pools 'Standard_D4ds_v6'
    Assert-SamplePools @($pools[0]) 'Standard_D4ds_v6' -AllowMissingGpu
    Expect-Failure { Assert-SamplePools @($pools[0]) 'Standard_D4ds_v6' } 'Expected one system'
}
foreach ($field in @('count', 'vmSize', 'osSku', 'mode', 'enableAutoScaling', 'provisioningState')) {
    Case "mismatched pool $field is rejected" {
        $pools = New-Pools
        $pools[1][$field] = switch ($field) {
            'count' { 2 }
            'enableAutoScaling' { $true }
            default { 'incorrect' }
        }
        Expect-Failure { Assert-SamplePools $pools 'Standard_D4ds_v6' } 'does not match'
    }
}
Case 'extra pools and automatic GPU drivers are rejected' {
    $pools = New-Pools
    Expect-Failure { Assert-SamplePools ($pools + @(@{ name = 'unexpected' })) 'Standard_D4ds_v6' } 'Expected one system'
    $pools[1].gpuProfile.driver = 'Install'
    Expect-Failure { Assert-SamplePools $pools 'Standard_D4ds_v6' } 'disable automatic drivers'
}
Case 'pool checks support case-sensitive Azure JSON dictionaries' {
    $pools = @(New-Pools | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable)
    Assert-SamplePools $pools 'Standard_D4ds_v6'
}
Case 'confidential scale set requires one instance, Secure Boot and vTPM' {
    $vm = @{
        sku = @{ name = 'Standard_NCC40ads_H100_v5'; capacity = 1 }
        virtualMachineProfile = @{ securityProfile = @{
            securityType = 'ConfidentialVM'
            uefiSettings = @{ secureBootEnabled = $true; vTpmEnabled = $true }
        } }
    }
    Assert-ConfidentialGpuScaleSet @($vm)
    $vm.virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled = $false
    Expect-Failure { Assert-ConfidentialGpuScaleSet @($vm) } 'Secure Boot'
    $vm.virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled = $true
    $vm.virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled = $false
    Expect-Failure { Assert-ConfidentialGpuScaleSet @($vm) } 'vTPM'
    $vm.virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled = $true
    $vm.sku.capacity = 2
    Expect-Failure { Assert-ConfidentialGpuScaleSet @($vm) } 'one ConfidentialVM'
}
Case 'native failure propagates' {
    $pwsh = @(Get-Command pwsh -CommandType Application)[0].Source
    Expect-Failure {
        Invoke-CheckedCommand $pwsh @('-NoProfile', '-Command', 'exit 7')
    } 'exit code 7'
}

# Replace the native boundary only for the node-discovery cases.
function Invoke-CheckedCommand { $state.nodes | ConvertTo-Json -Depth 10 }
Case 'node lookup rejects zero and multiple workers' {
    foreach ($items in @(@(), @(@{ name = 'one' }, @{ name = 'two' }))) {
        $state.nodes = @{ items = $items }
        Expect-Failure { Get-GpuNode -KubeConfig 'offline' } 'Expected exactly one node'
    }
}
Case 'node lookup returns exactly one worker' {
    $state.nodes = @{ items = @(@{ name = 'one' }) }
    Assert ((Get-GpuNode -KubeConfig 'offline').name -eq 'one') 'Wrong node returned.'
}
Write-Host "$script:passed tests passed."
