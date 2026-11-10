#Requires -Version 7.2
[CmdletBinding(DefaultParameterSetName = 'Kernel')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Kernel')]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-azure-fde$')]
    [string]$KernelVersion,
    [Parameter(Mandatory, ParameterSetName = 'Node')][string]$KubeConfig,
    [Parameter(ParameterSetName = 'Node')][string]$PoolName = 'gpunp',
    [ValidateNotNullOrEmpty()][string[]]$DriverBranches = @('580', '595'),
    [string]$OutputPath,
    [switch]$RequireAvailable
)
. (Join-Path $PSScriptRoot 'Common.ps1')

if ($PSCmdlet.ParameterSetName -eq 'Node') {
    $node = Get-GpuNode -KubeConfig $KubeConfig -PoolName $PoolName
    if ($node.status.nodeInfo.osImage -notlike 'Ubuntu 24.04*') {
        throw "Unsupported worker OS: $($node.status.nodeInfo.osImage). Expected Ubuntu 24.04."
    }
    $KernelVersion = $node.status.nodeInfo.kernelVersion
}
if ($KernelVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-azure-fde$') {
    throw "Unsupported confidential worker kernel: $KernelVersion."
}
$results = @(foreach ($branch in $DriverBranches) {
    if ($branch -notmatch '^[0-9]+$') { throw "Invalid driver branch: $branch" }
    Get-DriverManifest -Tag "$branch-$KernelVersion-ubuntu24.04"
})
$report = [pscustomobject]@{
    KernelVersion = $KernelVersion
    Manifests = $results
    MatchingImageAvailable = (@($results | Where-Object Available).Count -gt 0)
    SupportValidated = $false
}
$json = $report | ConvertTo-Json -Depth 10
if ($OutputPath) { $json | Set-Content -LiteralPath $OutputPath }
$json
if ($RequireAvailable -and -not $report.MatchingImageAvailable) {
    throw "BLOCKED: no exact-kernel driver image for $KernelVersion. Do not install a different kernel's module or downgrade the AKS image."
}
