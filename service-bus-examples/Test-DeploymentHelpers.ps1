$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentHelpers.ps1')
$cases = @(
    @{ Message = 'ConfidentialCompute is not supported in region koreacentral'; Expected = $true },
    @{ Message = 'Region koreacentral is unavailable for confidential computing'; Expected = $true },
    @{ Message = 'SkuNotAvailable'; Expected = $true },
    @{ Message = 'InsufficientCapacity'; Expected = $true },
    @{ Message = 'AuthorizationFailed'; Expected = $false },
    @{ Message = 'Authorization failed: RegionNotSupported'; Expected = $false },
    @{ Message = 'RequestDisallowedByPolicy: confidential compute is not supported in this region'; Expected = $false },
    @{ Message = 'RoleAssignment failed: RegionNotSupported'; Expected = $false },
    @{ Message = 'BadRequest: invalid namespace name'; Expected = $false },
    @{ Message = 'Premium is unavailable'; Expected = $false }
)
foreach ($case in $cases) {
    if ((Test-RegionalAvailabilityError -Message $case.Message) -ne $case.Expected) {
        throw "Incorrect fallback classification: $($case.Message)"
    }
}
Write-Host "PASS: $($cases.Count) regional fallback classifications."
