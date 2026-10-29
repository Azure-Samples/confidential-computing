#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
$ErrorActionPreference = 'Stop'
$template = Get-Content (Join-Path $PSScriptRoot 'namespace.json') -Raw | ConvertFrom-Json
if ($template.variables.senderRole -ne '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39' -or
    $template.variables.receiverRole -ne '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0') {
    throw 'Template must use the built-in Service Bus Data Sender and Data Receiver role IDs.'
}
$testState = @{
    Attempts = [System.Collections.Generic.List[string]]::new()
    Deployments = 0
    Scenario = ''
}

function Get-AzContext {
    [pscustomobject]@{
        Subscription = @{ Id = '11111111-1111-1111-1111-111111111111' }
        Tenant = @{ Id = '22222222-2222-2222-2222-222222222222' }
        Environment = @{ Name = 'AzureCloud' }
    }
}
function Get-AzResourceGroup {
    [pscustomobject]@{ ResourceGroupName = 'rg-mock-servicebus' }
}
function New-AzResourceGroup { throw 'Tests must never create a resource group.' }
function Test-AzResourceGroupDeployment {
    param($location)
    $testState.Attempts.Add($location)
    if ($testState.Scenario -eq 'authorization') {
        return [pscustomobject]@{ Code = 'AuthorizationFailed'; Message = 'No roleAssignments/write permission' }
    }
    if ($testState.Scenario -eq 'invalid') {
        return [pscustomobject]@{ Code = 'BadRequest'; Message = 'Invalid namespace name' }
    }
    if ($testState.Scenario -eq 'all-regions' -or
        ($testState.Scenario -eq 'regional-preflight' -and $location -eq 'koreacentral')) {
        return [pscustomobject]@{ Code = 'BadRequest'; Message = "ConfidentialCompute is not supported in region $location" }
    }
    if ($testState.Scenario -eq 'empty-string-success') {
        return ''
    }
}
function New-AzResourceGroupDeployment {
    param($location)
    $testState.Deployments++
    if ($testState.Scenario -eq 'regional-deploy' -and $location -eq 'koreacentral') {
        throw 'DeploymentFailed'
    }
    [pscustomobject]@{
        Outputs = @{
            namespaceId = @{ Value = '/mock/namespace' }
            fullyQualifiedNamespace = @{ Value = "sbcc-mock-$location.servicebus.windows.net" }
        }
    }
}
function Get-AzResourceGroupDeploymentOperation {
    [pscustomobject]@{
        ProvisioningState = 'Failed'
        TargetResource = @{ ResourceType = 'Microsoft.ServiceBus/namespaces' }
        StatusMessage = @{ error = @{ code = 'RegionNotSupported'; message = 'ConfidentialCompute is not supported in region koreacentral' } }
    }
}
function Invoke-AzRestMethod {
    $mode = if ($testState.Scenario -eq 'not-confidential') { 'Disabled' } else { 'Enabled' }
    [pscustomobject]@{
        StatusCode = 200
        Content = @{
            location = $testState.Attempts[-1]
            sku = @{ name = 'Premium' }
            properties = @{
                disableLocalAuth = $true
                platformCapabilities = @{ confidentialCompute = @{ mode = $mode } }
            }
        } | ConvertTo-Json -Depth 10
    }
}

$cases = @(
    @{ Scenario = 'success'; Locations = 'koreacentral'; Deployments = 1; Error = $null },
    @{ Scenario = 'empty-string-success'; Locations = 'koreacentral'; Deployments = 1; Error = $null },
    @{ Scenario = 'regional-preflight'; Locations = 'koreacentral,uaenorth'; Deployments = 1; Error = $null },
    @{ Scenario = 'regional-deploy'; Locations = 'koreacentral,uaenorth'; Deployments = 2; Error = $null },
    @{ Scenario = 'authorization'; Locations = 'koreacentral'; Deployments = 0; Error = 'AuthorizationFailed' },
    @{ Scenario = 'invalid'; Locations = 'koreacentral'; Deployments = 0; Error = 'Invalid namespace name' },
    @{ Scenario = 'all-regions'; Locations = 'koreacentral,uaenorth'; Deployments = 0; Error = 'every requested location' },
    @{ Scenario = 'not-confidential'; Locations = 'koreacentral'; Deployments = 1; Error = 'Refusing to send' }
)
foreach ($case in $cases) {
    $testState.Scenario = $case.Scenario
    $testState.Attempts.Clear()
    $testState.Deployments = 0
    $caught = $null
    try {
        $result = & (Join-Path $PSScriptRoot 'Deploy-ServiceBus.ps1') -SkipMessages `
            -ResourceGroupName 'rg-mock-servicebus' -NamespacePrefix 'sbcc-mock' `
            -PrincipalId '33333333-3333-3333-3333-333333333333'
    }
    catch {
        $caught = $_.Exception.Message
    }
    if (($testState.Attempts -join ',') -ne $case.Locations -or $testState.Deployments -ne $case.Deployments) {
        throw "Incorrect deployment/fallback behavior: $($case.Scenario)"
    }
    if ($case.Error) {
        if (-not $caught -or $caught -notmatch [regex]::Escape($case.Error)) {
            throw "Expected error '$($case.Error)' for $($case.Scenario), got '$caught'"
        }
    }
    elseif ($caught -or $result.ConfidentialCompute -ne 'Enabled') {
        throw "Expected verified deployment for $($case.Scenario), got '$caught'"
    }
}
Write-Host "PASS: $($cases.Count) mocked deployment/preflight/verification scenarios (no Azure calls)."
