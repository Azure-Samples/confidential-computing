#Requires -Version 7.0
#Requires -Modules Az.Accounts
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9._()-]{1,90}$')][string]$ResourceGroupName,
    [ValidatePattern('^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$EnvironmentName = 'cae-acc-hello',
    [ValidatePattern('^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$AppName = 'ca-acc-hello'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentHelpers.ps1')

if (-not (Get-AzContext)) {
    throw 'Sign in with Connect-AzAccount first.'
}
$currentContext = Get-AzContext
$context = Set-AzContext -SubscriptionId $SubscriptionId -TenantId $currentContext.Tenant.Id -ErrorAction Stop
if ($context.Environment.Name -ne 'AzureCloud') {
    throw 'This sample supports Azure public cloud only.'
}
$base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App"
for ($attempt = 1; $attempt -le 60; $attempt++) {
    $environment = Get-ArmJson -Path "$base/managedEnvironments/${EnvironmentName}?api-version=2025-07-01"
    $app = Get-ArmJson -Path "$base/containerApps/${AppName}?api-version=2025-07-01"
    $states = @($environment.properties.provisioningState, $app.properties.provisioningState)
    if (@($states | Where-Object { $_ -notin @('Succeeded', 'Creating', 'Updating', 'InProgress') }).Count -gt 0) {
        throw "Unexpected or failed provisioning state: environment=$($states[0]); app=$($states[1])."
    }
    if ($states[0] -eq 'Succeeded' -and $states[1] -eq 'Succeeded' -and
        -not [string]::IsNullOrWhiteSpace($app.properties.latestRevisionName) -and
        $app.properties.latestReadyRevisionName -eq $app.properties.latestRevisionName) {
        break
    }
    if ($attempt -eq 60) {
        throw 'Timed out waiting for successful provisioning and the latest ready revision; resources are retained.'
    }
    Write-Host "Waiting for provisioning and revision readiness ($attempt/60)."
    Start-Sleep -Seconds 10
}
$url = Assert-ConfidentialContainerApp -App $app -Environment $environment
Test-HelloWorldEndpoint -Uri $url

[pscustomobject]@{
    SubscriptionId = $SubscriptionId
    ResourceGroupName = $ResourceGroupName
    EnvironmentId = $environment.id
    AppId = $app.id
    Location = $app.location
    WorkloadProfileName = $app.properties.workloadProfileName
    WorkloadProfileType = 'DC4'
    AppUrl = $url
    PortalUrl = "https://portal.azure.com/#resource$($app.id)/overview"
    Verification = 'Azure-reported DC4 placement and HTTPS hello-world response (not cryptographic attestation)'
}
