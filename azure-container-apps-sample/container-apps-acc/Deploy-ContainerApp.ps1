#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [ValidateSet('uaenorth', 'westeurope')][string]$Location = 'uaenorth',
    [ValidatePattern('^[a-zA-Z0-9._()-]{1,90}$')]
    [string]$ResourceGroupName = "rg-container-apps-acc-$([guid]::NewGuid().ToString('N').Substring(0, 8))",
    [ValidatePattern('^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$EnvironmentName = 'cae-acc-hello',
    [ValidatePattern('^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$AppName = 'ca-acc-hello',
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentHelpers.ps1')

if (-not (Get-AzContext)) {
    throw 'Sign in with Connect-AzAccount before running this script.'
}
$currentContext = Get-AzContext
$context = Set-AzContext -SubscriptionId $SubscriptionId -TenantId $currentContext.Tenant.Id -ErrorAction Stop
if ($context.Environment.Name -ne 'AzureCloud') {
    throw 'This sample supports Azure public cloud only.'
}
Write-Host "Subscription: $SubscriptionId; tenant: $($context.Tenant.Id); region: $Location"
Write-Host "Resource group: $ResourceGroupName; environment: $EnvironmentName; app: $AppName"
Write-Warning 'One dedicated DC4 node will incur ongoing charges. Nothing is automatically deleted, including on failure.'
foreach ($namespace in @('Microsoft.App', 'Microsoft.Network')) {
    $provider = Get-ArmJson -Path "/subscriptions/$SubscriptionId/providers/${namespace}?api-version=2021-04-01"
    if ($provider.registrationState -ne 'Registered') {
        throw "Register $namespace with Register-AzResourceProvider -ProviderNamespace $namespace and wait for Registered, then retry."
    }
}
$regionalBase = "/subscriptions/$SubscriptionId/providers/Microsoft.App/locations/$Location"
$types = Get-ArmJson -Path "${regionalBase}/availableManagedEnvironmentsWorkloadProfileTypes?api-version=2025-07-01"
if (-not ($types.value | Where-Object name -eq 'DC4')) {
    throw "$Location does not advertise DC4 for this subscription. No other compute or region will be used."
}
$usage = Get-ArmJson -Path "${regionalBase}/usages?api-version=2025-07-01"
$quota = @($usage.value | Where-Object { $_.name.value -eq 'ManagedEnvironmentCount' })
if ($quota.Count -ne 1 -or $null -eq $quota[0].currentValue -or $null -eq $quota[0].limit) {
    throw 'Could not determine the regional managed-environment quota. Check Azure quota before retrying.'
}
if ($quota[0].currentValue -ge $quota[0].limit) {
    throw "$Location managed-environment quota exhausted ($($quota[0].currentValue)/$($quota[0].limit)). Request quota; no fallback is permitted."
}

$group = Get-AzResourceGroup -ErrorAction Stop | Where-Object ResourceGroupName -eq $ResourceGroupName
if ($group) {
    if ($group.Tags['sample'] -ne 'container-apps-acc' -or
        @(Get-AzResource -ResourceGroupName $ResourceGroupName -ErrorAction Stop).Count -ne 0) {
        throw 'Refusing to deploy into an existing populated or unrelated resource group. Use a new dedicated group; use Test-ContainerApp.ps1 to verify an existing deployment.'
    }
}
else {
    $null = New-AzResourceGroup -Name $ResourceGroupName -Location $Location `
        -Tag @{ sample = 'container-apps-acc' } -ErrorAction Stop
}

$parameters = @{
    ResourceGroupName = $ResourceGroupName
    TemplateFile = Join-Path $PSScriptRoot 'main.json'
    TemplateParameterObject = @{
        location = $Location
        environmentName = $EnvironmentName
        appName = $AppName
    }
    ErrorAction = 'Stop'
}
$deploymentName = "acc-hello-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
try {
    # Az.Resources can return an empty string rather than no output on success.
    $errors = @(Test-AzResourceGroupDeployment @parameters | Where-Object { $null -ne $_ -and $_ -cne '' })
    if ($errors.Count -gt 0) {
        throw "ARM validation failed: $($errors | ConvertTo-Json -Depth 20 -Compress)"
    }
    if ($ValidateOnly) {
        Write-Host "ARM validation passed. Only the empty resource group '$ResourceGroupName' has been created; no app or environment deployed."
        return
    }
    $deployment = New-AzResourceGroupDeployment -Name $deploymentName @parameters
    if ($deployment.ProvisioningState -ne 'Succeeded') {
        throw "Deployment '$deploymentName' did not succeed: $($deployment.ProvisioningState)"
    }
    & (Join-Path $PSScriptRoot 'Test-ContainerApp.ps1') -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName -EnvironmentName $EnvironmentName -AppName $AppName -Location $Location
}
catch {
    Write-Warning "Validation, deployment or verification failed. Resources are retained in '$ResourceGroupName'. Inspect deployment '$deploymentName' and any partial resources; this is NOT a successful confidential deployment."
    Write-Warning "Resource group: https://portal.azure.com/#resource/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/overview"
    throw
}
