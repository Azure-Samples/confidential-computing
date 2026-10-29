#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [ValidatePattern('^[a-zA-Z0-9._()-]+$')]
    [string]$ResourceGroupName = "rg-servicebus-confidential-demo-$([guid]::NewGuid().ToString('N').Substring(0, 8))",
    [ValidatePattern('^[a-z][a-z0-9-]{4,29}$')]
    [string]$NamespacePrefix = "sbcc-$([guid]::NewGuid().ToString('N').Substring(0, 12))",
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$QueueName = "sample-$([guid]::NewGuid().ToString('N').Substring(0, 8))",
    [ValidateNotNullOrEmpty()]
    [string[]]$Locations = @('koreacentral', 'uaenorth'),
    [string]$PrincipalId,
    [ValidateSet('User', 'ServicePrincipal')]
    [string]$PrincipalType = 'User',
    [switch]$SkipMessages
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentHelpers.ps1')

if (-not (Get-AzContext)) {
    throw 'Sign in with Connect-AzAccount before running this script.'
}
if ($SubscriptionId) {
    $null = Set-AzContext -SubscriptionId $SubscriptionId
}
$context = Get-AzContext
if ($context.Environment.Name -ne 'AzureCloud') {
    throw 'This preview sample targets Azure public cloud only.'
}
if (-not $SkipMessages) {
    $null = Get-Command node -ErrorAction Stop
    if (-not (Test-Path (Join-Path $PSScriptRoot 'node_modules\@azure\service-bus'))) {
        throw "Run npm ci in $PSScriptRoot before deploying."
    }
}
if (-not $PrincipalId) {
    if ($PrincipalType -ne 'User') {
        throw 'Pass -PrincipalId when using -PrincipalType ServicePrincipal.'
    }
    $PrincipalId = (Get-AzADUser -SignedIn).Id
    if (-not $PrincipalId) {
        throw 'Cannot resolve the signed-in user. For automation, pass -PrincipalId and -PrincipalType ServicePrincipal.'
    }
}
$null = [guid]::Parse($PrincipalId)
foreach ($location in $Locations) {
    if ($location -notmatch '^[a-z0-9]+$') {
        throw "Use Azure location codes, not display names: $location"
    }
}
Write-Host "Subscription: $($context.Subscription.Id); tenant: $($context.Tenant.Id)"
Write-Host "Resource group: $ResourceGroupName; data-plane principal: $PrincipalId"
Write-Warning 'Premium messaging units incur ongoing charges. Delete the demo resource group when finished.'

$group = Get-AzResourceGroup | Where-Object ResourceGroupName -eq $ResourceGroupName
if (-not $group) {
    $null = New-AzResourceGroup -Name $ResourceGroupName -Location $Locations[0] -Tag @{ sample = 'confidential-service-bus' }
}
Write-Host "Cleanup: Remove-AzResourceGroup -Name '$ResourceGroupName' (only if dedicated to this demo)"
$selectedNamespace = $null
foreach ($location in $Locations) {
    $namespaceName = "$NamespacePrefix-$location"
    $deploymentName = "sbcc-$location-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    Write-Host "Trying confidential Premium namespace '$namespaceName' in $location..."
    $deploymentStarted = $false
    try {
        $parameters = @{
            ResourceGroupName = $ResourceGroupName
            TemplateFile = Join-Path $PSScriptRoot 'namespace.json'
            namespaceName = $namespaceName
            location = $location
            queueName = $QueueName
            principalId = $PrincipalId
            principalType = $PrincipalType
        }
        $validationErrors = @(Test-AzResourceGroupDeployment @parameters | Where-Object {
            $null -ne $_ -and -not ($_ -is [string] -and [string]::IsNullOrWhiteSpace($_))
        })
        if ($validationErrors.Count -gt 0) {
            throw "Azure template preflight failed: $($validationErrors | ConvertTo-Json -Depth 20 -Compress)"
        }
        $deploymentStarted = $true
        $deployment = New-AzResourceGroupDeployment -Name $deploymentName @parameters
    }
    catch {
        $failure = $_
        $failedOperations = @()
        if ($deploymentStarted) {
            $operations = @(Get-AzResourceGroupDeploymentOperation -ResourceGroupName $ResourceGroupName `
                -DeploymentName $deploymentName)
            $failedOperations = @($operations | Where-Object ProvisioningState -eq 'Failed')
        }
        $details = ($failedOperations | ForEach-Object { $_.StatusMessage | ConvertTo-Json -Depth 20 -Compress }) -join "`n"
        $message = "$($failure.Exception.Message)`n$details"
        Write-Warning "Deployment in $location failed: $message"
        $nonNamespaceFailure = @($failedOperations | Where-Object {
            $_.TargetResource.ResourceType -ne 'Microsoft.ServiceBus/namespaces'
        })
        if ($nonNamespaceFailure.Count -gt 0 -or -not (Test-RegionalAvailabilityError -Message $message)) {
            throw $failure
        }
        if ($deploymentStarted) {
            Write-Warning "Regional availability failure; trying the next location. Inspect '$deploymentName' for any partial resources."
        }
        else {
            Write-Warning 'Regional availability preflight failed; trying the next location. No namespace was created by this attempt.'
        }
        continue
    }
    $namespaceId = $deployment.Outputs.namespaceId.Value
    $response = Invoke-AzRestMethod -Method GET -Path "${namespaceId}?api-version=2025-05-01-preview"
    if ($response.StatusCode -ne 200) {
        throw "Namespace verification failed: HTTP $($response.StatusCode): $($response.Content)"
    }
    $namespace = $response.Content | ConvertFrom-Json
    if ($namespace.sku.name -ne 'Premium' -or
        $namespace.properties.platformCapabilities.confidentialCompute.mode -ne 'Enabled' -or
        $namespace.properties.disableLocalAuth -ne $true) {
        throw 'Namespace does not report Premium, confidential compute Enabled, and local authentication disabled. Refusing to send.'
    }
    $selectedNamespace = $deployment.Outputs.fullyQualifiedNamespace.Value
    Write-Host "Verified: $selectedNamespace; location=$($namespace.location); Premium; confidentialCompute=Enabled"
    break
}
if (-not $selectedNamespace) {
    throw "Confidential Premium creation failed in every requested location: $($Locations -join ', '). See warnings and Azure deployments."
}
if (-not $SkipMessages) {
    & node (Join-Path $PSScriptRoot 'send-receive.mjs') $selectedNamespace $QueueName $context.Tenant.Id
    if ($LASTEXITCODE -ne 0) {
        throw "Message round-trip failed (exit $LASTEXITCODE). Resources remain in '$ResourceGroupName' for investigation."
    }
}
[pscustomobject]@{
    SubscriptionId = $context.Subscription.Id
    ResourceGroupName = $ResourceGroupName
    Namespace = $selectedNamespace
    QueueName = $QueueName
    Location = $namespace.location
    ConfidentialCompute = $namespace.properties.platformCapabilities.confidentialCompute.mode
}
