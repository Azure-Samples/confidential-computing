#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
$ErrorActionPreference = 'Stop'
$sampleRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $sampleRoot 'DeploymentHelpers.ps1')
$script:passed = 0
$state = @{}

function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Expect-Failure([scriptblock]$Action, [string]$Pattern) {
    try { & $Action }
    catch {
        Assert ($_.Exception.Message -match $Pattern) "Unexpected error: $_"
        return
    }
    throw "Expected a failure matching '$Pattern'."
}
function Case([string]$Name, [scriptblock]$Action) {
    & $Action
    $script:passed++
    Write-Host "PASS $Name"
}
function New-Fixture {
    @{
        Environment = @{
            id = '/subscriptions/test/resourceGroups/test/providers/Microsoft.App/managedEnvironments/test'
            location = $state.fixtureLocation ?? 'uaenorth'
            properties = @{
                provisioningState = 'Succeeded'
                workloadProfiles = @(@{ name = 'confidential'; workloadProfileType = 'DC4'; minimumCount = 1; maximumCount = 1 })
            }
        }
        App = @{
            id = '/subscriptions/test/resourceGroups/test/providers/Microsoft.App/containerApps/test'
            location = $state.fixtureLocation ?? 'uaenorth'
            properties = @{
                provisioningState = 'Succeeded'
                environmentId = '/subscriptions/test/resourceGroups/test/providers/Microsoft.App/managedEnvironments/test'
                workloadProfileName = 'confidential'
                latestRevisionName = 'test--ready'
                latestReadyRevisionName = 'test--ready'
                configuration = @{ ingress = @{ external = $true; allowInsecure = $false; targetPort = 80; fqdn = 'test.example.com' } }
            }
        }
    }
}

# All external calls are mocked at script scope, including the child deployment script.
function Get-AzContext { @{ Environment = @{ Name = 'AzureCloud' }; Tenant = @{ Id = 'offline-test' } } }
function Set-AzContext { @{ Environment = @{ Name = 'AzureCloud' }; Tenant = @{ Id = 'offline-test' } } }
function Get-AzResourceGroup {
    if ($state.existing) { @{ ResourceGroupName = 'rg-offline'; Tags = @{ sample = 'container-apps-acc' } } }
}
function Get-AzResource { if ($state.populated) { @{ Name = 'unrelated' } } }
function New-AzResourceGroup { param($Location) $state.groupCreates++; $state.groupLocation = $Location }
function Test-AzResourceGroupDeployment {
    if ($state.invalid) { @{ Code = 'InvalidTemplate'; Message = 'test rejection' } }
    elseif ($state.validationEmptyString) { '' }
}
function New-AzResourceGroupDeployment {
    param($TemplateParameterObject)
    $state.templateLocation = $TemplateParameterObject.location
    $state.deployments++
    if ($state.deployFails) { throw 'Mock capacity rejection' }
    @{ ProvisioningState = 'Succeeded' }
}
function Invoke-AzRestMethod {
    param($Path)
    if ($state.restFails) { return @{ StatusCode = 403; Content = 'Forbidden' } }
    $data = switch -Wildcard ($Path) {
        '*availableManagedEnvironmentsWorkloadProfileTypes*' {
            $state.profilePath = $Path
            if ($state.noProfile) { @{ value = @() } }
            else { @{ value = @(@{ name = 'DC4' }) } }
        }
        '*/usages?*' { @{ value = @(@{ name = @{ value = 'ManagedEnvironmentCount' }; currentValue = 0; limit = $state.limit }) } }
        '*/managedEnvironments/*' {
            $state.environmentReads++
            $environment = (New-Fixture).Environment
            if ($state.environmentReads -le $state.updatingReads) {
                $environment.properties.provisioningState = 'Updating'
            }
            if ($state.failedEnvironment) { $environment.properties.provisioningState = 'Failed' }
            $environment
        }
        '*/containerApps/*' { (New-Fixture).App }
        default { @{ registrationState = $state.registration } }
    }
    @{ StatusCode = 200; Content = ($data | ConvertTo-Json -Depth 20) }
}
function Invoke-WebRequest {
    $state.httpCalls++
    $status = if ($state.httpCalls -le $state.transientCount) { 503 } else { $state.httpStatus }
    @{ StatusCode = $status; Content = $state.content }
}
function Start-Sleep {}
function Reset-Mocks {
    $state.fixtureLocation = 'uaenorth'
    $state.groupLocation = $null
    $state.templateLocation = $null
    $state.profilePath = $null
    $state.existing = $false
    $state.populated = $false
    $state.groupCreates = 0
    $state.deployments = 0
    $state.invalid = $false
    $state.validationEmptyString = $true
    $state.deployFails = $false
    $state.restFails = $false
    $state.noProfile = $false
    $state.limit = 50
    $state.registration = 'Registered'
    $state.httpCalls = 0
    $state.httpStatus = 200
    $state.transientCount = 0
    $state.content = '<html>Azure Container Apps hello world</html>'
    $state.environmentReads = 0
    $state.updatingReads = 0
    $state.failedEnvironment = $false
}
$deployArgs = @{ SubscriptionId = '00000000-0000-0000-0000-000000000001'; ResourceGroupName = 'rg-offline' }
$deployScript = Join-Path $sampleRoot 'Deploy-ContainerApp.ps1'

Case 'PowerShell parses cleanly' {
    foreach ($file in Get-ChildItem $sampleRoot -Filter '*.ps1' -Recurse) {
        $tokens = $null; $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        Assert ($parseErrors.Count -eq 0) ($parseErrors -join "`n")
    }
}
Case 'ARM template binds DC4, HTTPS and bounded scaling' {
    $template = Get-Content (Join-Path $sampleRoot 'main.json') -Raw | ConvertFrom-Json
    $envResource = $template.resources | Where-Object type -eq 'Microsoft.App/managedEnvironments'
    $appResource = $template.resources | Where-Object type -eq 'Microsoft.App/containerApps'
    Assert ($template.resources.Count -eq 4) 'Unexpected supporting resources.'
    Assert ($template.parameters.location.defaultValue -eq 'uaenorth') 'Default region changed.'
    Assert (($template.parameters.location.allowedValues -join ',') -eq 'uaenorth,westeurope') 'Unexpected region allowed.'
    Assert ($envResource.properties.workloadProfiles.Count -eq 1) 'Unexpected additional profiles.'
    Assert ($envResource.properties.appLogsConfiguration.destination -ceq '') 'Expected disabled centralized logging via empty ARM destination.'
    $profile = $envResource.properties.workloadProfiles[0]
    Assert ($profile.workloadProfileType -eq 'DC4' -and $profile.minimumCount -eq 1 -and $profile.maximumCount -eq 1) 'Not one DC4 node.'
    Assert ($appResource.properties.workloadProfileName -eq $profile.name) 'Profile binding mismatch.'
    Assert ($appResource.properties.environmentId -eq $appResource.dependsOn[0]) 'Environment dependency mismatch.'
    Assert ($appResource.properties.configuration.ingress.allowInsecure -eq $false -and $appResource.properties.configuration.ingress.external -eq $true) 'Incorrect ingress.'
    Assert ($appResource.properties.configuration.ingress.targetPort -eq 80) 'Wrong target port.'
    Assert ($appResource.properties.template.scale.minReplicas -eq 1 -and $appResource.properties.template.scale.maxReplicas -eq 1) 'Unexpected scaling.'
    Assert ($appResource.properties.template.containers[0].image -eq 'mcr.microsoft.com/k8se/quickstart:latest') 'Wrong quickstart image.'
    $vnet = $template.resources | Where-Object type -eq 'Microsoft.Network/virtualNetworks'
    Assert ($vnet.properties.subnets[0].properties.delegations[0].properties.serviceName -eq 'Microsoft.App/environments') 'Missing subnet delegation.'
    Assert ($null -ne $vnet.properties.subnets[0].properties.networkSecurityGroup.id) 'Missing subnet NSG.'
    Assert ($null -ne $envResource.properties.vnetConfiguration.infrastructureSubnetId -and $envResource.properties.vnetConfiguration.internal -eq $false) 'Missing external VNet-integrated environment.'
}
Case 'Accept valid Azure-reported confidential placement' {
    $f = New-Fixture
    Assert ((Assert-ConfidentialContainerApp -App $f.App -Environment $f.Environment) -eq 'https://test.example.com') 'Wrong URL.'
}
Case 'Accept explicitly selected West Europe and reject region mismatch' {
    $f = New-Fixture
    $f.App.location = 'West Europe'
    $f.Environment.location = 'westeurope'
    Assert ((Assert-ConfidentialContainerApp -App $f.App -Environment $f.Environment -Location westeurope) -eq 'https://test.example.com') 'West Europe rejected.'
    Expect-Failure { Assert-ConfidentialContainerApp -App $f.App -Environment $f.Environment } 'Expected the app and environment'
    $f.Environment.location = 'uaenorth'
    Expect-Failure { Assert-ConfidentialContainerApp -App $f.App -Environment $f.Environment -Location westeurope } 'Expected the app and environment'
}
Case 'Accept UAE North display name returned by the live API' {
    $f = New-Fixture
    $f.App.location = 'UAE North'
    $f.Environment.location = 'UAE North'
    Assert ((Assert-ConfidentialContainerApp -App $f.App -Environment $f.Environment) -eq 'https://test.example.com') 'Region display name rejected.'
}
Case 'Wait for transient environment update before verifying' {
    Reset-Mocks
    $state.updatingReads = 2
    $result = & (Join-Path $sampleRoot 'Test-ContainerApp.ps1') @deployArgs
    Assert ($result.WorkloadProfileType -eq 'DC4' -and $state.environmentReads -eq 3) 'Readiness wait failed.'
}
Case 'Bound readiness polling and never verify a failed environment' {
    Reset-Mocks
    $state.updatingReads = 60
    Expect-Failure { & (Join-Path $sampleRoot 'Test-ContainerApp.ps1') @deployArgs } 'Timed out'
    Assert ($state.environmentReads -eq 60 -and $state.httpCalls -eq 0) 'Unbounded polling or premature endpoint verification.'
    Reset-Mocks
    $state.failedEnvironment = $true
    Expect-Failure { & (Join-Path $sampleRoot 'Test-ContainerApp.ps1') @deployArgs } 'failed provisioning'
    Assert ($state.environmentReads -eq 1 -and $state.httpCalls -eq 0) 'Failed environment was retried or accepted.'
}
foreach ($change in @(
    @{ Name = 'Consumption binding'; Edit = { param($f) $f.App.properties.workloadProfileName = 'Consumption' }; Pattern = 'DC4' },
    @{ Name = 'ordinary D4 profile'; Edit = { param($f) $f.Environment.properties.workloadProfiles[0].workloadProfileType = 'D4' }; Pattern = 'DC4' },
    @{ Name = 'wrong environment'; Edit = { param($f) $f.App.properties.environmentId = '/other' }; Pattern = 'environment' },
    @{ Name = 'unready revision'; Edit = { param($f) $f.App.properties.latestReadyRevisionName = 'old' }; Pattern = 'not ready' },
    @{ Name = 'insecure ingress'; Edit = { param($f) $f.App.properties.configuration.ingress.allowInsecure = $true }; Pattern = 'HTTPS-only' },
    @{ Name = 'failed provisioning'; Edit = { param($f) $f.Environment.properties.provisioningState = 'Failed' }; Pattern = 'Succeeded' },
    @{ Name = 'wrong region'; Edit = { param($f) $f.App.location = 'eastus' }; Pattern = 'Expected the app and environment in uaenorth' },
    @{ Name = 'malformed FQDN'; Edit = { param($f) $f.App.properties.configuration.ingress.fqdn = 'example.com/other' }; Pattern = 'FQDN' }
)) {
    Case "Reject $($change.Name)" {
        $f = New-Fixture
        & $change.Edit $f
        Expect-Failure { Assert-ConfidentialContainerApp -App $f.App -Environment $f.Environment } $change.Pattern
    }
}
Case 'Retry transient HTTP failure then require content' {
    Reset-Mocks; $state.transientCount = 1
    Test-HelloWorldEndpoint -Uri 'https://test.example.com' -DelaySeconds 0
    Assert ($state.httpCalls -eq 2) 'Did not retry.'
}
Case 'Reject HTTP 200 without hello-world signature' {
    Reset-Mocks; $state.content = 'unrelated page'
    Expect-Failure { Test-HelloWorldEndpoint -Uri 'https://test.example.com' } 'signature'
}
Case 'Reject persistent HTTP failure' {
    Reset-Mocks; $state.httpStatus = 503
    Expect-Failure { Test-HelloWorldEndpoint -Uri 'https://test.example.com' -Attempts 2 -DelaySeconds 0 } 'after 2'
}
Case 'Reject plaintext endpoint and redirects' {
    Reset-Mocks
    Expect-Failure { Test-HelloWorldEndpoint -Uri 'http://test.example.com' } 'HTTPS'
    $state.httpStatus = 302
    Expect-Failure { Test-HelloWorldEndpoint -Uri 'https://test.example.com' } 'HTTP 302'
}
Case 'ValidateOnly never provisions compute' {
    Reset-Mocks
    & $deployScript @deployArgs -ValidateOnly
    Assert ($state.groupCreates -eq 1 -and $state.deployments -eq 0) 'ValidateOnly deployed resources.'
}
Case 'ARM preflight failure prevents deployment' {
    Reset-Mocks; $state.invalid = $true
    Expect-Failure { & $deployScript @deployArgs } 'ARM validation failed'
    Assert ($state.deployments -eq 0) 'Deployed after failed validation.'
}
Case 'Provider, profile, quota and access failures prevent group creation' {
    foreach ($flag in @('registration', 'noProfile', 'limit', 'restFails')) {
        Reset-Mocks
        switch ($flag) {
            registration { $state.registration = 'NotRegistered'; $pattern = 'Register Microsoft.App' }
            noProfile { $state.noProfile = $true; $pattern = 'does not advertise DC4' }
            limit { $state.limit = 0; $pattern = 'quota exhausted' }
            restFails { $state.restFails = $true; $pattern = 'HTTP 403' }
        }
        Expect-Failure { & $deployScript @deployArgs } $pattern
        Assert ($state.groupCreates -eq 0 -and $state.deployments -eq 0) 'Created resources after prerequisite failure.'
    }
}
Case 'Refuse populated existing group' {
    Reset-Mocks; $state.existing = $true; $state.populated = $true
    Expect-Failure { & $deployScript @deployArgs } 'Refusing'
    Assert ($state.deployments -eq 0) 'Modified populated group.'
}
Case 'Preserve deployment failure instead of claiming success' {
    Reset-Mocks; $state.deployFails = $true
    Expect-Failure { & $deployScript @deployArgs } 'Mock capacity rejection'
    Assert ($state.deployments -eq 1) 'Unexpected fallback attempt.'
}
Case 'Successful deployment returns verified result and retains resources' {
    Reset-Mocks; $state.existing = $true
    $result = & $deployScript @deployArgs
    Assert ($state.groupCreates -eq 0 -and $state.deployments -eq 1) 'Unexpected resource changes.'
    Assert ($result.WorkloadProfileType -eq 'DC4' -and $result.AppUrl -eq 'https://test.example.com') 'Missing verification result.'
}
Case 'HTTP verification failure propagates from deployment' {
    Reset-Mocks; $state.content = 'wrong app'
    Expect-Failure { & $deployScript @deployArgs } 'signature'
}
Case 'Explicit West Europe flows through discovery, deployment and verification' {
    Reset-Mocks; $state.fixtureLocation = 'westeurope'
    $result = & $deployScript @deployArgs -Location westeurope
    Assert ($state.profilePath -match '/locations/westeurope/') 'Discovery used the wrong region.'
    Assert ($state.groupLocation -eq 'westeurope' -and $state.templateLocation -eq 'westeurope') 'Deployment used the wrong region.'
    Assert ($result.Location -eq 'westeurope' -and $result.WorkloadProfileType -eq 'DC4') 'Verification used the wrong region.'
}
Write-Host "$script:passed offline tests passed."
