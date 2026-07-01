<#
.SYNOPSIS
Deploy a confidential ACI demo that uses Secure Key Release for client-side encryption.

.DESCRIPTION
Creates a new resource group named <prefix><5-random-letters>, then deploys:
- User-assigned managed identity
- Azure Container Registry
- Storage account (Blob/Table/Queue)
- Key Vault Premium with key: customer-secret-key
- Confidential ACI running a Flask UI + SKR service

The web app:
- Shows the secure key release process
- Encrypts an initial string supplied on the command line
- Stores encrypted records in Blob, Table, and Queue
- Shows encrypted and decrypted values side by side

.PARAMETER SecretString
Initial string to encrypt and store.

.PARAMETER Prefix
Prefix used for naming resources. The resource group will be named <prefix><5 letters>.

.PARAMETER Location
Azure region. Default: eastus.

.PARAMETER SubscriptionId
Optional subscription ID. If omitted, uses current az account.

.PARAMETER SkipBrowser
Do not auto-open browser after deployment.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SecretString,

    [Parameter(Mandatory = $true)]
    [string]$Prefix,

    [string]$Location = "eastus",
    [string]$SubscriptionId,
    [string]$SubnetId = "",
    [switch]$SkipBrowser
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function New-RandomLetters {
    param([int]$Count = 5)
    -join ((97..122) | Get-Random -Count $Count | ForEach-Object { [char]$_ })
}

function New-SafeName {
    param(
        [string]$Raw,
        [int]$MaxLength,
        [string]$Fallback = "sample"
    )

    $value = ($Raw.ToLower() -replace "[^a-z0-9]", "")
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = $Fallback
    }
    if ($value.Length -gt $MaxLength) {
        $value = $value.Substring(0, $MaxLength)
    }
    return $value
}

function Invoke-Az {
    param([string]$CommandText)
    Write-Host "-> $CommandText" -ForegroundColor DarkGray
    $result = Invoke-Expression $CommandText
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $CommandText"
    }
    return $result
}

function Test-RoleAssignmentPermission {
    param(
        [string]$SubscriptionId,
        [string]$Upn
    )

    $scope = "/subscriptions/$SubscriptionId"
    $allowedRoles = @(
        "Owner",
        "User Access Administrator",
        "Role Based Access Control Administrator"
    )

    try {
        $assignments = Invoke-Az "az role assignment list --assignee `"$Upn`" --scope $scope --include-inherited --output json" | ConvertFrom-Json
    } catch {
        throw "Unable to query role assignments for $Upn at $scope. Re-run after refreshing Azure credentials if needed."
    }

    try {
        $permissionsUri = "https://management.azure.com$scope/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"
        $permissionsResponse = Invoke-Az "az rest --method get --uri $permissionsUri --output json" | ConvertFrom-Json
    } catch {
        throw "Unable to query effective Azure permissions for $scope. Re-run after refreshing Azure credentials if needed."
    }

    $matches = @($assignments | Where-Object { $allowedRoles -contains $_.roleDefinitionName })
    $grantsRoleAssignmentWrite = $false

    foreach ($entry in @($permissionsResponse.value)) {
        $actions = @($entry.actions)
        $notActions = @($entry.notActions)
        $allowsWrite = ($actions -contains "*") -or ($actions -contains "Microsoft.Authorization/*") -or ($actions -contains "Microsoft.Authorization/roleAssignments/*") -or ($actions -contains "Microsoft.Authorization/roleAssignments/write")
        $deniesWrite = ($notActions -contains "Microsoft.Authorization/*") -or ($notActions -contains "Microsoft.Authorization/roleAssignments/*") -or ($notActions -contains "Microsoft.Authorization/roleAssignments/write")

        if ($allowsWrite -and -not $deniesWrite) {
            $grantsRoleAssignmentWrite = $true
            break
        }
    }

    return [pscustomobject]@{
        Scope = $scope
        AllowedRoles = $allowedRoles
        MatchingAssignments = $matches
        CanAssignRoles = $matches.Count -gt 0 -and $grantsRoleAssignmentWrite
        HasMatchingRole = $matches.Count -gt 0
        HasEffectiveWritePermission = $grantsRoleAssignmentWrite
    }
}

function Assert-RoleAssignmentPermission {
    param(
        [string]$SubscriptionId,
        [string]$Upn
    )

    Write-Header "Checking required Azure roles"
    $permission = Test-RoleAssignmentPermission -SubscriptionId $SubscriptionId -Upn $Upn

    if ($permission.CanAssignRoles) {
        $roles = ($permission.MatchingAssignments | Select-Object -ExpandProperty roleDefinitionName -Unique) -join ", "
        Write-Host "Verified role-assignment capability at $($permission.Scope)" -ForegroundColor Green
        Write-Host "Active role(s): $roles"
        return
    }

    $expected = $permission.AllowedRoles -join ", "
    $detail = if ($permission.HasMatchingRole -and -not $permission.HasEffectiveWritePermission) {
        "A matching role assignment was found, but the current token does not have effective Microsoft.Authorization/roleAssignments/write permission yet. If you just activated the role through PIM, refresh Azure CLI authentication and open a new shell before re-running."
    } else {
        "No active assignment was found that can grant roleAssignments/write at the required scope."
    }
    $message = @(
        "Missing required Azure RBAC permissions before deployment starts.",
        "This script needs one of these active roles at subscription scope: $expected.",
        "Checked scope: $($permission.Scope)",
        $detail,
        "If your organization uses Microsoft Entra Privileged Identity Management (PIM), activate one of those roles and then re-run the script.",
        "No resources were created because the check ran before provisioning."
    ) -join " `n"

    throw $message
}

Write-Header "Preparing deployment"

if ($SubscriptionId) {
    Invoke-Az "az account set --subscription $SubscriptionId"
}

$account = Invoke-Az "az account show --output json" | ConvertFrom-Json
$upn = $account.user.name

if ([string]::IsNullOrWhiteSpace($upn)) {
    throw "Could not resolve current user UPN from 'az account show'."
}

Assert-RoleAssignmentPermission -SubscriptionId $account.id -Upn $upn

$prefixSafe = New-SafeName -Raw $Prefix -MaxLength 10 -Fallback "cse"
$random5 = New-RandomLetters -Count 5

$resourceGroupName = "$prefixSafe$random5"
$acrName = New-SafeName -Raw ("$prefixSafe" + "acr" + (New-RandomLetters -Count 8)) -MaxLength 50 -Fallback "cseacr"
$storageName = New-SafeName -Raw ("$prefixSafe" + "st" + (New-RandomLetters -Count 8)) -MaxLength 24 -Fallback "csestorage"
$keyVaultName = New-SafeName -Raw ("$prefixSafe" + "kv" + (New-RandomLetters -Count 10)) -MaxLength 24 -Fallback "csekv"
$identityName = "$prefixSafe-id"
$containerGroupName = "$prefixSafe-cse-aci"
$dnsLabel = New-SafeName -Raw ("$prefixSafe" + (New-RandomLetters -Count 8)) -MaxLength 60 -Fallback "csedemo"
$imageName = "client-side-encryption-demo"
$imageTag = "latest"
$maaEndpoint = "sharedeus.eus.attest.azure.net"
$keyName = "customer-secret-key"

$tags = @{
    ownerUpn = $upn
    scenario = "client-side-encryption"
    createdBy = "Deploy-ClientSideEncryption.ps1"
}
$tagArgs = ($tags.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join " "

Write-Host "Subscription: $($account.id)"
Write-Host "UPN:          $upn"
Write-Host "ResourceGroup:$resourceGroupName"
Write-Host "ACR:          $acrName"
Write-Host "Storage:      $storageName"
Write-Host "Key Vault:    $keyVaultName"
Write-Host "Identity:     $identityName"
Write-Host ""

Write-Header "Creating resource group"
Invoke-Az "az group create --name $resourceGroupName --location $Location --tags $tagArgs --output table"

Write-Header "Creating managed identity"
Invoke-Az "az identity create --resource-group $resourceGroupName --name $identityName --tags $tagArgs --output table"
$identityJson = Invoke-Az "az identity show --resource-group $resourceGroupName --name $identityName --output json" | ConvertFrom-Json
$identityResourceId = $identityJson.id
$identityPrincipalId = $identityJson.principalId
$identityClientId = $identityJson.clientId

Write-Header "Creating Azure Container Registry"
Invoke-Az "az acr create --resource-group $resourceGroupName --name $acrName --sku Basic --admin-enabled false --tags $tagArgs --output table"
$resourceGroupScope = "/subscriptions/$($account.id)/resourceGroups/$resourceGroupName"
$acrId = (Invoke-Az "az acr show --resource-group $resourceGroupName --name $acrName --query id --output tsv").Trim()
$acrLoginServer = (Invoke-Az "az acr show --resource-group $resourceGroupName --name $acrName --query loginServer --output tsv").Trim()

Write-Header "Creating policy-aware storage account"
try {
    Invoke-Az "az storage account create --name $storageName --resource-group $resourceGroupName --location $Location --sku Standard_LRS --kind StorageV2 --https-only true --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false --public-network-access Enabled --tags $tagArgs --output table"
} catch {
    Write-Host "Secure create options were restricted; retrying with baseline compliant options..." -ForegroundColor Yellow
    Invoke-Az "az storage account create --name $storageName --resource-group $resourceGroupName --location $Location --sku Standard_LRS --kind StorageV2 --https-only true --min-tls-version TLS1_2 --allow-blob-public-access false --public-network-access Enabled --tags $tagArgs --output table"
}

$storageId = (Invoke-Az "az storage account show --resource-group $resourceGroupName --name $storageName --query id --output tsv").Trim()

# Enforce secure settings post-create to align with common Azure Policy baselines.
Invoke-Az "az storage account update --resource-group $resourceGroupName --name $storageName --https-only true --min-tls-version TLS1_2 --allow-blob-public-access false --public-network-access Enabled --output none"

Write-Header "Creating Key Vault and SKR key"
Invoke-Az "az keyvault create --name $keyVaultName --resource-group $resourceGroupName --location $Location --sku premium --enable-rbac-authorization false --enable-purge-protection true --tags $tagArgs --output table"

$akvEndpoint = (Invoke-Az "az keyvault show --name $keyVaultName --query properties.vaultUri --output tsv").Trim()

Invoke-Az "az keyvault set-policy --name $keyVaultName --object-id $identityPrincipalId --key-permissions get release --output none"

$policyPath = Join-Path $PSScriptRoot "skr-release-policy.json"
$policyObject = @{
    version = "1.0.0"
    anyOf = @(
        @{
            authority = "https://$maaEndpoint"
            allOf = @(
                @{
                    claim = "x-ms-attestation-type"
                    equals = "sevsnpvm"
                }
            )
        }
    )
}
$policyObject | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Encoding UTF8

Invoke-Az "az keyvault key create --vault-name $keyVaultName --name $keyName --kty RSA-HSM --size 2048 --ops encrypt decrypt wrapKey unwrapKey --exportable true --policy $policyPath --output table"
Remove-Item $policyPath -Force

Write-Header "Assigning RBAC roles"
$roles = @(
    @{ Name = "AcrPull"; Scope = $resourceGroupScope },
    @{ Name = "Storage Blob Data Contributor"; Scope = $resourceGroupScope },
    @{ Name = "Storage Queue Data Contributor"; Scope = $resourceGroupScope },
    @{ Name = "Storage Table Data Contributor"; Scope = $resourceGroupScope }
)

foreach ($role in $roles) {
    try {
        Invoke-Az "az role assignment create --assignee-object-id $identityPrincipalId --assignee-principal-type ServicePrincipal --role '$($role.Name)' --scope $($role.Scope) --output none"
    } catch {
        throw "Failed to assign role '$($role.Name)' at scope '$($role.Scope)'. If you activated access through PIM, confirm the role is active in the current shell and re-run the script."
    }
}
$registryUsername = ""
$registryPassword = ""
$storageConnectionString = ""

Write-Header "Building and pushing container image"
Invoke-Az "az acr build --registry $acrName --image $imageName`:$imageTag $PSScriptRoot --no-logs --output none"

Write-Header "Refreshing local image cache for confcom"
& docker pull "$acrLoginServer/$imageName`:$imageTag"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to pull the freshly built image from ACR into the local Docker cache for confcom policy generation."
}

Write-Header "Preparing confidential container deployment"
Set-Location $PSScriptRoot

Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template.json" -Force

$deploymentParams = @{
    '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
    contentVersion = "1.0.0.0"
    parameters = @{
        containerGroupName = @{ value = $containerGroupName }
        location = @{ value = $Location }
        appImage = @{ value = "$acrLoginServer/$imageName`:$imageTag" }
        registryServer = @{ value = $acrLoginServer }
        registryUsername = @{ value = $registryUsername }
        registryPassword = @{ value = $registryPassword }
        dnsNameLabel = @{ value = $dnsLabel }
        subnetId = @{ value = $SubnetId }
        identityResourceId = @{ value = $identityResourceId }
        identityClientId = @{ value = $identityClientId }
        skrKeyName = @{ value = $keyName }
        skrMaaEndpoint = @{ value = $maaEndpoint }
        skrAkvEndpoint = @{ value = $akvEndpoint }
        storageAccount = @{ value = $storageName }
        storageConnectionString = @{ value = $storageConnectionString }
        secretString = @{ value = $SecretString }
    }
}
$deploymentParams | ConvertTo-Json -Depth 20 | Set-Content -Path "deployment-params.json" -Encoding UTF8

Write-Header "Authenticating Docker to ACR"
try {
    Invoke-Az "az acr login --name $acrName --output none"
} catch {
    throw "Failed to authenticate Docker to ACR '$acrName'. Ensure Docker Desktop is running and your Azure token can access the registry."
}

Invoke-Az "az extension add --name confcom --upgrade --output none"
Invoke-Az "az confcom acipolicygen -a deployment-template.json --parameters deployment-params.json --disable-stdio --approve-wildcards"

Write-Header "Deploying confidential ACI"
Invoke-Az "az deployment group create --resource-group $resourceGroupName --template-file deployment-template.json --parameters @deployment-params.json --output table"

$fqdn = (Invoke-Az "az container show --resource-group $resourceGroupName --name $containerGroupName --query ipAddress.fqdn --output tsv").Trim()
$url = "http://$fqdn"

Write-Header "Deployment complete"
Write-Host "Resource Group:  $resourceGroupName" -ForegroundColor Green
Write-Host "Container URL:   $url" -ForegroundColor Green
Write-Host "Storage account: $storageName" -ForegroundColor Green
Write-Host "Key Vault:       $keyVaultName" -ForegroundColor Green
Write-Host "SKR key:         $keyName" -ForegroundColor Green
Write-Host ""
Write-Host "Open the page, click 'get secret data', then use 'add record'." -ForegroundColor Cyan

if (-not $SkipBrowser) {
    Start-Process $url | Out-Null
}
