<#
.SYNOPSIS
    Deploy multi-party confidential computing demonstration.

.DESCRIPTION
    Deploys three containers to demonstrate multi-party confidential computing:
    - Contoso: Confidential container (AMD SEV-SNP) - Can attest and access secrets
    - Fabrikam: Confidential container (AMD SEV-SNP) - Can attest and access secrets  
    - snooper: Standard container (no TEE) - Cannot attest, cannot access secrets

    This demonstrates how confidential computing protects data even from 
    infrastructure operators, showing that only attested containers can 
    release cryptographic keys.

.PARAMETER Prefix
    REQUIRED. A short, unique identifier (3-8 characters) to prefix all Azure resources.
    Use something that identifies you or your team, like initials or team code.
    Examples: "jd01", "dev", "team42", "acme"
    This helps identify who owns the resources in shared subscriptions.

.PARAMETER Build
    Build and push the container image to Azure Container Registry.
    Creates ACR and Key Vault if they don't exist.

.PARAMETER Deploy
    Deploy all three containers (Contoso, Fabrikam, snooper).
    Requires a previous build (acr-config.json must exist).

.PARAMETER Cleanup
    Delete all Azure resources created by this script.

.PARAMETER SkipBrowser
    Skip opening the browser after deployment.

.PARAMETER RegistryName
    Custom name for the Azure Container Registry.
    If not provided, a random name will be generated.

.PARAMETER Location
    Azure region to deploy resources into.
    Defaults to "eastus" if not specified.
    Example regions: eastus, westus2, northeurope, westeurope, uksouth

.EXAMPLE
    .\Deploy-SimpleDemo.ps1 -Prefix "jd01" -Build
    Build and push the container image with prefix "jd01"

.EXAMPLE
    .\Deploy-SimpleDemo.ps1 -Prefix "dev" -Deploy
    Deploy all three containers with prefix "dev"

.EXAMPLE
    .\Deploy-SimpleDemo.ps1 -Prefix "team42" -Build -Deploy
    Build and deploy in one command with prefix "team42"

.EXAMPLE
    .\Deploy-SimpleDemo.ps1 -Prefix "acme" -Cleanup
    Delete all Azure resources with prefix "acme"
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[a-z0-9]{3,8}$')]
    [string]$Prefix,
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [switch]$SkipBrowser,
    [string]$RegistryName,
    [string]$Location = "eastus"
)

$ErrorActionPreference = "Stop"
$ImageName = "aci-attestation-demo"
$ImageTag = "latest"

# Set UTF-8 encoding to handle Unicode characters in Azure CLI output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Get-SharedMaaEndpoint {
    <#
    .SYNOPSIS
        Resolve the shared Microsoft Azure Attestation (MAA) endpoint for a given Azure region.
    
    .DESCRIPTION
        Returns the shared MAA endpoint URL for the specified Azure region.
        Shared MAA endpoints follow the pattern: shared<code>.<code>.attest.azure.net
        
        These endpoints are required for Secure Key Release (SKR) policies in 
        confidential container deployments, where the attestation authority in the
        release policy must match the region where the container is deployed.
        
        Source: https://github.com/microsoft/confidential-sidecar-containers
        Verify: Get-AzAttestationDefaultProvider -Location "<region>"
        List:   (Get-AzAttestationDefaultProvider).Value | Sort-Object Location | Format-Table Location, AttestUri
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Location
    )
    
    # Shared MAA endpoint mappings: region name → "shared<code>.<code>"
    # Confirmed endpoints from Microsoft confidential-sidecar-containers documentation
    $maaEndpoints = @{
        # US regions
        "eastus"            = "sharedeus.eus"
        "eastus2"           = "sharedeus2.eus2"
        "westus"            = "sharedwus.wus"
        "westus2"           = "sharedwus2.wus2"
        "westus3"           = "sharedwus3.wus3"
        "centralus"         = "sharedcus.cus"
        "northcentralus"    = "sharedncus.ncus"
        "southcentralus"    = "sharedscus.scus"
        "westcentralus"     = "sharedwcus.wcus"
        # Canada
        "canadacentral"     = "sharedcac.cac"
        "canadaeast"        = "sharedcae.cae"
        # Europe
        "northeurope"       = "sharedneu.neu"
        "westeurope"        = "sharedweu.weu"
        "uksouth"           = "shareduks.uks"
        "ukwest"            = "sharedukw.ukw"
        "francecentral"     = "sharedfrc.frc"
        "germanywestcentral" = "sharedgwc.gwc"
        "switzerlandnorth"  = "sharedswn.swn"
        "swedencentral"     = "sharedswc.swc"
        "norwayeast"        = "sharednoe.noe"
        # Asia Pacific
        "eastasia"          = "sharedea.ea"
        "southeastasia"     = "sharedsea.sea"
        "japaneast"         = "sharedjpe.jpe"
        "japanwest"         = "sharedjpw.jpw"
        "koreacentral"      = "sharedkrc.krc"
        "australiaeast"     = "sharedaue.aue"
        "centralindia"      = "sharedinc.inc"
        "southindia"        = "sharedins.ins"
        # Other
        "brazilsouth"       = "sharedbrs.brs"
        "southafricanorth"  = "sharedsan.san"
        "uaenorth"          = "shareduan.uan"
    }
    
    $regionKey = $Location.ToLower()
    $prefix = $maaEndpoints[$regionKey]
    
    if (-not $prefix) {
        Write-Host ""
        Write-Host "ERROR: No known shared MAA endpoint for region '$Location'" -ForegroundColor Red
        Write-Host ""
        Write-Host "Regions with known shared MAA endpoints:" -ForegroundColor Yellow
        $maaEndpoints.Keys | Sort-Object | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        Write-Host ""
        Write-Host "To look up the MAA endpoint for your region, run:" -ForegroundColor Cyan
        Write-Host "  Get-AzAttestationDefaultProvider -Location '$Location' | Format-Table AttestUri" -ForegroundColor White
        Write-Host ""
        throw "No shared MAA endpoint available for region '$Location'. Use -Location with a supported region."
    }
    
    $endpoint = "$prefix.attest.azure.net"
    Write-Host "MAA Endpoint for $($Location): $endpoint" -ForegroundColor Cyan
    return $endpoint
}

function Get-Config {
    if (Test-Path "acr-config.json") {
        return Get-Content "acr-config.json" | ConvertFrom-Json
    }
    return $null
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json | Out-File -FilePath "acr-config.json" -Encoding UTF8
}

# ============================================================================
# Build Phase
# ============================================================================

function Invoke-Build {
    param([string]$RegistryName)
    
    Write-Header "Building Container Image"
    
    # Generate registry name if not provided
    if (-not $RegistryName) {
        $random = -join ((97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $RegistryName = "acr$random"
        Write-Warning "No registry name provided. Using: $RegistryName"
    }
    
    $ResourceGroup = "${Prefix}${RegistryName}-rg"
    $KeyVaultName = "kv$RegistryName"
    
    Write-Host "Registry Name: $RegistryName"
    Write-Host "Resource Group: $ResourceGroup"
    Write-Host "Location: $Location"
    Write-Host "Image: ${ImageName}:${ImageTag}"
    Write-Host ""
    
    # Create resource group
    Write-Host "Creating resource group..." -ForegroundColor Green
    az group create --name $ResourceGroup --location $Location | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create resource group"
    }
    
    # Create Azure Container Registry
    Write-Host "Creating Azure Container Registry..." -ForegroundColor Green
    az acr create `
        --resource-group $ResourceGroup `
        --name $RegistryName `
        --sku Basic `
        --admin-enabled true | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create ACR"
    }
    
    $MaaEndpoint = Get-SharedMaaEndpoint -Location $Location
    
    # Create release policy JSON for confidential containers
    $releasePolicy = @{
        version = "1.0.0"
        anyOf = @(
            @{
                authority = "https://$MaaEndpoint"
                allOf = @(
                    @{
                        claim = "x-ms-attestation-type"
                        equals = "sevsnpvm"
                    }
                )
            }
        )
    }
    $releasePolicyPath = Join-Path $PSScriptRoot "skr-release-policy.json"
    $releasePolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $releasePolicyPath -Encoding UTF8
    
    # ========== Create Key Vault and Identity for Contoso ==========
    Write-Header "Creating Resources for Contoso"
    
    $KeyVaultNameA = "kv${RegistryName}a"
    $IdentityNameA = "id-${RegistryName}-contoso"
    $SkrKeyNameA = "contoso-secret-key"
    
    Write-Host "Creating Key Vault for Contoso: $KeyVaultNameA..." -ForegroundColor Green
    az keyvault create `
        --resource-group $ResourceGroup `
        --name $KeyVaultNameA `
        --location $Location `
        --sku premium `
        --enable-rbac-authorization false | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to create Key Vault for Contoso"
    }
    
    Write-Host "Creating managed identity for Contoso: $IdentityNameA..." -ForegroundColor Green
    az identity create --resource-group $ResourceGroup --name $IdentityNameA | Out-Null
    
    $IdentityClientIdA = az identity show --resource-group $ResourceGroup --name $IdentityNameA --query clientId -o tsv
    $IdentityResourceIdA = az identity show --resource-group $ResourceGroup --name $IdentityNameA --query id -o tsv
    $IdentityPrincipalIdA = az identity show --resource-group $ResourceGroup --name $IdentityNameA --query principalId -o tsv
    
    Write-Host "Granting Contoso identity access to Key Vault..." -ForegroundColor Green
    az keyvault set-policy --name $KeyVaultNameA --object-id $IdentityPrincipalIdA --key-permissions get release | Out-Null
    
    Write-Host "Creating SKR key for Contoso: $SkrKeyNameA..." -ForegroundColor Green
    az keyvault key create `
        --vault-name $KeyVaultNameA `
        --name $SkrKeyNameA `
        --kty RSA-HSM `
        --size 2048 `
        --ops wrapKey unwrapKey encrypt decrypt `
        --exportable true `
        --policy $releasePolicyPath | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Contoso: Key Vault '$KeyVaultNameA' with key '$SkrKeyNameA' created"
    }
    
    # ========== Create Key Vault and Identity for Fabrikam ==========
    Write-Header "Creating Resources for Fabrikam"
    
    $KeyVaultNameB = "kv${RegistryName}b"
    $IdentityNameB = "id-${RegistryName}-fabrikam"
    $SkrKeyNameB = "fabrikam-secret-key"
    
    Write-Host "Creating Key Vault for Fabrikam: $KeyVaultNameB..." -ForegroundColor Green
    az keyvault create `
        --resource-group $ResourceGroup `
        --name $KeyVaultNameB `
        --location $Location `
        --sku premium `
        --enable-rbac-authorization false | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to create Key Vault for Fabrikam"
    }
    
    Write-Host "Creating managed identity for Fabrikam: $IdentityNameB..." -ForegroundColor Green
    az identity create --resource-group $ResourceGroup --name $IdentityNameB | Out-Null
    
    $IdentityClientIdB = az identity show --resource-group $ResourceGroup --name $IdentityNameB --query clientId -o tsv
    $IdentityResourceIdB = az identity show --resource-group $ResourceGroup --name $IdentityNameB --query id -o tsv
    $IdentityPrincipalIdB = az identity show --resource-group $ResourceGroup --name $IdentityNameB --query principalId -o tsv
    
    Write-Host "Granting Fabrikam identity access to Key Vault..." -ForegroundColor Green
    az keyvault set-policy --name $KeyVaultNameB --object-id $IdentityPrincipalIdB --key-permissions get release | Out-Null
    
    Write-Host "Creating SKR key for Fabrikam: $SkrKeyNameB..." -ForegroundColor Green
    az keyvault key create `
        --vault-name $KeyVaultNameB `
        --name $SkrKeyNameB `
        --kty RSA-HSM `
        --size 2048 `
        --ops wrapKey unwrapKey encrypt decrypt `
        --exportable true `
        --policy $releasePolicyPath | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Fabrikam: Key Vault '$KeyVaultNameB' with key '$SkrKeyNameB' created"
    }
    
    # Clean up temporary policy file
    if (Test-Path $releasePolicyPath) {
        Remove-Item $releasePolicyPath -Force
    }
    
    # Store ACR credentials in Contoso's Key Vault (for retrieval during deploy)
    $KeyVaultName = $KeyVaultNameA
    
    # Build and push image
    Write-Host "Building and pushing container image..." -ForegroundColor Green
    Write-Host "This may take a few minutes..."
    
    $buildResult = az acr build `
        --registry $RegistryName `
        --image "${ImageName}:${ImageTag}" `
        --file Dockerfile `
        --no-logs `
        . 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        $imageExists = az acr repository show --name $RegistryName --image "${ImageName}:${ImageTag}" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host $buildResult
            throw "Failed to build and push image"
        }
    }
    
    Write-Success "Container image built and pushed successfully"
    
    # Get ACR credentials
    Write-Host "Retrieving ACR credentials..." -ForegroundColor Green
    $acrUsername = az acr credential show --name $RegistryName --query username -o tsv
    $acrPassword = az acr credential show --name $RegistryName --query "passwords[0].value" -o tsv
    $loginServer = az acr show --name $RegistryName --query loginServer -o tsv
    
    # Store credentials in Key Vault
    Write-Host "Storing credentials in Key Vault..." -ForegroundColor Green
    az keyvault secret set --vault-name $KeyVaultName --name "acr-username" --value $acrUsername --only-show-errors | Out-Null
    az keyvault secret set --vault-name $KeyVaultName --name "acr-password" --value $acrPassword --only-show-errors | Out-Null
    
    # Save configuration with both companies
    $config = @{
        registryName = $RegistryName
        resourceGroup = $ResourceGroup
        loginServer = $loginServer
        imageName = $ImageName
        imageTag = $ImageTag
        fullImage = "$loginServer/${ImageName}:${ImageTag}"
        keyVaultName = $KeyVaultNameA
        skrMaaEndpoint = $MaaEndpoint
        # Contoso configuration
        companyA = @{
            keyVaultName = $KeyVaultNameA
            skrKeyName = $SkrKeyNameA
            skrAkvEndpoint = "$KeyVaultNameA.vault.azure.net"
            identityName = $IdentityNameA
            identityResourceId = $IdentityResourceIdA
            identityClientId = $IdentityClientIdA
        }
        # Fabrikam configuration
        companyB = @{
            keyVaultName = $KeyVaultNameB
            skrKeyName = $SkrKeyNameB
            skrAkvEndpoint = "$KeyVaultNameB.vault.azure.net"
            identityName = $IdentityNameB
            identityResourceId = $IdentityResourceIdB
            identityClientId = $IdentityClientIdB
        }
    }
    Save-Config $config
    
    Write-Header "Build Complete"
    Write-Host "Registry: $loginServer"
    Write-Host "Image: $loginServer/${ImageName}:${ImageTag}"
    Write-Host ""
    Write-Host "Contoso Resources:" -ForegroundColor Green
    Write-Host "  Key Vault: $KeyVaultNameA"
    Write-Host "  SKR Key: $SkrKeyNameA"
    Write-Host "  Identity: $IdentityNameA"
    Write-Host ""
    Write-Host "Fabrikam Resources:" -ForegroundColor Green
    Write-Host "  Key Vault: $KeyVaultNameB"
    Write-Host "  SKR Key: $SkrKeyNameB"
    Write-Host "  Identity: $IdentityNameB"
    Write-Host ""
    Write-Host "MAA Endpoint: $MaaEndpoint"
    Write-Host ""
    Write-Success "Credentials stored securely in Azure Key Vault"
    Write-Host "Configuration saved to acr-config.json"
    
    return $config
}

# ============================================================================
# Deploy Phase - Multi-Party (Contoso, Fabrikam, snooper)
# ============================================================================

function Invoke-Deploy {
    param([switch]$SkipBrowser)
    
    Write-Header "Deploying Multi-Party Demonstration"
    Write-Host "This will deploy 3 containers:" -ForegroundColor Yellow
    Write-Host "  - Contoso:   Confidential (AMD SEV-SNP TEE)" -ForegroundColor Green
    Write-Host "  - Fabrikam:  Confidential (AMD SEV-SNP TEE)" -ForegroundColor Green
    Write-Host "  - snooper:    Standard (No TEE - cannot attest)" -ForegroundColor Red
    Write-Host ""
    
    $config = Get-Config
    if (-not $config) {
        throw "acr-config.json not found. Run with -Build first."
    }
    
    $resource_group = $config.resourceGroup
    $ACR_LOGIN_SERVER = $config.loginServer
    $FULL_IMAGE = $config.fullImage
    $KeyVaultName = $config.keyVaultName
    
    # Get ACR credentials from Key Vault
    Write-Host "Retrieving ACR credentials from Key Vault..."
    $ACR_USERNAME = az keyvault secret show --vault-name $KeyVaultName --name "acr-username" --query "value" -o tsv
    $ACR_PASSWORD = az keyvault secret show --vault-name $KeyVaultName --name "acr-password" --query "value" -o tsv
    
    if (-not $ACR_USERNAME -or -not $ACR_PASSWORD) {
        throw "Failed to retrieve ACR credentials from Key Vault"
    }
    Write-Success "Credentials retrieved successfully"
    Write-Host ""
    
    # Use storage connection string validated at script startup
    $StorageConnectionString = $script:StorageConnectionString
    
    # Generate unique names for all containers
    $timestamp = Get-Date -Format "MMddHHmm"
    $container_companyA = "aci-contoso-$timestamp"
    $container_companyB = "aci-fabrikam-$timestamp"
    $container_snooper = "aci-snooper-$timestamp"
    $dns_companyA = "contoso-$timestamp"
    $dns_companyB = "fabrikam-$timestamp"
    $dns_snooper = "snooper-$timestamp"
    
    Write-Host "Container Names:"
    Write-Host "  Contoso:   $container_companyA"
    Write-Host "  Fabrikam:  $container_companyB"
    Write-Host "  snooper:   $container_snooper"
    Write-Host ""
    
    # Check Docker for confidential deployments
    Write-Host "Checking if Docker is running (required for Confidential SKU)..."
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Required for security policy generation. Start Docker Desktop."
    }
    Write-Success "Docker is running"
    Write-Host ""
    
    # Login to ACR
    Write-Host "Logging into Azure Container Registry..."
    az acr login --name $ACR_LOGIN_SERVER --username $ACR_USERNAME --password $ACR_PASSWORD 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        docker login $ACR_LOGIN_SERVER -u $ACR_USERNAME -p $ACR_PASSWORD 2>&1 | Out-Null
    }
    Write-Success "ACR login complete"
    Write-Host ""
    
    # ========== Deploy Contoso (Confidential) ==========
    Write-Header "Deploying Contoso (Confidential)"
    
    # Use Contoso's specific SKR configuration
    $companyAConfig = $config.companyA
    Write-Host "Using Contoso's Key Vault: $($companyAConfig.keyVaultName)" -ForegroundColor Cyan
    Write-Host "Using Contoso's SKR Key: $($companyAConfig.skrKeyName)" -ForegroundColor Cyan
    
    $params_companyA = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_companyA }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_companyA }
            'skrKeyName' = @{ 'value' = $companyAConfig.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $companyAConfig.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $companyAConfig.identityResourceId }
            'storageConnectionString' = @{ 'value' = $StorageConnectionString }
            'resourceGroupName' = @{ 'value' = $resource_group }
        }
    }
    $params_companyA | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-contoso.json'
    
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template-contoso.json" -Force
    
    Write-Host "Generating security policy for Contoso..."
    az confcom acipolicygen -a deployment-template-contoso.json --parameters deployment-params-contoso.json --disable-stdio
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to generate security policy for Contoso"
    }
    Write-Success "Security policy generated for Contoso"
    
    Write-Host "Deploying Contoso container..."
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-contoso.json `
        --parameters '@deployment-params-contoso.json' | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to deploy Contoso container"
    }
    Write-Success "Contoso container deployed!"
    
    # ========== Deploy Fabrikam (Confidential) ==========
    Write-Header "Deploying Fabrikam (Confidential)"
    
    # Use Fabrikam's specific SKR configuration
    $companyBConfig = $config.companyB
    Write-Host "Using Fabrikam's Key Vault: $($companyBConfig.keyVaultName)" -ForegroundColor Cyan
    Write-Host "Using Fabrikam's SKR Key: $($companyBConfig.skrKeyName)" -ForegroundColor Cyan
    
    $params_companyB = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_companyB }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_companyB }
            'skrKeyName' = @{ 'value' = $companyBConfig.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $companyBConfig.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $companyBConfig.identityResourceId }
            'storageConnectionString' = @{ 'value' = $StorageConnectionString }
            'resourceGroupName' = @{ 'value' = $resource_group }
        }
    }
    $params_companyB | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-fabrikam.json'
    
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template-fabrikam.json" -Force
    
    Write-Host "Generating security policy for Fabrikam..."
    az confcom acipolicygen -a deployment-template-fabrikam.json --parameters deployment-params-fabrikam.json --disable-stdio
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to generate security policy for Fabrikam"
    }
    Write-Success "Security policy generated for Fabrikam"
    
    Write-Host "Deploying Fabrikam container..."
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-fabrikam.json `
        --parameters '@deployment-params-fabrikam.json' | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to deploy Fabrikam container"
    }
    Write-Success "Fabrikam container deployed!"
    
    # ========== Deploy snooper (Standard - No TEE) ==========
    Write-Header "Deploying snooper (Standard - No TEE)"
    
    # Snooper uses Contoso's config but won't be able to release keys (no TEE)
    Write-Host "Snooper will try to access Contoso's key but will FAIL (no TEE)" -ForegroundColor Yellow
    
    $params_snooper = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_snooper }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_snooper }
            'skrKeyName' = @{ 'value' = $companyAConfig.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $companyAConfig.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $companyAConfig.identityResourceId }
            'storageConnectionString' = @{ 'value' = $StorageConnectionString }
            'resourceGroupName' = @{ 'value' = $resource_group }
        }
    }
    $params_snooper | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-snooper.json'
    
    # Use standard template (no security policy, no confidential SKU)
    Copy-Item -Path "deployment-template-standard.json" -Destination "deployment-template-snooper.json" -Force
    
    Write-Host "Deploying snooper container (no security policy needed)..."
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-snooper.json `
        --parameters '@deployment-params-snooper.json' | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to deploy snooper container"
    }
    Write-Success "snooper container deployed!"
    
    # ========== Wait for All Containers ==========
    Write-Header "Waiting for All Containers to Start"
    
    $fqdn_companyA = az container show --resource-group $resource_group --name $container_companyA --query "ipAddress.fqdn" --output tsv
    $fqdn_companyB = az container show --resource-group $resource_group --name $container_companyB --query "ipAddress.fqdn" --output tsv
    $fqdn_snooper = az container show --resource-group $resource_group --name $container_snooper --query "ipAddress.fqdn" --output tsv
    
    Write-Host "FQDNs:"
    Write-Host "  Contoso:   http://$fqdn_companyA" -ForegroundColor Green
    Write-Host "  Fabrikam:  http://$fqdn_companyB" -ForegroundColor Green
    Write-Host "  snooper:   http://$fqdn_snooper" -ForegroundColor Red
    Write-Host ""
    
    $timeout_seconds = 240
    $elapsed_seconds = 0
    $companyA_ready = $false
    $companyB_ready = $false
    $snooper_ready = $false
    
    while ($elapsed_seconds -lt $timeout_seconds -and (-not $companyA_ready -or -not $companyB_ready -or -not $snooper_ready)) {
        if (-not $companyA_ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://$fqdn_companyA" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { 
                    $companyA_ready = $true
                    Write-Success "Contoso is ready!"
                }
            } catch { }
        }
        
        if (-not $companyB_ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://$fqdn_companyB" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { 
                    $companyB_ready = $true
                    Write-Success "Fabrikam is ready!"
                }
            } catch { }
        }
        
        if (-not $snooper_ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://$fqdn_snooper" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { 
                    $snooper_ready = $true
                    Write-Success "snooper is ready!"
                }
            } catch { }
        }
        
        if (-not $companyA_ready -or -not $companyB_ready -or -not $snooper_ready) {
            $status = "Waiting... ($elapsed_seconds/$timeout_seconds sec) - "
            $status += "A: $(if ($companyA_ready) { 'Ready' } else { '...' }), "
            $status += "B: $(if ($companyB_ready) { 'Ready' } else { '...' }), "
            $status += "Snooper: $(if ($snooper_ready) { 'Ready' } else { '...' })"
            Write-Host $status
            Start-Sleep -Seconds 5
            $elapsed_seconds += 5
        }
    }
    
    if (-not $companyA_ready -or -not $companyB_ready -or -not $snooper_ready) {
        Write-Warning "Some containers did not start in time"
        if (-not $companyA_ready) { Write-Warning "  - Contoso not ready" }
        if (-not $companyB_ready) { Write-Warning "  - Fabrikam not ready" }
        if (-not $snooper_ready) { Write-Warning "  - snooper not ready" }
    }
    
    # ========== Open Edge with Multi-Party View ==========
    Write-Header "Opening Multi-Party Comparison View"
    
    Write-Host "Creating multi-party comparison view..."
    Write-Host "  Top Left:     Contoso (Confidential) - http://$fqdn_companyA"
    Write-Host "  Top Right:    Fabrikam (Confidential) - http://$fqdn_companyB"
    Write-Host "  Bottom:       snooper (Standard)       - http://$fqdn_snooper"
    Write-Host ""
    
    # Get key names for display
    $keyNameA = $companyAConfig.skrKeyName
    $keyNameB = $companyBConfig.skrKeyName
    $kvNameA = $companyAConfig.keyVaultName
    $kvNameB = $companyBConfig.keyVaultName
    
    # Create a local HTML file with iframes for multi-party view
    $multiPartyHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Multi-Party Confidential Computing Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { display: flex; flex-direction: column; height: 100vh; font-family: 'Segoe UI', sans-serif; background: #1a1a2e; }
        .header { 
            background: #1a1a2e; 
            color: white; 
            padding: 8px 20px;
            text-align: center;
            border-bottom: 2px solid #333;
        }
        .header h1 { font-size: 18px; font-weight: 500; margin-bottom: 4px; }
        .header p { font-size: 12px; color: #888; }
        .top-row { display: flex; flex: 1; }
        .bottom-row { flex: 1; display: flex; flex-direction: column; }
        .pane { 
            flex: 1; 
            display: flex; 
            flex-direction: column;
            border: 2px solid #333;
        }
        .label { 
            padding: 8px 12px; 
            font-weight: bold;
            font-size: 13px;
            text-align: center;
        }
        .label.confidential { background: #28a745; color: white; }
        .label.standard { background: #dc3545; color: white; }
        .label .subtitle { font-size: 10px; font-weight: normal; opacity: 0.9; }
        .label .key-name { font-size: 11px; font-family: monospace; background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 3px; margin-top: 4px; display: inline-block; }
        iframe { flex: 1; width: 100%; border: none; background: white; }
        .divider-v { width: 2px; background: #1a1a2e; }
        .divider-h { height: 2px; background: #1a1a2e; }
        .legend {
            background: #252545;
            padding: 8px 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            font-size: 11px;
            color: #ccc;
        }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .legend-dot { width: 10px; height: 10px; border-radius: 50%; }
        .legend-dot.green { background: #28a745; }
        .legend-dot.red { background: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Multi-Party Confidential Computing Demonstration</h1>
        <p>Each company has their own Key Vault and SKR key - only their confidential container can release it</p>
    </div>
    <div class="legend">
        <div class="legend-item">
            <div class="legend-dot green"></div>
            <span>Confidential containers can attest and release their own cryptographic keys</span>
        </div>
        <div class="legend-item">
            <div class="legend-dot red"></div>
            <span>Standard containers cannot attest - key release will fail</span>
        </div>
    </div>
    <div class="top-row">
        <div class="pane">
            <div class="label confidential">
                ✅ CONTOSO (Confidential)
                <div class="subtitle">AMD SEV-SNP TEE • Key Vault: $kvNameA</div>
                <div class="key-name">🔑 $keyNameA</div>
            </div>
            <iframe src="http://$fqdn_companyA" title="Contoso - Confidential Container"></iframe>
        </div>
        <div class="divider-v"></div>
        <div class="pane">
            <div class="label confidential">
                ✅ FABRIKAM (Confidential)
                <div class="subtitle">AMD SEV-SNP TEE • Key Vault: $kvNameB</div>
                <div class="key-name">🔑 $keyNameB</div>
            </div>
            <iframe src="http://$fqdn_companyB" title="Fabrikam - Confidential Container"></iframe>
        </div>
    </div>
    <div class="divider-h"></div>
    <div class="bottom-row">
        <div class="pane">
            <div class="label standard">
                ❌ SNOOPER (Standard - No Hardware Protection)
                <div class="subtitle">No TEE • Cannot attest • Tries to access: $kvNameA</div>
                <div class="key-name" style="background: rgba(0,0,0,0.2);">🔒 $keyNameA (ACCESS DENIED)</div>
            </div>
            <iframe src="http://$fqdn_snooper" title="Snooper - Standard Container (No TEE)"></iframe>
        </div>
    </div>
</body>
</html>
"@
    
    $multiPartyHtmlPath = Join-Path $PSScriptRoot "multiparty-view.html"
    $multiPartyHtml | Out-File -FilePath $multiPartyHtmlPath -Encoding UTF8
    
    if (-not $SkipBrowser) {
        # Open the multi-party view HTML in Edge
        Start-Process "msedge" -ArgumentList "--new-window `"file:///$($multiPartyHtmlPath.Replace('\', '/'))`"" -Wait
    } else {
        Write-Host "Browser skipped. Open manually:"
        Write-Host "  file:///$($multiPartyHtmlPath.Replace('\', '/'))"
    }
    
    # Cleanup prompt
    Write-Host ""
    Write-Host "Press Enter when done viewing to cleanup containers..." -ForegroundColor Yellow
    Read-Host
    
    Write-Header "Cleanup Multi-Party Containers"
    
    Write-Host "Deleting all containers..."
    az container delete --resource-group $resource_group --name $container_companyA --yes 2>&1 | Out-Null
    az container delete --resource-group $resource_group --name $container_companyB --yes 2>&1 | Out-Null
    az container delete --resource-group $resource_group --name $container_snooper --yes 2>&1 | Out-Null
    
    # Cleanup temp files
    Remove-Item -Path "deployment-params-contoso.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-params-fabrikam.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-params-snooper.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-contoso.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-fabrikam.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-snooper.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "multiparty-view.html" -Force -ErrorAction SilentlyContinue
    
    Write-Success "All containers deleted. ACR and Key Vault preserved."
    Write-Host "Run -Cleanup to delete all resources including ACR and Key Vault."
}

# ============================================================================
# Cleanup Phase
# ============================================================================

function Invoke-Cleanup {
    param([switch]$Confirm)
    
    $config = Get-Config
    if (-not $config) {
        Write-Warning "No acr-config.json found. Nothing to clean up."
        return
    }
    
    $resource_group = $config.resourceGroup
    
    Write-Header "Cleanup Resources"
    Write-Warning "This will delete the ENTIRE resource group: $resource_group"
    Write-Host "Including:"
    Write-Host "  - Azure Container Registry: $($config.registryName)"
    if ($config.companyA) {
        Write-Host "  - Contoso Key Vault: $($config.companyA.keyVaultName)"
    }
    if ($config.companyB) {
        Write-Host "  - Fabrikam Key Vault: $($config.companyB.keyVaultName)"
    }
    Write-Host "  - All container instances and managed identities"
    Write-Host "  - Consolidated records from blob storage"
    Write-Host ""
    
    if (-not $Confirm) {
        $response = Read-Host "Type 'yes' to confirm deletion"
        if ($response -ne 'yes') {
            Write-Warning "Cleanup cancelled."
            return
        }
    }
    
    # Delete consolidated-records blob from blob storage (unique per resource group)
    Write-Host ""
    Write-Host "Cleaning up blob storage..."
    
    # Construct the blob name that matches the deployment
    $blobName = "consolidated-records-$resource_group.json"
    
    # Use storage connection string validated at script startup
    $connectionString = $script:StorageConnectionString
    if ($connectionString) {
        # Delete consolidated records blob from external storage
        Write-Host "  Deleting $blobName..."
        $deleteResult = az storage blob delete `
            --name $blobName `
            --container-name "privateappdata" `
            --connection-string $connectionString `
            --only-show-errors 2>&1
        
        # Any result is fine - either deleted or didn't exist
        Write-Host "  Blob cleanup complete" -ForegroundColor Green
    } else {
        Write-Warning "No storage connection string available - skipping blob cleanup"
    }
    
    Write-Host ""
    Write-Host "Deleting resource group: $resource_group"
    Write-Host "This may take a few minutes..."
    az group delete --name $resource_group --yes --no-wait
    
    # Remove local config
    if (Test-Path "acr-config.json") {
        Remove-Item "acr-config.json" -Force
        Write-Host "Removed acr-config.json"
    }
    
    Write-Host ""
    Write-Success "Resource group deletion initiated."
    Write-Host "Deletion is running in the background."
    Write-Host "Run 'az group show --name $resource_group' to check status."
}

# ============================================================================
# Main Entry Point
# ============================================================================

# Show help if no action specified
if (-not $Build -and -not $Deploy -and -not $Cleanup) {
    Write-Host ""
    Write-Host "Multi-Party Confidential Computing Demo" -ForegroundColor Cyan
    Write-Host "========================================"
    Write-Host ""
    Write-Host "This script deploys 3 containers to demonstrate multi-party"
    Write-Host "confidential computing:"
    Write-Host ""
    Write-Host "  Contoso:   Confidential (AMD SEV-SNP) - CAN attest" -ForegroundColor Green
    Write-Host "  Fabrikam:  Confidential (AMD SEV-SNP) - CAN attest" -ForegroundColor Green
    Write-Host "  snooper:   Standard (No TEE)         - CANNOT attest" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix <code> -Build         # Build container image"
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix <code> -Deploy        # Deploy all 3 containers"
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix <code> -Build -Deploy # Build and deploy"
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix <code> -Cleanup       # Delete all resources"
    Write-Host ""
    Write-Host "Required Parameter:" -ForegroundColor Yellow
    Write-Host "  -Prefix <code>  A short, unique identifier (3-8 lowercase alphanumeric chars)"
    Write-Host "                  to prefix all Azure resources. Use your initials, team code,"
    Write-Host "                  or project name to easily identify resource ownership."
    Write-Host "                  Examples: jd01, dev, team42, acme" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -SkipBrowser    Don't open browser after deployment"
    Write-Host "  -RegistryName   Custom ACR name (default: random)"
    Write-Host "  -Location       Azure region (default: eastus)"
    Write-Host ""
    
    $config = Get-Config
    if ($config) {
        Write-Host "Current configuration (from acr-config.json):" -ForegroundColor Green
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Registry: $($config.loginServer)"
        Write-Host "  Image: $($config.fullImage)"
    } else {
        Write-Host "No existing configuration. Run with -Prefix <code> -Build to get started." -ForegroundColor Yellow
    }
    Write-Host ""
    exit 0
}

# Validate Prefix is provided when an action is specified
if (-not $Prefix) {
    Write-Host ""
    Write-Host "ERROR: The -Prefix parameter is required." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please provide a short, unique identifier (3-8 lowercase alphanumeric characters)" -ForegroundColor Yellow
    Write-Host "to prefix all Azure resources. This helps identify who owns the resources."
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix jd01 -Build      # Use your initials + number"
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix dev -Build       # Use a project code"
    Write-Host "  .\Deploy-SimpleDemo.ps1 -Prefix team42 -Build    # Use your team identifier"
    Write-Host ""
    Write-Host "The prefix must be:" -ForegroundColor Gray
    Write-Host "  - 3 to 8 characters long"
    Write-Host "  - Lowercase letters and numbers only (a-z, 0-9)"
    Write-Host ""
    exit 1
}

# ============================================================================
# Validate Storage Connection String (.env)
# ============================================================================

$script:StorageConnectionString = ""
$envFilePath = Join-Path $PSScriptRoot ".env"

if (Test-Path $envFilePath) {
    $envContent = Get-Content $envFilePath
    foreach ($line in $envContent) {
        if ($line -match "^AZURE_STORAGE_CONNECTION_STRING=(.+)$") {
            $value = $matches[1].Trim('"').Trim("'")
            if ($value -and $value -ne "your_connection_string_here") {
                $script:StorageConnectionString = $value
            }
            break
        }
    }
}

if (-not $script:StorageConnectionString) {
    Write-Host ""
    Write-Host "No valid Azure Storage connection string found." -ForegroundColor Yellow
    Write-Host "The demo requires an Azure Storage Account to store encrypted data externally."
    Write-Host ""
    Write-Host "You can create one by running:" -ForegroundColor Cyan
    Write-Host "  .\Create-StorageAccount.ps1"
    Write-Host ""
    Write-Host "Then copy the connection string from the output, or find it in the Azure Portal" -ForegroundColor Gray
    Write-Host "under Storage Account > Access keys > Connection string." -ForegroundColor Gray
    Write-Host ""
    $input = Read-Host "Paste your Azure Storage connection string (or press Enter to abort)"
    $input = $input.Trim('"').Trim("'")

    if (-not $input -or $input -eq "your_connection_string_here") {
        Write-Host ""
        Write-Host "ERROR: A valid Azure Storage connection string is required." -ForegroundColor Red
        Write-Host ""
        Write-Host "To get a connection string:" -ForegroundColor Yellow
        Write-Host "  1. Run .\Create-StorageAccount.ps1 to create a new storage account, or"
        Write-Host "  2. Use an existing storage account from the Azure Portal:"
        Write-Host "     Portal > Storage Account > Security + networking > Access keys > Connection string"
        Write-Host ""
        Write-Host "Then either:" -ForegroundColor Yellow
        Write-Host "  a) Re-run this script and paste the connection string when prompted, or"
        Write-Host "  b) Create a .env file in this folder with the following content:"
        Write-Host ""
        Write-Host "     AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=..." -ForegroundColor Gray
        Write-Host ""
        exit 1
    }

    # Validate it looks like a connection string
    if ($input -notmatch "DefaultEndpointsProtocol=.+;AccountName=.+;AccountKey=.+") {
        Write-Host ""
        Write-Host "ERROR: That doesn't look like a valid Azure Storage connection string." -ForegroundColor Red
        Write-Host "Expected format: DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<key>;..." -ForegroundColor Gray
        Write-Host ""
        exit 1
    }

    # Save to .env file
    $script:StorageConnectionString = $input
    @(
        "# Azure Storage Connection String",
        "# Auto-generated by Deploy-SimpleDemo.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "# NEVER commit this file to git!",
        "",
        "AZURE_STORAGE_CONNECTION_STRING=$input"
    ) | Set-Content -Path $envFilePath -Encoding UTF8

    Write-Success "Connection string saved to .env file."
    Write-Host "  You won't be prompted again for future runs." -ForegroundColor Gray
}

Write-Host ""
Write-Success "Storage connection string validated"

# Extract account name for display
if ($script:StorageConnectionString -match 'AccountName=([^;]+)') {
    Write-Host "  Storage Account: $($matches[1])" -ForegroundColor Gray
}
Write-Host ""

# Execute requested actions
try {
    if ($Build) {
        $config = Invoke-Build -RegistryName $RegistryName
    }
    
    if ($Deploy) {
        Invoke-Deploy -SkipBrowser:$SkipBrowser
    }
    
    if ($Cleanup) {
        Invoke-Cleanup
    }
} catch {
    Write-Error "Error: $_"
    exit 1
}
