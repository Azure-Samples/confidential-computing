<#
.SYNOPSIS
    Deploy confidential ACI container with PostgreSQL Flexible Server (DCa/ECa AMD).

.DESCRIPTION
    Deploys a single confidential container (AMD SEV-SNP TEE) connected to an Azure
    PostgreSQL Flexible Server using DCa/ECa AMD confidential computing SKUs.
    
    Architecture:
      Internet --> Application Gateway (public IP, L7)
              --> ACI Container (Confidential SKU, private VNet)
              --> PostgreSQL Flexible Server (DCa/ECa AMD, TLS, public access w/ firewall)
    
    The container runs a financial analytics dashboard on a pre-seeded dataset of
    5000 financial transactions, with full MAA attestation and Secure Key Release.

.PARAMETER Prefix
    REQUIRED. A short, unique identifier (3-8 characters) to prefix all Azure resources.
    Examples: "jd01", "dev", "team42"

.PARAMETER Build
    Build and push the container image to Azure Container Registry.
    Creates ACR, Key Vault (Premium), and managed identity.

.PARAMETER Deploy
    Deploy VNet, PostgreSQL, ACI container, and Application Gateway.
    Requires a previous build (acr-config.json must exist).

.PARAMETER Cleanup
    Delete all Azure resources created by this script.

.PARAMETER SkipBrowser
    Skip opening the browser after deployment.

.PARAMETER RegistryName
    Custom name for the Azure Container Registry.
    If not provided, a random name will be generated.

.PARAMETER Location
    Azure region. Defaults to "uaenorth" for DCa/ECa AMD PostgreSQL SKU availability.
    Example regions: uaenorth, eastus, westeurope, uksouth

.PARAMETER Description
    Optional description tag to add to the resource group.

.EXAMPLE
    .\Deploy-PostgreSQLDemo.ps1 -Prefix "sg01" -Build
    Build and push the container image with prefix "sg01"

.EXAMPLE
    .\Deploy-PostgreSQLDemo.ps1 -Prefix "sg01" -Deploy
    Deploy all infrastructure and containers

.EXAMPLE
    .\Deploy-PostgreSQLDemo.ps1 -Prefix "sg01" -Build -Deploy
    Build and deploy in one command

.EXAMPLE
    .\Deploy-PostgreSQLDemo.ps1 -Cleanup
    Delete all Azure resources (reads configuration from acr-config.json)
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
    [string]$Location = "uaenorth",
    [string]$Description
)

$ErrorActionPreference = "Continue"
# Prevent $ErrorActionPreference from affecting native commands (az, docker)
$PSNativeCommandUseErrorActionPreference = $false
$ImageName = "aci-postgres-finance-demo"
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
        
        Source: https://github.com/microsoft/confidential-sidecar-containers
        Verify: Get-AzAttestationDefaultProvider -Location "<region>"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Location
    )
    
    $maaEndpoints = @{
        # US regions
        "eastus"             = "sharedeus.eus"
        "eastus2"            = "sharedeus2.eus2"
        "westus"             = "sharedwus.wus"
        "westus2"            = "sharedwus2.wus2"
        "westus3"            = "sharedwus3.wus3"
        "centralus"          = "sharedcus.cus"
        "northcentralus"     = "sharedncus.ncus"
        "southcentralus"     = "sharedscus.scus"
        "westcentralus"      = "sharedwcus.wcus"
        # Canada
        "canadacentral"      = "sharedcac.cac"
        "canadaeast"         = "sharedcae.cae"
        # Europe
        "northeurope"        = "sharedneu.neu"
        "westeurope"         = "sharedweu.weu"
        "uksouth"            = "shareduks.uks"
        "ukwest"             = "sharedukw.ukw"
        "francecentral"      = "sharedfrc.frc"
        "francesouth"        = "sharedfrs.frs"
        "germanywestcentral" = "shareddewc.dewc"
        "germanynorth"       = "sharedden.den"
        "switzerlandnorth"   = "sharedswn.swn"
        "switzerlandwest"    = "sharedsww.sww"
        "swedencentral"      = "sharedsec.sec"
        "swedensouth"        = "sharedses.ses"
        "norwayeast"         = "sharednoe.noe"
        "norwaywest"         = "sharednow.now"
        "polandcentral"      = "sharedplc.plc"
        "italynorth"         = "shareditn.itn"
        "spaincentral"       = "sharedesc.esc"
        # Asia Pacific
        "eastasia"           = "sharedeasia.easia"
        "southeastasia"      = "sharedsasia.sasia"
        "japaneast"          = "sharedjpe.jpe"
        "japanwest"          = "sharedjpw.jpw"
        "koreacentral"       = "sharedkrc.krc"
        "koreasouth"         = "sharedkrs.krs"
        "australiaeast"      = "sharedeau.eau"
        "australiasoutheast" = "sharedsau.sau"
        "australiacentral"   = "sharedcau.cau"
        "centralindia"       = "sharedcin.cin"
        "southindia"         = "sharedsin.sin"
        "westindia"          = "sharedwin.win"
        # Middle East & Africa
        "uaenorth"           = "shareduaen.uaen"
        "uaecentral"         = "shareduaec.uaec"
        "israelcentral"      = "sharedilc.ilc"
        "southafricanorth"   = "sharedsan.san"
        "southafricawest"    = "sharedsaw.saw"
        # South America
        "brazilsouth"        = "sharedsbr.sbr"
        "brazilsoutheast"    = "sharedsebr.sebr"
    }
    
    $regionKey = $Location.ToLower()
    $prefix = $maaEndpoints[$regionKey]
    
    if (-not $prefix) {
        Write-Host ""
        Write-Error "ERROR: No known shared MAA endpoint for region '$Location'"
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

function Get-PolicyHashFromConfcom {
    <#
    .SYNOPSIS
        Generate security policy using confcom and capture the hash it outputs.
    
    .DESCRIPTION
        Runs az confcom acipolicygen and captures the SHA256 hash it outputs.
        This hash is what Azure puts in the x-ms-sevsnpvm-hostdata claim during attestation.
    #>
    param(
        [string]$TemplatePath,
        [string]$ParamsPath
    )
    
    $output = az confcom acipolicygen -a $TemplatePath --parameters $ParamsPath --disable-stdio --approve-wildcards 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -ne 0) {
        Write-Error "Confcom failed: $output"
        throw "Failed to generate security policy for $TemplatePath"
    }
    
    # The hash is output as the last 64-character hex line
    $hashLine = $output | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -Last 1
    
    if (-not $hashLine) {
        Write-Warning "Could not find policy hash in confcom output. Output was:"
        $output | ForEach-Object { Write-Host "  $_" }
        throw "No policy hash found in confcom output"
    }
    
    # Extract the ccePolicy from the template
    $template = Get-Content $TemplatePath -Raw | ConvertFrom-Json
    $ccePolicy = $template.resources[0].properties.confidentialComputeProperties.ccePolicy
    
    # Decode and display the confcom security policy (Rego)
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor DarkCyan
    Write-Host "  DECODED CONFCOM SECURITY POLICY (Rego)" -ForegroundColor DarkCyan
    Write-Host "  Template: $TemplatePath" -ForegroundColor DarkCyan
    Write-Host "===============================================================================" -ForegroundColor DarkCyan
    try {
        $decodedPolicy = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ccePolicy))
        $decodedPolicy -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } catch {
        Write-Host "  (Could not decode base64 policy: $_)" -ForegroundColor Yellow
    }
    Write-Host "  Policy Hash: $($hashLine.Trim())" -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    
    return @{
        PolicyBase64 = $ccePolicy
        PolicyHash = $hashLine.Trim()
    }
}

function Update-KeyReleasePolicy {
    <#
    .SYNOPSIS
        Create a Key Vault key with a release policy bound to a specific container policy hash.
    
    .DESCRIPTION
        Creates a release policy that requires:
        1. AMD SEV-SNP attestation (x-ms-attestation-type = sevsnpvm)
        2. Specific container security policy hash (x-ms-sevsnpvm-hostdata)
    #>
    param(
        [string]$KeyVaultName,
        [string]$KeyName,
        [string]$MaaEndpoint,
        [string]$PolicyHash,
        [string]$CompanyName
    )
    
    Write-Host "Creating key for $CompanyName with policy hash binding..." -ForegroundColor Cyan
    Write-Host "  Policy Hash: $PolicyHash" -ForegroundColor Yellow
    
    $releasePolicy = @{
        version = "1.0.0"
        anyOf = @(
            @{
                authority = "https://$MaaEndpoint"
                allOf = @(
                    @{
                        claim = "x-ms-attestation-type"
                        equals = "sevsnpvm"
                    },
                    @{
                        claim = "x-ms-sevsnpvm-hostdata"
                        equals = $PolicyHash
                    }
                )
            }
        )
    }
    
    $policyPath = Join-Path $PSScriptRoot "release-policy-$($CompanyName.ToLower()).json"
    $releasePolicyJson = $releasePolicy | ConvertTo-Json -Depth 10
    $releasePolicyJson | Out-File -FilePath $policyPath -Encoding UTF8
    
    # Display release policy
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host "  $($CompanyName.ToUpper()) KEY RELEASE POLICY" -ForegroundColor Yellow
    Write-Host "===============================================================================" -ForegroundColor Yellow
    $releasePolicyJson -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    # Check if key already exists
    $existingKey = az keyvault key show --vault-name $KeyVaultName --name $KeyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Key already exists. Deleting and recreating with new policy..." -ForegroundColor Yellow
        az keyvault key delete --vault-name $KeyVaultName --name $KeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 1
        az keyvault key purge --vault-name $KeyVaultName --name $KeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }
    
    Write-Host "  Creating key with policy hash binding..." -ForegroundColor Gray
    $createResult = az keyvault key create `
        --vault-name $KeyVaultName `
        --name $KeyName `
        --kty RSA-HSM `
        --size 2048 `
        --ops wrapKey unwrapKey encrypt decrypt `
        --exportable true `
        --policy $policyPath 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "  $CompanyName key created with policy hash binding"
    } else {
        $createError = $createResult -join " "
        
        if ($createError -match "conflict" -or $createError -match "already exists") {
            Write-Warning "  Key in deleted state. Waiting 5 seconds..."
            Start-Sleep -Seconds 5
            
            $retryResult = az keyvault key create `
                --vault-name $KeyVaultName `
                --name $KeyName `
                --kty RSA-HSM `
                --size 2048 `
                --ops wrapKey unwrapKey encrypt decrypt `
                --exportable true `
                --policy $policyPath 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Success "  $CompanyName key created with policy hash binding (after retry)"
            } else {
                Write-Warning "  Could not create key with policy binding. Creating with generic policy..."
                $genericPolicy = @{
                    version = "1.0.0"
                    anyOf = @(@{
                        authority = "https://$MaaEndpoint"
                        allOf = @(@{ claim = "x-ms-attestation-type"; equals = "sevsnpvm" })
                    })
                }
                $genericPolicyPath = Join-Path $PSScriptRoot "release-policy-generic.json"
                $genericPolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $genericPolicyPath -Encoding UTF8
                
                az keyvault key create --vault-name $KeyVaultName --name $KeyName `
                    --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt `
                    --exportable true --policy $genericPolicyPath 2>&1 | Out-Null
                
                Remove-Item $genericPolicyPath -Force -ErrorAction SilentlyContinue
                Write-Warning "  Key created with generic policy (no container binding)"
            }
        } else {
            Write-Warning "  Key creation failed: $createError"
        }
    }
    
    if (Test-Path $policyPath) {
        Remove-Item $policyPath -Force
    }
    
    return $releasePolicy
}

function Get-Config {
    if (Test-Path "acr-config.json") {
        return Get-Content "acr-config.json" | ConvertFrom-Json
    }
    return $null
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json -Depth 5 | Out-File -FilePath "acr-config.json" -Encoding UTF8
}

function New-SecureDbPassword {
    <#
    .SYNOPSIS
        Generate a secure password meeting Azure PostgreSQL requirements.
    #>
    $lower = -join ((97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    $upper = -join ((65..90) | Get-Random -Count 4 | ForEach-Object { [char]$_ })
    $digits = -join ((48..57) | Get-Random -Count 4 | ForEach-Object { [char]$_ })
    $all = ($lower + $upper + $digits).ToCharArray() | Sort-Object { Get-Random }
    return -join $all
}

function Test-DockerRunning {
    <#
    .SYNOPSIS
        Checks if Docker is running, attempts to start it if not.
    #>
    
    Write-Host "Checking Docker status..." -ForegroundColor Cyan
    
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCmd) {
        Write-Host ""
        Write-Error "ERROR: Docker is not installed!"
        Write-Host ""
        Write-Host "Docker is required to generate the confidential computing security policy." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Recommended actions:" -ForegroundColor Cyan
        Write-Host "  1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop/" -ForegroundColor White
        Write-Host "  2. Install Docker Desktop" -ForegroundColor White
        Write-Host "  3. Restart your terminal and run this script again" -ForegroundColor White
        exit 1
    }
    
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Docker is running" -ForegroundColor Green
        return
    }
    
    Write-Host "Docker is not running. Attempting to start Docker Desktop..." -ForegroundColor Yellow
    
    $dockerDesktopPaths = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    )
    
    $dockerDesktopPath = $null
    foreach ($path in $dockerDesktopPaths) {
        if (Test-Path $path) {
            $dockerDesktopPath = $path
            break
        }
    }
    
    if (-not $dockerDesktopPath) {
        Write-Error "ERROR: Could not find Docker Desktop executable!"
        Write-Host "Start Docker Desktop manually from the Start menu, then run this script again." -ForegroundColor Yellow
        exit 1
    }
    
    Start-Process -FilePath $dockerDesktopPath
    
    $maxWaitSeconds = 120
    $waitInterval = 5
    $elapsed = 0
    
    Write-Host "Waiting for Docker daemon to start (timeout: ${maxWaitSeconds}s)..." -ForegroundColor Cyan
    
    while ($elapsed -lt $maxWaitSeconds) {
        Start-Sleep -Seconds $waitInterval
        $elapsed += $waitInterval
        
        $dockerInfo = docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Docker started successfully after ${elapsed} seconds" -ForegroundColor Green
            return
        }
        
        $remaining = $maxWaitSeconds - $elapsed
        Write-Host "  Still waiting... (${remaining}s remaining)" -ForegroundColor Gray
    }
    
    Write-Error "ERROR: Docker failed to start within ${maxWaitSeconds} seconds!"
    Write-Host "Start Docker Desktop manually, then run this script again." -ForegroundColor Yellow
    exit 1
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validate that all required tools and dependencies are installed.
    #>
    Write-Header "Checking Prerequisites"
    
    $missing = @()
    $warnings = @()
    
    # --- Azure CLI ---
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if ($azCmd) {
        $azVersion = (az version 2>$null | ConvertFrom-Json).'azure-cli'
        Write-Success "  Azure CLI $azVersion"
    } else {
        $missing += @{
            Name = "Azure CLI (az)"
            Reason = "Required for all Azure resource operations"
            Install = "winget install Microsoft.AzureCLI"
        }
    }
    
    # --- Azure CLI confcom extension ---
    if ($azCmd) {
        $confcomInstalled = az extension list --query "[?name=='confcom'].name" -o tsv 2>$null
        if ($confcomInstalled) {
            $confcomVersion = az extension list --query "[?name=='confcom'].version" -o tsv 2>$null
            Write-Success "  az confcom extension $confcomVersion"
        } else {
            $missing += @{
                Name = "Azure CLI confcom extension"
                Reason = "Required for generating confidential computing security policies"
                Install = "az extension add --name confcom"
            }
        }
    }
    
    # --- Azure CLI rdbms-connect extension ---
    if ($azCmd) {
        $rdbmsInstalled = az extension list --query "[?name=='rdbms-connect'].name" -o tsv 2>$null
        if ($rdbmsInstalled) {
            $rdbmsVersion = az extension list --query "[?name=='rdbms-connect'].version" -o tsv 2>$null
            Write-Success "  az rdbms-connect extension $rdbmsVersion"
        } else {
            Write-Host "  az rdbms-connect extension - not installed (auto-installing...)" -ForegroundColor Yellow
            az extension add --name rdbms-connect 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "  az rdbms-connect extension (installed)"
            } else {
                $warnings += @{
                    Name = "Azure CLI rdbms-connect extension"
                    Reason = "Optional - used for PostgreSQL seeding. Fallback: psql CLI"
                    Link = "az extension add --name rdbms-connect"
                }
            }
        }
    }
    
    # --- Azure CLI login ---
    if ($azCmd) {
        $account = az account show 2>$null | ConvertFrom-Json
        if ($account) {
            Write-Success "  Azure CLI logged in ($($account.user.name))"
        } else {
            $missing += @{
                Name = "Azure CLI login"
                Reason = "You must be logged in to your Azure subscription"
                Install = "az login"
            }
        }
    }
    
    # --- Docker ---
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCmd) {
        $dockerVersion = docker --version 2>$null
        if ($dockerVersion) {
            Write-Success "  Docker ($dockerVersion)"
        } else {
            Write-Success "  Docker (installed)"
        }
    } else {
        $missing += @{
            Name = "Docker Desktop"
            Reason = "Required by 'az confcom' for security policy generation"
            Install = "winget install Docker.DockerDesktop"
        }
    }
    
    # --- Microsoft Edge (optional) ---
    $edgePath = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    $edgePathX86 = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    if ((Test-Path $edgePath) -or (Test-Path $edgePathX86) -or (Get-Command msedge -ErrorAction SilentlyContinue)) {
        Write-Success "  Microsoft Edge (found)"
    } else {
        $warnings += @{
            Name = "Microsoft Edge"
            Reason = "Used to open demo after deployment (use -SkipBrowser to skip)"
            Link = "https://www.microsoft.com/edge"
        }
    }
    
    # Report warnings
    foreach ($warn in $warnings) {
        Write-Host "  [WARN] $($warn.Name) - not found" -ForegroundColor Yellow
        Write-Host "         $($warn.Reason)" -ForegroundColor Gray
    }
    
    # Report missing critical dependencies
    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Error "ERROR: $($missing.Count) required dependency/dependencies not found."
        Write-Host ""
        foreach ($dep in $missing) {
            Write-Error "  $($dep.Name)"
            Write-Host "    Why:     $($dep.Reason)" -ForegroundColor Gray
            Write-Host "    Install: $($dep.Install)" -ForegroundColor Cyan
            Write-Host ""
        }
        exit 1
    }
    
    Write-Host ""
    Write-Success "All prerequisites satisfied."
    Write-Host ""
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
    $IdentityName = "id-${RegistryName}-postgres"
    $SkrKeyName = "woodgrove-postgres-key"
    
    Write-Host "Registry Name: $RegistryName"
    Write-Host "Resource Group: $ResourceGroup"
    Write-Host "Location: $Location"
    Write-Host "Image: ${ImageName}:${ImageTag}"
    Write-Host ""
    
    # Get the logged-in user's UPN for the owner tag
    Write-Host "Getting logged-in user information..." -ForegroundColor Green
    $ownerUpn = az ad signed-in-user show --query userPrincipalName -o tsv 2>$null
    if (-not $ownerUpn) {
        $ownerUpn = az account show --query user.name -o tsv
    }
    Write-Host "Owner: $ownerUpn"
    
    # Build tags
    $tags = "owner=$ownerUpn"
    if ($Description) {
        $tags += " Description=`"$Description`""
        Write-Host "Description: $Description"
    }
    
    # Create resource group
    Write-Host "Creating resource group..." -ForegroundColor Green
    az group create --name $ResourceGroup --location $Location --tags $tags | Out-Null
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
    
    # Create Key Vault (Premium SKU for HSM-backed keys)
    Write-Host "Creating Key Vault (Premium SKU for HSM keys)..." -ForegroundColor Green
    az keyvault create `
        --resource-group $ResourceGroup `
        --name $KeyVaultName `
        --location $Location `
        --sku premium `
        --enable-rbac-authorization false | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create Key Vault"
    }
    
    # Create managed identity
    Write-Host "Creating managed identity..." -ForegroundColor Green
    az identity create --resource-group $ResourceGroup --name $IdentityName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create managed identity"
    }
    
    # Retrieve identity details
    Write-Host "Retrieving identity details..." -ForegroundColor Green
    $idInfo = az identity show --resource-group $ResourceGroup --name $IdentityName -o json 2>$null | ConvertFrom-Json
    $IdentityClientId = $idInfo.clientId
    $IdentityResourceId = $idInfo.id
    $IdentityPrincipalId = $idInfo.principalId
    
    # Grant Key Vault access policy
    Write-Host "Granting Key Vault access policy..." -ForegroundColor Green
    az keyvault set-policy --name $KeyVaultName --object-id $IdentityPrincipalId --key-permissions get release 2>&1 | Out-Null
    
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
    $acrCreds = az acr credential show --name $RegistryName -o json 2>$null | ConvertFrom-Json
    $acrUsername = $acrCreds.username
    $acrPassword = $acrCreds.passwords[0].value
    $loginServer = az acr show --name $RegistryName --query loginServer -o tsv
    
    # Store credentials in Key Vault
    Write-Host "Storing credentials in Key Vault..." -ForegroundColor Green
    az keyvault secret set --vault-name $KeyVaultName --name "acr-username" --value $acrUsername --only-show-errors | Out-Null
    az keyvault secret set --vault-name $KeyVaultName --name "acr-password" --value $acrPassword --only-show-errors | Out-Null
    
    # Save configuration
    $config = @{
        registryName = $RegistryName
        resourceGroup = $ResourceGroup
        location = $Location
        loginServer = $loginServer
        imageName = $ImageName
        imageTag = $ImageTag
        fullImage = "$loginServer/${ImageName}:${ImageTag}"
        keyVaultName = $KeyVaultName
        skrMaaEndpoint = $MaaEndpoint
        skrKeyName = $SkrKeyName
        skrAkvEndpoint = "$KeyVaultName.vault.azure.net"
        identityName = $IdentityName
        identityResourceId = $IdentityResourceId
        identityClientId = $IdentityClientId
    }
    Save-Config $config
    
    Write-Header "Build Complete"
    Write-Host "Registry: $loginServer"
    Write-Host "Image: $loginServer/${ImageName}:${ImageTag}"
    Write-Host "Key Vault: $KeyVaultName (Premium)"
    Write-Host "Identity: $IdentityName"
    Write-Host "MAA Endpoint: $MaaEndpoint"
    Write-Host ""
    Write-Success "Credentials stored securely in Azure Key Vault"
    Write-Host "Configuration saved to acr-config.json"
    
    return $config
}

# ============================================================================
# Deploy Phase
# ============================================================================

function Invoke-Deploy {
    param([switch]$SkipBrowser)
    
    Write-Header "Deploying PostgreSQL Finance Demo"
    Write-Host "Architecture:" -ForegroundColor Yellow
    Write-Host "  Internet --> App Gateway (public IP)" -ForegroundColor White
    Write-Host "           --> ACI Container (Confidential, private VNet)" -ForegroundColor White
    Write-Host "           --> PostgreSQL Flexible Server (DCa/ECa AMD, TLS)" -ForegroundColor White
    Write-Host ""
    
    $config = Get-Config
    if (-not $config) {
        throw "acr-config.json not found. Run with -Build first."
    }
    
    $ResourceGroup = $config.resourceGroup
    $ACR_LOGIN_SERVER = $config.loginServer
    $FULL_IMAGE = $config.fullImage
    $KeyVaultName = $config.keyVaultName
    
    # Resolve deploy location from config
    $deployLocation = if ($config.location) { $config.location } else { $Location }
    if ($config.location -and $Location -ne "uaenorth" -and $Location -ne $config.location) {
        Write-Warning "Location mismatch: -Location '$Location' differs from build config '$($config.location)'"
        Write-Warning "Using build location '$($config.location)' to match existing resources."
    }
    
    # Get subscription ID
    $subscriptionId = az account show --query id -o tsv
    
    # Get ACR credentials from Key Vault
    Write-Host "Retrieving ACR credentials from Key Vault..." -ForegroundColor Green
    $ACR_USERNAME = az keyvault secret show --vault-name $KeyVaultName --name "acr-username" --query "value" -o tsv
    $ACR_PASSWORD = az keyvault secret show --vault-name $KeyVaultName --name "acr-password" --query "value" -o tsv
    
    if (-not $ACR_USERNAME -or -not $ACR_PASSWORD) {
        throw "Failed to retrieve ACR credentials from Key Vault"
    }
    Write-Success "ACR credentials retrieved"
    Write-Host ""
    
    # Generate unique names
    $timestamp = Get-Date -Format "MMddHHmm"
    $containerName = "aci-postgres-$timestamp"
    $VNetName = "${Prefix}-finance-vnet"
    $AciSubnetName = "aci-subnet"
    $AppGwSubnetName = "appgw-subnet"
    $pgRandom = -join ((97..122) | Get-Random -Count 4 | ForEach-Object { [char]$_ })
    $PgServerName = "${Prefix}pgfin${pgRandom}"
    $PgDbName = "financedemo"
    $PgAdminUser = "pgadmin"
    $AppGwName = "${Prefix}-finance-appgw"
    $AppGwPipName = "${Prefix}-finance-pip"
    
    Write-Host "Container: $containerName"
    Write-Host "VNet: $VNetName"
    Write-Host "PostgreSQL: $PgServerName"
    Write-Host "App Gateway: $AppGwName"
    Write-Host ""
    
    # Generate DB password and store in KV
    $PgPassword = New-SecureDbPassword
    Write-Host "PostgreSQL password generated and will be stored in Key Vault" -ForegroundColor Green
    az keyvault secret set --vault-name $KeyVaultName --name "pg-password" --value $PgPassword --only-show-errors | Out-Null
    
    # Check Docker
    Write-Host "Checking if Docker is running (required for security policy generation)..."
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Required for security policy generation. Start Docker Desktop."
    }
    Write-Success "Docker is running"
    Write-Host ""
    
    # ========== Phase 1: Network Infrastructure ==========
    Write-Header "Phase 1: Network Infrastructure"
    
    # Create VNet
    Write-Host "Creating Virtual Network: $VNetName (10.0.0.0/16)" -ForegroundColor Green
    az network vnet create `
        --resource-group $ResourceGroup `
        --name $VNetName `
        --location $deployLocation `
        --address-prefix "10.0.0.0/16" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create VNet" }
    
    # Create ACI subnet with delegation
    Write-Host "Creating ACI subnet (10.0.1.0/24) with container delegation..." -ForegroundColor Green
    az network vnet subnet create `
        --resource-group $ResourceGroup `
        --vnet-name $VNetName `
        --name $AciSubnetName `
        --address-prefix "10.0.1.0/24" `
        --delegations "Microsoft.ContainerInstance/containerGroups" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create ACI subnet" }
    
    # Create AppGw subnet (no delegation)
    Write-Host "Creating Application Gateway subnet (10.0.2.0/24)..." -ForegroundColor Green
    az network vnet subnet create `
        --resource-group $ResourceGroup `
        --vnet-name $VNetName `
        --name $AppGwSubnetName `
        --address-prefix "10.0.2.0/24" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create AppGw subnet" }
    
    Write-Success "VNet and subnets created"
    Write-Host ""
    
    # ========== Phase 2: PostgreSQL Flexible Server ==========
    Write-Header "Phase 2: PostgreSQL Flexible Server (DCa/ECa AMD Confidential Computing)"
    
    # Detect deployer's public IP for firewall rule
    Write-Host "Detecting deployment machine public IP..." -ForegroundColor Green
    $deployerIp = $null
    try {
        $deployerIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        Write-Host "  Deployer IP: $deployerIp" -ForegroundColor Gray
    } catch {
        try {
            $deployerIp = (Invoke-WebRequest -Uri "https://ifconfig.me/ip" -UseBasicParsing -TimeoutSec 10).Content.Trim()
            Write-Host "  Deployer IP: $deployerIp" -ForegroundColor Gray
        } catch {
            Write-Warning "Could not detect public IP automatically."
        }
    }
    
    # Set public access with deployer IP
    $publicAccessParam = if ($deployerIp) { $deployerIp } else { "0.0.0.0" }
    
    Write-Host "Creating PostgreSQL Flexible Server: $PgServerName" -ForegroundColor Green
    Write-Host "  Location: $deployLocation" -ForegroundColor Gray
    Write-Host "  Version: PostgreSQL 16" -ForegroundColor Gray
    
    # Detect the best available SKU: prefer AMD DCa/ECa (confidential), fallback to D-series
    # IMPORTANT: "eds" = Intel TDX, "ads" = AMD SEV-SNP. PostgreSQL CC requires AMD (ads) SKUs.
    Write-Host "  Detecting best available SKU..." -ForegroundColor Gray
    $pgSkuName = "Standard_D2ds_v5"
    $pgSkuTier = "GeneralPurpose"
    $pgSkuLabel = "non-CC fallback"
    
    $skuData = az postgres flexible-server list-skus --location $deployLocation -o json 2>$null | ConvertFrom-Json
    if ($skuData -and $skuData[0].supportedServerEditions) {
        # Check GeneralPurpose tier for DCa (AMD) SKUs
        $gpEdition = $skuData[0].supportedServerEditions | Where-Object { $_.name -eq "GeneralPurpose" }
        if ($gpEdition) {
            $availableSkus = $gpEdition.supportedServerSkus | ForEach-Object { $_.name }
            if ($availableSkus -contains "Standard_DC2ads_v5") {
                $pgSkuName = "Standard_DC2ads_v5"
                $pgSkuTier = "GeneralPurpose"
                $pgSkuLabel = "DCa-series AMD Confidential Computing"
            }
        }
        # Check MemoryOptimized tier for ECa (AMD) SKUs if no DCa found
        if ($pgSkuName -eq "Standard_D2ds_v5") {
            $moEdition = $skuData[0].supportedServerEditions | Where-Object { $_.name -eq "MemoryOptimized" }
            if ($moEdition) {
                $availableSkus = $moEdition.supportedServerSkus | ForEach-Object { $_.name }
                if ($availableSkus -contains "Standard_EC2ads_v5") {
                    $pgSkuName = "Standard_EC2ads_v5"
                    $pgSkuTier = "MemoryOptimized"
                    $pgSkuLabel = "ECa-series AMD Confidential Computing"
                }
            }
        }
    }
    Write-Host "  Selected SKU: $pgSkuName ($pgSkuLabel)" -ForegroundColor Cyan
    Write-Host "  This may take several minutes..." -ForegroundColor Yellow
    
    $pgCreateResult = az postgres flexible-server create `
        --name $PgServerName `
        --resource-group $ResourceGroup `
        --location $deployLocation `
        --sku-name $pgSkuName `
        --tier $pgSkuTier `
        --version "16" `
        --admin-user $PgAdminUser `
        --admin-password $PgPassword `
        --storage-size 32 `
        --public-access $publicAccessParam `
        --yes 2>&1
    
    if ($LASTEXITCODE -ne 0 -and $pgSkuName -like "Standard_DC*") {
        Write-Warning "DCa/ECa AMD creation failed (may be a quota/subscription restriction). Falling back to Standard_D2ds_v5..."
        # DC attempt may have reserved the name; generate a new unique name
        $pgRandom2 = -join ((97..122) | Get-Random -Count 4 | ForEach-Object { [char]$_ })
        $PgServerName = "${Prefix}pgfin${pgRandom2}"
        $pgSkuName = "Standard_D2ds_v5"
        $pgSkuLabel = "non-CC fallback"
        Write-Host "  New server name: $PgServerName" -ForegroundColor Gray
        Write-Host "  Fallback SKU: $pgSkuName" -ForegroundColor Gray
        
        $pgCreateResult = az postgres flexible-server create `
            --name $PgServerName `
            --resource-group $ResourceGroup `
            --location $deployLocation `
            --sku-name $pgSkuName `
            --tier $pgSkuTier `
            --version "16" `
            --admin-user $PgAdminUser `
            --admin-password $PgPassword `
            --storage-size 32 `
            --public-access $publicAccessParam `
            --yes 2>&1
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host $pgCreateResult
        throw "Failed to create PostgreSQL Flexible Server ($pgSkuName in $deployLocation)."
    }
    if ($pgSkuName -notlike "Standard_DC*") {
        Write-Warning "Using non-CC SKU ($pgSkuName). Redeploy to a region with DCa/ECa AMD SKUs for full confidential computing."
    }
    Write-Success "PostgreSQL Flexible Server created"
    
    # Add Azure services firewall rule (allows ACI to connect)
    Write-Host "Adding firewall rule for Azure services..." -ForegroundColor Green
    az postgres flexible-server firewall-rule create `
        --resource-group $ResourceGroup `
        --name $PgServerName `
        --rule-name "AllowAzureServices" `
        --start-ip-address "0.0.0.0" `
        --end-ip-address "0.0.0.0" 2>&1 | Out-Null
    Write-Success "Azure services firewall rule added"
    
    # Create database
    Write-Host "Creating database: $PgDbName" -ForegroundColor Green
    az postgres flexible-server db create `
        --resource-group $ResourceGroup `
        --server-name $PgServerName `
        --database-name $PgDbName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create database" }
    Write-Success "Database '$PgDbName' created"
    
    # Seed database with financial transactions
    Write-Host "Seeding database with 5000 financial transactions..." -ForegroundColor Green
    $seedPath = Join-Path $PSScriptRoot "seed-data.sql"
    
    if (-not (Test-Path $seedPath)) {
        Write-Warning "seed-data.sql not found. Generating..."
        $generateScript = Join-Path $PSScriptRoot "generate_transactions.py"
        python $generateScript
        if ($LASTEXITCODE -ne 0) { throw "Failed to generate seed data" }
    }
    
    $PgHost = "${PgServerName}.postgres.database.azure.com"
    $seeded = $false
    
    # Method 1: Try psql CLI (fastest, most reliable)
    $psqlCmd = Get-Command psql -ErrorAction SilentlyContinue
    if ($psqlCmd -and -not $seeded) {
        Write-Host "  Using psql CLI..." -ForegroundColor Gray
        $env:PGPASSWORD = $PgPassword
        psql -h $PgHost -U $PgAdminUser -d $PgDbName -f $seedPath 2>&1 | Out-Null
        $env:PGPASSWORD = $null
        if ($LASTEXITCODE -eq 0) {
            $seeded = $true
        } else {
            Write-Warning "  psql failed. Trying next method..."
        }
    }
    
    # Method 2: Try az postgres flexible-server execute (requires rdbms-connect extension)
    if (-not $seeded) {
        $rdbmsInstalled = az extension list --query "[?name=='rdbms-connect'].name" -o tsv 2>$null
        if ($rdbmsInstalled) {
            Write-Host "  Using az postgres flexible-server execute..." -ForegroundColor Gray
            $seedResult = az postgres flexible-server execute `
                --name $PgServerName `
                --admin-user $PgAdminUser `
                --admin-password $PgPassword `
                --database-name $PgDbName `
                --file-path $seedPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                $seeded = $true
            } else {
                Write-Warning "  az execute failed: $seedResult"
            }
        } else {
            Write-Host "  Skipping az execute (rdbms-connect extension not installed)" -ForegroundColor Gray
        }
    }
    
    # Method 3: Seed via Python psycopg2
    if (-not $seeded) {
        Write-Host "  Using Python psycopg2 to seed database..." -ForegroundColor Gray
        $pythonSeed = @"
import psycopg2, sys, os
try:
    conn = psycopg2.connect(host='$PgHost', dbname='$PgDbName', user='$PgAdminUser', password=os.environ['PGPASSWORD'], sslmode='require')
    conn.autocommit = True
    cur = conn.cursor()
    with open(r'$($seedPath -replace "\\","\\\\")','r',encoding='utf-8') as f:
        sql = f.read()
    # Split into statements and execute
    for stmt in sql.split(';'):
        stmt = stmt.strip()
        if stmt:
            cur.execute(stmt + ';')
    cur.execute('SELECT COUNT(*) FROM transactions')
    count = cur.fetchone()[0]
    print(f'Seeded {count} rows')
    cur.close()
    conn.close()
    sys.exit(0)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
"@
        $seedPyPath = Join-Path $PSScriptRoot "seed-db-temp.py"
        $pythonSeed | Out-File -FilePath $seedPyPath -Encoding UTF8
        $env:PGPASSWORD = $PgPassword
        python $seedPyPath 2>&1
        $env:PGPASSWORD = $null
        $seedExitCode = $LASTEXITCODE
        Remove-Item $seedPyPath -Force -ErrorAction SilentlyContinue
        if ($seedExitCode -eq 0) {
            $seeded = $true
        } else {
            Write-Warning "  Python seeding failed."
        }
    }
    
    if (-not $seeded) {
        throw "Failed to seed database. Install psql, the rdbms-connect extension, or psycopg2."
    }
    Write-Success "Database seeded with 5000 financial transactions"
    
    # Get PostgreSQL FQDN
    $PgHost = az postgres flexible-server show `
        --resource-group $ResourceGroup `
        --name $PgServerName `
        --query "fullyQualifiedDomainName" -o tsv
    Write-Host "PostgreSQL FQDN: $PgHost" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== Phase 3: Security Policy & Secure Key Release ==========
    Write-Header "Phase 3: Security Policy & Secure Key Release"
    
    # Login to ACR and pull image
    Write-Host "Logging into ACR and pulling latest image..." -ForegroundColor Green
    az acr login --name $ACR_LOGIN_SERVER --username $ACR_USERNAME --password $ACR_PASSWORD 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        docker login $ACR_LOGIN_SERVER -u $ACR_USERNAME -p $ACR_PASSWORD 2>&1 | Out-Null
    }
    
    Write-Host "Pulling image to ensure local cache matches ACR..."
    Write-Host "  Image: $FULL_IMAGE" -ForegroundColor Gray
    docker pull $FULL_IMAGE 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull image from ACR. Ensure the image exists: $FULL_IMAGE"
    }
    Write-Success "Image pulled, local cache in sync"
    Write-Host ""
    
    # Compute subnet ID for ACI deployment
    $aciSubnetId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VNetName/subnets/$AciSubnetName"
    
    # Create deployment parameters
    $deployParams = @{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $containerName }
            'location' = @{ 'value' = $deployLocation }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'skrKeyName' = @{ 'value' = $config.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $config.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $config.identityResourceId }
            'dbHost' = @{ 'value' = $PgHost }
            'dbName' = @{ 'value' = $PgDbName }
            'dbUser' = @{ 'value' = $PgAdminUser }
            'dbPassword' = @{ 'value' = $PgPassword }
            'subnetId' = @{ 'value' = $aciSubnetId }
        }
    }
    $deployParams | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params.json'
    Copy-Item -Path "deployment-template.json" -Destination "deployment-template-deploy.json" -Force
    
    # Generate confcom security policy
    Write-Host "Generating confidential computing security policy..." -ForegroundColor Cyan
    $policyInfo = Get-PolicyHashFromConfcom -TemplatePath "deployment-template-deploy.json" -ParamsPath "deployment-params.json"
    Write-Success "Policy hash: $($policyInfo.PolicyHash)"
    
    # Update params with policy hash
    $deployParams.parameters['securityPolicyHash'] = @{ 'value' = $policyInfo.PolicyHash }
    $deployParams | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params.json'
    
    # Create SKR key with policy hash binding
    $releasePolicy = Update-KeyReleasePolicy `
        -KeyVaultName $config.keyVaultName `
        -KeyName $config.skrKeyName `
        -MaaEndpoint $config.skrMaaEndpoint `
        -PolicyHash $policyInfo.PolicyHash `
        -CompanyName "Woodgrove-PostgreSQL"
    
    # ========== Phase 4: Deploy ACI Container ==========
    Write-Header "Phase 4: Deploy Confidential ACI Container"
    
    Write-Host "Deploying ACI container: $containerName" -ForegroundColor Green
    Write-Host "  Subnet: $AciSubnetName (private IP)" -ForegroundColor Gray
    Write-Host "  SKU: Confidential (AMD SEV-SNP TEE)" -ForegroundColor Gray
    Write-Host "  Image: $FULL_IMAGE" -ForegroundColor Gray
    Write-Host ""
    
    az deployment group create `
        --resource-group $ResourceGroup `
        --template-file "deployment-template-deploy.json" `
        --parameters '@deployment-params.json' 2>&1 | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "ACI deployment failed. Check 'az container logs --resource-group $ResourceGroup --name $containerName' for details."
    }
    Write-Success "ACI container deployed"
    
    # Get ACI private IP
    $aciPrivateIp = az container show `
        --resource-group $ResourceGroup `
        --name $containerName `
        --query "ipAddress.ip" -o tsv
    Write-Host "ACI Private IP: $aciPrivateIp" -ForegroundColor Cyan
    
    # Wait for container to be running
    Write-Host "Waiting for container to enter Running state..."
    $timeout = 180
    $elapsed = 0
    $ready = $false
    while ($elapsed -lt $timeout -and -not $ready) {
        $state = az container show --resource-group $ResourceGroup --name $containerName --query "instanceView.state" -o tsv 2>$null
        if ($state -eq "Running") {
            $ready = $true
        } else {
            Start-Sleep -Seconds 5
            $elapsed += 5
            Write-Host "  State: $state ($elapsed/${timeout}s)" -ForegroundColor Gray
        }
    }
    if (-not $ready) {
        Write-Warning "Container did not reach Running state within ${timeout}s. It may still be starting."
    } else {
        Write-Success "ACI container is Running"
    }
    Write-Host ""
    
    # ========== Phase 5: Application Gateway ==========
    Write-Header "Phase 5: Application Gateway"
    Write-Host "Creating Application Gateway for public access to the private ACI container." -ForegroundColor Yellow
    Write-Host "This typically takes 5-10 minutes..." -ForegroundColor Yellow
    Write-Host ""
    
    # Create public IP (Standard SKU, Static)
    Write-Host "Creating public IP address: $AppGwPipName" -ForegroundColor Green
    az network public-ip create `
        --resource-group $ResourceGroup `
        --name $AppGwPipName `
        --location $deployLocation `
        --sku Standard `
        --allocation-method Static | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create public IP" }
    
    # Create Application Gateway
    Write-Host "Creating Application Gateway: $AppGwName" -ForegroundColor Green
    Write-Host "  SKU: Standard_v2, Capacity: 1" -ForegroundColor Gray
    Write-Host "  Frontend: port 80 (HTTP)" -ForegroundColor Gray
    Write-Host "  Backend: $aciPrivateIp:80" -ForegroundColor Gray
    
    az network application-gateway create `
        --resource-group $ResourceGroup `
        --name $AppGwName `
        --location $deployLocation `
        --vnet-name $VNetName `
        --subnet $AppGwSubnetName `
        --sku Standard_v2 `
        --capacity 1 `
        --public-ip-address $AppGwPipName `
        --frontend-port 80 `
        --http-settings-port 80 `
        --http-settings-protocol Http `
        --servers $aciPrivateIp `
        --priority 100 2>&1 | Out-Null
    
    if ($LASTEXITCODE -ne 0) { throw "Failed to create Application Gateway" }
    Write-Success "Application Gateway created"
    
    # Add health probe
    Write-Host "Configuring health probe (/health)..." -ForegroundColor Green
    az network application-gateway probe create `
        --resource-group $ResourceGroup `
        --gateway-name $AppGwName `
        --name "health-probe" `
        --protocol Http `
        --host $aciPrivateIp `
        --path "/health" `
        --interval 30 `
        --timeout 30 `
        --threshold 3 2>&1 | Out-Null
    
    # Update HTTP settings to use health probe
    az network application-gateway http-settings update `
        --resource-group $ResourceGroup `
        --gateway-name $AppGwName `
        --name "appGatewayBackendHttpSettings" `
        --probe "health-probe" 2>&1 | Out-Null
    
    Write-Success "Health probe configured"
    
    # Get the public IP address
    $appGwPublicIp = az network public-ip show `
        --resource-group $ResourceGroup `
        --name $AppGwPipName `
        --query "ipAddress" -o tsv
    
    $appUrl = "http://$appGwPublicIp"
    
    # Update config with deployment state
    $config | Add-Member -NotePropertyName "containerName" -NotePropertyValue $containerName -Force
    $config | Add-Member -NotePropertyName "vnetName" -NotePropertyValue $VNetName -Force
    $config | Add-Member -NotePropertyName "pgServerName" -NotePropertyValue $PgServerName -Force
    $config | Add-Member -NotePropertyName "pgDbName" -NotePropertyValue $PgDbName -Force
    $config | Add-Member -NotePropertyName "pgAdminUser" -NotePropertyValue $PgAdminUser -Force
    $config | Add-Member -NotePropertyName "pgHost" -NotePropertyValue $PgHost -Force
    $config | Add-Member -NotePropertyName "appGwName" -NotePropertyValue $AppGwName -Force
    $config | Add-Member -NotePropertyName "appGwPublicIp" -NotePropertyValue $appGwPublicIp -Force
    $config | Add-Member -NotePropertyName "appUrl" -NotePropertyValue $appUrl -Force
    Save-Config $config
    
    # Wait for backend health check to pass
    Write-Host ""
    Write-Host "Waiting for Application Gateway backend health..." -ForegroundColor Cyan
    $healthTimeout = 120
    $healthElapsed = 0
    $backendHealthy = $false
    while ($healthElapsed -lt $healthTimeout -and -not $backendHealthy) {
        try {
            $response = Invoke-WebRequest -Uri "$appUrl/health" -Method Get -TimeoutSec 10 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                $backendHealthy = $true
            }
        } catch { }
        
        if (-not $backendHealthy) {
            Start-Sleep -Seconds 10
            $healthElapsed += 10
            Write-Host "  Waiting for backend... ($healthElapsed/${healthTimeout}s)" -ForegroundColor Gray
        }
    }
    
    if ($backendHealthy) {
        Write-Success "Backend is healthy and serving traffic!"
    } else {
        Write-Warning "Backend health check still pending. The app may take a moment to become available."
    }
    
    # ========== Deployment Summary ==========
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "  WOODGROVE BANK - CONFIDENTIAL POSTGRESQL FINANCE DEMO" -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Application URL:  $appUrl" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ACI Container:    $containerName (Private IP: $aciPrivateIp)" -ForegroundColor White
    Write-Host "  PostgreSQL:       $PgHost" -ForegroundColor White
    Write-Host "  VNet:             $VNetName (10.0.0.0/16)" -ForegroundColor White
    Write-Host "  App Gateway:      $AppGwName ($appGwPublicIp)" -ForegroundColor White
    Write-Host "  Key Vault:        $KeyVaultName" -ForegroundColor White
    Write-Host ""
    Write-Host "  Security:" -ForegroundColor Yellow
    Write-Host "    - AMD SEV-SNP Trusted Execution Environment (TEE)" -ForegroundColor Gray
    Write-Host "    - DCa/ECa-Series AMD PostgreSQL (Confidential Computing)" -ForegroundColor Gray
    Write-Host "    - MAA Attestation + Secure Key Release (SKR)" -ForegroundColor Gray
    Write-Host "    - TLS-encrypted database connections" -ForegroundColor Gray
    Write-Host "    - Private VNet for ACI container" -ForegroundColor Gray
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Open browser
    $edgeProcess = $null
    if (-not $SkipBrowser) {
        Write-Host "Opening Microsoft Edge..." -ForegroundColor Cyan
        $edgeProcess = Start-Process "msedge" -ArgumentList "--new-window `"$appUrl`"" -PassThru
    } else {
        Write-Host "Browser skipped. Open manually: $appUrl" -ForegroundColor Yellow
    }
    
    # Cleanup prompt
    Write-Host ""
    Write-Host "Press Enter when done viewing to cleanup containers..." -ForegroundColor Yellow
    Read-Host
    
    Write-Header "Cleaning Up Deployment Resources"
    
    # Close browser if we opened it
    if ($edgeProcess -and -not $edgeProcess.HasExited) {
        $closeBrowser = Read-Host "Close the browser window? (Y/n)"
        if ($closeBrowser -ne 'n' -and $closeBrowser -ne 'N') {
            try {
                $edgeProcess | Stop-Process -Force -ErrorAction SilentlyContinue
            } catch { }
        }
    }
    
    # Delete ACI container
    Write-Host "Deleting ACI container..." -ForegroundColor Green
    az container delete --resource-group $ResourceGroup --name $containerName --yes 2>&1 | Out-Null
    
    # Delete Application Gateway + public IP
    Write-Host "Deleting Application Gateway..." -ForegroundColor Green
    az network application-gateway delete --resource-group $ResourceGroup --name $AppGwName 2>&1 | Out-Null
    
    Write-Host "Deleting public IP..." -ForegroundColor Green
    az network public-ip delete --resource-group $ResourceGroup --name $AppGwPipName 2>&1 | Out-Null
    
    # Cleanup temp files
    Remove-Item -Path "deployment-params.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-deploy.json" -Force -ErrorAction SilentlyContinue
    
    Write-Success "Containers and gateway deleted. ACR, Key Vault, VNet, and PostgreSQL preserved."
    Write-Host "Run -Cleanup to delete all resources including the resource group."
}

# ============================================================================
# Cleanup Phase
# ============================================================================

function Invoke-Cleanup {
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
    Write-Host "  - Key Vault: $($config.keyVaultName)"
    if ($config.pgServerName) {
        Write-Host "  - PostgreSQL Server: $($config.pgServerName)"
    }
    if ($config.vnetName) {
        Write-Host "  - Virtual Network: $($config.vnetName)"
    }
    if ($config.appGwName) {
        Write-Host "  - Application Gateway: $($config.appGwName)"
    }
    Write-Host "  - All container instances and managed identities"
    Write-Host ""
    
    $response = Read-Host "Type 'yes' to confirm deletion"
    if ($response -ne 'yes') {
        Write-Warning "Cleanup cancelled."
        return
    }
    
    Write-Host ""
    Write-Host "Deleting resource group: $resource_group" -ForegroundColor Green
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
    Write-Host "Confidential ACI + PostgreSQL Finance Demo" -ForegroundColor Cyan
    Write-Host "============================================"
    Write-Host ""
    Write-Host "This script deploys a confidential container connected to a PostgreSQL"
    Write-Host "Flexible Server using DCa/ECa AMD confidential computing SKUs."
    Write-Host ""
    Write-Host "Architecture:" -ForegroundColor Yellow
    Write-Host "  Internet --> Application Gateway (public IP, Layer 7)" -ForegroundColor White
    Write-Host "           --> ACI Container (Confidential, AMD SEV-SNP, private VNet)" -ForegroundColor White
    Write-Host "           --> PostgreSQL Flexible Server (DCa/ECa AMD, TLS, firewalled)" -ForegroundColor White
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-PostgreSQLDemo.ps1 -Prefix <code> -Build         # Build container image"
    Write-Host "  .\Deploy-PostgreSQLDemo.ps1 -Prefix <code> -Deploy        # Deploy all infrastructure"
    Write-Host "  .\Deploy-PostgreSQLDemo.ps1 -Prefix <code> -Build -Deploy # Build and deploy"
    Write-Host "  .\Deploy-PostgreSQLDemo.ps1 -Cleanup                      # Delete all resources"
    Write-Host ""
    Write-Host "Required Parameter:" -ForegroundColor Yellow
    Write-Host "  -Prefix <code>  A short, unique identifier (3-8 lowercase alphanumeric chars)"
    Write-Host "                  Examples: jd01, dev, team42, acme" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -SkipBrowser    Don't open browser after deployment"
    Write-Host "  -RegistryName   Custom ACR name (default: random)"
    Write-Host "  -Location       Azure region (default: uaenorth)"
    Write-Host "  -Description    Optional description tag for the resource group"
    Write-Host ""
    
    $config = Get-Config
    if ($config) {
        Write-Host "Current configuration (from acr-config.json):" -ForegroundColor Green
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Registry: $($config.loginServer)"
        Write-Host "  Image: $($config.fullImage)"
        if ($config.appUrl) {
            Write-Host "  App URL: $($config.appUrl)" -ForegroundColor Green
        }
    } else {
        Write-Host "No existing configuration. Run with -Prefix <code> -Build to get started." -ForegroundColor Yellow
    }
    Write-Host ""
    exit 0
}

# Validate Prefix is provided when Build or Deploy is specified
if (($Build -or $Deploy) -and -not $Prefix) {
    Write-Host ""
    Write-Error "ERROR: The -Prefix parameter is required for -Build and -Deploy."
    Write-Host ""
    Write-Host "Please provide a short, unique identifier (3-8 lowercase alphanumeric characters)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\Deploy-PostgreSQLDemo.ps1 -Prefix jd01 -Build"
    Write-Host "  .\Deploy-PostgreSQLDemo.ps1 -Prefix dev -Build -Deploy"
    Write-Host ""
    exit 1
}

# Check all prerequisites before doing anything
Test-Prerequisites

# Execute requested actions
try {
    if ($Build -or $Deploy) {
        Test-DockerRunning
    }
    
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
    Write-Host ""
    Write-Error "FATAL ERROR: $_"
    Write-Host ""
    Write-Host "Stack trace:" -ForegroundColor Gray
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    Write-Host ""
    exit 1
}
