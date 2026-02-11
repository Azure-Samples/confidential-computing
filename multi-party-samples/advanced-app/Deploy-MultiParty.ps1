<#
.SYNOPSIS
    Deploy multi-party confidential computing demonstration.

.DESCRIPTION
    Deploys three confidential containers to demonstrate multi-party confidential computing:
    - Contoso Corporation: Enterprise data provider with encrypted employee records
    - Fabrikam Fashion: Online retail data provider with encrypted customer records  
    - Woodgrove Bank: Financial analytics platform that processes partner data securely

    This demonstrates how confidential computing enables secure multi-party data sharing,
    where each company's secrets are protected by hardware attestation and only accessible
    by verified confidential containers.

.PARAMETER Prefix
    REQUIRED. A short, unique identifier (3-8 characters) to prefix all Azure resources.
    Use something that identifies you or your team, like initials or team code.
    Examples: "jd01", "dev", "team42", "acme"
    This helps identify who owns the resources in shared subscriptions.

.PARAMETER Build
    Build and push the container image to Azure Container Registry.
    Creates ACR and Key Vault if they don't exist.

.PARAMETER Deploy
    Deploy all three confidential containers (Contoso, Fabrikam, Woodgrove-Bank).
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

.PARAMETER Description
    Optional description tag to add to the resource group.

.EXAMPLE
    .\Deploy-MultiParty.ps1 -Prefix "jd01" -Build
    Build and push the container image with prefix "jd01"

.EXAMPLE
    .\Deploy-MultiParty.ps1 -Prefix "dev" -Deploy
    Deploy all three containers with prefix "dev"

.EXAMPLE
    .\Deploy-MultiParty.ps1 -Prefix "team42" -Build -Deploy
    Build and deploy in one command with prefix "team42"

.EXAMPLE
    .\Deploy-MultiParty.ps1 -Cleanup
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
    [string]$Location = "eastus",
    [string]$Description
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
    # Verified via: (Get-AzAttestationDefaultProvider).Value | Sort-Object Location | Format-Table Location, AttestUri
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

function Get-PolicyHashFromConfcom {
    <#
    .SYNOPSIS
        Generate security policy using confcom and capture the hash it outputs.
    
    .DESCRIPTION
        Runs az confcom acipolicygen and captures the SHA256 hash it outputs.
        This hash is what Azure puts in the x-ms-sevsnpvm-hostdata claim during attestation.
        
        IMPORTANT: The hash output by confcom is NOT the same as SHA256(ccePolicy).
        Confcom computes the hash internally and this is what we must use.
    #>
    param(
        [string]$TemplatePath,
        [string]$ParamsPath
    )
    
    # Run confcom and capture output
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
    
    # Also extract the ccePolicy from the template (for reference)
    $template = Get-Content $TemplatePath -Raw | ConvertFrom-Json
    $ccePolicy = $template.resources[0].properties.confidentialComputeProperties.ccePolicy
    
    # Decode and display the confcom security policy (Rego)
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "║  DECODED CONFCOM SECURITY POLICY (Rego)                                      ║" -ForegroundColor DarkCyan
    Write-Host "║  Template: $($TemplatePath.PadRight(63))║" -ForegroundColor DarkCyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    try {
        $decodedPolicy = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ccePolicy))
        $decodedPolicy -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } catch {
        Write-Host "  (Could not decode base64 policy: $_)" -ForegroundColor Yellow
    }
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "║  Policy Hash: $($hashLine.Trim())  ║" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
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
        
        This ensures the key can ONLY be released to containers running the exact
        approved code, identified by the policy hash.
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
    
    # Create release policy with policy hash requirement
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
    
    # Display release policy on the console
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  $($CompanyName.ToUpper().PadRight(8)) KEY RELEASE POLICY (Single-Party)                            ║" -ForegroundColor Yellow
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
    $releasePolicyJson -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    # Check if key already exists
    $existingKey = az keyvault key show --vault-name $KeyVaultName --name $KeyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Key already exists. Deleting and recreating with new policy..." -ForegroundColor Yellow
        
        # Delete existing key
        az keyvault key delete --vault-name $KeyVaultName --name $KeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        
        # Purge deleted key
        az keyvault key purge --vault-name $KeyVaultName --name $KeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 3
    }
    
    # Create key with policy binding
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
        
        # If key still exists in deleted state, wait and retry
        if ($createError -match "conflict" -or $createError -match "already exists") {
            Write-Warning "  Key in deleted state. Waiting 15 seconds..."
            Start-Sleep -Seconds 15
            
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
                # Create with generic sevsnpvm-only policy as fallback
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
    
    # Clean up policy file
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
    $Config | ConvertTo-Json | Out-File -FilePath "acr-config.json" -Encoding UTF8
}

function Test-DockerRunning {
    <#
    .SYNOPSIS
        Checks if Docker is running, attempts to start it if not, and exits with helpful error if it fails.
    
    .DESCRIPTION
        Docker is required for generating the confidential computing security policy (ccepolicy).
        This function checks if Docker daemon is running, attempts to start Docker Desktop if not,
        and provides helpful error messages if Docker cannot be started.
    #>
    
    Write-Host "Checking Docker status..." -ForegroundColor Cyan
    
    # Check if docker command exists
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCmd) {
        Write-Host ""
        Write-Host "ERROR: Docker is not installed!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Docker is required to generate the confidential computing security policy." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Recommended actions:" -ForegroundColor Cyan
        Write-Host "  1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop/" -ForegroundColor White
        Write-Host "  2. Install Docker Desktop" -ForegroundColor White
        Write-Host "  3. Restart your terminal and run this script again" -ForegroundColor White
        Write-Host ""
        exit 1
    }
    
    # Check if Docker daemon is running
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Docker is running" -ForegroundColor Green
        return
    }
    
    Write-Host "Docker is not running. Attempting to start Docker Desktop..." -ForegroundColor Yellow
    
    # Try to find and start Docker Desktop
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
        Write-Host ""
        Write-Host "ERROR: Could not find Docker Desktop executable!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Docker Desktop appears to be installed but the executable was not found." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Recommended actions:" -ForegroundColor Cyan
        Write-Host "  1. Start Docker Desktop manually from the Start menu" -ForegroundColor White
        Write-Host "  2. Wait for it to fully initialize (check the system tray icon)" -ForegroundColor White
        Write-Host "  3. Run this script again" -ForegroundColor White
        Write-Host ""
        exit 1
    }
    
    # Start Docker Desktop
    Write-Host "Starting Docker Desktop from: $dockerDesktopPath" -ForegroundColor Cyan
    Start-Process -FilePath $dockerDesktopPath
    
    # Wait for Docker to start (check every 5 seconds, timeout after 120 seconds)
    $maxWaitSeconds = 120
    $waitInterval = 5
    $elapsed = 0
    
    Write-Host "Waiting for Docker daemon to start (timeout: ${maxWaitSeconds}s)..." -ForegroundColor Cyan
    
    while ($elapsed -lt $maxWaitSeconds) {
        Start-Sleep -Seconds $waitInterval
        $elapsed += $waitInterval
        
        # Check if Docker is now running
        $dockerInfo = docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Docker started successfully after ${elapsed} seconds" -ForegroundColor Green
            return
        }
        
        # Show progress
        $remaining = $maxWaitSeconds - $elapsed
        Write-Host "  Still waiting... (${remaining}s remaining)" -ForegroundColor Gray
    }
    
    # Docker didn't start in time
    Write-Host ""
    Write-Host "ERROR: Docker failed to start within ${maxWaitSeconds} seconds!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Docker is required to generate the confidential computing security policy." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Recommended actions:" -ForegroundColor Cyan
    Write-Host "  1. Check if Docker Desktop is starting in the system tray" -ForegroundColor White
    Write-Host "  2. If Docker shows an error, restart Docker Desktop manually" -ForegroundColor White
    Write-Host "  3. Ensure Windows Subsystem for Linux (WSL 2) is properly installed:" -ForegroundColor White
    Write-Host "       wsl --install" -ForegroundColor Gray
    Write-Host "       wsl --update" -ForegroundColor Gray
    Write-Host "  4. Try restarting your computer if Docker continues to fail" -ForegroundColor White
    Write-Host "  5. Check Docker Desktop settings - ensure WSL 2 backend is enabled" -ForegroundColor White
    Write-Host "  6. Once Docker is running, run this script again" -ForegroundColor White
    Write-Host ""
    Write-Host "For more troubleshooting, see: https://docs.docker.com/desktop/troubleshoot/overview/" -ForegroundColor Gray
    Write-Host ""
    exit 1
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
    
    # Get the logged-in user's UPN for the owner tag
    Write-Host "Getting logged-in user information..." -ForegroundColor Green
    $ownerUpn = az ad signed-in-user show --query userPrincipalName -o tsv 2>$null
    if (-not $ownerUpn) {
        # Fallback to account show if ad signed-in-user doesn't work
        $ownerUpn = az account show --query user.name -o tsv
    }
    Write-Host "Owner: $ownerUpn"
    
    # Build tags
    $tags = "owner=$ownerUpn"
    if ($Description) {
        $tags += " Description=`"$Description`""
        Write-Host "Description: $Description"
    }
    
    # Create resource group with tags
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
    $releasePolicyJson = $releasePolicy | ConvertTo-Json -Depth 10
    $releasePolicyPath = Join-Path $PSScriptRoot "skr-release-policy.json"
    $releasePolicyJson | Out-File -FilePath $releasePolicyPath -Encoding UTF8
    
    # Display the release policy on the console
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "║  SECURE KEY RELEASE POLICY (Build Phase - Generic)                           ║" -ForegroundColor DarkCyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    $releasePolicyJson -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
    
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
    
    # NOTE: Key will be created during Deploy phase with proper policy hash binding
    Write-Host "Key '$SkrKeyNameA' will be created during Deploy with security policy binding" -ForegroundColor Cyan
    Write-Success "Contoso: Key Vault '$KeyVaultNameA' created (key created during Deploy)"
    
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
    
    # NOTE: Key will be created during Deploy phase with proper policy hash binding
    Write-Host "Key '$SkrKeyNameB' will be created during Deploy with security policy binding" -ForegroundColor Cyan
    Write-Success "Fabrikam: Key Vault '$KeyVaultNameB' created (key created during Deploy)"
    
    # ========== Create Key Vault and Identity for Woodgrove-Bank ==========
    Write-Header "Creating Resources for Woodgrove-Bank"
    
    $KeyVaultNameC = "kv${RegistryName}c"
    $IdentityNameC = "id-${RegistryName}-woodgrove"
    $SkrKeyNameC = "woodgrove-secret-key"
    
    Write-Host "Creating Key Vault for Woodgrove-Bank: $KeyVaultNameC..." -ForegroundColor Green
    az keyvault create `
        --resource-group $ResourceGroup `
        --name $KeyVaultNameC `
        --location $Location `
        --sku premium `
        --enable-rbac-authorization false | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to create Key Vault for Woodgrove-Bank"
    }
    
    Write-Host "Creating managed identity for Woodgrove-Bank: $IdentityNameC..." -ForegroundColor Green
    az identity create --resource-group $ResourceGroup --name $IdentityNameC | Out-Null
    
    $IdentityClientIdC = az identity show --resource-group $ResourceGroup --name $IdentityNameC --query clientId -o tsv
    $IdentityResourceIdC = az identity show --resource-group $ResourceGroup --name $IdentityNameC --query id -o tsv
    $IdentityPrincipalIdC = az identity show --resource-group $ResourceGroup --name $IdentityNameC --query principalId -o tsv
    
    Write-Host "Granting Woodgrove-Bank identity access to its own Key Vault..." -ForegroundColor Green
    az keyvault set-policy --name $KeyVaultNameC --object-id $IdentityPrincipalIdC --key-permissions get release | Out-Null
    
    # NOTE: Key will be created during Deploy phase with proper policy hash binding
    Write-Host "Key '$SkrKeyNameC' will be created during Deploy with security policy binding" -ForegroundColor Cyan
    Write-Success "Woodgrove-Bank: Key Vault '$KeyVaultNameC' created (key created during Deploy)"
    
    # ========== Grant Woodgrove-Bank Access to Partner Key Vaults ==========
    Write-Header "Granting Woodgrove-Bank Cross-Company Access"
    
    Write-Host "Granting Woodgrove-Bank identity access to Contoso's Key Vault..." -ForegroundColor Cyan
    az keyvault set-policy --name $KeyVaultNameA --object-id $IdentityPrincipalIdC --key-permissions get release | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Woodgrove-Bank can now release keys from Contoso's Key Vault"
    }
    
    Write-Host "Granting Woodgrove-Bank identity access to Fabrikam's Key Vault..." -ForegroundColor Cyan
    az keyvault set-policy --name $KeyVaultNameB --object-id $IdentityPrincipalIdC --key-permissions get release | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Woodgrove-Bank can now release keys from Fabrikam's Key Vault"
    }
    
    Write-Host ""
    Write-Host "Woodgrove-Bank Multi-Party Access Configured:" -ForegroundColor Green
    Write-Host "  - Own Key Vault: $KeyVaultNameC ($SkrKeyNameC)" -ForegroundColor White
    Write-Host "  - Partner Access: $KeyVaultNameA ($SkrKeyNameA)" -ForegroundColor White
    Write-Host "  - Partner Access: $KeyVaultNameB ($SkrKeyNameB)" -ForegroundColor White
    
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
        contoso = @{
            keyVaultName = $KeyVaultNameA
            skrKeyName = $SkrKeyNameA
            skrAkvEndpoint = "$KeyVaultNameA.vault.azure.net"
            identityName = $IdentityNameA
            identityResourceId = $IdentityResourceIdA
            identityClientId = $IdentityClientIdA
        }
        # Fabrikam configuration
        fabrikam = @{
            keyVaultName = $KeyVaultNameB
            skrKeyName = $SkrKeyNameB
            skrAkvEndpoint = "$KeyVaultNameB.vault.azure.net"
            identityName = $IdentityNameB
            identityResourceId = $IdentityResourceIdB
            identityClientId = $IdentityClientIdB
        }
        # Woodgrove-Bank configuration
        woodgrove = @{
            keyVaultName = $KeyVaultNameC
            skrKeyName = $SkrKeyNameC
            skrAkvEndpoint = "$KeyVaultNameC.vault.azure.net"
            identityName = $IdentityNameC
            identityResourceId = $IdentityResourceIdC
            identityClientId = $IdentityClientIdC
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
    Write-Host "Woodgrove-Bank Resources:" -ForegroundColor Green
    Write-Host "  Key Vault: $KeyVaultNameC"
    Write-Host "  SKR Key: $SkrKeyNameC"
    Write-Host "  Identity: $IdentityNameC"
    Write-Host "  Cross-Company Access: Contoso + Fabrikam Key Vaults"
    Write-Host ""
    Write-Host "MAA Endpoint: $MaaEndpoint"
    Write-Host ""
    Write-Success "Credentials stored securely in Azure Key Vault"
    Write-Host "Configuration saved to acr-config.json"
    
    return $config
}

# ============================================================================
# Deploy Phase - Multi-Party (Contoso, Fabrikam Fashion, Woodgrove Bank)
# ============================================================================

function Invoke-Deploy {
    param([switch]$SkipBrowser)
    
    Write-Header "Deploying Multi-Party Demonstration"
    Write-Host "This will deploy 3 containers:" -ForegroundColor Yellow
    Write-Host "  - Contoso:        Confidential (AMD SEV-SNP TEE) - Corporate data provider" -ForegroundColor Green
    Write-Host "  - Fabrikam:       Confidential (AMD SEV-SNP TEE) - Online retailer" -ForegroundColor Magenta
    Write-Host "  - Woodgrove-Bank: Confidential (AMD SEV-SNP TEE) - Analytics partner" -ForegroundColor Green
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
    
    # Load storage connection string from .env file if it exists
    $StorageConnectionString = ""
    $envFilePath = Join-Path $PSScriptRoot ".env"
    if (Test-Path $envFilePath) {
        Write-Host "Loading storage connection string from .env file..."
        $envContent = Get-Content $envFilePath
        foreach ($line in $envContent) {
            if ($line -match "^AZURE_STORAGE_CONNECTION_STRING=(.+)$") {
                $StorageConnectionString = $matches[1]
                Write-Success "Storage connection string loaded"
                break
            }
        }
    } else {
        Write-Warning "No .env file found. Storage access will use public anonymous access only."
        Write-Host "Create a .env file with AZURE_STORAGE_CONNECTION_STRING to enable authenticated access."
    }
    Write-Host ""
    
    # Generate unique names for all containers
    $timestamp = Get-Date -Format "MMddHHmm"
    $container_companyA = "aci-contoso-$timestamp"
    $container_companyB = "aci-fabrikam-$timestamp"
    $container_companyC = "aci-woodgrove-$timestamp"
    $dns_companyA = "contoso-$timestamp"
    $dns_companyB = "fabrikam-$timestamp"
    $dns_companyC = "woodgrove-$timestamp"
    
    Write-Host "Container Names:"
    Write-Host "  Contoso:        $container_companyA"
    Write-Host "  Fabrikam:       $container_companyB"
    Write-Host "  Woodgrove-Bank: $container_companyC"
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
    
    # Force a fresh pull of the image from ACR to ensure local Docker cache matches ACR
    # This is CRITICAL - the policy generator uses local Docker images, and mismatches cause deployment failures
    Write-Host "Pulling latest image from ACR to ensure local cache matches remote..."
    Write-Host "  Image: $FULL_IMAGE" -ForegroundColor Gray
    docker pull $FULL_IMAGE 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull image from ACR. Ensure the image exists: $FULL_IMAGE"
    }
    Write-Success "Image pulled successfully - local Docker cache is now in sync with ACR"
    Write-Host ""
    
    # ========== PHASE 1: Generate All Security Policies ==========
    # We need all policy hashes BEFORE creating keys so we can set up multi-party access
    
    Write-Header "Phase 1: Generating Security Policies for All Companies"
    Write-Host "All policies must be generated first to enable cross-company key access" -ForegroundColor Yellow
    Write-Host ""
    
    # --- Contoso Policy Generation ---
    $contosoConfig = $config.contoso
    Write-Host "[1/3] Generating Contoso security policy..." -ForegroundColor Cyan
    
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
            'skrKeyName' = @{ 'value' = $contosoConfig.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $contosoConfig.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $contosoConfig.identityResourceId }
            'storageConnectionString' = @{ 'value' = $StorageConnectionString }
            'resourceGroupName' = @{ 'value' = $resource_group }
        }
    }
    $params_companyA | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-contoso.json'
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template-contoso.json" -Force
    
    $contosoPolicyInfo = Get-PolicyHashFromConfcom -TemplatePath "deployment-template-contoso.json" -ParamsPath "deployment-params-contoso.json"
    Write-Success "Contoso policy hash: $($contosoPolicyInfo.PolicyHash)"
    
    # --- Fabrikam Policy Generation ---
    $fabrikamConfig = $config.fabrikam
    Write-Host "[2/3] Generating Fabrikam security policy..." -ForegroundColor Magenta
    
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
            'skrKeyName' = @{ 'value' = $fabrikamConfig.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $fabrikamConfig.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $fabrikamConfig.identityResourceId }
            'storageConnectionString' = @{ 'value' = $StorageConnectionString }
            'resourceGroupName' = @{ 'value' = $resource_group }
        }
    }
    $params_companyB | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-fabrikam.json'
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template-fabrikam.json" -Force
    
    $fabrikamPolicyInfo = Get-PolicyHashFromConfcom -TemplatePath "deployment-template-fabrikam.json" -ParamsPath "deployment-params-fabrikam.json"
    Write-Success "Fabrikam policy hash: $($fabrikamPolicyInfo.PolicyHash)"
    
    # --- Woodgrove Policy Generation ---
    $woodgroveConfig = $config.woodgrove
    Write-Host "[3/3] Generating Woodgrove-Bank security policy..." -ForegroundColor Yellow
    
    # Build partner container URLs based on DNS names
    $contosoContainerUrl = "https://${dns_companyA}.${Location}.azurecontainer.io"
    $fabrikamContainerUrl = "https://${dns_companyB}.${Location}.azurecontainer.io"
    
    $params_companyC = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_companyC }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_companyC }
            'skrKeyName' = @{ 'value' = $woodgroveConfig.skrKeyName }
            'skrMaaEndpoint' = @{ 'value' = $config.skrMaaEndpoint }
            'skrAkvEndpoint' = @{ 'value' = $woodgroveConfig.skrAkvEndpoint }
            'identityResourceId' = @{ 'value' = $woodgroveConfig.identityResourceId }
            'storageConnectionString' = @{ 'value' = $StorageConnectionString }
            'resourceGroupName' = @{ 'value' = $resource_group }
            'partnerContosoAkvEndpoint' = @{ 'value' = $config.contoso.skrAkvEndpoint }
            'partnerFabrikamAkvEndpoint' = @{ 'value' = $config.fabrikam.skrAkvEndpoint }
            'partnerContosoUrl' = @{ 'value' = $contosoContainerUrl }
            'partnerFabrikamUrl' = @{ 'value' = $fabrikamContainerUrl }
        }
    }
    $params_companyC | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-woodgrove.json'
    Copy-Item -Path "deployment-template-woodgrove-base.json" -Destination "deployment-template-woodgrove.json" -Force
    
    $woodgrovePolicyInfo = Get-PolicyHashFromConfcom -TemplatePath "deployment-template-woodgrove.json" -ParamsPath "deployment-params-woodgrove.json"
    Write-Success "Woodgrove policy hash: $($woodgrovePolicyInfo.PolicyHash)"
    
    # ========== Display All Policy Hashes ==========
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  SECURITY POLICY HASHES - ALL COMPANIES                                      ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Contoso:   $($contosoPolicyInfo.PolicyHash)  ║" -ForegroundColor Green
    Write-Host "║  Fabrikam:  $($fabrikamPolicyInfo.PolicyHash)  ║" -ForegroundColor Magenta
    Write-Host "║  Woodgrove: $($woodgrovePolicyInfo.PolicyHash)  ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== PHASE 2: Create Keys with Multi-Party Policies ==========
    Write-Header "Phase 2: Creating Keys with Multi-Party Access Policies"
    Write-Host "Now that we have all policy hashes, we can create keys with proper bindings" -ForegroundColor Yellow
    Write-Host ""
    
    # --- Create Contoso Key (allows Contoso + Woodgrove) ---
    Write-Host "Creating Contoso key (multi-party: Contoso + Woodgrove)..." -ForegroundColor Cyan
    $contosoMultiPartyPolicy = @{
        version = "1.0.0"
        anyOf = @(
            @{
                authority = "https://$($config.skrMaaEndpoint)"
                allOf = @(
                    @{ claim = "x-ms-attestation-type"; equals = "sevsnpvm" },
                    @{ claim = "x-ms-sevsnpvm-hostdata"; equals = $contosoPolicyInfo.PolicyHash }
                )
            },
            @{
                authority = "https://$($config.skrMaaEndpoint)"
                allOf = @(
                    @{ claim = "x-ms-attestation-type"; equals = "sevsnpvm" },
                    @{ claim = "x-ms-sevsnpvm-hostdata"; equals = $woodgrovePolicyInfo.PolicyHash }
                )
            }
        )
    }
    $contosoMultiPolicyPath = Join-Path $PSScriptRoot "release-policy-contoso-multiparty.json"
    $contosoMultiPolicyJson = $contosoMultiPartyPolicy | ConvertTo-Json -Depth 10
    $contosoMultiPolicyJson | Out-File -FilePath $contosoMultiPolicyPath -Encoding UTF8
    
    # Display Contoso release policy on the console
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  CONTOSO KEY RELEASE POLICY (Multi-Party: Contoso + Woodgrove)               ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    $contosoMultiPolicyJson -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    # Check if key exists and delete/purge if needed
    $existingKey = az keyvault key show --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Deleting existing Contoso key..." -ForegroundColor Gray
        az keyvault key delete --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "    Purging Contoso key..." -ForegroundColor Gray
        az keyvault key purge --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 5
    }
    
    az keyvault key create --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName `
        --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt --exportable true `
        --policy $contosoMultiPolicyPath 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "  Contoso key created: allows Contoso + Woodgrove containers"
    } else {
        Write-Warning "  Contoso key creation failed - attempting without policy binding"
        az keyvault key create --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName `
            --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt --exportable true 2>&1 | Out-Null
    }
    Remove-Item $contosoMultiPolicyPath -Force -ErrorAction SilentlyContinue
    
    # --- Create Fabrikam Key (allows Fabrikam + Woodgrove) ---
    Write-Host "Creating Fabrikam key (multi-party: Fabrikam + Woodgrove)..." -ForegroundColor Magenta
    $fabrikamMultiPartyPolicy = @{
        version = "1.0.0"
        anyOf = @(
            @{
                authority = "https://$($config.skrMaaEndpoint)"
                allOf = @(
                    @{ claim = "x-ms-attestation-type"; equals = "sevsnpvm" },
                    @{ claim = "x-ms-sevsnpvm-hostdata"; equals = $fabrikamPolicyInfo.PolicyHash }
                )
            },
            @{
                authority = "https://$($config.skrMaaEndpoint)"
                allOf = @(
                    @{ claim = "x-ms-attestation-type"; equals = "sevsnpvm" },
                    @{ claim = "x-ms-sevsnpvm-hostdata"; equals = $woodgrovePolicyInfo.PolicyHash }
                )
            }
        )
    }
    $fabrikamMultiPolicyPath = Join-Path $PSScriptRoot "release-policy-fabrikam-multiparty.json"
    $fabrikamMultiPolicyJson = $fabrikamMultiPartyPolicy | ConvertTo-Json -Depth 10
    $fabrikamMultiPolicyJson | Out-File -FilePath $fabrikamMultiPolicyPath -Encoding UTF8
    
    # Display Fabrikam release policy on the console
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║  FABRIKAM KEY RELEASE POLICY (Multi-Party: Fabrikam + Woodgrove)              ║" -ForegroundColor Magenta
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
    $fabrikamMultiPolicyJson -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    # Check if key exists and delete/purge if needed
    $existingKey = az keyvault key show --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Deleting existing Fabrikam key..." -ForegroundColor Gray
        az keyvault key delete --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "    Purging Fabrikam key..." -ForegroundColor Gray
        az keyvault key purge --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 5
    }
    
    az keyvault key create --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName `
        --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt --exportable true `
        --policy $fabrikamMultiPolicyPath 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "  Fabrikam key created: allows Fabrikam + Woodgrove containers"
    } else {
        Write-Warning "  Fabrikam key creation failed - attempting without policy binding"
        az keyvault key create --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName `
            --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt --exportable true 2>&1 | Out-Null
    }
    Remove-Item $fabrikamMultiPolicyPath -Force -ErrorAction SilentlyContinue
    
    # --- Create Woodgrove Key (Woodgrove only) ---
    Write-Host "Creating Woodgrove key (single-party: Woodgrove only)..." -ForegroundColor Yellow
    $woodgroveReleasePolicy = Update-KeyReleasePolicy `
        -KeyVaultName $woodgroveConfig.keyVaultName `
        -KeyName $woodgroveConfig.skrKeyName `
        -MaaEndpoint $config.skrMaaEndpoint `
        -PolicyHash $woodgrovePolicyInfo.PolicyHash `
        -CompanyName "Woodgrove"
    
    # ========== Display Security Summary ==========
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  SECURITY POLICY BINDING SUMMARY                                             ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Contoso Key:   Releases to Contoso OR Woodgrove containers                  ║" -ForegroundColor White
    Write-Host "║  Fabrikam Key:  Releases to Fabrikam OR Woodgrove containers                 ║" -ForegroundColor White
    Write-Host "║  Woodgrove Key: Releases to Woodgrove container ONLY                         ║" -ForegroundColor White
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Keys are cryptographically bound to container code via policy hash          ║" -ForegroundColor Gray
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== PHASE 3: Deploy All Containers ==========
    Write-Header "Phase 3: Deploying All Containers"
    
    # Add policy hashes to deployment parameters for UI display
    $params_companyA.parameters['securityPolicyHash'] = @{ 'value' = $contosoPolicyInfo.PolicyHash }
    $params_companyA | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-contoso.json'
    
    $params_companyB.parameters['securityPolicyHash'] = @{ 'value' = $fabrikamPolicyInfo.PolicyHash }
    $params_companyB | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-fabrikam.json'
    
    $params_companyC.parameters['securityPolicyHash'] = @{ 'value' = $woodgrovePolicyInfo.PolicyHash }
    $params_companyC | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-woodgrove.json'
    
    # Deploy Contoso
    Write-Host "Deploying Contoso container..." -ForegroundColor Cyan
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-contoso.json `
        --parameters '@deployment-params-contoso.json' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to deploy Contoso container" }
    Write-Success "Contoso container deployed!"
    
    # Deploy Fabrikam
    Write-Host "Deploying Fabrikam container..." -ForegroundColor Magenta
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-fabrikam.json `
        --parameters '@deployment-params-fabrikam.json' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to deploy Fabrikam container" }
    Write-Success "Fabrikam container deployed!"
    
    # Deploy Woodgrove
    Write-Host "Deploying Woodgrove-Bank container..." -ForegroundColor Yellow
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-woodgrove.json `
        --parameters '@deployment-params-woodgrove.json' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to deploy Woodgrove-Bank container" }
    Write-Success "Woodgrove-Bank container deployed!"
    
    # ========== Wait for All Containers ==========
    Write-Header "Waiting for All Containers to Start"
    
    $fqdn_companyA = az container show --resource-group $resource_group --name $container_companyA --query "ipAddress.fqdn" --output tsv
    $fqdn_companyB = az container show --resource-group $resource_group --name $container_companyB --query "ipAddress.fqdn" --output tsv
    $fqdn_companyC = az container show --resource-group $resource_group --name $container_companyC --query "ipAddress.fqdn" --output tsv
    
    Write-Host "FQDNs:"
    Write-Host "  Contoso:        http://$fqdn_companyA" -ForegroundColor Green
    Write-Host "  Fabrikam:       http://$fqdn_companyB" -ForegroundColor Green
    Write-Host "  Woodgrove-Bank: http://$fqdn_companyC" -ForegroundColor Green
    Write-Host ""
    
    $timeout_seconds = 300
    $elapsed_seconds = 0
    $companyA_ready = $false
    $companyB_ready = $false
    $companyC_ready = $false
    
    while ($elapsed_seconds -lt $timeout_seconds -and (-not $companyA_ready -or -not $companyB_ready -or -not $companyC_ready)) {
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
        
        if (-not $companyC_ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://$fqdn_companyC" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { 
                    $companyC_ready = $true
                    Write-Success "Woodgrove-Bank is ready!"
                }
            } catch { }
        }
        
        if (-not $companyA_ready -or -not $companyB_ready -or -not $companyC_ready) {
            $status = "Waiting... ($elapsed_seconds/$timeout_seconds sec) - "
            $status += "Contoso: $(if ($companyA_ready) { 'Ready' } else { '...' }), "
            $status += "Fabrikam: $(if ($companyB_ready) { 'Ready' } else { '...' }), "
            $status += "Woodgrove: $(if ($companyC_ready) { 'Ready' } else { '...' })"
            Write-Host $status
            Start-Sleep -Seconds 5
            $elapsed_seconds += 5
        }
    }
    
    if (-not $companyA_ready -or -not $companyB_ready -or -not $companyC_ready) {
        Write-Warning "Some containers did not start in time"
        if (-not $companyA_ready) { Write-Warning "  - Contoso not ready" }
        if (-not $companyB_ready) { Write-Warning "  - Fabrikam not ready" }
        if (-not $companyC_ready) { Write-Warning "  - Woodgrove-Bank not ready" }
    }
    
    # ========== Open Edge with Multi-Party View ==========
    Write-Header "Opening Multi-Party Comparison View"
    
    Write-Host "Creating multi-party comparison view..."
    Write-Host "  Left:    Contoso (Confidential) - http://$fqdn_companyA"
    Write-Host "  Center:  Fabrikam (Confidential) - http://$fqdn_companyB"
    Write-Host "  Right:   Woodgrove-Bank (Confidential + Cross-company) - http://$fqdn_companyC"
    Write-Host ""
    
    # Open Edge with each company website in a separate tab
    $urlA = "http://$fqdn_companyA"
    $urlB = "http://$fqdn_companyB"
    $urlC = "http://$fqdn_companyC"
    
    $edgeProcess = $null
    if (-not $SkipBrowser) {
        Write-Host "Opening Microsoft Edge with each company in a separate tab..."
        Write-Host "  Tab 1: Contoso      - $urlA"
        Write-Host "  Tab 2: Fabrikam     - $urlB"
        Write-Host "  Tab 3: Woodgrove    - $urlC"
        Write-Host ""
        # Open Edge with all three URLs as separate tabs in a new window
        $edgeProcess = Start-Process "msedge" -ArgumentList "--new-window `"$urlA`" `"$urlB`" `"$urlC`"" -PassThru
    } else {
        Write-Host "Browser skipped. Open manually:"
        Write-Host "  $urlA"
        Write-Host "  $urlB"
        Write-Host "  $urlC"
    }
    
    # Cleanup prompt
    Write-Host ""
    Write-Host "Press Enter when done viewing to cleanup containers..." -ForegroundColor Yellow
    Read-Host
    
    Write-Header "Cleanup Multi-Party Containers"
    
    # Prompt to close the Edge window if we opened it
    if ($edgeProcess -and -not $edgeProcess.HasExited) {
        $closeBrowser = Read-Host "Close the browser window? (Y/n)"
        if ($closeBrowser -ne 'n' -and $closeBrowser -ne 'N') {
            Write-Host "Closing browser window..."
            try {
                $edgeProcess | Stop-Process -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore errors - user may have already closed the window
            }
        }
    }
    
    Write-Host "Deleting all containers..."
    az container delete --resource-group $resource_group --name $container_companyA --yes 2>&1 | Out-Null
    az container delete --resource-group $resource_group --name $container_companyB --yes 2>&1 | Out-Null
    az container delete --resource-group $resource_group --name $container_companyC --yes 2>&1 | Out-Null
    
    # Cleanup temp files
    Remove-Item -Path "deployment-params-contoso.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-params-fabrikam.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-params-woodgrove.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-contoso.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-fabrikam.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-woodgrove.json" -Force -ErrorAction SilentlyContinue
    
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
    if ($config.companyC) {
        Write-Host "  - Woodgrove-Bank Key Vault: $($config.companyC.keyVaultName)"
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
    
    # Load storage connection string from .env file
    if (Test-Path ".env") {
        $envContent = Get-Content ".env" -Raw
        # Handle both quoted and unquoted values
        if ($envContent -match 'AZURE_STORAGE_CONNECTION_STRING=([^\r\n]+)') {
            $connectionString = $matches[1].Trim('"').Trim("'")
            
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
            Write-Warning "Could not find storage connection string in .env file"
        }
    } else {
        Write-Warning "No .env file found - skipping blob cleanup"
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
    Write-Host "Multi-Party Confidential Computing Demo (Advanced)" -ForegroundColor Cyan
    Write-Host "==================================================="
    Write-Host ""
    Write-Host "This script deploys 3 confidential containers to demonstrate multi-party"
    Write-Host "confidential computing with cross-company data sharing:"
    Write-Host ""
    Write-Host "  Contoso:        Confidential (AMD SEV-SNP) - CAN attest" -ForegroundColor Green
    Write-Host "  Fabrikam:       Confidential (AMD SEV-SNP) - CAN attest" -ForegroundColor Green
    Write-Host "  Woodgrove-Bank: Confidential (AMD SEV-SNP) - CAN attest + cross-company access" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Build         # Build container image"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Deploy        # Deploy all 3 containers"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Build -Deploy # Build and deploy"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Cleanup       # Delete all resources"
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
    Write-Host "  -Description    Optional description tag for the resource group"
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

# Validate Prefix is provided when Build or Deploy is specified (not needed for Cleanup)
if (($Build -or $Deploy) -and -not $Prefix) {
    Write-Host ""
    Write-Host "ERROR: The -Prefix parameter is required for -Build and -Deploy." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please provide a short, unique identifier (3-8 lowercase alphanumeric characters)" -ForegroundColor Yellow
    Write-Host "to prefix all Azure resources. This helps identify who owns the resources."
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix jd01 -Build      # Use your initials + number"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix dev -Build       # Use a project code"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix team42 -Build    # Use your team identifier"
    Write-Host ""
    Write-Host "The prefix must be:" -ForegroundColor Gray
    Write-Host "  - 3 to 8 characters long"
    Write-Host "  - Lowercase letters and numbers only (a-z, 0-9)"
    Write-Host ""
    Write-Host "Note: -Cleanup does not require -Prefix (uses acr-config.json)" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# Execute requested actions
try {
    # Docker is required for Build (container image) and Deploy (security policy generation)
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
    Write-Error "Error: $_"
    exit 1
}
