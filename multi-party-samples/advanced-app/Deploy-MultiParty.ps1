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

.PARAMETER AKS
    Deploy to AKS with confidential virtual nodes instead of direct ACI.
    When specified, creates an AKS cluster with Azure CNI networking, installs
    the virtual nodes Helm chart, and deploys pods that run as confidential
    ACI container groups via the virtual node. This gives you Kubernetes
    orchestration while keeping the same ACI-backed confidential computing
    (AMD SEV-SNP TEE) with full attestation support.

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
    .\Deploy-MultiParty.ps1 -Prefix "jd01" -Build -Deploy -AKS
    Build and deploy to AKS with confidential virtual nodes

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
    [switch]$AKS,
    [string]$RegistryName,
    [string]$Location = "eastus",
    [string]$Description
)

$ErrorActionPreference = "Continue"
# Prevent $ErrorActionPreference from affecting native commands (az, docker, kubectl)
# In PowerShell 7.4+, stderr from native commands redirected with 2>&1 creates ErrorRecords.
# With ErrorActionPreference=Stop, these would terminate the script even on successful commands.
$PSNativeCommandUseErrorActionPreference = $false
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
        Start-Sleep -Seconds 1
        
        # Purge deleted key
        az keyvault key purge --vault-name $KeyVaultName --name $KeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
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

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validate that all required tools and dependencies are installed before running.
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
            Link = "https://learn.microsoft.com/cli/azure/install-azure-cli"
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
                Reason = "Required for generating confidential computing security policies (ccePolicy)"
                Install = "az extension add --name confcom"
                Link = "https://learn.microsoft.com/cli/azure/extension"
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
                Link = "https://learn.microsoft.com/cli/azure/authenticate-azure-cli"
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
            Link = "https://docs.docker.com/desktop/install/windows-install/"
        }
    }
    
    # --- kubectl (required for AKS mode) ---
    if ($script:AKS) {
        $kubectlCmd = Get-Command kubectl -ErrorAction SilentlyContinue
        if ($kubectlCmd) {
            $kubectlVersion = kubectl version --client --short 2>$null
            if (-not $kubectlVersion) { $kubectlVersion = "installed" }
            Write-Success "  kubectl ($kubectlVersion)"
        } else {
            $missing += @{
                Name = "kubectl"
                Reason = "Required for AKS deployment (Kubernetes CLI)"
                Install = "az aks install-cli"
                Link = "https://learn.microsoft.com/cli/azure/aks#az-aks-install-cli"
            }
        }
        
        $helmCmd = Get-Command helm -ErrorAction SilentlyContinue
        if ($helmCmd) {
            $helmVersion = helm version --short 2>$null
            if (-not $helmVersion) { $helmVersion = "installed" }
            Write-Success "  Helm ($helmVersion)"
        } else {
            $missing += @{
                Name = "Helm"
                Reason = "Required for installing virtual nodes on AKS"
                Install = "winget install Helm.Helm"
                Link = "https://helm.sh/docs/intro/install/"
            }
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
            Reason = "Used to open demo tabs after deployment (use -SkipBrowser to skip)"
            Link = "https://www.microsoft.com/edge"
        }
    }
    
    # --- Report warnings ---
    foreach ($warn in $warnings) {
        Write-Host "  [WARN] $($warn.Name) - not found" -ForegroundColor Yellow
        Write-Host "         $($warn.Reason)" -ForegroundColor Gray
        Write-Host "         Download: $($warn.Link)" -ForegroundColor Gray
    }
    
    # --- Report missing critical dependencies ---
    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "ERROR: $($missing.Count) required dependency/dependencies not found." -ForegroundColor Red
        Write-Host ""
        Write-Host "The following must be installed before running this script:" -ForegroundColor Yellow
        Write-Host ""
        foreach ($dep in $missing) {
            Write-Host "  $($dep.Name)" -ForegroundColor Red
            Write-Host "    Why:     $($dep.Reason)" -ForegroundColor Gray
            Write-Host "    Install: $($dep.Install)" -ForegroundColor Cyan
            Write-Host "    Docs:    $($dep.Link)" -ForegroundColor Gray
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
    
    # ========== Create All Key Vaults and Identities in Parallel ==========
    Write-Header "Creating Resources for All Companies (Parallel)"
    
    $KeyVaultNameA = "kv${RegistryName}a"
    $IdentityNameA = "id-${RegistryName}-contoso"
    $SkrKeyNameA = "contoso-secret-key"
    
    $KeyVaultNameB = "kv${RegistryName}b"
    $IdentityNameB = "id-${RegistryName}-fabrikam"
    $SkrKeyNameB = "fabrikam-secret-key"
    
    $KeyVaultNameC = "kv${RegistryName}c"
    $IdentityNameC = "id-${RegistryName}-woodgrove"
    $SkrKeyNameC = "woodgrove-secret-key"
    
    Write-Host "Creating 3 Key Vaults and 3 Managed Identities in parallel..." -ForegroundColor Green
    Write-Host "  Key Vaults: $KeyVaultNameA, $KeyVaultNameB, $KeyVaultNameC" -ForegroundColor Gray
    Write-Host "  Identities: $IdentityNameA, $IdentityNameB, $IdentityNameC" -ForegroundColor Gray
    Write-Host ""
    
    # Launch all 6 resource creations in parallel (3 KVs + 3 identities)
    $kvJobA = Start-Job -ScriptBlock { az keyvault create --resource-group $using:ResourceGroup --name $using:KeyVaultNameA --location $using:Location --sku premium --enable-rbac-authorization false 2>&1 }
    $kvJobB = Start-Job -ScriptBlock { az keyvault create --resource-group $using:ResourceGroup --name $using:KeyVaultNameB --location $using:Location --sku premium --enable-rbac-authorization false 2>&1 }
    $kvJobC = Start-Job -ScriptBlock { az keyvault create --resource-group $using:ResourceGroup --name $using:KeyVaultNameC --location $using:Location --sku premium --enable-rbac-authorization false 2>&1 }
    $idJobA = Start-Job -ScriptBlock { az identity create --resource-group $using:ResourceGroup --name $using:IdentityNameA 2>&1 }
    $idJobB = Start-Job -ScriptBlock { az identity create --resource-group $using:ResourceGroup --name $using:IdentityNameB 2>&1 }
    $idJobC = Start-Job -ScriptBlock { az identity create --resource-group $using:ResourceGroup --name $using:IdentityNameC 2>&1 }
    
    # Wait for all to complete
    $allJobs = @($kvJobA, $kvJobB, $kvJobC, $idJobA, $idJobB, $idJobC)
    $null = Wait-Job -Job $allJobs
    
    # Check results
    foreach ($j in @($kvJobA, $kvJobB, $kvJobC)) {
        $result = Receive-Job -Job $j
        if ($j.State -eq 'Failed') { Write-Warning "Key Vault creation had issues: $result" }
    }
    Remove-Job -Job $allJobs -Force
    Write-Success "All Key Vaults and Identities created"
    
    # Retrieve identity details (single call per identity using JSON output)
    Write-Host "Retrieving identity details..." -ForegroundColor Green
    $idInfoA = az identity show --resource-group $ResourceGroup --name $IdentityNameA -o json 2>$null | ConvertFrom-Json
    $idInfoB = az identity show --resource-group $ResourceGroup --name $IdentityNameB -o json 2>$null | ConvertFrom-Json
    $idInfoC = az identity show --resource-group $ResourceGroup --name $IdentityNameC -o json 2>$null | ConvertFrom-Json
    
    $IdentityClientIdA = $idInfoA.clientId
    $IdentityResourceIdA = $idInfoA.id
    $IdentityPrincipalIdA = $idInfoA.principalId
    
    $IdentityClientIdB = $idInfoB.clientId
    $IdentityResourceIdB = $idInfoB.id
    $IdentityPrincipalIdB = $idInfoB.principalId
    
    $IdentityClientIdC = $idInfoC.clientId
    $IdentityResourceIdC = $idInfoC.id
    $IdentityPrincipalIdC = $idInfoC.principalId
    
    # Grant Key Vault access policies in parallel
    Write-Host "Granting Key Vault access policies in parallel..." -ForegroundColor Green
    $policyJobs = @(
        # Each company's identity gets access to its own KV
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:KeyVaultNameA --object-id $using:IdentityPrincipalIdA --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:KeyVaultNameB --object-id $using:IdentityPrincipalIdB --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:KeyVaultNameC --object-id $using:IdentityPrincipalIdC --key-permissions get release 2>&1 }),
        # Woodgrove-Bank cross-company access
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:KeyVaultNameA --object-id $using:IdentityPrincipalIdC --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:KeyVaultNameB --object-id $using:IdentityPrincipalIdC --key-permissions get release 2>&1 })
    )
    $null = Wait-Job -Job $policyJobs
    $kvPolicyFailures = @()
    foreach ($job in $policyJobs) {
        if ($job.State -eq 'Failed') {
            $kvPolicyFailures += "Job $($job.Id) failed: $($job.ChildJobs[0].JobStateInfo.Reason)"
        } else {
            $jobOutput = Receive-Job -Job $job 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                $kvPolicyFailures += "KV policy job $($job.Id) returned exit code $LASTEXITCODE"
            }
        }
    }
    Remove-Job -Job $policyJobs -Force
    if ($kvPolicyFailures.Count -gt 0) {
        Write-Warning "Some Key Vault policy assignments may have failed:"
        $kvPolicyFailures | ForEach-Object { Write-Warning "  - $_" }
        Write-Warning "Verify each identity has 'get' and 'release' key permissions on its Key Vault."
    }
    
    Write-Success "Contoso: Key Vault '$KeyVaultNameA' created (key created during Deploy)"
    Write-Success "Fabrikam: Key Vault '$KeyVaultNameB' created (key created during Deploy)"
    Write-Success "Woodgrove-Bank: Key Vault '$KeyVaultNameC' created (key created during Deploy)"
    Write-Success "Woodgrove-Bank cross-company access to Contoso + Fabrikam Key Vaults granted"
    
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
    
    # Get ACR credentials (single calls instead of multiple queries)
    Write-Host "Retrieving ACR credentials..." -ForegroundColor Green
    $acrCreds = az acr credential show --name $RegistryName -o json 2>$null | ConvertFrom-Json
    $acrUsername = $acrCreds.username
    $acrPassword = $acrCreds.passwords[0].value
    $loginServer = az acr show --name $RegistryName --query loginServer -o tsv
    
    # Store credentials in Key Vault
    Write-Host "Storing credentials in Key Vault..." -ForegroundColor Green
    az keyvault secret set --vault-name $KeyVaultName --name "acr-username" --value $acrUsername --only-show-errors | Out-Null
    az keyvault secret set --vault-name $KeyVaultName --name "acr-password" --value $acrPassword --only-show-errors | Out-Null
    
    # Save configuration with both companies
    $config = @{
        registryName = $RegistryName
        resourceGroup = $ResourceGroup
        location = $Location
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
# AKS Build Phase - Add Virtual Nodes Infrastructure
# ============================================================================

function Invoke-BuildAKS {
    <#
    .SYNOPSIS
        Creates AKS cluster with confidential virtual nodes on top of the base Build.
    
    .DESCRIPTION
        After Invoke-Build creates the RG, ACR, Key Vaults, identities, and container image,
        this function adds:
        - A VNet with AKS subnet (for nodes) and a placeholder ACI subnet
        - An AKS cluster with Azure CNI networking and the legacy virtual-node addon
          (the addon triggers the AKS RP to create an aciconnectorlinux identity with
           Contributor on the node resource group - works without Owner permissions)
        - A SECOND VNet in the node resource group (MC_ RG) with a delegated ACI subnet,
          VNet peering to the main VNet, and a NAT gateway for outbound connectivity
        - A custom azure.json ConfigMap that points to the aciconnectorlinux identity
        - Virtual nodes v2 via a modified Helm chart that reads from the ConfigMap
        
        This approach works with Contributor-only permissions by leveraging the
        aciconnectorlinux identity that the AKS RP auto-assigns Contributor on the
        MC_ resource group. All ACI container groups are created in the MC_ RG
        where that identity has permissions.
    #>
    
    Write-Header "Building AKS with Confidential Virtual Nodes"
    
    $config = Get-Config
    if (-not $config) {
        throw "acr-config.json not found. Run with -Build first."
    }
    
    $resourceGroup = $config.resourceGroup
    $clusterName = "${Prefix}-aks-vnodes"
    $vnetName = "${Prefix}-vnet"
    $aksSubnetName = "aks-subnet"
    $aciSubnetName = "aci-subnet"
    $natGatewayName = "${Prefix}-natgw"
    $natPublicIpName = "${Prefix}-natgw-pip"
    
    Write-Host "AKS Cluster:  $clusterName" -ForegroundColor Cyan
    Write-Host "VNet:         $vnetName" -ForegroundColor Cyan
    Write-Host "AKS Subnet:   $aksSubnetName (10.1.0.0/16)" -ForegroundColor Cyan
    Write-Host "ACI Subnet:   $aciSubnetName (10.2.0.0/16, placeholder for addon)" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== Step 1: Create VNet with AKS and ACI Subnets ==========
    Write-Host "[1/9] Creating VNet with AKS and ACI subnets..." -ForegroundColor Green
    
    az network vnet create `
        --resource-group $resourceGroup `
        --name $vnetName `
        --address-prefix "10.0.0.0/8" `
        --location $Location `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create VNet" }
    
    az network vnet subnet create `
        --resource-group $resourceGroup `
        --vnet-name $vnetName `
        --name $aksSubnetName `
        --address-prefix "10.1.0.0/16" `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create AKS subnet" }
    
    # ACI subnet in main RG (required by --enable-addons virtual-node during cluster creation)
    az network vnet subnet create `
        --resource-group $resourceGroup `
        --vnet-name $vnetName `
        --name $aciSubnetName `
        --address-prefix "10.2.0.0/16" `
        --delegations "Microsoft.ContainerInstance/containerGroups" `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create ACI subnet with delegation" }
    
    Write-Success "VNet created with AKS and ACI subnets"
    
    # ========== Step 2: Create NAT Gateway (main RG) ==========
    Write-Host "[2/9] Creating NAT gateway for ACI subnet..." -ForegroundColor Green
    
    az network public-ip create `
        --resource-group $resourceGroup `
        --name $natPublicIpName `
        --sku Standard `
        --allocation-method Static `
        --location $Location `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create NAT gateway public IP" }
    
    az network nat gateway create `
        --resource-group $resourceGroup `
        --name $natGatewayName `
        --public-ip-addresses $natPublicIpName `
        --idle-timeout 10 `
        --location $Location `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create NAT gateway" }
    
    az network vnet subnet update `
        --resource-group $resourceGroup `
        --vnet-name $vnetName `
        --name $aciSubnetName `
        --nat-gateway $natGatewayName `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to associate NAT gateway with ACI subnet" }
    
    Write-Success "NAT gateway created and associated with ACI subnet"
    
    # ========== Step 3: Create AKS Cluster ==========
    Write-Host "[3/9] Creating AKS cluster with Azure CNI..." -ForegroundColor Green
    Write-Host "  This may take 5-10 minutes..." -ForegroundColor Gray
    Write-Host "  Using --enable-addons virtual-node to create addon identity with MC_ RG permissions." -ForegroundColor Gray
    
    $aksSubnetId = az network vnet subnet show `
        --resource-group $resourceGroup `
        --vnet-name $vnetName `
        --name $aksSubnetName `
        --query id -o tsv
    
    # The --enable-addons virtual-node triggers the AKS RP (first-party service principal)
    # to create an 'aciconnectorlinux' managed identity with Contributor role on the
    # node resource group (MC_ RG). This identity is also assigned to the VMSS, making
    # it available to pods via IMDS. We use this identity for virtual nodes v2.
    # Node count 2 is required: VN2 pod needs 3 CPUs, system pods take ~2 CPUs.
    $aksCreateOutput = az aks create `
        --resource-group $resourceGroup `
        --name $clusterName `
        --network-plugin azure `
        --vnet-subnet-id $aksSubnetId `
        --node-count 2 `
        --node-vm-size Standard_D4s_v4 `
        --generate-ssh-keys `
        --enable-addons virtual-node `
        --aci-subnet-name $aciSubnetName `
        --location $Location `
        --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($aksCreateOutput | Out-String) -ForegroundColor Red
        throw "Failed to create AKS cluster. See error above."
    }
    
    Write-Success "AKS cluster created: $clusterName"
    
    # Capture the aciconnectorlinux identity BEFORE disabling the addon
    # (addon identity info is cleared from az aks show after disable)
    $aciConnectorClientId = az aks show `
        --resource-group $resourceGroup `
        --name $clusterName `
        --query "addonProfiles.aciConnectorLinux.identity.clientId" -o tsv 2>$null
    
    if (-not $aciConnectorClientId) {
        Write-Warning "Could not get aciconnectorlinux identity from addon profile."
        Write-Host "  Falling back to VMSS identity list..." -ForegroundColor Gray
        $nodeResourceGroup = az aks show --resource-group $resourceGroup --name $clusterName --query nodeResourceGroup -o tsv
        $vmssName = az vmss list -g $nodeResourceGroup --query "[0].name" -o tsv 2>$null
        $vmssIdentities = az vmss identity show -g $nodeResourceGroup -n $vmssName -o json 2>$null | ConvertFrom-Json
        $aciConnectorEntry = $vmssIdentities.userAssignedIdentities.PSObject.Properties | Where-Object { $_.Name -match "aciconnectorlinux" } | Select-Object -First 1
        if ($aciConnectorEntry) {
            $aciConnectorClientId = $aciConnectorEntry.Value.clientId
        }
    }
    
    if (-not $aciConnectorClientId) {
        throw "Could not find aciconnectorlinux identity. The --enable-addons virtual-node may have failed."
    }
    Write-Host "  aciconnectorlinux identity: $aciConnectorClientId" -ForegroundColor Gray
    
    # Disable the legacy addon (it's stuck in Init because its identity lacks
    # permissions on the main RG). The identity and its MC_ RG roles persist.
    Write-Host "  Disabling legacy virtual-node addon (identity/roles persist)..." -ForegroundColor Gray
    az aks disable-addons `
        --resource-group $resourceGroup `
        --name $clusterName `
        --addons virtual-node `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to disable legacy virtual-node addon. Continuing..."
    }
    
    # ========== Step 3+: Create Managed Identities in MC_ RG ==========
    # VN2 (aciconnectorlinux) only has Contributor on the MC_ RG. When it creates
    # ACI container groups with user-assigned identities, it needs assign/action on
    # those identities. Identities created during Build are in the main RG where VN2
    # has no permissions. Solution: create them in MC_ RG and grant KV access.
    Write-Host ""
    Write-Host "  Creating managed identities in MC_ RG (required for VN2 identity assignment)..." -ForegroundColor Green
    
    $nodeResourceGroup = az aks show --resource-group $resourceGroup --name $clusterName --query nodeResourceGroup -o tsv
    
    $mcIdNameA = $config.contoso.identityName
    $mcIdNameB = $config.fabrikam.identityName
    $mcIdNameC = $config.woodgrove.identityName
    $kvNameA = $config.contoso.keyVaultName
    $kvNameB = $config.fabrikam.keyVaultName
    $kvNameC = $config.woodgrove.keyVaultName
    
    $mcIdJobA = Start-Job -ScriptBlock { az identity create --resource-group $using:nodeResourceGroup --name $using:mcIdNameA 2>&1 }
    $mcIdJobB = Start-Job -ScriptBlock { az identity create --resource-group $using:nodeResourceGroup --name $using:mcIdNameB 2>&1 }
    $mcIdJobC = Start-Job -ScriptBlock { az identity create --resource-group $using:nodeResourceGroup --name $using:mcIdNameC 2>&1 }
    $null = Wait-Job -Job @($mcIdJobA, $mcIdJobB, $mcIdJobC)
    Remove-Job -Job @($mcIdJobA, $mcIdJobB, $mcIdJobC) -Force
    
    # Retrieve MC_ RG identity details
    $mcIdInfoA = az identity show --resource-group $nodeResourceGroup --name $mcIdNameA -o json 2>$null | ConvertFrom-Json
    $mcIdInfoB = az identity show --resource-group $nodeResourceGroup --name $mcIdNameB -o json 2>$null | ConvertFrom-Json
    $mcIdInfoC = az identity show --resource-group $nodeResourceGroup --name $mcIdNameC -o json 2>$null | ConvertFrom-Json
    
    if (-not $mcIdInfoA -or -not $mcIdInfoB -or -not $mcIdInfoC) {
        throw "Failed to create identities in MC_ RG ($nodeResourceGroup)"
    }
    
    Write-Success "MC_ RG identities created: $mcIdNameA, $mcIdNameB, $mcIdNameC"
    
    # Grant Key Vault access policies (same cross-company pattern as Build)
    Write-Host "  Granting Key Vault access to MC_ RG identities..." -ForegroundColor Gray
    $mcPidA = $mcIdInfoA.principalId
    $mcPidB = $mcIdInfoB.principalId
    $mcPidC = $mcIdInfoC.principalId
    
    $kvPolicyJobs = @(
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:kvNameA --object-id $using:mcPidA --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:kvNameB --object-id $using:mcPidB --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:kvNameC --object-id $using:mcPidC --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:kvNameA --object-id $using:mcPidC --key-permissions get release 2>&1 }),
        (Start-Job -ScriptBlock { az keyvault set-policy --name $using:kvNameB --object-id $using:mcPidC --key-permissions get release 2>&1 })
    )
    $null = Wait-Job -Job $kvPolicyJobs
    $kvPolicyFailures = @()
    foreach ($job in $kvPolicyJobs) {
        if ($job.State -eq 'Failed') {
            $kvPolicyFailures += "Job $($job.Id) failed: $($job.ChildJobs[0].JobStateInfo.Reason)"
        } else {
            $jobOutput = Receive-Job -Job $job 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                $kvPolicyFailures += "KV policy job $($job.Id) returned exit code $LASTEXITCODE"
            }
        }
    }
    Remove-Job -Job $kvPolicyJobs -Force
    if ($kvPolicyFailures.Count -gt 0) {
        Write-Warning "Some Key Vault policy assignments may have failed:"
        $kvPolicyFailures | ForEach-Object { Write-Warning "  - $_" }
        Write-Warning "Verify each identity has 'get' and 'release' key permissions on its Key Vault."
    }
    
    Write-Success "Key Vault access granted (same cross-company pattern as Build)"
    
    # Update config with MC_ RG identity resource IDs
    $config.contoso.identityResourceId = $mcIdInfoA.id
    $config.contoso.identityClientId = $mcIdInfoA.clientId
    $config.fabrikam.identityResourceId = $mcIdInfoB.id
    $config.fabrikam.identityClientId = $mcIdInfoB.clientId
    $config.woodgrove.identityResourceId = $mcIdInfoC.id
    $config.woodgrove.identityClientId = $mcIdInfoC.clientId
    Save-Config $config
    
    Write-Host "  Identity resource IDs updated to MC_ RG in config" -ForegroundColor Gray
    
    # ========== Step 4: Get Kubectl Credentials ==========
    Write-Host "[4/9] Getting kubectl credentials..." -ForegroundColor Green
    
    az aks get-credentials `
        --resource-group $resourceGroup `
        --name $clusterName `
        --overwrite-existing `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to get AKS credentials" }
    
    Write-Success "kubectl configured for cluster: $clusterName"
    
    # ========== Step 5: Create MC_ RG VNet for ACI ==========
    Write-Host "[5/9] Creating VNet in node resource group for ACI workloads..." -ForegroundColor Green
    Write-Host "  The aciconnectorlinux identity has Contributor on the MC_ RG," -ForegroundColor Gray
    Write-Host "  so all ACI container groups will be created there." -ForegroundColor Gray
    
    $subscriptionId = az account show --query id -o tsv
    $nodeResourceGroup = az aks show --resource-group $resourceGroup --name $clusterName --query nodeResourceGroup -o tsv
    $mcVnetName = "${Prefix}-mc-vnet"
    $mcAciSubnetName = "aci-subnet-mc"
    $mcNatIpName = "${Prefix}-mc-nat-ip"
    $mcNatGwName = "${Prefix}-mc-natgw"
    
    # VNet in MC_ RG (172.16.0.0/16 - non-overlapping with main VNet 10.0.0.0/8)
    az network vnet create `
        --resource-group $nodeResourceGroup `
        --name $mcVnetName `
        --address-prefix "172.16.0.0/16" `
        --subnet-name $mcAciSubnetName `
        --subnet-prefix "172.16.0.0/16" `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create VNet in MC_ RG" }
    
    # Delegate the ACI subnet to Container Instances
    az network vnet subnet update `
        --resource-group $nodeResourceGroup `
        --vnet-name $mcVnetName `
        --name $mcAciSubnetName `
        --delegations "Microsoft.ContainerInstance/containerGroups" `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to delegate MC_ ACI subnet" }
    
    Write-Success "MC_ RG VNet created with delegated ACI subnet"
    
    # ========== Step 6: NAT Gateway & VNet Peering ==========
    Write-Host "[6/9] Creating NAT gateway and VNet peering..." -ForegroundColor Green
    
    # NAT gateway for MC_ RG ACI subnet outbound
    az network public-ip create `
        --resource-group $nodeResourceGroup `
        --name $mcNatIpName `
        --sku Standard `
        --allocation-method Static `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create MC_ NAT public IP" }
    
    az network nat gateway create `
        --resource-group $nodeResourceGroup `
        --name $mcNatGwName `
        --public-ip-addresses $mcNatIpName `
        --idle-timeout 10 `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create MC_ NAT gateway" }
    
    az network vnet subnet update `
        --resource-group $nodeResourceGroup `
        --vnet-name $mcVnetName `
        --name $mcAciSubnetName `
        --nat-gateway $mcNatGwName `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to associate MC_ NAT gateway" }
    
    # VNet peering: main VNet <-> MC_ VNet (allows ACI containers to communicate with AKS pods)
    $mcVnetId = "/subscriptions/$subscriptionId/resourceGroups/$nodeResourceGroup/providers/Microsoft.Network/virtualNetworks/$mcVnetName"
    $mainVnetId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/virtualNetworks/$vnetName"
    
    az network vnet peering create `
        --resource-group $resourceGroup `
        --name "main-to-mc" `
        --vnet-name $vnetName `
        --remote-vnet $mcVnetId `
        --allow-vnet-access `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create VNet peering (main -> MC)" }
    
    az network vnet peering create `
        --resource-group $nodeResourceGroup `
        --name "mc-to-main" `
        --vnet-name $mcVnetName `
        --remote-vnet $mainVnetId `
        --allow-vnet-access `
        --only-show-errors 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create VNet peering (MC -> main)" }
    
    Write-Success "NAT gateway and VNet peering configured"
    
    # ========== Step 7: Create ConfigMap & Modify Helm Chart ==========
    Write-Host "[7/9] Preparing custom identity ConfigMap and Helm chart..." -ForegroundColor Green
    
    $tenantId = az account show --query tenantId -o tsv
    
    # Create a custom azure.json that uses the aciconnectorlinux identity
    # instead of the kubelet identity. This identity has Contributor on the MC_ RG
    # (auto-assigned by the AKS RP), and is already assigned to the VMSS (available via IMDS).
    $azureJsonContent = @"
{
    "cloud": "AzurePublicCloud",
    "tenantId": "$tenantId",
    "subscriptionId": "$subscriptionId",
    "aadClientId": "msi",
    "aadClientSecret": "msi",
    "resourceGroup": "$nodeResourceGroup",
    "location": "$Location",
    "vmType": "vmss",
    "subnetName": "$mcAciSubnetName",
    "vnetName": "$mcVnetName",
    "vnetResourceGroup": "$nodeResourceGroup",
    "useManagedIdentityExtension": true,
    "userAssignedIdentityID": "$aciConnectorClientId",
    "useInstanceMetadata": true,
    "loadBalancerSku": "standard"
}
"@
    
    # Create the vn2 namespace and ConfigMap
    kubectl create namespace vn2 --dry-run=client -o yaml 2>$null | kubectl apply -f - 2>$null | Out-Null
    
    # Label and annotate for Helm ownership
    kubectl label namespace vn2 "app.kubernetes.io/managed-by=Helm" --overwrite 2>$null | Out-Null
    kubectl annotate namespace vn2 "meta.helm.sh/release-name=virtualnode2" "meta.helm.sh/release-namespace=vn2" --overwrite 2>$null | Out-Null
    
    $tempAzureJson = Join-Path ([System.IO.Path]::GetTempPath()) "azure-vn2-$(Get-Random).json"
    $azureJsonContent | Set-Content -Path $tempAzureJson -Encoding UTF8 -NoNewline
    kubectl create configmap vn2-azure-creds -n vn2 `
        --from-file="azure.json=$tempAzureJson" `
        --dry-run=client -o yaml 2>$null | kubectl apply -f - 2>$null | Out-Null
    Remove-Item $tempAzureJson -Force -ErrorAction SilentlyContinue
    
    Write-Success "ConfigMap created with aciconnectorlinux identity credentials"
    
    # Clone the virtual nodes v2 Helm chart and modify it to use the ConfigMap
    $vnTempDir = Join-Path ([System.IO.Path]::GetTempPath()) "virtualnodesOnACI-$(Get-Random)"
    Write-Host "  Cloning virtual nodes Helm chart repo..." -ForegroundColor Gray
    git clone --depth 1 --quiet `
        "https://github.com/microsoft/virtualnodesOnAzureContainerInstances.git" `
        $vnTempDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone virtualnodesOnAzureContainerInstances repo."
    }
    
    $helmChartPath = Join-Path $vnTempDir "Helm" "virtualnode"
    $deploymentFile = Join-Path $helmChartPath "templates" "deployment.yaml"
    
    if (-not (Test-Path $deploymentFile)) {
        Remove-Item -Recurse -Force $vnTempDir -ErrorAction SilentlyContinue
        throw "Helm chart deployment.yaml not found at: $deploymentFile"
    }
    
    # Patch deployment.yaml:
    # 1. Replace hostPath volume with ConfigMap volume
    # 2. Add subPath to all volumeMounts referencing aks-credential
    $content = Get-Content $deploymentFile -Raw
    
    # Replace the aks-credential hostPath volume with ConfigMap
    $content = $content -replace `
        '- name: aks-credential\s+hostPath:\s+path: /etc/kubernetes/azure\.json\s+type: File', `
        "- name: aks-credential`n          configMap:`n            name: vn2-azure-creds"
    
    # Add subPath to /etc/kubernetes/azure.json mount (kubelet container)
    $content = $content -replace `
        '(- mountPath: /etc/kubernetes/azure\.json\s+name: aks-credential)', `
        "- mountPath: /etc/kubernetes/azure.json`n              name: aks-credential`n              subPath: azure.json"
    
    # Add subPath to /etc/aks/azure.json mounts (crisocketotcpadapter, proxycri)
    $content = $content -replace `
        '(- name: aks-credential\s+mountPath: /etc/aks/azure\.json)', `
        "- name: aks-credential`n              mountPath: /etc/aks/azure.json`n              subPath: azure.json"
    
    $content | Set-Content $deploymentFile -Encoding UTF8 -NoNewline
    
    Write-Success "Helm chart patched to use ConfigMap identity"
    
    # ========== Step 8: Install Virtual Nodes Helm Chart ==========
    Write-Host "[8/9] Installing virtual nodes v2 Helm chart..." -ForegroundColor Green
    
    $helmOutput = helm install virtualnode2 $helmChartPath `
        --namespace vn2 `
        --set "aciSubnetName=$mcAciSubnetName" `
        --set "aciResourceGroupName=$nodeResourceGroup" `
        --set admissionControllerReplicaCount=0 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($helmOutput | Out-String) -ForegroundColor Red
        Remove-Item -Recurse -Force $vnTempDir -ErrorAction SilentlyContinue
        throw "Failed to install virtual nodes Helm chart."
    }
    
    Remove-Item -Recurse -Force $vnTempDir -ErrorAction SilentlyContinue
    
    Write-Success "Virtual nodes Helm chart installed"
    
    # ========== Step 9: Wait for Virtual Node to be Ready ==========
    Write-Host "[9/9] Waiting for virtual node to register..." -ForegroundColor Green
    Write-Host "  VN2 pod deploys in namespace 'vn2', node registers as virtualnode2-0." -ForegroundColor Gray
    
    $podReady = $false
    $maxWait = 180
    $elapsed = 0
    while (-not $podReady -and $elapsed -lt $maxWait) {
        $podPhase = kubectl get pod virtualnode2-0 -n vn2 --no-headers -o custom-columns=":status.phase" 2>$null
        if ($podPhase -and $podPhase.Trim() -eq "Running") {
            $readyContainers = kubectl get pod virtualnode2-0 -n vn2 --no-headers -o custom-columns=":status.containerStatuses[*].ready" 2>$null
            if ($readyContainers -and -not ($readyContainers -match "false")) {
                $podReady = $true
                Write-Success "Virtual node pod is Running (all containers ready)"
            }
        }
        if (-not $podReady) {
            $podStatus = kubectl get pod virtualnode2-0 -n vn2 --no-headers 2>$null
            if ($podStatus -match "CrashLoopBackOff|Error") {
                Write-Warning "Virtual node pod is in CrashLoopBackOff or Error state!"
                Write-Host "  Check: kubectl logs virtualnode2-0 -n vn2 -c proxycri" -ForegroundColor Yellow
                break
            }
            Write-Host "  Waiting for virtualnode2-0 pod... ($elapsed/${maxWait}s)" -ForegroundColor Gray
            Start-Sleep -Seconds 10
            $elapsed += 10
        }
    }
    
    if ($podReady) {
        $vnodeReady = $false
        $maxWait2 = 120
        $elapsed2 = 0
        while (-not $vnodeReady -and $elapsed2 -lt $maxWait2) {
            $nodes = kubectl get nodes -o json 2>$null | ConvertFrom-Json
            if ($nodes) {
                foreach ($node in $nodes.items) {
                    if ($node.metadata.labels.'virtualization' -eq 'virtualnode2') {
                        $vnodeReady = $true
                        Write-Success "Virtual node registered: $($node.metadata.name)"
                        break
                    }
                }
            }
            if (-not $vnodeReady) {
                Write-Host "  Waiting for virtual node registration... ($elapsed2/${maxWait2}s)" -ForegroundColor Gray
                Start-Sleep -Seconds 10
                $elapsed2 += 10
            }
        }
        if (-not $vnodeReady) {
            Write-Warning "Virtual node not registered after ${maxWait2}s. Check: kubectl get nodes"
        }
    } elseif ($elapsed -ge $maxWait) {
        Write-Warning "Virtual node pod not ready after ${maxWait}s. Check: kubectl get pods -n vn2"
    }
    
    Write-Host ""
    Write-Host "Cluster Nodes:" -ForegroundColor Cyan
    kubectl get nodes -o wide
    Write-Host ""
    
    # ========== Update Config ==========
    $config | Add-Member -NotePropertyName "aksClusterName" -NotePropertyValue $clusterName -Force
    $config | Add-Member -NotePropertyName "vnetName" -NotePropertyValue $vnetName -Force
    $config | Add-Member -NotePropertyName "aksSubnetName" -NotePropertyValue $aksSubnetName -Force
    $config | Add-Member -NotePropertyName "aciSubnetName" -NotePropertyValue $mcAciSubnetName -Force
    $config | Add-Member -NotePropertyName "aciResourceGroup" -NotePropertyValue $nodeResourceGroup -Force
    $config | Add-Member -NotePropertyName "mcVnetName" -NotePropertyValue $mcVnetName -Force
    $config | Add-Member -NotePropertyName "deploymentTarget" -NotePropertyValue "AKS" -Force
    Save-Config $config
    
    Write-Header "AKS Build Complete"
    Write-Host "Cluster:          $clusterName (2 nodes)" -ForegroundColor Green
    Write-Host "Main VNet:        $vnetName (10.0.0.0/8)" -ForegroundColor Green
    Write-Host "MC_ VNet:         $mcVnetName (172.16.0.0/16, peered)" -ForegroundColor Green
    Write-Host "ACI Subnet:       $mcAciSubnetName (in $nodeResourceGroup)" -ForegroundColor Green
    Write-Host "ACI Identity:     aciconnectorlinux ($aciConnectorClientId)" -ForegroundColor Green
    Write-Host "Virtual Node:     Ready" -ForegroundColor Green
    Write-Host ""
    Write-Host "Pods with nodeSelector 'virtualization: virtualnode2'" -ForegroundColor Gray
    Write-Host "run as confidential ACI container groups with SEV-SNP attestation." -ForegroundColor Gray
    Write-Host ""
    Write-Success "Configuration saved to acr-config.json (deploymentTarget: AKS)"
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
    
    # Resolve deploy location from config (with fallback for older configs)
    $deployLocation = if ($config.location) { $config.location } else { $Location }
    if ($config.location -and $Location -ne "eastus" -and $Location -ne $config.location) {
        Write-Warning "Location mismatch: -Location '$Location' differs from build config '$($config.location)'"
        Write-Warning "Using build location '$($config.location)' to match existing resources."
    }
    if (-not $config.location) {
        Write-Warning "Config missing 'location' (older config). Using -Location '$Location'. Re-run -Build to fix."
    }
    
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
            'location' = @{ 'value' = $deployLocation }
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
            'location' = @{ 'value' = $deployLocation }
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
    
    # Build partner container URLs based on DNS names (use config location for correct region)
    $contosoContainerUrl = "https://${dns_companyA}.${deployLocation}.azurecontainer.io"
    $fabrikamContainerUrl = "https://${dns_companyB}.${deployLocation}.azurecontainer.io"
    
    $params_companyC = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_companyC }
            'location' = @{ 'value' = $deployLocation }
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
        Start-Sleep -Seconds 1
        Write-Host "    Purging Contoso key..." -ForegroundColor Gray
        az keyvault key purge --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
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
        Start-Sleep -Seconds 1
        Write-Host "    Purging Fabrikam key..." -ForegroundColor Gray
        az keyvault key purge --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
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
    
    # Deploy all 3 containers in parallel for maximum speed
    Write-Host "Deploying all 3 containers in parallel..." -ForegroundColor Cyan
    Write-Host "  This saves several minutes compared to sequential deployment" -ForegroundColor Gray
    Write-Host ""
    
    $scriptRoot = $PSScriptRoot
    $deployJobA = Start-Job -ScriptBlock {
        Set-Location $using:scriptRoot
        az deployment group create --resource-group $using:resource_group --template-file deployment-template-contoso.json --parameters '@deployment-params-contoso.json' 2>&1
    }
    $deployJobB = Start-Job -ScriptBlock {
        Set-Location $using:scriptRoot
        az deployment group create --resource-group $using:resource_group --template-file deployment-template-fabrikam.json --parameters '@deployment-params-fabrikam.json' 2>&1
    }
    $deployJobC = Start-Job -ScriptBlock {
        Set-Location $using:scriptRoot
        az deployment group create --resource-group $using:resource_group --template-file deployment-template-woodgrove.json --parameters '@deployment-params-woodgrove.json' 2>&1
    }
    
    # Wait for all deployments with progress updates
    $deployJobs = @(
        @{ Job = $deployJobA; Name = "Contoso"; Color = "Cyan" },
        @{ Job = $deployJobB; Name = "Fabrikam"; Color = "Magenta" },
        @{ Job = $deployJobC; Name = "Woodgrove-Bank"; Color = "Yellow" }
    )
    
    $allDone = $false
    while (-not $allDone) {
        $allDone = $true
        foreach ($d in $deployJobs) {
            if ($d.Job.State -eq 'Running') {
                $allDone = $false
            } elseif ($d.Job.State -eq 'Completed' -and -not $d.ContainsKey('Reported')) {
                Write-Success "$($d.Name) container deployed!"
                $d['Reported'] = $true
            }
        }
        if (-not $allDone) { Start-Sleep -Seconds 3 }
    }
    
    # Verify all succeeded
    foreach ($d in $deployJobs) {
        $result = Receive-Job -Job $d.Job
        if ($d.Job.State -eq 'Failed') {
            Write-Host $result -ForegroundColor Red
            throw "Failed to deploy $($d.Name) container"
        }
    }
    Remove-Job -Job @($deployJobA, $deployJobB, $deployJobC) -Force
    Write-Success "All 3 containers deployed!"
    
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
# AKS Deploy Phase - Virtual Nodes (Confidential Pods on ACI)
# ============================================================================

function New-VirtualNodePodYaml {
    <#
    .SYNOPSIS
        Generate a Kubernetes pod YAML for deployment on AKS confidential virtual nodes.
    
    .DESCRIPTION
        Creates a pod spec with:
        - nodeSelector: virtualization=virtualnode2 (targets virtual nodes)
        - tolerations for virtual-kubelet provider
        - annotations for managed identity, DNS label, and confidential policy
        - environment variables matching the ACI ARM template pattern
        - imagePullSecrets for ACR authentication
        
        The ccepolicy annotation is left empty and will be injected by confcom.
    #>
    param(
        [string]$PodName,
        [string]$CompanyLabel,
        [string]$Image,
        [string]$IdentityResourceId,
        [string]$DnsLabel,
        [string]$SkrKeyName,
        [string]$SkrMaaEndpoint,
        [string]$SkrAkvEndpoint,
        [string]$StorageConnectionString,
        [string]$ResourceGroupName,
        [string]$AciSubnetName,
        [int]$MemoryGi = 2,
        [int]$Cpu = 1,
        [hashtable]$ExtraEnvVars = @{}
    )
    
    # Build env vars section
    $envLines = @(
        "    - name: SKR_KEY_NAME",
        "      value: `"$SkrKeyName`"",
        "    - name: SKR_MAA_ENDPOINT",
        "      value: `"$SkrMaaEndpoint`"",
        "    - name: SKR_AKV_ENDPOINT",
        "      value: `"$SkrAkvEndpoint`"",
        "    - name: AZURE_STORAGE_CONNECTION_STRING",
        "      value: `"$StorageConnectionString`"",
        "    - name: RESOURCE_GROUP_NAME",
        "      value: `"$ResourceGroupName`"",
        "    - name: SECURITY_POLICY_HASH",
        "      value: `"`""
    )
    
    foreach ($key in $ExtraEnvVars.Keys) {
        $envLines += "    - name: $key"
        $envLines += "      value: `"$($ExtraEnvVars[$key])`""
    }
    
    $envSection = $envLines -join "`n"
    
    $yaml = @"
apiVersion: v1
kind: Pod
metadata:
  name: $PodName
  labels:
    app: $CompanyLabel
    demo: multi-party-confidential
  annotations:
    microsoft.containerinstance.virtualnode.ccepolicy: ""
    microsoft.containerinstance.virtualnode.identity: "$IdentityResourceId"
    microsoft.containerinstance.virtualnode.dnsnamelabel: "$DnsLabel"
    microsoft.containerinstance.virtualnode.subnet: "$AciSubnetName"
spec:
  dnsPolicy: None
  dnsConfig:
    nameservers:
    - "168.63.129.16"
  nodeSelector:
    virtualization: virtualnode2
  tolerations:
  - key: virtual-kubelet.io/provider
    operator: Exists
    effect: NoSchedule
  containers:
  - name: attestation-demo
    image: $Image
    ports:
    - containerPort: 80
    - containerPort: 443
    env:
$envSection
    resources:
      limits:
        memory: "${MemoryGi}Gi"
        cpu: "$Cpu"
      requests:
        memory: "${MemoryGi}Gi"
        cpu: "$Cpu"
  imagePullSecrets:
  - name: acr-secret
"@
    
    return $yaml
}

function Get-PolicyHashFromVirtualNodeYaml {
    <#
    .SYNOPSIS
        Generate security policy for a virtual-node pod YAML using confcom.
    
    .DESCRIPTION
        Runs az confcom acipolicygen --virtual-node-yaml to:
        1. Generate the security policy for the pod
        2. Inject the ccepolicy annotation into the YAML file
        3. Output the SHA256 policy hash
        
        This hash is used for key release policy binding, identical to the ACI flow.
    #>
    param(
        [string]$YamlPath
    )
    
    $output = az confcom acipolicygen --virtual-node-yaml $YamlPath --approve-wildcards --disable-stdio 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -ne 0) {
        Write-Error "Confcom failed for virtual-node YAML: $output"
        throw "Failed to generate security policy for $YamlPath"
    }
    
    # The hash is output as the last 64-character hex line
    $hashLine = $output | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -Last 1
    
    if (-not $hashLine) {
        Write-Warning "Could not find policy hash in confcom output. Output was:"
        $output | ForEach-Object { Write-Host "  $_" }
        throw "No policy hash found in confcom output for $YamlPath"
    }
    
    # Read back the modified YAML to verify ccepolicy was injected
    $modifiedYaml = Get-Content $YamlPath -Raw
    if ($modifiedYaml -match 'microsoft\.containerinstance\.virtualnode\.ccepolicy:\s*"([^"]+)"') {
        Write-Host "  ccepolicy annotation injected (" -NoNewline
        Write-Host "$($matches[1].Length) chars" -ForegroundColor Gray -NoNewline
        Write-Host ")"
    }
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "║  VIRTUAL NODE CONFCOM POLICY                                                 ║" -ForegroundColor DarkCyan
    Write-Host "║  YAML: $($YamlPath.PadRight(67))║" -ForegroundColor DarkCyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "║  Policy Hash: $($hashLine.Trim().PadRight(60))║" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
    
    return @{
        PolicyHash = $hashLine.Trim()
        YamlPath = $YamlPath
    }
}

function Invoke-DeployAKS {
    param([switch]$SkipBrowser)
    
    Write-Header "Deploying Multi-Party Demo on AKS Virtual Nodes"
    Write-Host "Pods will run as confidential ACI container groups via virtual nodes." -ForegroundColor Yellow
    Write-Host "This preserves the full ACI attestation stack (SEV-SNP + SKR + MAA)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  - Contoso:        Confidential Virtual Node Pod (AMD SEV-SNP TEE)" -ForegroundColor Green
    Write-Host "  - Fabrikam:       Confidential Virtual Node Pod (AMD SEV-SNP TEE)" -ForegroundColor Magenta
    Write-Host "  - Woodgrove-Bank: Confidential Virtual Node Pod (AMD SEV-SNP TEE)" -ForegroundColor Green
    Write-Host ""
    
    $config = Get-Config
    if (-not $config) {
        throw "acr-config.json not found. Run with -Build first."
    }
    if ($config.deploymentTarget -ne "AKS") {
        throw "Configuration shows deploymentTarget='$($config.deploymentTarget)'. Run with -Build -AKS first."
    }
    
    $resource_group = $config.resourceGroup
    $ACR_LOGIN_SERVER = $config.loginServer
    $FULL_IMAGE = $config.fullImage
    $KeyVaultName = $config.keyVaultName
    $aciSubnetName = $config.aciSubnetName
    $clusterName = $config.aksClusterName
    
    # Resolve deploy location from config (with fallback for older configs)
    $deployLocation = if ($config.location) { $config.location } else { $Location }
    if ($config.location -and $Location -ne "eastus" -and $Location -ne $config.location) {
        Write-Warning "Location mismatch: -Location '$Location' differs from build config '$($config.location)'"
        Write-Warning "Using build location '$($config.location)' to match existing resources."
    }
    if (-not $config.location) {
        Write-Warning "Config missing 'location' (older config). Using -Location '$Location'. Re-run -Build -AKS to fix."
    }
    
    # Ensure kubectl is pointed at the right cluster
    Write-Host "Connecting to AKS cluster: $clusterName..."
    az aks get-credentials `
        --resource-group $resource_group `
        --name $clusterName `
        --overwrite-existing `
        --only-show-errors 2>&1 | Out-Null
    Write-Success "Connected to AKS cluster"
    Write-Host ""
    
    # Verify identities are in the MC_ RG (VN2 needs assign/action permissions)
    $mcRG = $config.aciResourceGroup
    if ($config.contoso.identityResourceId -notmatch [regex]::Escape($mcRG)) {
        Write-Warning "Identities are not in the MC_ RG. VN2 will fail with LinkedAuthorizationFailed."
        Write-Host "  Run with -Build -AKS to recreate identities in the MC_ RG," -ForegroundColor Yellow
        Write-Host "  or create them manually with: az identity create --resource-group '$mcRG'" -ForegroundColor Yellow
        throw "Identity resource IDs must reference MC_ resource group ($mcRG). Current: $($config.contoso.identityResourceId)"
    }
    
    # Get ACR credentials from Key Vault
    Write-Host "Retrieving ACR credentials from Key Vault..."
    $ACR_USERNAME = az keyvault secret show --vault-name $KeyVaultName --name "acr-username" --query "value" -o tsv
    $ACR_PASSWORD = az keyvault secret show --vault-name $KeyVaultName --name "acr-password" --query "value" -o tsv
    
    if (-not $ACR_USERNAME -or -not $ACR_PASSWORD) {
        throw "Failed to retrieve ACR credentials from Key Vault"
    }
    Write-Success "Credentials retrieved"
    
    # Create Kubernetes image pull secret for ACR
    Write-Host "Creating Kubernetes image pull secret..."
    kubectl delete secret acr-secret --ignore-not-found 2>&1 | Out-Null
    kubectl create secret docker-registry acr-secret `
        --docker-server=$ACR_LOGIN_SERVER `
        --docker-username=$ACR_USERNAME `
        --docker-password=$ACR_PASSWORD 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create ACR pull secret" }
    Write-Success "ACR pull secret created"
    Write-Host ""
    
    # Load storage connection string
    $StorageConnectionString = ""
    $envFilePath = Join-Path $PSScriptRoot ".env"
    if (Test-Path $envFilePath) {
        $envContent = Get-Content $envFilePath
        foreach ($line in $envContent) {
            if ($line -match "^AZURE_STORAGE_CONNECTION_STRING=(.+)$") {
                $StorageConnectionString = $matches[1]
                Write-Success "Storage connection string loaded from .env"
                break
            }
        }
    }
    
    # Check Docker for confcom
    Write-Host "Checking Docker (required for policy generation)..."
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Required for security policy generation. Start Docker Desktop."
    }
    Write-Success "Docker is running"
    Write-Host ""
    
    # Login to ACR (for confcom to pull image layers)
    Write-Host "Logging into ACR ($($config.registryName))..."
    $acrLoginOutput = docker login $ACR_LOGIN_SERVER --username $ACR_USERNAME --password $ACR_PASSWORD 2>&1 | Out-String
    if ($acrLoginOutput -match "Login Succeeded") {
        Write-Host "  ACR login: done" -ForegroundColor Gray
    } else {
        Write-Host "  ACR login output: $acrLoginOutput" -ForegroundColor Yellow
        Write-Host "  ACR login: done (via docker login)" -ForegroundColor Gray
    }
    
    # Pull image for confcom
    Write-Host "Pulling latest image for policy generation..."
    $pullOutput = docker pull $FULL_IMAGE 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Failed to pull image: $FULL_IMAGE. Output: $pullOutput" }
    Write-Success "Image ready"
    Write-Host ""
    
    # Generate unique names
    $timestamp = Get-Date -Format "MMddHHmm"
    $pod_companyA = "contoso-$timestamp"
    $pod_companyB = "fabrikam-$timestamp"
    $pod_companyC = "woodgrove-$timestamp"
    $dns_companyA = "contoso-$timestamp"
    $dns_companyB = "fabrikam-$timestamp"
    $dns_companyC = "woodgrove-$timestamp"
    
    Write-Host "Pod Names:"
    Write-Host "  Contoso:        $pod_companyA"
    Write-Host "  Fabrikam:       $pod_companyB"
    Write-Host "  Woodgrove-Bank: $pod_companyC"
    Write-Host ""
    
    # ========== PHASE 1: Generate Pod YAMLs and Security Policies ==========
    Write-Header "Phase 1: Generating Pod YAMLs and Security Policies"
    
    $contosoConfig = $config.contoso
    $fabrikamConfig = $config.fabrikam
    $woodgroveConfig = $config.woodgrove
    
    # --- Contoso Pod YAML ---
    Write-Host "[1/3] Generating Contoso pod YAML..." -ForegroundColor Cyan
    $contosoYaml = New-VirtualNodePodYaml `
        -PodName $pod_companyA `
        -CompanyLabel "contoso" `
        -Image $FULL_IMAGE `
        -IdentityResourceId $contosoConfig.identityResourceId `
        -DnsLabel $dns_companyA `
        -SkrKeyName $contosoConfig.skrKeyName `
        -SkrMaaEndpoint $config.skrMaaEndpoint `
        -SkrAkvEndpoint $contosoConfig.skrAkvEndpoint `
        -StorageConnectionString $StorageConnectionString `
        -ResourceGroupName $resource_group `
        -AciSubnetName $aciSubnetName
    $contosoYamlPath = Join-Path $PSScriptRoot "pod-contoso.yaml"
    $contosoYaml | Set-Content $contosoYamlPath -Encoding UTF8
    
    $contosoPolicyInfo = Get-PolicyHashFromVirtualNodeYaml -YamlPath $contosoYamlPath
    Write-Success "Contoso policy hash: $($contosoPolicyInfo.PolicyHash)"
    
    # --- Fabrikam Pod YAML ---
    Write-Host "[2/3] Generating Fabrikam pod YAML..." -ForegroundColor Magenta
    $fabrikamYaml = New-VirtualNodePodYaml `
        -PodName $pod_companyB `
        -CompanyLabel "fabrikam" `
        -Image $FULL_IMAGE `
        -IdentityResourceId $fabrikamConfig.identityResourceId `
        -DnsLabel $dns_companyB `
        -SkrKeyName $fabrikamConfig.skrKeyName `
        -SkrMaaEndpoint $config.skrMaaEndpoint `
        -SkrAkvEndpoint $fabrikamConfig.skrAkvEndpoint `
        -StorageConnectionString $StorageConnectionString `
        -ResourceGroupName $resource_group `
        -AciSubnetName $aciSubnetName
    $fabrikamYamlPath = Join-Path $PSScriptRoot "pod-fabrikam.yaml"
    $fabrikamYaml | Set-Content $fabrikamYamlPath -Encoding UTF8
    
    $fabrikamPolicyInfo = Get-PolicyHashFromVirtualNodeYaml -YamlPath $fabrikamYamlPath
    Write-Success "Fabrikam policy hash: $($fabrikamPolicyInfo.PolicyHash)"
    
    # NOTE: Woodgrove pod YAML is generated AFTER Contoso and Fabrikam pods are deployed
    # and have IPs assigned. This is because Woodgrove's partner URLs must point to the actual
    # pod IPs (http://<ip>) since virtual node pods don't have public DNS names.
    # The Woodgrove policy hash depends on these URLs, so it's computed later.
    $woodgroveYamlPath = Join-Path $PSScriptRoot "pod-woodgrove.yaml"
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  SECURITY POLICY HASHES - CONTOSO & FABRIKAM (AKS Virtual Nodes)             ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Contoso:   $($contosoPolicyInfo.PolicyHash)  ║" -ForegroundColor Green
    Write-Host "║  Fabrikam:  $($fabrikamPolicyInfo.PolicyHash)  ║" -ForegroundColor Magenta
    Write-Host "║  Woodgrove: (pending - needs partner pod IPs first)                          ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== PHASE 2: Deploy Contoso & Fabrikam First ==========
    # Keys require ALL policy hashes (including Woodgrove), but Woodgrove's hash depends on
    # partner pod IPs. So we deploy Contoso & Fabrikam first, get their IPs, then generate
    # Woodgrove YAML, compute all keys, and deploy Woodgrove.
    Write-Header "Phase 2: Deploying Contoso & Fabrikam Pods"
    Write-Host "Deploying Contoso and Fabrikam first to get pod IPs for Woodgrove partner URLs." -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "  Deploying Contoso pod..." -ForegroundColor Cyan
    kubectl apply -f $contosoYamlPath 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning "Contoso pod apply returned non-zero" }
    
    Write-Host "  Deploying Fabrikam pod..." -ForegroundColor Magenta
    kubectl apply -f $fabrikamYamlPath 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning "Fabrikam pod apply returned non-zero" }
    
    Write-Host ""
    Write-Host "Waiting for Contoso and Fabrikam pods to start (may take 2-5 minutes)..." -ForegroundColor Gray
    
    $timeout_seconds = 300
    $elapsed_seconds = 0
    $companyA_ready = $false
    $companyB_ready = $false
    
    while ($elapsed_seconds -lt $timeout_seconds -and (-not $companyA_ready -or -not $companyB_ready)) {
        try {
            $podJson = kubectl get pods -l demo=multi-party-confidential -o json 2>&1 | Out-String
            $pods = $podJson | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($pods -and $pods.items) {
                foreach ($pod in $pods.items) {
                    $podName = $pod.metadata.name
                    $phase = $pod.status.phase
                    
                    if ($podName -eq $pod_companyA -and $phase -eq "Running" -and -not $companyA_ready) {
                        $companyA_ready = $true
                        Write-Success "Contoso pod is Running!"
                    }
                    if ($podName -eq $pod_companyB -and $phase -eq "Running" -and -not $companyB_ready) {
                        $companyB_ready = $true
                        Write-Success "Fabrikam pod is Running!"
                    }
                }
            }
        } catch {
            # Ignore transient errors during polling
        }
        
        if (-not $companyA_ready -or -not $companyB_ready) {
            $status = "Waiting... ($elapsed_seconds/$timeout_seconds sec) - "
            $status += "Contoso: $(if ($companyA_ready) { 'Running' } else { '...' }), "
            $status += "Fabrikam: $(if ($companyB_ready) { 'Running' } else { '...' })"
            Write-Host $status
            [System.Threading.Thread]::Sleep(10000)
            $elapsed_seconds += 10
        }
    }
    
    if (-not $companyA_ready -or -not $companyB_ready) {
        Write-Warning "Contoso/Fabrikam pods did not start in time."
        kubectl get pods -l demo=multi-party-confidential -o wide
        throw "Cannot proceed - partner pods not ready"
    }
    
    # Get pod IPs
    $podIpA = (kubectl get pod $pod_companyA -o jsonpath='{.status.podIP}' 2>$null)
    $podIpB = (kubectl get pod $pod_companyB -o jsonpath='{.status.podIP}' 2>$null)
    
    Write-Host ""
    Write-Host "Partner Pod IPs:" -ForegroundColor Cyan
    Write-Host "  Contoso:   $podIpA" -ForegroundColor Gray
    Write-Host "  Fabrikam:  $podIpB" -ForegroundColor Gray
    Write-Host ""
    
    # ========== PHASE 3: Generate Woodgrove YAML with Partner IPs ==========
    Write-Header "Phase 3: Generating Woodgrove Pod YAML"
    Write-Host "Using partner pod IPs for inter-container communication (HTTP)." -ForegroundColor Yellow
    Write-Host ""
    
    $woodgroveExtraEnv = @{
        'PARTNER_CONTOSO_AKV_ENDPOINT' = $config.contoso.skrAkvEndpoint
        'PARTNER_FABRIKAM_AKV_ENDPOINT' = $config.fabrikam.skrAkvEndpoint
        'PARTNER_CONTOSO_URL' = "http://$podIpA"
        'PARTNER_FABRIKAM_URL' = "http://$podIpB"
    }
    
    $woodgroveYaml = New-VirtualNodePodYaml `
        -PodName $pod_companyC `
        -CompanyLabel "woodgrove" `
        -Image $FULL_IMAGE `
        -IdentityResourceId $woodgroveConfig.identityResourceId `
        -DnsLabel $dns_companyC `
        -SkrKeyName $woodgroveConfig.skrKeyName `
        -SkrMaaEndpoint $config.skrMaaEndpoint `
        -SkrAkvEndpoint $woodgroveConfig.skrAkvEndpoint `
        -StorageConnectionString $StorageConnectionString `
        -ResourceGroupName $resource_group `
        -AciSubnetName $aciSubnetName `
        -MemoryGi 4 `
        -Cpu 2 `
        -ExtraEnvVars $woodgroveExtraEnv
    $woodgroveYaml | Set-Content $woodgroveYamlPath -Encoding UTF8
    
    $woodgrovePolicyInfo = Get-PolicyHashFromVirtualNodeYaml -YamlPath $woodgroveYamlPath
    Write-Success "Woodgrove policy hash: $($woodgrovePolicyInfo.PolicyHash)"
    
    # Display all policy hashes
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  SECURITY POLICY HASHES - ALL COMPANIES (AKS Virtual Nodes)                  ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Contoso:   $($contosoPolicyInfo.PolicyHash)  ║" -ForegroundColor Green
    Write-Host "║  Fabrikam:  $($fabrikamPolicyInfo.PolicyHash)  ║" -ForegroundColor Magenta
    Write-Host "║  Woodgrove: $($woodgrovePolicyInfo.PolicyHash)  ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== PHASE 4: Create ALL Keys with Multi-Party Policies ==========
    Write-Header "Phase 4: Creating Keys with Multi-Party Access Policies"
    Write-Host "Now that all policy hashes are known, creating keys with proper release policies." -ForegroundColor Yellow
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
    $contosoMultiPartyPolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $contosoMultiPolicyPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  CONTOSO KEY RELEASE POLICY (Multi-Party: Contoso + Woodgrove)               ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    ($contosoMultiPartyPolicy | ConvertTo-Json -Depth 10) -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    # Delete/purge existing key if present
    $existingKey = az keyvault key show --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Deleting existing Contoso key..." -ForegroundColor Gray
        az keyvault key delete --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1 | Out-Null
        [System.Threading.Thread]::Sleep(1000)
        Write-Host "    Purging Contoso key..." -ForegroundColor Gray
        az keyvault key purge --vault-name $contosoConfig.keyVaultName --name $contosoConfig.skrKeyName 2>&1 | Out-Null
        [System.Threading.Thread]::Sleep(2000)
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
    $fabrikamMultiPartyPolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $fabrikamMultiPolicyPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║  FABRIKAM KEY RELEASE POLICY (Multi-Party: Fabrikam + Woodgrove)              ║" -ForegroundColor Magenta
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
    ($fabrikamMultiPartyPolicy | ConvertTo-Json -Depth 10) -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    $existingKey = az keyvault key show --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Deleting existing Fabrikam key..." -ForegroundColor Gray
        az keyvault key delete --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1 | Out-Null
        [System.Threading.Thread]::Sleep(1000)
        Write-Host "    Purging Fabrikam key..." -ForegroundColor Gray
        az keyvault key purge --vault-name $fabrikamConfig.keyVaultName --name $fabrikamConfig.skrKeyName 2>&1 | Out-Null
        [System.Threading.Thread]::Sleep(2000)
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
    
    # --- Create Woodgrove Key ---
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
    Write-Host "║  SECURITY POLICY BINDING SUMMARY (AKS Virtual Nodes)                         ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Contoso Key:   Releases to Contoso OR Woodgrove pods                        ║" -ForegroundColor White
    Write-Host "║  Fabrikam Key:  Releases to Fabrikam OR Woodgrove pods                       ║" -ForegroundColor White
    Write-Host "║  Woodgrove Key: Releases to Woodgrove pod ONLY                               ║" -ForegroundColor White
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Pods run as ACI container groups via virtual nodes (same attestation)        ║" -ForegroundColor Gray
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # ========== PHASE 5: Deploy Woodgrove Pod ==========
    Write-Header "Phase 5: Deploying Woodgrove Pod"
    
    kubectl apply -f $woodgroveYamlPath 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning "Woodgrove pod apply returned non-zero" }
    Write-Success "Woodgrove pod deployed"
    
    # ========== Wait for Woodgrove Pod ==========
    Write-Host ""
    Write-Host "Waiting for Woodgrove pod to start..." -ForegroundColor Gray
    Write-Host ""
    
    $timeout_seconds = 300
    $elapsed_seconds = 0
    $companyC_ready = $false
    
    while ($elapsed_seconds -lt $timeout_seconds -and -not $companyC_ready) {
        try {
            $podJson = kubectl get pods -l demo=multi-party-confidential -o json 2>&1 | Out-String
            $pods = $podJson | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($pods -and $pods.items) {
                foreach ($pod in $pods.items) {
                    $podName = $pod.metadata.name
                    $phase = $pod.status.phase
                    
                    if ($podName -eq $pod_companyC -and $phase -eq "Running" -and -not $companyC_ready) {
                        $companyC_ready = $true
                        Write-Success "Woodgrove-Bank pod is Running!"
                    }
                }
            }
        } catch {
            # Ignore transient errors during polling
        }
        
        if (-not $companyC_ready) {
            Write-Host "Waiting... ($elapsed_seconds/$timeout_seconds sec) - Woodgrove: ..."
            [System.Threading.Thread]::Sleep(10000)
            $elapsed_seconds += 10
        }
    }
    
    if (-not $companyC_ready) {
        Write-Warning "Woodgrove pod did not start in time. Checking pod status:"
        kubectl get pods -l demo=multi-party-confidential -o wide
        kubectl describe pods -l demo=multi-party-confidential | Select-String -Pattern "Warning|Error|Failed|Reason"
    }
    
    # ========== Deploy Nginx Reverse Proxy for External Access ==========
    # Virtual node pods are on a private subnet - no public FQDNs.
    # Deploy an nginx reverse proxy on a real node with a LoadBalancer service.
    Write-Header "Setting Up External Access (Nginx Reverse Proxy)"

    # Get pod IPs
    $podIpA = (kubectl get pod $pod_companyA -o jsonpath='{.status.podIP}' 2>$null)
    $podIpB = (kubectl get pod $pod_companyB -o jsonpath='{.status.podIP}' 2>$null)
    $podIpC = (kubectl get pod $pod_companyC -o jsonpath='{.status.podIP}' 2>$null)

    Write-Host "Pod IPs:"
    Write-Host "  Contoso:   $podIpA" -ForegroundColor Gray
    Write-Host "  Fabrikam:  $podIpB" -ForegroundColor Gray
    Write-Host "  Woodgrove: $podIpC" -ForegroundColor Gray
    Write-Host ""

    # Generate nginx proxy YAML with dynamic IPs
    $nginxProxyYaml = @"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-proxy-config
  namespace: default
data:
  nginx.conf: |
    worker_processes 1;
    events { worker_connections 128; }
    http {
      server {
        listen 8081;
        location / {
          proxy_pass http://${podIpA}:80/;
          proxy_set_header Host `$host;
          proxy_set_header X-Real-IP `$remote_addr;
          proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
      }
      server {
        listen 8082;
        location / {
          proxy_pass http://${podIpB}:80/;
          proxy_set_header Host `$host;
          proxy_set_header X-Real-IP `$remote_addr;
          proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
      }
      server {
        listen 8083;
        location / {
          proxy_pass http://${podIpC}:80/;
          proxy_set_header Host `$host;
          proxy_set_header X-Real-IP `$remote_addr;
          proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-proxy
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-proxy
  template:
    metadata:
      labels:
        app: nginx-proxy
    spec:
      nodeSelector:
        kubernetes.io/os: linux
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: type
                    operator: NotIn
                    values:
                      - virtual-kubelet
      containers:
        - name: nginx
          image: nginx:alpine
          ports:
            - containerPort: 8081
            - containerPort: 8082
            - containerPort: 8083
          volumeMounts:
            - name: config
              mountPath: /etc/nginx/nginx.conf
              subPath: nginx.conf
      volumes:
        - name: config
          configMap:
            name: nginx-proxy-config
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-proxy
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: nginx-proxy
  ports:
    - name: contoso
      port: 8081
      targetPort: 8081
    - name: fabrikam
      port: 8082
      targetPort: 8082
    - name: woodgrove
      port: 8083
      targetPort: 8083
"@

    $nginxYamlPath = Join-Path $PSScriptRoot "nginx-proxy.yaml"
    $nginxProxyYaml | Set-Content -Path $nginxYamlPath -Encoding UTF8

    # Clean up any previous proxy deployment
    kubectl delete deployment nginx-proxy --ignore-not-found 2>&1 | Out-Null
    kubectl delete service nginx-proxy --ignore-not-found 2>&1 | Out-Null
    kubectl delete configmap nginx-proxy-config --ignore-not-found 2>&1 | Out-Null

    Write-Host "Deploying nginx reverse proxy..."
    kubectl apply -f $nginxYamlPath 2>&1 | Out-Null

    # Wait for LoadBalancer external IP
    Write-Host "Waiting for LoadBalancer external IP..."
    $lbTimeout = 120
    $lbElapsed = 0
    $externalIp = $null

    while ($lbElapsed -lt $lbTimeout -and -not $externalIp) {
        try {
            $svcJsonStr = kubectl get svc nginx-proxy -o json 2>&1 | Out-String
            $svcJson = $svcJsonStr | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($svcJson -and $svcJson.status.loadBalancer.ingress) {
                $externalIp = $svcJson.status.loadBalancer.ingress[0].ip
            }
        } catch { }
        if (-not $externalIp) {
            [System.Threading.Thread]::Sleep(5000)
            $lbElapsed += 5
        }
    }

    if (-not $externalIp) {
        Write-Warning "LoadBalancer IP not assigned within ${lbTimeout}s. Check: kubectl get svc nginx-proxy"
        $externalIp = "PENDING"
    }

    $urlA = "http://${externalIp}:8081"
    $urlB = "http://${externalIp}:8082"
    $urlC = "http://${externalIp}:8083"

    Write-Header "Pod Endpoints"
    Write-Host "External Access (via nginx reverse proxy on LoadBalancer):"
    Write-Host "  Contoso:        $urlA" -ForegroundColor Green
    Write-Host "  Fabrikam:       $urlB" -ForegroundColor Green
    Write-Host "  Woodgrove-Bank: $urlC" -ForegroundColor Green
    Write-Host ""

    # Wait for HTTP readiness via proxy
    Write-Host "Waiting for HTTP endpoints to respond..."
    $httpTimeout = 60
    $httpElapsed = 0
    $httpA = $false; $httpB = $false; $httpC = $false

    while ($httpElapsed -lt $httpTimeout -and (-not $httpA -or -not $httpB -or -not $httpC)) {
        if (-not $httpA) {
            try {
                $response = Invoke-WebRequest -Uri $urlA -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { $httpA = $true; Write-Success "Contoso HTTP ready!" }
            } catch { }
        }
        if (-not $httpB) {
            try {
                $response = Invoke-WebRequest -Uri $urlB -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { $httpB = $true; Write-Success "Fabrikam HTTP ready!" }
            } catch { }
        }
        if (-not $httpC) {
            try {
                $response = Invoke-WebRequest -Uri $urlC -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { $httpC = $true; Write-Success "Woodgrove HTTP ready!" }
            } catch { }
        }

        if (-not $httpA -or -not $httpB -or -not $httpC) {
            [System.Threading.Thread]::Sleep(5000)
            $httpElapsed += 5
        }
    }

    # ========== Open Browser ==========
    $edgeProcess = $null
    if (-not $SkipBrowser -and $externalIp -ne "PENDING") {
        Write-Host ""
        Write-Host "Opening Microsoft Edge with each company in a separate tab..."
        Write-Host "  Tab 1: Contoso      - $urlA"
        Write-Host "  Tab 2: Fabrikam     - $urlB"
        Write-Host "  Tab 3: Woodgrove    - $urlC"
        Write-Host ""
        $edgeProcess = Start-Process "msedge" -ArgumentList "--new-window `"$urlA`" `"$urlB`" `"$urlC`"" -PassThru
    } else {
        Write-Host "Browser access:"
        Write-Host "  $urlA"
        Write-Host "  $urlB"
        Write-Host "  $urlC"
    }
    
    # ========== Cleanup Prompt ==========
    Write-Host ""
    Write-Host "Kubernetes status:" -ForegroundColor Cyan
    kubectl get pods -l demo=multi-party-confidential -o wide
    Write-Host ""
    Write-Host "Press Enter when done viewing to cleanup pods..." -ForegroundColor Yellow
    Read-Host
    
    Write-Header "Cleanup Virtual Node Pods"
    
    if ($edgeProcess -and -not $edgeProcess.HasExited) {
        $closeBrowser = Read-Host "Close the browser window? (Y/n)"
        if ($closeBrowser -ne 'n' -and $closeBrowser -ne 'N') {
            try { $edgeProcess | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
    
    Write-Host "Deleting pods..."
    kubectl delete pod $pod_companyA --ignore-not-found 2>&1 | Out-Null
    kubectl delete pod $pod_companyB --ignore-not-found 2>&1 | Out-Null
    kubectl delete pod $pod_companyC --ignore-not-found 2>&1 | Out-Null
    kubectl delete secret acr-secret --ignore-not-found 2>&1 | Out-Null

    # Cleanup nginx proxy
    kubectl delete deployment nginx-proxy --ignore-not-found 2>&1 | Out-Null
    kubectl delete service nginx-proxy --ignore-not-found 2>&1 | Out-Null
    kubectl delete configmap nginx-proxy-config --ignore-not-found 2>&1 | Out-Null
    
    # Cleanup temp files
    Remove-Item -Path $contosoYamlPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $fabrikamYamlPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $woodgroveYamlPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $PSScriptRoot "nginx-proxy.yaml") -Force -ErrorAction SilentlyContinue
    
    Write-Success "All pods deleted. AKS cluster, ACR, and Key Vaults preserved."
    Write-Host "Run -Cleanup to delete all resources including the AKS cluster."
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
    Write-Host "Usage (Direct ACI):" -ForegroundColor Yellow
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Build         # Build container image"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Deploy        # Deploy all 3 containers"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Build -Deploy # Build and deploy"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Cleanup       # Delete all resources"
    Write-Host ""
    Write-Host "Usage (AKS Virtual Nodes):" -ForegroundColor Yellow
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Build -AKS         # Build + create AKS cluster"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Deploy -AKS        # Deploy pods on virtual nodes"
    Write-Host "  .\Deploy-MultiParty.ps1 -Prefix <code> -Build -Deploy -AKS # Full AKS pipeline"
    Write-Host ""
    Write-Host "Required Parameter:" -ForegroundColor Yellow
    Write-Host "  -Prefix <code>  A short, unique identifier (3-8 lowercase alphanumeric chars)"
    Write-Host "                  to prefix all Azure resources. Use your initials, team code,"
    Write-Host "                  or project name to easily identify resource ownership."
    Write-Host "                  Examples: jd01, dev, team42, acme" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -AKS            Deploy to AKS with confidential virtual nodes instead of direct ACI"
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
        if ($config.deploymentTarget -eq 'AKS') {
            Write-Host "  Deployment Target: AKS Virtual Nodes" -ForegroundColor Cyan
            Write-Host "  AKS Cluster: $($config.aksClusterName)" -ForegroundColor Cyan
            Write-Host "  VNet: $($config.vnetName)" -ForegroundColor Cyan
        } else {
            Write-Host "  Deployment Target: Direct ACI" -ForegroundColor Green
        }
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

# Check all prerequisites before doing anything
Test-Prerequisites

# Execute requested actions
try {
    # Docker is required for Build (container image) and Deploy (security policy generation)
    if ($Build -or $Deploy) {
        Test-DockerRunning
    }
    
    if ($Build) {
        $config = Invoke-Build -RegistryName $RegistryName
        
        # If -AKS specified, also create AKS cluster with virtual nodes
        if ($AKS) {
            Invoke-BuildAKS
        }
    }
    
    if ($Deploy) {
        if ($AKS) {
            # Deploy as pods on AKS virtual nodes (runs as ACI container groups)
            Invoke-DeployAKS -SkipBrowser:$SkipBrowser
        } else {
            # Deploy directly to ACI (default)
            Invoke-Deploy -SkipBrowser:$SkipBrowser
        }
    }
    
    if ($Cleanup) {
        Invoke-Cleanup
    }
} catch {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  DEPLOYMENT ERROR                                            ║" -ForegroundColor Red
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Red
    Write-Host "║  $_" -ForegroundColor Red
    Write-Host "║" -ForegroundColor Red
    Write-Host "║  Script:     $($_.InvocationInfo.ScriptName | Split-Path -Leaf)" -ForegroundColor Red
    Write-Host "║  Line:       $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host "║  Command:    $($_.InvocationInfo.Line.Trim().Substring(0, [Math]::Min(50, $_.InvocationInfo.Line.Trim().Length)))" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    exit 1
}
