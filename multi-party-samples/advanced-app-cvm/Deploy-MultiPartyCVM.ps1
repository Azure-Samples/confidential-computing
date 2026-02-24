<#
.SYNOPSIS
    Deploy multi-party confidential computing demo on Ubuntu Confidential VMs (AMD SEV-SNP).

.DESCRIPTION
    Creates three Ubuntu 24.04 Confidential VMs (Contoso, Fabrikam, Woodgrove) on
    DCas_v5 series hardware (AMD SEV-SNP) with:
    
    - Confidential OS disk encryption (DiskWithVMGuestState) via customer-managed keys
    - Per-company Azure Key Vault (Premium) with HSM-backed exportable RSA keys
    - Per-company user-assigned managed identity for Key Vault access
    - Private VNet with no public IPs on any VM
    - Network Security Group blocking all inbound except application traffic
    - Application Gateway WAF_v2 with a single public IP (per-company port routing)
    - Random admin username + 40-char password per VM (hidden unless -EnableDebug)
    
    Woodgrove gets cross-company Key Vault access to Contoso and Fabrikam,
    enabling the multi-party analytics demo where Woodgrove can release partner
    keys and decrypt their data — all attested by AMD SEV-SNP via MAA.
    
    Trust Model (CVM vs ACI):
    Unlike ACI confidential containers which use per-container ccePolicy hashes
    (x-ms-sevsnpvm-hostdata) to bind keys to specific container images, CVM keys
    use a two-layer trust model:
    
    Layer 1 — Release Policy (hardware attestation):
    Each key's release policy requires TWO claims from the MAA attestation token:
      1. x-ms-isolation-tee.x-ms-compliance-status = azure-compliant-cvm
      2. x-ms-isolation-tee.x-ms-attestation-type  = sevsnpvm
    This ensures keys can ONLY be released to genuine Azure Confidential VMs
    running on AMD SEV-SNP hardware that pass MAA guest attestation.
    
    NOTE: AKV Secure Key Release does NOT support x-ms-runtime.* claims
    (including vm-configuration.vmUniqueId) in release policies. The release
    policy can only match claims at the top level or under x-ms-isolation-tee.
    
    Layer 2 — Key Vault Access Policies (identity-based):
    Per-VM managed identities restrict which VMs can call the release API:
      - Contoso key  → Contoso MI + Woodgrove MI
      - Fabrikam key → Fabrikam MI + Woodgrove MI
      - Woodgrove key → Woodgrove MI only
    This provides the per-VM scoping that the release policy cannot.

.PARAMETER Prefix
    3-8 character lowercase alphanumeric prefix for resource naming.

.PARAMETER Location
    Azure region (default: northeurope). Must support DCas_v5 series VMs.

.PARAMETER EnableDebug
    Debug mode: deploys Azure Bastion for SSH access, keeps SSH enabled on each
    CVM, and outputs the random VM credentials (username + password) at the end
    of the script.  Without this switch SSH is disabled on the VMs.

.PARAMETER Cleanup
    Remove all resources in the deployment's resource group.

.PARAMETER Description
    Optional description tag for the resource group.

.PARAMETER VMSize
    VM SKU (default: Standard_DC2as_v5). Must be a confidential VM SKU.

.EXAMPLE
    .\Deploy-MultiPartyCVM.ps1 -Prefix "demo"
    Standard deployment — credentials hidden, no Bastion.

.EXAMPLE
    .\Deploy-MultiPartyCVM.ps1 -Prefix "demo" -EnableDebug
    Debug deployment — Bastion enabled, SSH kept active, credentials printed at the end.

.EXAMPLE
    .\Deploy-MultiPartyCVM.ps1 -Cleanup
    Removes all deployed resources.
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z][a-z0-9]{2,7}$')]
    [string]$Prefix,

    [Parameter(Mandatory = $false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory = $false)]
    [switch]$EnableDebug,

    [Parameter(Mandatory = $false)]
    [switch]$Cleanup,

    [Parameter(Mandatory = $false)]
    [string]$Description = "",

    [Parameter(Mandatory = $false)]
    [string]$VMSize = "Standard_DC2as_v5"
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "cvm-config.json"

# Company definitions
$companies = @("contoso", "fabrikam", "woodgrove")
$companyAbbrev = @{ "contoso" = "con"; "fabrikam" = "fab"; "woodgrove" = "wdg" }

# Static private IPs in the VMSubnet (10.0.1.0/24; Azure reserves .0-.3)
$staticIPs = @{ "contoso" = "10.0.1.4"; "fabrikam" = "10.0.1.5"; "woodgrove" = "10.0.1.6" }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-SharedMaaEndpoint {
    <#
    .SYNOPSIS
        Returns the shared MAA endpoint for the specified Azure region.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Location
    )

    $maaEndpoints = @{
        # US
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
        Write-Host "`nERROR: No shared MAA endpoint for region '$Location'" -ForegroundColor Red
        Write-Host "Supported regions:" -ForegroundColor Yellow
        $maaEndpoints.Keys | Sort-Object | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        throw "No shared MAA endpoint for region '$Location'. Use -Location with a supported region."
    }

    $endpoint = "$prefix.attest.azure.net"
    Write-Host "  MAA Endpoint: $endpoint" -ForegroundColor Cyan
    return $endpoint
}


function New-RandomCredential {
    <#
    .SYNOPSIS
        Generate a random username (12 chars) and password (40 chars).
    #>
    $chars = "abcdefghijklmnopqrstuvwxyz"
    $username = "cvm" + -join ((0..7) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $passChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = -join ((0..39) | ForEach-Object { $passChars[(Get-Random -Maximum $passChars.Length)] })
    return @{ Username = $username; Password = $password }
}


function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verify Azure PowerShell is installed and user is logged in.
    #>
    Write-Host "Checking prerequisites..." -ForegroundColor Cyan

    # Azure PowerShell module
    $azModule = Get-Module -ListAvailable -Name Az.Accounts | Select-Object -First 1
    if (-not $azModule) {
        throw "Azure PowerShell module (Az) is not installed. Run: Install-Module -Name Az -Force"
    }
    Write-Host "  Az module: $($azModule.Version)" -ForegroundColor Green

    # Logged in
    $context = Get-AzContext
    if (-not $context) {
        throw "Not logged in to Azure. Run: Connect-AzAccount"
    }
    Write-Host "  Logged in as: $($context.Account.Id)" -ForegroundColor Green
    Write-Host "  Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -ForegroundColor Green
}


function Set-KVAccessPolicyWithRetry {
    <#
    .SYNOPSIS
        Wrapper around Set-AzKeyVaultAccessPolicy that retries on 'NotFound'
        errors caused by ARM propagation delays after Key Vault creation.
    #>
    param(
        [hashtable]$PolicyParams,
        [int]$MaxRetries = 6,
        [int]$DelaySeconds = 10
    )
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Set-AzKeyVaultAccessPolicy @PolicyParams
            return
        }
        catch {
            if ($_.Exception.Message -match 'NotFound' -and $attempt -lt $MaxRetries) {
                Write-Host "    Vault not yet available (attempt $attempt/$MaxRetries), retrying in ${DelaySeconds}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $DelaySeconds
            }
            else {
                throw
            }
        }
    }
}


function Save-Config {
    param([hashtable]$Config)
    $Config | ConvertTo-Json -Depth 5 | Set-Content -Path $configFile -Force
    Write-Host "  Config saved to $configFile" -ForegroundColor Gray
}


function Get-Config {
    if (-not (Test-Path $configFile)) {
        throw "Config file not found: $configFile. Run a deployment first."
    }
    return Get-Content -Path $configFile -Raw | ConvertFrom-Json
}


# ============================================================================
# CLEANUP
# ============================================================================
if ($Cleanup) {
    Write-Host "`n=== CLEANUP ===" -ForegroundColor Yellow

    if (Test-Path $configFile) {
        $config = Get-Config
        $resgrp = $config.resourceGroup
        Write-Host "Removing resource group: $resgrp (running in background)..." -ForegroundColor Yellow

        Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
        Remove-Item $configFile -Force -ErrorAction SilentlyContinue

        Write-Host "Cleanup job submitted. Resource group deletion continues in the background." -ForegroundColor Green
        Write-Host "Check status: Get-Job | Where-Object Command -like '*Remove-AzResourceGroup*'" -ForegroundColor Gray
    }
    else {
        Write-Host "No config file found. Nothing to clean up." -ForegroundColor Yellow
        Write-Host "To clean up manually: Remove-AzResourceGroup -Name <resource-group> -Force" -ForegroundColor Gray
    }
    exit
}


# ============================================================================
# VALIDATE
# ============================================================================
if (-not $Prefix) {
    Write-Host "`n=== Multi-Party Confidential VM Deployment ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\$scriptName -Prefix <name>          Deploy (credentials hidden)"
    Write-Host "  .\$scriptName -Prefix <name> -EnableDebug  Deploy with Bastion + SSH + credentials shown"
    Write-Host "  .\$scriptName -Cleanup                Remove all resources"
    Write-Host ""

    if (Test-Path $configFile) {
        $config = Get-Config
        Write-Host "Current deployment:" -ForegroundColor Cyan
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Location:       $($config.location)"
        Write-Host "  Basename:       $($config.basename)"
    }
    exit
}

Test-Prerequisites


# ============================================================================
# GENERATE NAMES
# ============================================================================
$suffix = -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
$basename = $Prefix + $suffix
$resgrp = "$basename-cvm-rg"
$vnetName = "$basename-vnet"
$storageName = ($basename + "stor") -replace '[^a-z0-9]', ''

# Per-company random credentials (NOT displayed unless -EnableDebug)
$credentials = @{}
foreach ($company in $companies) {
    $credentials[$company] = New-RandomCredential
}

# Key Vault names (max 24 chars: basename up to 13 + abbrev 3 + "kv" 2 = 18)
$kvNames = @{}
foreach ($company in $companies) {
    $kvNames[$company] = "$basename$($companyAbbrev[$company])kv"
}

# Git repo URL for tagging
$gitRemoteUrl = ""
try { $gitRemoteUrl = git remote get-url origin 2>$null } catch { }
if (-not $gitRemoteUrl) { $gitRemoteUrl = "https://github.com/Azure-Samples/confidential-computing" }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Multi-Party Confidential VM Deployment" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Basename:       $basename"
Write-Host "  Resource Group: $resgrp"
Write-Host "  Location:       $Location"
Write-Host "  VM Size:        $VMSize"
Write-Host "  Key Vaults:     $($kvNames['contoso']), $($kvNames['fabrikam']), $($kvNames['woodgrove'])"
if ($EnableDebug) {
    Write-Host "  DEBUG MODE:     ENABLED (Bastion + SSH + credentials)" -ForegroundColor Yellow
}
else {
    Write-Host "  Credentials:    Hidden (use -EnableDebug to display)"
}
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""


try {

# ============================================================================
# PHASE 1: RESOURCE GROUP + NETWORKING + STORAGE
# ============================================================================
Write-Host "Phase 1: Creating shared infrastructure..." -ForegroundColor White

$ownerName = (Get-AzContext).Account.Id
$tags = @{
    owner       = $ownerName
    BuiltBy     = $scriptName
    demo        = "multi-party-cvm"
    GitRepo     = $gitRemoteUrl
}
if ($Description) { $tags.Add("description", $Description) }

New-AzResourceGroup -Name $resgrp -Location $Location -Tag $tags -Force | Out-Null
Write-Host "  Resource group: $resgrp" -ForegroundColor Green

# --- VNet with subnets ---
$subnetConfigs = @(
    (New-AzVirtualNetworkSubnetConfig -Name "VMSubnet" -AddressPrefix "10.0.1.0/24"),
    (New-AzVirtualNetworkSubnetConfig -Name "AppGwSubnet" -AddressPrefix "10.0.2.0/24")
)
if ($EnableDebug) {
    $subnetConfigs += (New-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -AddressPrefix "10.0.99.0/26")
}

$vnet = New-AzVirtualNetwork `
    -Name $vnetName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AddressPrefix "10.0.0.0/16" `
    -Subnet $subnetConfigs
Write-Host "  VNet: $vnetName (10.0.0.0/16)" -ForegroundColor Green

# --- Network Security Group for VM Subnet ---
# Locks down each CVM to only the application traffic it needs.
# In -EnableDebug, SSH (port 22) from the Bastion subnet is also permitted.
$nsgName = "$basename-vm-nsg"
Write-Host "  Creating NSG: $nsgName"

$nsgRules = @()

# Allow HTTP from Application Gateway subnet (health probes + web traffic)
$nsgRules += New-AzNetworkSecurityRuleConfig `
    -Name "Allow-AppGw-HTTP" `
    -Description "Allow HTTP inbound from Application Gateway subnet" `
    -Access Allow `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 100 `
    -SourceAddressPrefix "10.0.2.0/24" `
    -SourcePortRange * `
    -DestinationAddressPrefix "10.0.1.0/24" `
    -DestinationPortRange 80

# Allow HTTPS between VMs (cross-company calls: Woodgrove → Contoso/Fabrikam)
$nsgRules += New-AzNetworkSecurityRuleConfig `
    -Name "Allow-InterVM-HTTPS" `
    -Description "Allow HTTPS between CVM instances for cross-company data exchange" `
    -Access Allow `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 110 `
    -SourceAddressPrefix "10.0.1.0/24" `
    -SourcePortRange * `
    -DestinationAddressPrefix "10.0.1.0/24" `
    -DestinationPortRange 443

if ($EnableDebug) {
    # Allow SSH from Azure Bastion subnet (DEBUG only)
    $nsgRules += New-AzNetworkSecurityRuleConfig `
        -Name "Allow-Bastion-SSH" `
        -Description "Allow SSH from Azure Bastion subnet (EnableDebug only)" `
        -Access Allow `
        -Protocol Tcp `
        -Direction Inbound `
        -Priority 120 `
        -SourceAddressPrefix "10.0.99.0/26" `
        -SourcePortRange * `
        -DestinationAddressPrefix "10.0.1.0/24" `
        -DestinationPortRange 22
}

# Deny all other VNet-sourced inbound (overrides default AllowVnetInBound at 65000)
$nsgRules += New-AzNetworkSecurityRuleConfig `
    -Name "Deny-All-Other-Inbound" `
    -Description "Deny all inbound traffic not explicitly allowed above" `
    -Access Deny `
    -Protocol * `
    -Direction Inbound `
    -Priority 4000 `
    -SourceAddressPrefix VirtualNetwork `
    -SourcePortRange * `
    -DestinationAddressPrefix VirtualNetwork `
    -DestinationPortRange *

$nsg = New-AzNetworkSecurityGroup `
    -Name $nsgName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -SecurityRules $nsgRules

# Associate NSG with VMSubnet
Set-AzVirtualNetworkSubnetConfig `
    -Name "VMSubnet" `
    -VirtualNetwork $vnet `
    -AddressPrefix "10.0.1.0/24" `
    -NetworkSecurityGroup $nsg | Out-Null
$vnet | Set-AzVirtualNetwork | Out-Null

if ($EnableDebug) {
    Write-Host "  NSG: $nsgName (HTTP 80, HTTPS 443, SSH 22)" -ForegroundColor Green
}
else {
    Write-Host "  NSG: $nsgName (HTTP 80, HTTPS 443 only — all other inbound denied)" -ForegroundColor Green
}

# --- Storage Account for app file delivery to VMs ---
$storageAccount = New-AzStorageAccount `
    -Name $storageName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -SkuName Standard_LRS `
    -Kind StorageV2 `
    -AllowBlobPublicAccess $true
$storageCtx = $storageAccount.Context

New-AzStorageContainer -Name "appfiles" -Context $storageCtx -Permission Off | Out-Null
Write-Host "  Storage: $storageName (for VM bootstrapping)" -ForegroundColor Green

# Upload application files to blob storage
Write-Host "  Uploading application files..." -ForegroundColor Gray
$appFiles = @("app.py", "skr_shim.py", "setup-vm.sh", "nginx.conf", "requirements.txt",
    "contoso-data.csv", "fabrikam-data.csv")
foreach ($file in $appFiles) {
    $filePath = Join-Path $scriptDir $file
    if (Test-Path $filePath) {
        Set-AzStorageBlobContent -File $filePath -Container "appfiles" -Blob $file -Context $storageCtx -Force | Out-Null
    }
    else {
        Write-Host "    WARNING: $file not found at $filePath" -ForegroundColor Yellow
    }
}
# Upload template files (from templates/ subfolder, uploaded flat)
foreach ($file in @("index.html", "index-woodgrove.html")) {
    $filePath = Join-Path $scriptDir "templates" $file
    if (Test-Path $filePath) {
        Set-AzStorageBlobContent -File $filePath -Container "appfiles" -Blob $file -Context $storageCtx -Force | Out-Null
    }
}
Write-Host "  App files uploaded to blob storage" -ForegroundColor Green

# Generate SAS token (valid for 4 hours)
$sasToken = New-AzStorageContainerSASToken `
    -Name "appfiles" `
    -Context $storageCtx `
    -Permission r `
    -ExpiryTime (Get-Date).AddHours(4)
# Ensure SAS token starts with '?' for URL concatenation
if ($sasToken -and -not $sasToken.StartsWith('?')) { $sasToken = "?$sasToken" }
$blobBaseUrl = "https://$storageName.blob.core.windows.net/appfiles"

Write-Host "Phase 1 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 2: PER-COMPANY SECURITY INFRASTRUCTURE
# ============================================================================
Write-Host "Phase 2: Creating security infrastructure (Key Vaults, identities, keys, DES)..." -ForegroundColor White

$maaEndpoint = Get-SharedMaaEndpoint -Location $Location

# CVM Orchestrator Service Principal (Microsoft-managed, required for disk encryption)
$cvmAgentAppId = 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
$cvmAgent = Get-AzADServicePrincipal -ApplicationId $cvmAgentAppId
if (-not $cvmAgent) {
    throw "CVM Orchestrator SP ($cvmAgentAppId) not found. Ensure your subscription supports Confidential VMs."
}

$identityIds = @{}
$identityClientIds = @{}
$identityPrincipalIds = @{}
$desIds = @{}

foreach ($company in $companies) {
    $abbrev = $companyAbbrev[$company]
    $kvName = $kvNames[$company]
    $identityName = "$basename-id-$company"
    $desName = "$basename-des-$abbrev"
    $cmkName = "$company-cmk-key"

    Write-Host "`n  --- $($company.ToUpper()) ---" -ForegroundColor Cyan

    # ---- Key Vault (Premium SKU for HSM-backed keys) ----
    Write-Host "  Creating Key Vault: $kvName"
    New-AzKeyVault `
        -Name $kvName `
        -Location $Location `
        -ResourceGroupName $resgrp `
        -Sku Premium `
        -EnabledForDiskEncryption `
        -DisableRbacAuthorization `
        -SoftDeleteRetentionInDays 10 `
        -EnablePurgeProtection | Out-Null

    # ---- User-Assigned Managed Identity ----
    Write-Host "  Creating managed identity: $identityName"
    $identity = New-AzUserAssignedIdentity `
        -Name $identityName `
        -ResourceGroupName $resgrp `
        -Location $Location
    $identityIds[$company] = $identity.Id
    $identityClientIds[$company] = $identity.ClientId
    $identityPrincipalIds[$company] = $identity.PrincipalId

    # ---- KV access: company's own identity ----
    Write-Host "  Granting identity KV access"
    Set-KVAccessPolicyWithRetry -PolicyParams @{
        VaultName        = $kvName
        ResourceGroupName = $resgrp
        ObjectId         = $identity.PrincipalId
        PermissionsToKeys    = @('get','release','wrapKey','unwrapKey','encrypt','decrypt')
        PermissionsToSecrets = @('get','list')
    }

    # ---- KV access: CVM Orchestrator SP (for disk encryption key release) ----
    Set-KVAccessPolicyWithRetry -PolicyParams @{
        VaultName        = $kvName
        ResourceGroupName = $resgrp
        ObjectId         = $cvmAgent.Id
        PermissionsToKeys = @('get','release')
    }

    # ---- CMK for confidential OS disk encryption ----
    # HSM key creation can fail transiently while the vault data plane warms up,
    # so retry with back-off (mirrors Set-KVAccessPolicyWithRetry pattern).
    Write-Host "  Creating CMK: $cmkName (RSA-HSM 3072-bit)"
    $cmkMaxRetries = 6
    $cmkDelay = 15
    for ($cmkAttempt = 1; $cmkAttempt -le $cmkMaxRetries; $cmkAttempt++) {
        try {
            Add-AzKeyVaultKey `
                -VaultName $kvName `
                -Name $cmkName `
                -Size 3072 `
                -KeyOps wrapKey, unwrapKey `
                -KeyType RSA `
                -Destination HSM `
                -Exportable `
                -UseDefaultCVMPolicy | Out-Null
            break   # success
        }
        catch {
            if ($cmkAttempt -lt $cmkMaxRetries) {
                Write-Host "    CMK creation not ready (attempt $cmkAttempt/$cmkMaxRetries), retrying in ${cmkDelay}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $cmkDelay
            }
            else {
                throw
            }
        }
    }

    $encryptionKeyVaultId = (Get-AzKeyVault -VaultName $kvName -ResourceGroupName $resgrp).ResourceId
    $encryptionKeyURL = (Get-AzKeyVaultKey -VaultName $kvName -KeyName $cmkName).Key.Kid

    # ---- DiskEncryptionSet ----
    Write-Host "  Creating DiskEncryptionSet: $desName"
    $desConfig = New-AzDiskEncryptionSetConfig `
        -Location $Location `
        -SourceVaultId $encryptionKeyVaultId `
        -KeyUrl $encryptionKeyURL `
        -IdentityType SystemAssigned `
        -EncryptionType ConfidentialVmEncryptedWithCustomerKey
    New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName -DiskEncryptionSet $desConfig | Out-Null

    $desIdentity = (Get-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resgrp).Identity.PrincipalId
    Set-KVAccessPolicyWithRetry -PolicyParams @{
        VaultName              = $kvName
        ResourceGroupName      = $resgrp
        ObjectId               = $desIdentity
        PermissionsToKeys      = @('wrapKey','unwrapKey','get')
        BypassObjectIdValidation = $true
    }

    $desIds[$company] = (Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName).Id
}

# ---- Cross-company access: Woodgrove → Contoso + Fabrikam KVs ----
Write-Host "`n  Granting Woodgrove cross-company Key Vault access..." -ForegroundColor Cyan
Set-KVAccessPolicyWithRetry -PolicyParams @{
    VaultName        = $kvNames["contoso"]
    ResourceGroupName = $resgrp
    ObjectId         = $identityPrincipalIds["woodgrove"]
    PermissionsToKeys = @('get','release')
}

Set-KVAccessPolicyWithRetry -PolicyParams @{
    VaultName        = $kvNames["fabrikam"]
    ResourceGroupName = $resgrp
    ObjectId         = $identityPrincipalIds["woodgrove"]
    PermissionsToKeys = @('get','release')
}

Write-Host "  Woodgrove can now release keys from Contoso and Fabrikam KVs" -ForegroundColor Green
Write-Host "`nPhase 2 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 3: DEPLOY CONFIDENTIAL VMs
# ============================================================================
Write-Host "Phase 3: Deploying Confidential VMs..." -ForegroundColor White

$vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
$vmSubnet = $vnet.Subnets | Where-Object { $_.Name -eq "VMSubnet" }

foreach ($company in $companies) {
    $vmName = "$basename-$company"
    $nicName = "$vmName-nic"
    $abbrev = $companyAbbrev[$company]
    $desName = "$basename-des-$abbrev"
    $cred = $credentials[$company]

    Write-Host "`n  --- $($company.ToUpper()) VM: $vmName ---" -ForegroundColor Cyan

    # ---- NIC with static private IP (no public IP) ----
    Write-Host "  Creating NIC: $nicName (IP: $($staticIPs[$company]))"
    $ipConfig = New-AzNetworkInterfaceIpConfig `
        -Name "ipconfig1" `
        -Subnet $vmSubnet `
        -PrivateIpAddress $staticIPs[$company]

    $nic = New-AzNetworkInterface `
        -Name $nicName `
        -ResourceGroupName $resgrp `
        -Location $Location `
        -IpConfiguration $ipConfig
    
    # ---- VM Configuration ----
    Write-Host "  Configuring VM: $VMSize, Ubuntu 24.04 CVM, ConfidentialVM"
    $securePassword = ConvertTo-SecureString -String $cred.Password -AsPlainText -Force
    $vmCred = New-Object System.Management.Automation.PSCredential ($cred.Username, $securePassword)

    $vm = New-AzVMConfig -VMName $vmName -VMSize $VMSize `
        -IdentityType UserAssigned -IdentityId $identityIds[$company]

    $vm = Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName $vmName -Credential $vmCred

    $vm = Set-AzVMSourceImage -VM $vm `
        -PublisherName 'Canonical' `
        -Offer 'ubuntu-24_04-lts' `
        -Skus 'cvm' `
        -Version "latest"

    $vm = Add-AzVMNetworkInterface -VM $vm -Id $nic.Id

    # Confidential OS disk with customer-managed key encryption
    $diskEncSet = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName
    $vm = Set-AzVMOSDisk -VM $vm `
        -StorageAccountType "StandardSSD_LRS" `
        -CreateOption "FromImage" `
        -SecurityEncryptionType "DiskWithVMGuestState" `
        -SecureVMDiskEncryptionSet $diskEncSet.Id `
        -Linux

    $vm = Set-AzVmSecurityProfile -VM $vm -SecurityType "ConfidentialVM"
    $vm = Set-AzVmUefi -VM $vm -EnableVtpm $true -EnableSecureBoot $true
    $vm = Set-AzVMBootDiagnostic -VM $vm -Disable

    # ---- Create VM ----
    Write-Host "  Creating VM (this takes 2-5 minutes)..."
    New-AzVM -ResourceGroupName $resgrp -Location $Location -VM $vm | Out-Null
    Write-Host "  VM created: $vmName" -ForegroundColor Green
}

# ---- Retrieve VmId for each CVM (logged for diagnostics/reference) ----
Write-Host "`n  Retrieving VM unique identifiers..." -ForegroundColor Cyan
$vmIds = @{}
foreach ($company in $companies) {
    $vmName = "$basename-$company"
    $vm = Get-AzVM -ResourceGroupName $resgrp -Name $vmName
    $vmIds[$company] = $vm.VmId
    Write-Host "    $($company.PadRight(12)) VmId: $($vm.VmId)" -ForegroundColor Gray
}

# ---- Create application keys with CVM release policy ----
# IMPORTANT: We use a CUSTOM release policy instead of -UseDefaultCVMPolicy.
#
# Why: UseDefaultCVMPolicy generates a policy that checks "x-ms-compliance-status"
# as a TOP-LEVEL claim. However, MAA guest attestation tokens (from cvm-attestation-tools)
# place this claim NESTED under "x-ms-isolation-tee.x-ms-compliance-status".
# AKV evaluates claims using dot-notation paths, so the top-level check fails.
#
# Our custom policy uses the correct nested claim paths:
#   1. x-ms-isolation-tee.x-ms-attestation-type    = sevsnpvm
#   2. x-ms-isolation-tee.x-ms-compliance-status    = azure-compliant-cvm
#
# NOTE: AKV Secure Key Release does NOT support x-ms-runtime.* claims in
# release policies (e.g. vm-configuration.vmUniqueId). Per-VM scoping is
# enforced via Key Vault access policies (managed identity per VM) instead.
#
# Key access matrix (via KV access policies on managed identities):
#   Contoso key  → Contoso identity + Woodgrove identity
#   Fabrikam key → Fabrikam identity + Woodgrove identity
#   Woodgrove key → Woodgrove identity only

Write-Host "`n  Creating application keys with CVM release policy..." -ForegroundColor Cyan

# Build a custom release policy using nested claim paths.
# UseDefaultCVMPolicy checks "x-ms-compliance-status" (top-level),
# but MAA guest attestation tokens place this claim under
# "x-ms-isolation-tee.x-ms-compliance-status" (nested).  AKV
# evaluates claims in dot-notation, so the default CVM policy fails.
# We use the REST API to create keys with the correct nested paths
# (compatible with any Az module version).
$maaAuthority = "https://$maaEndpoint"
$releasePolicyObj = @{
    version = "1.0.0"
    anyOf = @(
        @{
            authority = $maaAuthority
            allOf = @(
                @{
                    claim  = "x-ms-isolation-tee.x-ms-compliance-status"
                    equals = "azure-compliant-cvm"
                }
                @{
                    claim  = "x-ms-isolation-tee.x-ms-attestation-type"
                    equals = "sevsnpvm"
                }
            )
        }
    )
}
$releasePolicyJson = $releasePolicyObj | ConvertTo-Json -Depth 10 -Compress
$releasePolicyBase64Url = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes($releasePolicyJson)
).Replace('+','-').Replace('/','_').TrimEnd('=')

Write-Host "  Release policy authority: $maaAuthority" -ForegroundColor Gray
Write-Host "    x-ms-isolation-tee.x-ms-compliance-status = azure-compliant-cvm" -ForegroundColor Gray
Write-Host "    x-ms-isolation-tee.x-ms-attestation-type  = sevsnpvm" -ForegroundColor Gray
Write-Host "    Per-VM scoping: via Key Vault access policies (managed identity)" -ForegroundColor Gray

# Get AKV access token for REST API calls
$akvToken = (Get-AzAccessToken -ResourceUrl "https://vault.azure.net").Token

foreach ($company in $companies) {
    $kvName = $kvNames[$company]
    $appKeyName = "$company-secret-key"

    Write-Host "`n    $($company.ToUpper()) key: $appKeyName" -ForegroundColor Cyan
    Write-Host "      VmId: $($vmIds[$company])" -ForegroundColor Gray

    # Create HSM-backed exportable key via REST API with custom release policy
    $createKeyBody = @{
        kty      = "RSA-HSM"
        key_size = 2048
        key_ops  = @("wrapKey", "unwrapKey", "encrypt", "decrypt")
        attributes = @{
            exportable = $true
        }
        release_policy = @{
            contentType = "application/json; charset=utf-8"
            data        = $releasePolicyBase64Url
        }
    } | ConvertTo-Json -Depth 10

    $createKeyUri = "https://$kvName.vault.azure.net/keys/$($appKeyName)/create?api-version=7.4"
    try {
        $null = Invoke-RestMethod -Method POST -Uri $createKeyUri `
            -Headers @{ Authorization = "Bearer $akvToken" } `
            -ContentType "application/json" `
            -Body $createKeyBody
        Write-Host "      Key created with custom CVM release policy" -ForegroundColor Green
    }
    catch {
        Write-Host "      ERROR creating key: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

Write-Host "`n  All application keys created." -ForegroundColor Green

Write-Host "`n  All VMs created. Running bootstrap scripts..." -ForegroundColor Cyan

# ---- Run CustomScriptExtension on each VM to install the app ----
foreach ($company in $companies) {
    $vmName = "$basename-$company"

    Write-Host "`n  Bootstrapping $($company.ToUpper()) ($vmName)..." -ForegroundColor Cyan

    # Build list of file URIs to download
    $fileUris = @(
        "setup-vm.sh", "app.py", "skr_shim.py", "nginx.conf", "requirements.txt",
        "contoso-data.csv", "fabrikam-data.csv", "index.html", "index-woodgrove.html"
    ) | ForEach-Object { "$blobBaseUrl/$_$sasToken" }

    # Company-specific arguments for setup-vm.sh
    $akvEndpoint = "$($kvNames[$company]).vault.azure.net"
    $clientId = $identityClientIds[$company]

    if ($company -eq "woodgrove") {
        $partnerContosoUrl = "https://$($staticIPs['contoso'])"
        $partnerFabrikamUrl = "https://$($staticIPs['fabrikam'])"
        $partnerContosoAkv = "https://$($kvNames['contoso']).vault.azure.net"
        $partnerFabrikamAkv = "https://$($kvNames['fabrikam']).vault.azure.net"
    }
    else {
        $partnerContosoUrl = "NONE"
        $partnerFabrikamUrl = "NONE"
        $partnerContosoAkv = "NONE"
        $partnerFabrikamAkv = "NONE"
    }

    $debugFlag = if ($EnableDebug) { "true" } else { "false" }
    $commandToExecute = "bash setup-vm.sh $company $company-secret-key $akvEndpoint $maaEndpoint $clientId $partnerContosoUrl $partnerFabrikamUrl $partnerContosoAkv $partnerFabrikamAkv $debugFlag"

    $protectedSettings = @{
        fileUris         = $fileUris
        commandToExecute = $commandToExecute
    } | ConvertTo-Json -Depth 3

    Set-AzVMExtension `
        -ResourceGroupName $resgrp `
        -VMName $vmName `
        -Name "setup-$company" `
        -Publisher "Microsoft.Azure.Extensions" `
        -ExtensionType "CustomScript" `
        -TypeHandlerVersion "2.1" `
        -Location $Location `
        -ProtectedSettingString $protectedSettings | Out-Null

    Write-Host "  Bootstrap complete: $vmName" -ForegroundColor Green
}

Write-Host "`nPhase 3 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 4: APPLICATION GATEWAY WAF_v2
# ============================================================================
Write-Host "Phase 4: Deploying Application Gateway WAF_v2..." -ForegroundColor White
Write-Host "  (This typically takes 5-10 minutes)" -ForegroundColor Gray

# ---- Public IP ----
$pipName = "$basename-appgw-pip"
$pip = New-AzPublicIpAddress `
    -Name $pipName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AllocationMethod Static `
    -Sku Standard `
    -DomainNameLabel $basename
Write-Host "  Public IP: $pipName" -ForegroundColor Green

# ---- WAF Policy (Detection mode — logs but doesn't block for demo) ----
$wafPolicyName = "$basename-waf-policy"
$managedRuleSet = New-AzApplicationGatewayFirewallPolicyManagedRuleSet `
    -RuleSetType "OWASP" -RuleSetVersion "3.2"
$managedRules = New-AzApplicationGatewayFirewallPolicyManagedRule `
    -ManagedRuleSet $managedRuleSet
$policySetting = New-AzApplicationGatewayFirewallPolicySetting `
    -Mode "Detection" -State "Enabled" -MaxRequestBodySizeInKb 128
$wafPolicy = New-AzApplicationGatewayFirewallPolicy `
    -Name $wafPolicyName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -ManagedRule $managedRules `
    -PolicySetting $policySetting
Write-Host "  WAF Policy: $wafPolicyName (Detection mode)" -ForegroundColor Green

# ---- App Gateway configuration objects ----
$vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
$appGwSubnet = $vnet.Subnets | Where-Object { $_.Name -eq "AppGwSubnet" }

# Gateway IP configuration
$gipConfig = New-AzApplicationGatewayIPConfiguration `
    -Name "appgw-ipconfig" -Subnet $appGwSubnet

# Frontend IP configuration (public)
$fipConfig = New-AzApplicationGatewayFrontendIPConfig `
    -Name "frontend-ip" -PublicIPAddress $pip

# Frontend ports — one per company
$fpWoodgrove = New-AzApplicationGatewayFrontendPort -Name "port-80" -Port 80
$fpContoso = New-AzApplicationGatewayFrontendPort -Name "port-8080" -Port 8080
$fpFabrikam = New-AzApplicationGatewayFrontendPort -Name "port-8081" -Port 8081

# Backend pools — one per company VM
$poolContoso = New-AzApplicationGatewayBackendAddressPool `
    -Name "contoso-pool" -BackendIPAddresses $staticIPs["contoso"]
$poolFabrikam = New-AzApplicationGatewayBackendAddressPool `
    -Name "fabrikam-pool" -BackendIPAddresses $staticIPs["fabrikam"]
$poolWoodgrove = New-AzApplicationGatewayBackendAddressPool `
    -Name "woodgrove-pool" -BackendIPAddresses $staticIPs["woodgrove"]

# Backend HTTP settings (all VMs serve on port 80)
$backendSettings = New-AzApplicationGatewayBackendHttpSetting `
    -Name "http-settings" `
    -Port 80 `
    -Protocol Http `
    -CookieBasedAffinity Disabled `
    -RequestTimeout 120

# Health probe
$probe = New-AzApplicationGatewayProbeConfig `
    -Name "health-probe" `
    -Protocol Http `
    -Path "/" `
    -Interval 30 `
    -Timeout 10 `
    -UnhealthyThreshold 3 `
    -PickHostNameFromBackendHttpSettings

# Listeners — one per company/port
$listenerWoodgrove = New-AzApplicationGatewayHttpListener `
    -Name "listener-woodgrove" `
    -Protocol Http `
    -FrontendIPConfiguration $fipConfig `
    -FrontendPort $fpWoodgrove

$listenerContoso = New-AzApplicationGatewayHttpListener `
    -Name "listener-contoso" `
    -Protocol Http `
    -FrontendIPConfiguration $fipConfig `
    -FrontendPort $fpContoso

$listenerFabrikam = New-AzApplicationGatewayHttpListener `
    -Name "listener-fabrikam" `
    -Protocol Http `
    -FrontendIPConfiguration $fipConfig `
    -FrontendPort $fpFabrikam

# Routing rules — map listener to backend pool
$ruleWoodgrove = New-AzApplicationGatewayRequestRoutingRule `
    -Name "rule-woodgrove" `
    -RuleType Basic `
    -Priority 100 `
    -HttpListener $listenerWoodgrove `
    -BackendAddressPool $poolWoodgrove `
    -BackendHttpSettings $backendSettings

$ruleContoso = New-AzApplicationGatewayRequestRoutingRule `
    -Name "rule-contoso" `
    -RuleType Basic `
    -Priority 200 `
    -HttpListener $listenerContoso `
    -BackendAddressPool $poolContoso `
    -BackendHttpSettings $backendSettings

$ruleFabrikam = New-AzApplicationGatewayRequestRoutingRule `
    -Name "rule-fabrikam" `
    -RuleType Basic `
    -Priority 300 `
    -HttpListener $listenerFabrikam `
    -BackendAddressPool $poolFabrikam `
    -BackendHttpSettings $backendSettings

# ---- Create the Application Gateway (with retry for transient Azure errors) ----
$sku = New-AzApplicationGatewaySku -Name WAF_v2 -Tier WAF_v2 -Capacity 1
$appGwName = "$basename-appgw"

Write-Host "  Creating Application Gateway: $appGwName..."
$appGwCreated = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        # Check if a previous attempt left a failed gateway resource
        $existingGw = Get-AzApplicationGateway -Name $appGwName -ResourceGroupName $resgrp -ErrorAction SilentlyContinue
        if ($existingGw -and $existingGw.ProvisioningState -eq 'Failed') {
            Write-Host "    Existing gateway in Failed state — re-applying config (attempt $attempt/3)..." -ForegroundColor Yellow
            Set-AzApplicationGateway -ApplicationGateway $existingGw | Out-Null
        }
        elseif ($existingGw -and $existingGw.ProvisioningState -eq 'Succeeded') {
            Write-Host "    Gateway already exists and is healthy." -ForegroundColor Green
        }
        else {
            New-AzApplicationGateway `
                -Name $appGwName `
                -ResourceGroupName $resgrp `
                -Location $Location `
                -Sku $sku `
                -GatewayIPConfigurations $gipConfig `
                -FrontendIPConfigurations $fipConfig `
                -FrontendPorts @($fpWoodgrove, $fpContoso, $fpFabrikam) `
                -BackendAddressPools @($poolContoso, $poolFabrikam, $poolWoodgrove) `
                -BackendHttpSettingsCollection $backendSettings `
                -HttpListeners @($listenerWoodgrove, $listenerContoso, $listenerFabrikam) `
                -RequestRoutingRules @($ruleWoodgrove, $ruleContoso, $ruleFabrikam) `
                -Probes $probe `
                -FirewallPolicy $wafPolicy | Out-Null
        }
        $appGwCreated = $true
        break
    }
    catch {
        Write-Host "    App Gateway attempt $attempt/3 failed: $($_.Exception.Message)" -ForegroundColor Yellow
        if ($attempt -lt 3) {
            Write-Host "    Retrying in 30 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
        }
        else {
            throw
        }
    }
}

$appGwPip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resgrp
$publicIP = $appGwPip.IpAddress
$publicFqdn = $appGwPip.DnsSettings.Fqdn

Write-Host "  Application Gateway: $appGwName" -ForegroundColor Green
Write-Host "  Public IP: $publicIP" -ForegroundColor Green
if ($publicFqdn) {
    Write-Host "  FQDN: $publicFqdn" -ForegroundColor Green
}
Write-Host "`nPhase 4 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 5: OPTIONAL AZURE BASTION (EnableDebug only)
# ============================================================================
if ($EnableDebug) {
    Write-Host "Phase 5: Deploying Azure Bastion (EnableDebug)..." -ForegroundColor Yellow

    $bastionPipName = "$basename-bastion-pip"
    $bastionPip = New-AzPublicIpAddress `
        -Name $bastionPipName `
        -ResourceGroupName $resgrp `
        -Location $Location `
        -AllocationMethod Static `
        -Sku Standard
    Write-Host "  Bastion public IP: $bastionPipName" -ForegroundColor Green

    $bastionName = "$basename-bastion"
    New-AzBastion `
        -ResourceGroupName $resgrp `
        -Name $bastionName `
        -PublicIpAddressRgName $resgrp `
        -PublicIpAddressName $bastionPip.Name `
        -VirtualNetworkRgName $resgrp `
        -VirtualNetworkName $vnetName `
        -Sku "Basic" | Out-Null
    Write-Host "  Bastion: $bastionName (Basic SKU)" -ForegroundColor Green
    Write-Host "`nPhase 5 complete.`n" -ForegroundColor Green
}
else {
    Write-Host "Phase 5: Azure Bastion skipped (use -EnableDebug to enable).`n" -ForegroundColor Gray
}


# ============================================================================
# SAVE CONFIG (for Cleanup)
# ============================================================================
$config = @{
    resourceGroup = $resgrp
    basename      = $basename
    location      = $Location
    vmSize        = $VMSize
    publicIP      = $publicIP
    publicFqdn    = $publicFqdn
    companies     = @{}
}
foreach ($company in $companies) {
    $config.companies[$company] = @{
        vmName     = "$basename-$company"
        vmId       = $vmIds[$company]
        privateIP  = $staticIPs[$company]
        keyVault   = $kvNames[$company]
        identityId = $identityClientIds[$company]
    }
}
Save-Config -Config $config


# ============================================================================
# PHASE 6: OUTPUT
# ============================================================================
$elapsed = New-TimeSpan -Start $startTime -End (Get-Date)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Resource Group:  $resgrp"
Write-Host "  Location:        $Location"
Write-Host "  VM Size:         $VMSize"
Write-Host ""
Write-Host "  Application URLs (via Application Gateway WAF):" -ForegroundColor Cyan
Write-Host "    Woodgrove:  http://${publicIP}/" -ForegroundColor White
Write-Host "    Contoso:    http://${publicIP}:8080/" -ForegroundColor White
Write-Host "    Fabrikam:   http://${publicIP}:8081/" -ForegroundColor White
if ($publicFqdn) {
    Write-Host ""
    Write-Host "    Woodgrove:  http://${publicFqdn}/" -ForegroundColor White
    Write-Host "    Contoso:    http://${publicFqdn}:8080/" -ForegroundColor White
    Write-Host "    Fabrikam:   http://${publicFqdn}:8081/" -ForegroundColor White
}
Write-Host ""
Write-Host "  VMs (private IPs only — no public IPs):" -ForegroundColor Cyan
foreach ($company in $companies) {
    Write-Host "    $($company.PadRight(12)) $($staticIPs[$company])  ($basename-$company)"
}
Write-Host ""
Write-Host "  Security:" -ForegroundColor Cyan
Write-Host "    Confidential VMs:       AMD SEV-SNP (DCas_v5)" -ForegroundColor White
Write-Host "    OS Disk Encryption:     DiskWithVMGuestState (CMK)" -ForegroundColor White
Write-Host "    Key Release Policy:     Azure default CVM (azure-compliant-cvm)" -ForegroundColor White
Write-Host "    Key Access:" -ForegroundColor White
Write-Host "      contoso      → Contoso + Woodgrove identities (via KV access policy)" -ForegroundColor Gray
Write-Host "      fabrikam     → Fabrikam + Woodgrove identities (via KV access policy)" -ForegroundColor Gray
Write-Host "      woodgrove    → Woodgrove identity only" -ForegroundColor Gray
Write-Host "    MAA Endpoint:           $maaEndpoint" -ForegroundColor White
Write-Host "    WAF:                    OWASP 3.2 (Detection mode)" -ForegroundColor White
if ($EnableDebug) {
    Write-Host "    NSG:                    HTTP 80 + HTTPS 443 + SSH 22 (DEBUG)" -ForegroundColor Yellow
}
else {
    Write-Host "    NSG:                    HTTP 80 + HTTPS 443 only (SSH disabled)" -ForegroundColor White
}
Write-Host ""

if ($EnableDebug) {
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host " DEBUG: VM CREDENTIALS" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  These credentials are ONLY shown because -EnableDebug was specified." -ForegroundColor Yellow
    Write-Host "  In production, credentials would be stored in Key Vault." -ForegroundColor Yellow
    Write-Host ""
    foreach ($company in $companies) {
        $cred = $credentials[$company]
        Write-Host "  $($company.ToUpper()):" -ForegroundColor Yellow
        Write-Host "    VM:       $basename-$company" -ForegroundColor Yellow
        Write-Host "    Username: $($cred.Username)" -ForegroundColor Yellow
        Write-Host "    Password: $($cred.Password)" -ForegroundColor Yellow
        Write-Host ""
    }
    Write-Host "  Azure Bastion is enabled — use the Azure Portal to SSH into VMs." -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
}
else {
    Write-Host "  VM credentials are hidden. Use -EnableDebug to display them." -ForegroundColor Gray
    Write-Host "  Azure Bastion is NOT deployed. Use -EnableDebug to enable remote access." -ForegroundColor Gray
}

Write-Host ""
Write-Host "  Cleanup: .\$scriptName -Cleanup" -ForegroundColor Gray
Write-Host ""
Write-Host ("  Deployment time: {0} minutes and {1} seconds" -f [int]$elapsed.TotalMinutes, $elapsed.Seconds) -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green

}
catch {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " DEPLOYMENT FAILED" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    if ($resgrp -and (Get-AzResourceGroup -Name $resgrp -ErrorAction SilentlyContinue)) {
        $answer = Read-Host "  Do you want to delete resource group '$resgrp' and all its resources? (y/N)"
        if ($answer -match '^[Yy]') {
            Write-Host "  Removing resource group: $resgrp (running in background)..." -ForegroundColor Yellow
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
            Remove-Item $configFile -Force -ErrorAction SilentlyContinue
            Write-Host "  Cleanup job submitted. Resource group deletion continues in the background." -ForegroundColor Green
            Write-Host "  Check status: Get-Job | Where-Object Command -like '*Remove-AzResourceGroup*'" -ForegroundColor Gray
        }
        else {
            Write-Host "  Resources left in place. Clean up later with: .\$scriptName -Cleanup" -ForegroundColor Yellow
        }
    }

    exit 1
}
