<#
.SYNOPSIS
    Deploy a single Azure Confidential VM with Secure Key Release (SKR) end-to-end.

.DESCRIPTION
    Creates a minimal confidential computing environment that demonstrates
    AMD SEV-SNP Secure Key Release from Azure Key Vault:

    1. Resource Group with random suffix (from -Prefix)
    2. Private VNet (no public IPs on the VM)
    3. Azure Key Vault Premium with HSM-backed exportable RSA key
       ("fabrikam-totally-top-secret-key") bound to a CVM release policy
    4. User-assigned managed identity for Key Vault access
    5. Ubuntu 24.04 Confidential VM (DCas_v5) with DiskWithVMGuestState encryption
    6. CustomScriptExtension that:
       a. Installs cvm-attestation-tools (Python vTPM attestation)
       b. Gets an MAA token via the vTPM (proves AMD SEV-SNP hardware)
       c. Calls AKV key release API with the MAA token
       d. Prints the released key material to the VM bootstrap log

    After the VM boots and runs the bootstrap script, this PowerShell script
    retrieves the CustomScriptExtension output (which contains the SKR result)
    and displays it in the console.

    SKR Release Policy (explained):
    ┌──────────────────────────────────────────────────────────────────────┐
    │  {                                                                   │
    │    "version": "1.0.0",                                               │
    │    "anyOf": [{                                                       │
    │      "authority": "https://<maa-endpoint>",                          │
    │      "allOf": [                                                      │
    │        { "claim": "x-ms-isolation-tee.x-ms-compliance-status",       │
    │          "equals": "azure-compliant-cvm" },                          │
    │        { "claim": "x-ms-isolation-tee.x-ms-attestation-type",        │
    │          "equals": "sevsnpvm" }                                      │
    │      ]                                                               │
    │    }]                                                                │
    │  }                                                                   │
    └──────────────────────────────────────────────────────────────────────┘

    The policy requires BOTH conditions (allOf) from ANY trusted MAA authority:
      • x-ms-isolation-tee.x-ms-compliance-status = "azure-compliant-cvm"
        → The VM passed Azure's compliance checks for confidential VMs.
          MAA verifies the SNP report, VCEK certificate chain, and guest
          firmware measurements before issuing this claim.
      • x-ms-isolation-tee.x-ms-attestation-type = "sevsnpvm"
        → The attestation evidence came from an AMD SEV-SNP guest VM.
          This confirms the VM is running on genuine SEV-SNP hardware
          with memory encryption and integrity protection active.

    Together these claims ensure the key can ONLY be released to a genuine
    Azure Confidential VM running on AMD SEV-SNP hardware that passes MAA
    guest attestation. A standard VM, a VM with debug enabled, or a VM that
    fails firmware measurement checks will NOT receive the key.

    The managed identity provides the second layer: even if another CVM
    passes attestation, it cannot release the key unless its identity has
    'get' + 'release' permissions on the Key Vault.

.PARAMETER Prefix
    3-8 character lowercase alphanumeric prefix for resource naming.
    A random 5-character suffix is appended automatically.

.PARAMETER Location
    Azure region (default: northeurope). Must support DCas_v5 series.

.PARAMETER VMSize
    VM SKU (default: Standard_DC2as_v5). Must be a confidential VM SKU.

.PARAMETER Cleanup
    Remove all resources created by a previous deployment.

.EXAMPLE
    .\Deploy-SKRExample.ps1 -Prefix "skrdemo"
    Deploy the SKR example and display the released key in the console.

.EXAMPLE
    .\Deploy-SKRExample.ps1 -Cleanup
    Remove all deployed resources.
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z][a-z0-9]{2,7}$')]
    [string]$Prefix,

    [Parameter(Mandatory = $false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory = $false)]
    [string]$VMSize = "Standard_DC2as_v5",

    [Parameter(Mandatory = $false)]
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "skr-config.json"


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-SharedMaaEndpoint {
    param([string]$Location)
    $maaEndpoints = @{
        "eastus"             = "sharedeus.eus"
        "eastus2"            = "sharedeus2.eus2"
        "westus"             = "sharedwus.wus"
        "westus2"            = "sharedwus2.wus2"
        "westus3"            = "sharedwus3.wus3"
        "centralus"          = "sharedcus.cus"
        "northcentralus"     = "sharedncus.ncus"
        "southcentralus"     = "sharedscus.scus"
        "westcentralus"      = "sharedwcus.wcus"
        "canadacentral"      = "sharedcac.cac"
        "canadaeast"         = "sharedcae.cae"
        "northeurope"        = "sharedneu.neu"
        "westeurope"         = "sharedweu.weu"
        "uksouth"            = "shareduks.uks"
        "ukwest"             = "sharedukw.ukw"
        "francecentral"      = "sharedfrc.frc"
        "germanywestcentral" = "shareddewc.dewc"
        "switzerlandnorth"   = "sharedswn.swn"
        "swedencentral"      = "sharedsec.sec"
        "norwayeast"         = "sharednoe.noe"
        "eastasia"           = "sharedeasia.easia"
        "southeastasia"      = "sharedsasia.sasia"
        "japaneast"          = "sharedjpe.jpe"
        "australiaeast"      = "sharedeau.eau"
        "koreacentral"       = "sharedkrc.krc"
        "centralindia"       = "sharedcin.cin"
        "uaenorth"           = "shareduaen.uaen"
        "brazilsouth"        = "sharedsbr.sbr"
    }
    $ep = $maaEndpoints[$Location.ToLower()]
    if (-not $ep) {
        throw "No shared MAA endpoint for region '$Location'. Supported: $($maaEndpoints.Keys -join ', ')"
    }
    return "$ep.attest.azure.net"
}


function New-RandomCredential {
    $chars = "abcdefghijklmnopqrstuvwxyz"
    $username = "cvm" + -join ((0..7) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $passChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = -join ((0..39) | ForEach-Object { $passChars[(Get-Random -Maximum $passChars.Length)] })
    return @{ Username = $username; Password = $password }
}


function Set-KVAccessPolicyWithRetry {
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
                Write-Host "    Vault not ready (attempt $attempt/$MaxRetries), retrying in ${DelaySeconds}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $DelaySeconds
            }
            else { throw }
        }
    }
}


# ============================================================================
# CLEANUP
# ============================================================================
if ($Cleanup) {
    Write-Host "`n=== CLEANUP ===" -ForegroundColor Yellow
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        $rg = $config.resourceGroup
        Write-Host "Removing resource group: $rg ..." -ForegroundColor Yellow
        Remove-AzResourceGroup -Name $rg -Force -AsJob | Out-Null
        Remove-Item $configFile -Force -ErrorAction SilentlyContinue
        Write-Host "Cleanup job submitted. Deletion continues in background." -ForegroundColor Green
        Write-Host "Check status: Get-Job | Where-Object Command -like '*Remove-AzResourceGroup*'" -ForegroundColor Gray
    }
    else {
        Write-Host "No config file found. Nothing to clean up." -ForegroundColor Yellow
    }
    exit
}


# ============================================================================
# VALIDATE
# ============================================================================
if (-not $Prefix) {
    Write-Host "`n=== SKR Example — Secure Key Release from Azure Confidential VM ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\$scriptName -Prefix <name>     Deploy CVM + Key Vault + release key"
    Write-Host "  .\$scriptName -Cleanup           Remove all resources"
    Write-Host ""
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        Write-Host "Current deployment:" -ForegroundColor Cyan
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Location:       $($config.location)"
    }
    exit
}

# Prerequisites
Write-Host "`nChecking prerequisites..." -ForegroundColor Cyan
$azModule = Get-Module -ListAvailable -Name Az.Accounts | Select-Object -First 1
if (-not $azModule) { throw "Azure PowerShell (Az) not installed. Run: Install-Module -Name Az -Force" }
Write-Host "  Az module: $($azModule.Version)" -ForegroundColor Green
$context = Get-AzContext
if (-not $context) { throw "Not logged in to Azure. Run: Connect-AzAccount" }
Write-Host "  Logged in as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "  Subscription: $($context.Subscription.Name)" -ForegroundColor Green


# ============================================================================
# GENERATE NAMES
# ============================================================================
$suffix = -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
$basename = $Prefix + $suffix
$resgrp = "$basename-skr-rg"
$vnetName = "$basename-vnet"
$vmName = "$basename-cvm"
$kvName = "$($basename)kv"
$identityName = "$basename-id"
$desName = "$basename-des"
$cmkName = "disk-cmk"
$appKeyName = "fabrikam-totally-top-secret-key"
$cred = New-RandomCredential
$maaEndpoint = Get-SharedMaaEndpoint -Location $Location

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " SKR Example — Secure Key Release from Confidential VM" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Basename:       $basename"
Write-Host "  Resource Group: $resgrp"
Write-Host "  Location:       $Location"
Write-Host "  VM:             $vmName ($VMSize)"
Write-Host "  Key Vault:      $kvName"
Write-Host "  Secret Key:     $appKeyName"
Write-Host "  MAA Endpoint:   $maaEndpoint"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""


try {

# ============================================================================
# PHASE 1: RESOURCE GROUP + NETWORKING
# ============================================================================
Write-Host "Phase 1: Creating resource group and networking..." -ForegroundColor White

$tags = @{
    owner   = (Get-AzContext).Account.Id
    BuiltBy = $scriptName
    demo    = "skr-example"
}
New-AzResourceGroup -Name $resgrp -Location $Location -Tag $tags -Force | Out-Null
Write-Host "  Resource group: $resgrp" -ForegroundColor Green

# Private VNet — single subnet, no public IPs
$subnetConfig = New-AzVirtualNetworkSubnetConfig -Name "VMSubnet" -AddressPrefix "10.0.1.0/24"
$vnet = New-AzVirtualNetwork `
    -Name $vnetName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AddressPrefix "10.0.0.0/16" `
    -Subnet $subnetConfig
Write-Host "  VNet: $vnetName (10.0.0.0/16, no public IPs)" -ForegroundColor Green

Write-Host "Phase 1 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 2: KEY VAULT + IDENTITY + KEYS + DES
# ============================================================================
Write-Host "Phase 2: Creating Key Vault, identity, and keys..." -ForegroundColor White

# ---- User-Assigned Managed Identity ----
$identity = New-AzUserAssignedIdentity `
    -Name $identityName `
    -ResourceGroupName $resgrp `
    -Location $Location
Write-Host "  Managed identity: $identityName" -ForegroundColor Green

# ---- Key Vault Premium (HSM-backed keys) ----
New-AzKeyVault `
    -Name $kvName `
    -Location $Location `
    -ResourceGroupName $resgrp `
    -Sku Premium `
    -EnabledForDiskEncryption `
    -DisableRbacAuthorization `
    -SoftDeleteRetentionInDays 10 `
    -EnablePurgeProtection | Out-Null
Write-Host "  Key Vault: $kvName (Premium)" -ForegroundColor Green

# ---- KV access policy: VM identity → get + release keys ----
Set-KVAccessPolicyWithRetry -PolicyParams @{
    VaultName         = $kvName
    ResourceGroupName = $resgrp
    ObjectId          = $identity.PrincipalId
    PermissionsToKeys = @('get', 'release', 'wrapKey', 'unwrapKey')
}
Write-Host "  Access policy: $identityName → get, release, wrapKey, unwrapKey" -ForegroundColor Green

# ---- CVM Orchestrator SP (required for confidential disk encryption) ----
$cvmAgentAppId = 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
$cvmAgent = Get-AzADServicePrincipal -ApplicationId $cvmAgentAppId
if (-not $cvmAgent) { throw "CVM Orchestrator SP not found. Subscription may not support CVMs." }
Set-KVAccessPolicyWithRetry -PolicyParams @{
    VaultName         = $kvName
    ResourceGroupName = $resgrp
    ObjectId          = $cvmAgent.Id
    PermissionsToKeys = @('get', 'release')
}

# ---- CMK for confidential OS disk encryption ----
Write-Host "  Creating disk encryption key: $cmkName (RSA-HSM 3072-bit)"
$cmkMaxRetries = 6
for ($i = 1; $i -le $cmkMaxRetries; $i++) {
    try {
        Add-AzKeyVaultKey `
            -VaultName $kvName -Name $cmkName `
            -Size 3072 -KeyOps wrapKey, unwrapKey `
            -KeyType RSA -Destination HSM `
            -Exportable -UseDefaultCVMPolicy | Out-Null
        break
    }
    catch {
        if ($i -lt $cmkMaxRetries) {
            Write-Host "    Vault not ready (attempt $i/$cmkMaxRetries), retrying..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
        } else { throw }
    }
}
Write-Host "  Disk CMK created: $cmkName" -ForegroundColor Green

# ---- DiskEncryptionSet ----
$kvResource = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $resgrp
$cmkUrl = (Get-AzKeyVaultKey -VaultName $kvName -KeyName $cmkName).Key.Kid
$desConfig = New-AzDiskEncryptionSetConfig `
    -Location $Location `
    -SourceVaultId $kvResource.ResourceId `
    -KeyUrl $cmkUrl `
    -IdentityType SystemAssigned `
    -EncryptionType ConfidentialVmEncryptedWithCustomerKey
New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName -DiskEncryptionSet $desConfig | Out-Null
$desIdentity = (Get-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resgrp).Identity.PrincipalId
Set-KVAccessPolicyWithRetry -PolicyParams @{
    VaultName                = $kvName
    ResourceGroupName        = $resgrp
    ObjectId                 = $desIdentity
    PermissionsToKeys        = @('wrapKey', 'unwrapKey', 'get')
    BypassObjectIdValidation = $true
}
Write-Host "  DiskEncryptionSet: $desName" -ForegroundColor Green

# ---- Application SKR key with custom CVM release policy ----
# This is the key that the VM will release at boot time.
# We use the REST API to create it with a release policy that requires
# AMD SEV-SNP attestation via nested claim paths (see .DESCRIPTION).
Write-Host "`n  Creating SKR key: $appKeyName" -ForegroundColor Cyan

$maaAuthority = "https://$maaEndpoint"
$releasePolicyObj = @{
    version = "1.0.0"
    anyOf   = @(
        @{
            authority = $maaAuthority
            allOf     = @(
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
).Replace('+', '-').Replace('/', '_').TrimEnd('=')

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │  SKR Release Policy                                             │" -ForegroundColor DarkCyan
Write-Host "  │                                                                 │" -ForegroundColor DarkCyan
Write-Host "  │  Authority: $($maaAuthority.PadRight(40))       │" -ForegroundColor DarkCyan
Write-Host "  │                                                                 │" -ForegroundColor DarkCyan
Write-Host "  │  Required claims (ALL must match):                              │" -ForegroundColor DarkCyan
Write-Host "  │    1. x-ms-isolation-tee.x-ms-compliance-status                 │" -ForegroundColor DarkCyan
Write-Host "  │       = azure-compliant-cvm                                     │" -ForegroundColor DarkCyan
Write-Host "  │       → VM passed MAA compliance checks (SNP report valid,      │" -ForegroundColor DarkCyan
Write-Host "  │         VCEK chain verified, firmware measurements OK)           │" -ForegroundColor DarkCyan
Write-Host "  │                                                                 │" -ForegroundColor DarkCyan
Write-Host "  │    2. x-ms-isolation-tee.x-ms-attestation-type                  │" -ForegroundColor DarkCyan
Write-Host "  │       = sevsnpvm                                                │" -ForegroundColor DarkCyan
Write-Host "  │       → Attestation came from AMD SEV-SNP guest VM              │" -ForegroundColor DarkCyan
Write-Host "  │         (hardware memory encryption active, integrity enforced)  │" -ForegroundColor DarkCyan
Write-Host "  │                                                                 │" -ForegroundColor DarkCyan
Write-Host "  │  Result: Key can ONLY be released to a genuine Azure CVM        │" -ForegroundColor DarkCyan
Write-Host "  │  running on AMD SEV-SNP hardware. Standard VMs, debug-enabled   │" -ForegroundColor DarkCyan
Write-Host "  │  VMs, or VMs that fail measurement checks are REJECTED.         │" -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""

# Create the key via AKV REST API
$akvToken = (Get-AzAccessToken -ResourceUrl "https://vault.azure.net").Token
$createKeyBody = @{
    kty            = "RSA-HSM"
    key_size       = 2048
    key_ops        = @("wrapKey", "unwrapKey", "encrypt", "decrypt")
    attributes     = @{ exportable = $true }
    release_policy = @{
        contentType = "application/json; charset=utf-8"
        data        = $releasePolicyBase64Url
    }
} | ConvertTo-Json -Depth 10

$createKeyUri = "https://$kvName.vault.azure.net/keys/$appKeyName/create?api-version=7.4"
$null = Invoke-RestMethod -Method POST -Uri $createKeyUri `
    -Headers @{ Authorization = "Bearer $akvToken" } `
    -ContentType "application/json" `
    -Body $createKeyBody
Write-Host "  Key created: $appKeyName (RSA-HSM 2048, exportable, SKR policy bound)" -ForegroundColor Green

Write-Host "`nPhase 2 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 3: DEPLOY CONFIDENTIAL VM
# ============================================================================
Write-Host "Phase 3: Deploying Confidential VM..." -ForegroundColor White

$vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
$vmSubnet = $vnet.Subnets | Where-Object { $_.Name -eq "VMSubnet" }

# NIC (private IP only — no public IP)
$nicName = "$vmName-nic"
$ipConfig = New-AzNetworkInterfaceIpConfig -Name "ipconfig1" -Subnet $vmSubnet -PrivateIpAddress "10.0.1.4"
$nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $resgrp -Location $Location -IpConfiguration $ipConfig
Write-Host "  NIC: $nicName (private IP 10.0.1.4, no public IP)" -ForegroundColor Green

# VM configuration
$securePassword = ConvertTo-SecureString -String $cred.Password -AsPlainText -Force
$vmCred = New-Object System.Management.Automation.PSCredential ($cred.Username, $securePassword)

$vm = New-AzVMConfig -VMName $vmName -VMSize $VMSize `
    -IdentityType UserAssigned -IdentityId $identity.Id
$vm = Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName $vmName -Credential $vmCred
$vm = Set-AzVMSourceImage -VM $vm `
    -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest"
$vm = Add-AzVMNetworkInterface -VM $vm -Id $nic.Id

# Confidential OS disk
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

Write-Host "  Creating VM: $vmName (this takes 2-5 minutes)..." -ForegroundColor Cyan
New-AzVM -ResourceGroupName $resgrp -Location $Location -VM $vm | Out-Null
Write-Host "  VM created: $vmName" -ForegroundColor Green

$vmObj = Get-AzVM -ResourceGroupName $resgrp -Name $vmName
Write-Host "  VmId: $($vmObj.VmId)" -ForegroundColor Gray

Write-Host "Phase 3 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 4: BOOTSTRAP — INSTALL TOOLS + RUN SKR
# ============================================================================
Write-Host "Phase 4: Running bootstrap script (installs tools + performs SKR)..." -ForegroundColor White
Write-Host "  This installs cvm-attestation-tools, gets an MAA token from the vTPM," -ForegroundColor Gray
Write-Host "  and calls AKV key release. Output will appear below when complete." -ForegroundColor Gray
Write-Host ""

# The bootstrap script is embedded as a here-string and passed directly
# to CustomScriptExtension. No blob storage needed for this simple example.
$bootstrapScript = @'
#!/bin/bash
set -euo pipefail

echo ""
echo "================================================================"
echo " SKR Example — Secure Key Release Bootstrap"
echo "================================================================"
echo " Key:      __KEY_NAME__"
echo " Vault:    __AKV_ENDPOINT__"
echo " MAA:      __MAA_ENDPOINT__"
echo " Identity: __CLIENT_ID__"
echo " Started:  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"
echo ""

export DEBIAN_FRONTEND=noninteractive

# ---- Phase 1: System packages ----
echo "[1/5] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl jq tpm2-tools 2>&1 | tail -3

# ---- Phase 2: cvm-attestation-tools (Python vTPM attestation) ----
echo "[2/5] Installing cvm-attestation-tools..."
CVM_ATTEST_DIR="/opt/cvm-attestation-tools"
git clone --depth 1 https://github.com/Azure/cvm-attestation-tools.git "$CVM_ATTEST_DIR" 2>&1 | tail -2
git clone --depth 1 https://github.com/microsoft/TSS.MSR.git "$CVM_ATTEST_DIR/cvm-attestation/TSS_MSR" 2>&1 | tail -2

# Verify vTPM is present
if [ -e "/dev/tpmrm0" ]; then
    echo "  vTPM: /dev/tpmrm0 PRESENT"
else
    echo "  ERROR: No vTPM device found at /dev/tpmrm0"
    exit 1
fi

# ---- Phase 3: Python environment ----
echo "[3/5] Setting up Python environment..."
python3 -m venv /opt/skr-venv
source /opt/skr-venv/bin/activate
pip install --no-cache-dir --upgrade pip 2>&1 | tail -1
pip install --no-cache-dir flask requests pyjwt cryptography 2>&1 | tail -3
pip install --no-cache-dir -r "$CVM_ATTEST_DIR/cvm-attestation/requirements.txt" 2>&1 | tail -3

# ---- Phase 4: MAA attestation via vTPM ----
echo "[4/5] Getting MAA attestation token from vTPM..."
echo "  This proves the VM is running on AMD SEV-SNP hardware."

cat > /tmp/get_maa_token.py << 'PYEOF'
import sys, json, os
sys.path.insert(0, '/opt/cvm-attestation-tools/cvm-attestation')
from src.attestation_client import AttestationClient, AttestationClientParameters, Verifier
from src.isolation import IsolationType
from src.logger import Logger

maa_endpoint = sys.argv[1]
attest_url = f"https://{maa_endpoint}/attest/AzureGuest?api-version=2020-10-01"
logger = Logger("skr").get_logger()
params = AttestationClientParameters(
    endpoint=attest_url,
    verifier=Verifier.MAA,
    isolation_type=IsolationType.SEV_SNP,
    claims=None,
)
client = AttestationClient(logger, params)
token = client.attest_guest()
if isinstance(token, bytes):
    token = token.decode('utf-8').strip()
print(token)
PYEOF

MAA_TOKEN=$(python3 /tmp/get_maa_token.py "__MAA_ENDPOINT__")
if [ -z "$MAA_TOKEN" ]; then
    echo "  ERROR: Failed to get MAA token"
    exit 1
fi
TOKEN_LEN=${#MAA_TOKEN}
echo "  MAA token obtained ($TOKEN_LEN chars)"

# Decode and display key claims from the JWT payload
echo ""
echo "  ── MAA Token Claims (relevant to SKR policy) ──"
PAYLOAD=$(echo "$MAA_TOKEN" | cut -d. -f2)
# Add base64 padding
MOD=$((${#PAYLOAD} % 4))
if [ $MOD -eq 2 ]; then PAYLOAD="${PAYLOAD}=="; elif [ $MOD -eq 3 ]; then PAYLOAD="${PAYLOAD}="; fi
CLAIMS=$(echo "$PAYLOAD" | base64 -d 2>/dev/null | jq '.')
echo "$CLAIMS" | jq -r '."x-ms-isolation-tee" // empty' | jq '{
    "x-ms-compliance-status": ."x-ms-compliance-status",
    "x-ms-attestation-type": ."x-ms-attestation-type"
}'
echo ""

# ---- Phase 5: AKV Secure Key Release ----
echo "[5/5] Releasing key from Azure Key Vault..."
echo "  Key:   __KEY_NAME__"
echo "  Vault: __AKV_ENDPOINT__"
echo ""

# Get managed identity token for AKV
echo "  Getting managed identity token..."
AKV_TOKEN=$(curl -s -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net&client_id=__CLIENT_ID__" \
    | jq -r '.access_token')

if [ -z "$AKV_TOKEN" ] || [ "$AKV_TOKEN" = "null" ]; then
    echo "  ERROR: Failed to get managed identity token for AKV"
    exit 1
fi
echo "  AKV access token obtained"

# Get key version
echo "  Fetching key metadata..."
KEY_INFO=$(curl -s -H "Authorization: Bearer $AKV_TOKEN" \
    "https://__AKV_ENDPOINT__/keys/__KEY_NAME__?api-version=7.4")
KEY_KID=$(echo "$KEY_INFO" | jq -r '.key.kid')
KEY_VERSION=$(echo "$KEY_KID" | rev | cut -d/ -f1 | rev)
echo "  Key version: $KEY_VERSION"

# Show release policy
echo ""
echo "  ── Release Policy on Key ──"
echo "$KEY_INFO" | jq -r '.release_policy.data' | python3 -c "
import sys, base64, json
data = sys.stdin.read().strip()
padded = data + '=' * (4 - len(data) % 4)
decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
policy = json.loads(decoded)
print(json.dumps(policy, indent=2))
"
echo ""

# Call key release API
echo "  Calling AKV key release API..."
RELEASE_RESPONSE=$(curl -s -X POST \
    "https://__AKV_ENDPOINT__/keys/__KEY_NAME__/$KEY_VERSION/release?api-version=7.4" \
    -H "Authorization: Bearer $AKV_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"target\": \"$MAA_TOKEN\"}")

# Check for errors
if echo "$RELEASE_RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    echo "  ERROR: Key release failed!"
    echo "$RELEASE_RESPONSE" | jq '.error'
    exit 1
fi

# Extract the JWS value — this is the released key material
RELEASE_VALUE=$(echo "$RELEASE_RESPONSE" | jq -r '.value')
if [ -z "$RELEASE_VALUE" ] || [ "$RELEASE_VALUE" = "null" ]; then
    echo "  ERROR: No value in release response"
    echo "$RELEASE_RESPONSE" | head -c 500
    exit 1
fi

echo ""
echo "================================================================"
echo " ✅ SECURE KEY RELEASE SUCCESSFUL"
echo "================================================================"
echo ""
echo " Key Name:    __KEY_NAME__"
echo " Key Vault:   __AKV_ENDPOINT__"
echo " Key Version: $KEY_VERSION"
echo ""
echo " The key was released because this VM satisfied BOTH conditions"
echo " in the release policy:"
echo "   1. x-ms-isolation-tee.x-ms-compliance-status = azure-compliant-cvm"
echo "   2. x-ms-isolation-tee.x-ms-attestation-type  = sevsnpvm"
echo ""
echo " Released JWS token (first 200 chars):"
echo " ${RELEASE_VALUE:0:200}..."
echo ""

# Decode the JWS to extract the JWK (the actual key material)
echo " ── Decoded Key Material (JWK) ──"
JWS_PAYLOAD=$(echo "$RELEASE_VALUE" | cut -d. -f2)
MOD=$((${#JWS_PAYLOAD} % 4))
if [ $MOD -eq 2 ]; then JWS_PAYLOAD="${JWS_PAYLOAD}=="; elif [ $MOD -eq 3 ]; then JWS_PAYLOAD="${JWS_PAYLOAD}="; fi
echo "$JWS_PAYLOAD" | base64 -d 2>/dev/null | jq -r '.response.key.key' 2>/dev/null | jq '{
    kty: .kty,
    n: (.n[:40] + "...[truncated]"),
    e: .e,
    key_ops: .key_ops
}' 2>/dev/null || echo " (Could not decode JWK — raw JWS returned successfully)"

echo ""
echo "================================================================"
echo " Done: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"
'@

# Substitute placeholders in the bootstrap script
$bootstrapScript = $bootstrapScript `
    -replace '__KEY_NAME__', $appKeyName `
    -replace '__AKV_ENDPOINT__', "$kvName.vault.azure.net" `
    -replace '__MAA_ENDPOINT__', $maaEndpoint `
    -replace '__CLIENT_ID__', $identity.ClientId

# Base64 encode the script for CustomScriptExtension
$scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($bootstrapScript)
$scriptBase64 = [Convert]::ToBase64String($scriptBytes)

# Run via CustomScriptExtension (commandToExecute receives the base64-encoded script)
$publicSettings = @{
    commandToExecute = "echo $scriptBase64 | base64 -d > /tmp/skr-bootstrap.sh && bash /tmp/skr-bootstrap.sh"
} | ConvertTo-Json

Write-Host "  Running bootstrap on $vmName (installs tools + performs SKR)..." -ForegroundColor Cyan
Write-Host "  This typically takes 3-5 minutes..." -ForegroundColor Gray

Set-AzVMExtension `
    -ResourceGroupName $resgrp `
    -VMName $vmName `
    -Name "skr-bootstrap" `
    -Publisher "Microsoft.Azure.Extensions" `
    -ExtensionType "CustomScript" `
    -TypeHandlerVersion "2.1" `
    -Location $Location `
    -SettingString $publicSettings | Out-Null

Write-Host "`n  Bootstrap complete." -ForegroundColor Green


# ============================================================================
# PHASE 5: RETRIEVE AND DISPLAY SKR RESULT
# ============================================================================
Write-Host "`nPhase 5: Retrieving SKR result from VM..." -ForegroundColor White

# Get the extension instance view which contains stdout/stderr
$ext = Get-AzVMExtension `
    -ResourceGroupName $resgrp `
    -VMName $vmName `
    -Name "skr-bootstrap" `
    -Status

# The instance view contains substatus messages with stdout and stderr
$instanceView = $ext.Statuses + $ext.SubStatuses
$stdout = ""
$stderr = ""

if ($ext.SubStatuses) {
    foreach ($sub in $ext.SubStatuses) {
        if ($sub.Code -match 'StdOut') { $stdout = $sub.Message }
        if ($sub.Code -match 'StdErr') { $stderr = $sub.Message }
    }
}

# Also try the newer property path
if (-not $stdout -and $ext.PSObject.Properties['SubStatusesSerialized']) {
    $subStatuses = $ext.SubStatusesSerialized | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($subStatuses) {
        foreach ($sub in $subStatuses) {
            if ($sub.code -match 'StdOut') { $stdout = $sub.message }
            if ($sub.code -match 'StdErr') { $stderr = $sub.message }
        }
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " VM Bootstrap Output (from CustomScriptExtension)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if ($stdout) {
    Write-Host $stdout
}
else {
    Write-Host "  (No stdout captured — check stderr below)" -ForegroundColor Yellow
}

if ($stderr) {
    Write-Host "`n── stderr ──" -ForegroundColor Yellow
    # Only show last 30 lines of stderr (lots of apt noise)
    $stderrLines = $stderr -split "`n"
    if ($stderrLines.Count -gt 30) {
        Write-Host "  ... ($($stderrLines.Count - 30) lines omitted)" -ForegroundColor Gray
        $stderrLines[-30..-1] | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
    else {
        $stderrLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan


# ============================================================================
# SAVE CONFIG + FINAL OUTPUT
# ============================================================================
$config = @{
    resourceGroup = $resgrp
    basename      = $basename
    location      = $Location
    vmName        = $vmName
    vmSize        = $VMSize
    vmId          = $vmObj.VmId
    keyVault      = $kvName
    keyName       = $appKeyName
    identity      = $identityName
    identityClientId = $identity.ClientId
    maaEndpoint   = $maaEndpoint
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $configFile -Force

$elapsed = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Resource Group:  $resgrp"
Write-Host "  VM:              $vmName (private IP 10.0.1.4)"
Write-Host "  Key Vault:       $kvName"
Write-Host "  Key:             $appKeyName"
Write-Host "  MAA Endpoint:    $maaEndpoint"
Write-Host ""
Write-Host "  The key '$appKeyName' was released from the Key Vault" -ForegroundColor Cyan
Write-Host "  to the Confidential VM using AMD SEV-SNP attestation." -ForegroundColor Cyan
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
        $answer = Read-Host "  Delete resource group '$resgrp'? (y/N)"
        if ($answer -match '^[Yy]') {
            Write-Host "  Removing resource group (background)..." -ForegroundColor Yellow
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
            Remove-Item $configFile -Force -ErrorAction SilentlyContinue
            Write-Host "  Cleanup job submitted." -ForegroundColor Green
        }
        else {
            Write-Host "  Resources left in place. Clean up with: .\$scriptName -Cleanup" -ForegroundColor Yellow
        }
    }

    exit 1
}
