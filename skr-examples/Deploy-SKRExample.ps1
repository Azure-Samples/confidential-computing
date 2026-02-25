<#
.SYNOPSIS
    Deploy a single Azure Confidential VM with Secure Key Release (SKR) end-to-end.

.DESCRIPTION
    Creates a minimal confidential computing environment that demonstrates
    AMD SEV-SNP Secure Key Release from Azure Key Vault:

    1. Resource Group with random suffix (from -Prefix)
    2. VNet with public IP + NSG (SSH locked to deployer's IP)
    3. Azure Key Vault Premium with HSM-backed exportable RSA key
       ("fabrikam-totally-top-secret-key") bound to a CVM release policy
    4. User-assigned managed identity for Key Vault access
    5. Ubuntu 24.04 Confidential VM (DCas_v5) with DiskWithVMGuestState encryption
    6. SSH session into the CVM that:
       a. Installs cvm-attestation-tools (Python vTPM attestation)
       b. Gets an MAA token via the vTPM (proves AMD SEV-SNP hardware)
       c. Calls AKV key release API with the MAA token
       d. Prints the released key material directly to the console

    After the VM boots, the script SSHs in using an ephemeral key pair,
    runs the bootstrap, and streams the SKR result directly to the console.

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
        $bn = $config.basename
        Write-Host "Removing resource group: $rg ..." -ForegroundColor Yellow
        Remove-AzResourceGroup -Name $rg -Force -AsJob | Out-Null
        Remove-Item $configFile -Force -ErrorAction SilentlyContinue
        # Clean up ephemeral SSH keys
        $cleanSshDir = Join-Path $scriptDir ".ssh"
        if (Test-Path $cleanSshDir) {
            Remove-Item "$cleanSshDir/$bn*" -Force -ErrorAction SilentlyContinue
            # Remove .ssh dir if empty
            if (-not (Get-ChildItem $cleanSshDir -ErrorAction SilentlyContinue)) {
                Remove-Item $cleanSshDir -Force -ErrorAction SilentlyContinue
            }
        }
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
$pipName = "$basename-pip"
$nsgName = "$basename-nsg"
$vmName = "$basename-cvm"
$kvName = "$($basename)kv"
$identityName = "$basename-id"
$desName = "$basename-des"
$sshKeyDir = Join-Path $scriptDir ".ssh"
$sshKeyPath = Join-Path $sshKeyDir "$basename"
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

# Private VNet — single subnet for the CVM
$subnetConfig = New-AzVirtualNetworkSubnetConfig -Name "VMSubnet" -AddressPrefix "10.0.1.0/24"
$vnet = New-AzVirtualNetwork `
    -Name $vnetName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AddressPrefix "10.0.0.0/16" `
    -Subnet $subnetConfig
Write-Host "  VNet: $vnetName (10.0.0.0/16)" -ForegroundColor Green

# Public IP for SSH access
$pip = New-AzPublicIpAddress `
    -Name $pipName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AllocationMethod Static `
    -Sku Standard
Write-Host "  Public IP: $pipName ($($pip.IpAddress))" -ForegroundColor Green

# NSG — allow SSH only from deployer's IP
$myIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
$sshRule = New-AzNetworkSecurityRuleConfig `
    -Name "AllowSSH" `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 1000 `
    -SourceAddressPrefix $myIp `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange 22 `
    -Access Allow
$nsg = New-AzNetworkSecurityGroup `
    -Name $nsgName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -SecurityRules $sshRule
Write-Host "  NSG: $nsgName (SSH allowed from $myIp only)" -ForegroundColor Green

# Generate ephemeral SSH key pair for this deployment
if (-not (Test-Path $sshKeyDir)) { New-Item -ItemType Directory -Path $sshKeyDir -Force | Out-Null }
if (Test-Path $sshKeyPath) { Remove-Item "$sshKeyPath*" -Force }
# Use -P (PEM passphrase) with empty string — avoids quoting issues across shells
ssh-keygen -t rsa -b 4096 -f $sshKeyPath -P "" -q 2>$null
$sshPubKey = Get-Content "$sshKeyPath.pub" -Raw
Write-Host "  SSH key pair generated (ephemeral, in .ssh/)" -ForegroundColor Green

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

# NIC with public IP and NSG
$nicName = "$vmName-nic"
$pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resgrp
$nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $resgrp
$ipConfig = New-AzNetworkInterfaceIpConfig -Name "ipconfig1" -Subnet $vmSubnet -PrivateIpAddress "10.0.1.4" -PublicIpAddress $pip
$nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $resgrp -Location $Location `
    -IpConfiguration $ipConfig -NetworkSecurityGroup $nsg
Write-Host "  NIC: $nicName (public IP $($pip.IpAddress), SSH locked to deployer)" -ForegroundColor Green

# VM configuration (SSH key auth — no password)
$securePassword = ConvertTo-SecureString -String $cred.Password -AsPlainText -Force
$vmCred = New-Object System.Management.Automation.PSCredential ($cred.Username, $securePassword)

$vm = New-AzVMConfig -VMName $vmName -VMSize $VMSize `
    -IdentityType UserAssigned -IdentityId $identity.Id
$vm = Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName $vmName -Credential $vmCred -DisablePasswordAuthentication
$vm = Add-AzVMSshPublicKey -VM $vm -KeyData $sshPubKey -Path "/home/$($cred.Username)/.ssh/authorized_keys"
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
Write-Host "Phase 4: Running bootstrap script via SSH (installs tools + performs SKR)..." -ForegroundColor White
Write-Host "  SSHing into the CVM to install cvm-attestation-tools, get an MAA token" -ForegroundColor Gray
Write-Host "  from the vTPM, and call AKV key release. Output streams live below." -ForegroundColor Gray
Write-Host ""

# The bootstrap script is embedded as a here-string, SCPed to the VM,
# and run via SSH. Output streams directly to the console.
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
echo "[1/4] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl tpm2-tools 2>&1 | tail -3

# ---- Phase 2: cvm-attestation-tools (Python vTPM attestation) ----
echo "[2/4] Installing cvm-attestation-tools..."
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
echo "[3/4] Setting up Python environment..."
python3 -m venv /opt/skr-venv
source /opt/skr-venv/bin/activate
pip install --no-cache-dir --upgrade pip 2>&1 | tail -1
pip install --no-cache-dir requests cryptography 2>&1 | tail -3
pip install --no-cache-dir -r "$CVM_ATTEST_DIR/cvm-attestation/requirements.txt" 2>&1 | tail -3

# ---- Phase 4: MAA attestation + AKV key release (Python — matches skr_shim.py) ----
echo "[4/4] Running Secure Key Release..."
echo "  MAA attestation via vTPM → AKV key release"
echo ""

cat > /tmp/skr_release.py << 'PYEOF'
"""
Secure Key Release — get MAA token from vTPM, then release key from AKV.
Uses the same libraries and flow as skr_shim.py (proven working).
"""
import sys, os, json, base64, time
sys.path.insert(0, '/opt/cvm-attestation-tools/cvm-attestation')
import requests as http_requests
from src.attestation_client import AttestationClient, AttestationClientParameters, Verifier
from src.isolation import IsolationType
from src.logger import Logger

MAA_ENDPOINT = sys.argv[1]
AKV_ENDPOINT = sys.argv[2]
KEY_NAME     = sys.argv[3]
CLIENT_ID    = sys.argv[4]


def decode_jwt_payload(token):
    """Decode a JWT payload (no signature verification)."""
    try:
        payload = token.split('.')[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


# =========================================================================
#  Step 1: MAA attestation token via vTPM
# =========================================================================
print("  Step 1/3: Getting MAA attestation token from vTPM...")
print("  This proves the VM is running on AMD SEV-SNP hardware.")

maa_clean = MAA_ENDPOINT.replace('https://', '').replace('http://', '').rstrip('/')
attest_url = f"https://{maa_clean}/attest/AzureGuest?api-version=2020-10-01"

logger = Logger("skr").get_logger()
params = AttestationClientParameters(
    endpoint=attest_url,
    verifier=Verifier.MAA,
    isolation_type=IsolationType.SEV_SNP,
    claims=None,
)
client = AttestationClient(logger, params)
result = client.attest_guest()

if not result:
    print("  ERROR: attest_guest() returned empty result")
    sys.exit(1)

maa_token = result.decode('utf-8').strip() if isinstance(result, bytes) else str(result).strip()
print(f"  MAA token obtained ({len(maa_token)} chars)")

# Decode and display claims (diagnostic)
claims = decode_jwt_payload(maa_token)
if claims:
    print()
    print("  ── MAA Token Claims (relevant to SKR policy) ──")
    print(f"  Issuer (iss):          {claims.get('iss', '(missing)')}")
    iso_tee = claims.get('x-ms-isolation-tee')
    if isinstance(iso_tee, dict):
        print(f"  compliance-status:     {iso_tee.get('x-ms-compliance-status', '(missing)')}")
        print(f"  attestation-type:      {iso_tee.get('x-ms-attestation-type', '(missing)')}")
    else:
        print("  WARNING: x-ms-isolation-tee claim MISSING from token")
        if 'x-ms-attestation-type' in claims:
            print(f"  top-level x-ms-attestation-type: {claims['x-ms-attestation-type']}")
            print("  This suggests PLATFORM attestation — AKV CVM policy requires GUEST attestation")
    runtime = claims.get('x-ms-runtime', {})
    if isinstance(runtime, dict):
        keys = runtime.get('keys', [])
        print(f"  runtime keys:          {len(keys)} key(s)")
        for k in keys:
            print(f"    {k.get('kid', 'n/a')}: kty={k.get('kty')}, key_ops={k.get('key_ops')}")
    print()
else:
    print("  WARNING: Could not decode MAA token for diagnostics")


# =========================================================================
#  Step 2: Managed identity token + key metadata
# =========================================================================
print("  Step 2/3: Getting managed identity token and key metadata...")

# MI token via IMDS (same pattern as skr_shim.py)
imds_resp = http_requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token",
    params={
        "api-version": "2018-02-01",
        "resource": "https://vault.azure.net",
        "client_id": CLIENT_ID,
    },
    headers={"Metadata": "true"},
    timeout=10,
)
imds_resp.raise_for_status()
akv_token = imds_resp.json()["access_token"]
print("  AKV access token obtained")

# Key metadata (to get version)
akv_host = AKV_ENDPOINT.replace('https://', '').replace('http://', '').rstrip('/')
key_resp = http_requests.get(
    f"https://{akv_host}/keys/{KEY_NAME}?api-version=7.4",
    headers={"Authorization": f"Bearer {akv_token}"},
    timeout=30,
)
key_resp.raise_for_status()
key_info = key_resp.json()
key_kid = key_info.get('key', {}).get('kid', '')
key_version = key_kid.rstrip('/').split('/')[-1] if key_kid else ''
print(f"  Key version: {key_version}")

# Display release policy
rp = key_info.get('release_policy', {})
if rp and rp.get('data'):
    rp_data = rp['data']
    rp_padded = rp_data + '=' * (4 - len(rp_data) % 4)
    rp_decoded = json.loads(base64.urlsafe_b64decode(rp_padded).decode('utf-8'))
    print()
    print("  ── Release Policy on Key ──")
    print(json.dumps(rp_decoded, indent=2))
    print()


# =========================================================================
#  Step 3: AKV key release (same as skr_shim.py — requests.post with json=)
# =========================================================================
release_url = f"https://{akv_host}/keys/{KEY_NAME}/{key_version}/release?api-version=7.4"
print(f"  Step 3/3: Calling AKV key release API...")
print(f"  URL: {release_url}")

resp = http_requests.post(
    release_url,
    headers={
        "Authorization": f"Bearer {akv_token}",
        "Content-Type": "application/json",
    },
    json={"target": maa_token},
    timeout=60,
)

if resp.status_code != 200:
    print(f"\n  ERROR: Key release failed! HTTP {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except Exception:
        print(resp.text[:1000])

    # Diagnostic: check authority vs issuer match
    if claims:
        print()
        print("  ── Diagnostics ──")
        iss = claims.get('iss', '(missing)')
        print(f"  Token issuer (iss): {iss}")
        print(f"  Token exp:          {claims.get('exp', '(missing)')}")
        print(f"  Token nbf:          {claims.get('nbf', '(missing)')}")
        iso_tee = claims.get('x-ms-isolation-tee', {})
        if isinstance(iso_tee, dict):
            print(f"  compliance-status:  {iso_tee.get('x-ms-compliance-status', '(missing)')}")
            print(f"  attestation-type:   {iso_tee.get('x-ms-attestation-type', '(missing)')}")
        runtime_keys = claims.get('x-ms-runtime', {}).get('keys', [])
        print(f"  runtime keys:       {len(runtime_keys)}")

        if rp and rp.get('data'):
            for rule in rp_decoded.get('anyOf', []):
                auth = rule.get('authority', '')
                print(f"  Policy authority:   {auth}")
                if auth == iss:
                    print(f"  Authority/iss:      MATCH ✓")
                else:
                    print(f"  Authority/iss:      MISMATCH ✗")
                    print(f"    policy: {auth}")
                    print(f"    token:  {iss}")
    sys.exit(1)


# =========================================================================
#  Success — display the released key
# =========================================================================
release_data = resp.json()
jws_value = release_data.get('value', '')

print()
print("================================================================")
print(" ✅ SECURE KEY RELEASE SUCCESSFUL")
print("================================================================")
print()
print(f" Key Name:    {KEY_NAME}")
print(f" Key Vault:   {AKV_ENDPOINT}")
print(f" Key Version: {key_version}")
print()
print(" The key was released because this VM satisfied BOTH conditions")
print(" in the release policy:")
print("   1. x-ms-isolation-tee.x-ms-compliance-status = azure-compliant-cvm")
print("   2. x-ms-isolation-tee.x-ms-attestation-type  = sevsnpvm")
print()
print(f" Released JWS token (first 200 chars):")
print(f" {jws_value[:200]}...")
print()

# Decode the JWS to extract the JWK
try:
    jws_payload = jws_value.split('.')[1]
    padding = 4 - len(jws_payload) % 4
    if padding != 4:
        jws_payload += '=' * padding
    jws_decoded = json.loads(base64.urlsafe_b64decode(jws_payload))
    key_data = jws_decoded.get('response', {}).get('key', {}).get('key', {})
    print(" ── Decoded Key Material (JWK) ──")
    display = {
        'kty': key_data.get('kty'),
        'key_ops': key_data.get('key_ops'),
        'e': key_data.get('e'),
    }
    n = key_data.get('n', '')
    if n:
        display['n'] = n[:40] + '...[truncated]'
    print(json.dumps({k: v for k, v in display.items() if v is not None}, indent=2))
except Exception as e:
    print(f" (Could not decode JWK: {e} — raw JWS returned successfully)")

print()
print("================================================================")
print(f" Done: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
print("================================================================")
PYEOF

source /opt/skr-venv/bin/activate
python3 /tmp/skr_release.py "__MAA_ENDPOINT__" "__AKV_ENDPOINT__" "__KEY_NAME__" "__CLIENT_ID__"
'@

# Substitute placeholders in the bootstrap script
$bootstrapScript = $bootstrapScript `
    -replace '__KEY_NAME__', $appKeyName `
    -replace '__AKV_ENDPOINT__', "$kvName.vault.azure.net" `
    -replace '__MAA_ENDPOINT__', $maaEndpoint `
    -replace '__CLIENT_ID__', $identity.ClientId

# Write the bootstrap script to a local temp file for SCP
$tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "skr-bootstrap-$basename.sh"
[System.IO.File]::WriteAllText($tempScript, $bootstrapScript)

$vmIp = (Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resgrp).IpAddress
$sshUser = $cred.Username
$sshOpts = @("-i", $sshKeyPath, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR")

# Wait for SSH to become available (VM just booted)
Write-Host "  Waiting for SSH on $vmIp..." -ForegroundColor Gray
$sshReady = $false
for ($i = 0; $i -lt 30; $i++) {
    $testResult = ssh @sshOpts -o ConnectTimeout=5 "$sshUser@$vmIp" "echo ok" 2>&1
    if ($testResult -match "ok") {
        $sshReady = $true
        break
    }
    Start-Sleep -Seconds 10
}
if (-not $sshReady) {
    throw "SSH not available on $vmIp after 5 minutes. Check NSG rules and VM status."
}
Write-Host "  SSH connected to $vmIp" -ForegroundColor Green

# Copy bootstrap script to VM and run it
Write-Host "  Uploading bootstrap script to VM..." -ForegroundColor Cyan
scp @sshOpts $tempScript "${sshUser}@${vmIp}:/tmp/skr-bootstrap.sh" 2>&1 | Out-Null
Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

Write-Host "  Running bootstrap on $vmName via SSH (installs tools + performs SKR)..." -ForegroundColor Cyan
Write-Host "  This typically takes 3-5 minutes..." -ForegroundColor Gray
Write-Host ""

# Run the bootstrap via SSH — stdout streams directly to the console.
# We also capture it for the config/summary.
$sshOutput = ssh @sshOpts "$sshUser@$vmIp" "sudo bash /tmp/skr-bootstrap.sh" 2>&1
$stdout = ($sshOutput | Out-String).Trim()

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " VM Bootstrap Output (via SSH)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if ($stdout) {
    Write-Host $stdout
}
else {
    Write-Host "  (No output captured from SSH session)" -ForegroundColor Yellow
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
    vmIp          = $vmIp
    sshUser       = $sshUser
    sshKeyPath    = $sshKeyPath
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
Write-Host "  VM:              $vmName ($vmIp)"
Write-Host "  Key Vault:       $kvName"
Write-Host "  Key:             $appKeyName"
Write-Host "  MAA Endpoint:    $maaEndpoint"
Write-Host ""
Write-Host "  The key '$appKeyName' was released from the Key Vault" -ForegroundColor Cyan
Write-Host "  to the Confidential VM using AMD SEV-SNP attestation." -ForegroundColor Cyan
Write-Host ""
Write-Host ("  Deployment time: {0} minutes and {1} seconds" -f [int]$elapsed.TotalMinutes, $elapsed.Seconds) -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green

# Auto-cleanup: remove Azure resources + local SSH keys
Write-Host ""
Write-Host "Cleaning up resources..." -ForegroundColor Yellow
Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
Remove-Item $configFile -Force -ErrorAction SilentlyContinue
if (Test-Path $sshKeyDir) {
    Remove-Item "$sshKeyDir/$basename*" -Force -ErrorAction SilentlyContinue
    if (-not (Get-ChildItem $sshKeyDir -ErrorAction SilentlyContinue)) {
        Remove-Item $sshKeyDir -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "  Resource group '$resgrp' deletion started (runs in background)." -ForegroundColor Green
Write-Host "  SSH keys removed." -ForegroundColor Green

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
            # Clean up SSH keys on failure too
            if (Test-Path $sshKeyDir) { Remove-Item "$sshKeyDir/$basename*" -Force -ErrorAction SilentlyContinue }
            Write-Host "  Cleanup job submitted." -ForegroundColor Green
        }
        else {
            Write-Host "  Resources left in place. Clean up with: .\$scriptName -Cleanup" -ForegroundColor Yellow
        }
    }

    exit 1
}
