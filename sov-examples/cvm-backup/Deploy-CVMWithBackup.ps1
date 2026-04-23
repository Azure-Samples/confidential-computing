# Deploy a Windows Confidential VM with Azure Backup enabled
# VM will be created in a private VNet with no public IP; access is via Azure Bastion
# Azure Backup (Recovery Services Vault) is configured to protect the CVM OS disk
#
# April 2025 - initial version
#
# Usage: ./Deploy-CVMWithBackup.ps1 -subsID <SUBSCRIPTION_ID> -basename <BASENAME> [-description <DESC>]
#        [-region <AZURE_REGION>] [-vmsize <VM_SKU>] [-backupRetentionDays <DAYS>] [-smoketest] [-DisableBastion]
#
# basename     : Prefix for all resources; a 5-char random suffix is appended automatically.
# description  : Optional tag added to the resource group.
# region       : Azure region (defaults to northeurope). Must support Confidential VMs.
# vmsize       : VM SKU (defaults to Standard_DC2as_v5).
# backupRetentionDays : Daily backup retention in days (defaults to 30).
# smoketest    : When set, all resources are automatically removed after deployment.
# DisableBastion : Skip Bastion creation (VM accessible only via private network).
#
# Prerequisites:
#   - Azure PowerShell (Az module, latest version):  Install-Module -Name Az -Force
#   - You must be logged in to Azure PowerShell:     Connect-AzAccount
#
# Use at your own risk, no warranties implied, test in a non-production environment first.

param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$basename,
    [Parameter(Mandatory=$false)]$description        = "",
    [Parameter(Mandatory=$false)]$region             = "northeurope",
    [Parameter(Mandatory=$false)]$vmsize             = "Standard_DC2as_v5",
    [Parameter(Mandatory=$false)]$backupRetentionDays = 30,
    [Parameter(Mandatory=$false)][switch]$smoketest,
    [Parameter(Mandatory=$false)][switch]$DisableBastion
)

# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------
if ($subsID -eq "" -or $basename -eq "") {
    Write-Host "You must provide a subscription ID and a basename." -ForegroundColor Red
    exit 1
}

$startTime  = Get-Date
$scriptName = $MyInvocation.MyCommand.Name

# Detect git remote URL for resource tagging
$gitRemoteUrl = git remote get-url origin 2>$null
if ($gitRemoteUrl) {
    $gitRemoteUrl = $gitRemoteUrl -replace "\.git$", ""
} else {
    $gitRemoteUrl = "[Originally from] https://github.com/vinfnet/confidential-computing"
}

# ---------------------------------------------------------------------------
# Resource names
# ---------------------------------------------------------------------------
$suffix       = -join ((97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
$basename     = $basename + $suffix
$resgrp       = $basename
$akvname      = $basename + "akv"
$desname      = $basename + "des"
$keyname      = $basename + "-cmk-key"
$vmname       = $basename
$vnetname     = $vmname  + "vnet"
$bastionname  = $vnetname + "-bastion"
$vnetipname   = $vnetname + "-pip"
$nicPrefix    = $basename + "-nic"
$vmsubnetname = $basename + "vmsubnet"
$rsvname      = $basename + "rsv"          # Recovery Services Vault name
$backupPolicyName = "CVMDailyBackupPolicy"

# VM settings
$vmusername             = "azureuser"
$vmadminpassword        = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40)
$vmSize                 = $vmsize
$identityType           = "SystemAssigned"
$secureEncryptGuestState = "DiskWithVMGuestState"
$vmSecurityType         = "ConfidentialVM"
$KeySize                = 3072
$diskEncryptionType     = "ConfidentialVmEncryptedWithCustomerKey"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host "----------------------------------------------------------------------------------------------------------------"
Write-Host "Deploying Windows Confidential VM with Azure Backup: $basename  |  Region: $region"
if ($smoketest)      { Write-Host "SMOKETEST MODE: resources will be removed after deployment"        -ForegroundColor Yellow }
if ($DisableBastion) { Write-Host "BASTION DISABLED: VM is accessible only via private connectivity" -ForegroundColor Yellow }
Write-Host "VM admin username : $vmusername"
Write-Host "VM admin password : $vmadminpassword  <-- SAVE THIS NOW, it cannot be retrieved later"
Write-Host "Backup retention  : $backupRetentionDays day(s)"
Write-Host "Script            : $scriptName"
Write-Host "Repository URL    : $gitRemoteUrl"
Write-Host "----------------------------------------------------------------------------------------------------------------"

# ---------------------------------------------------------------------------
# Azure context
# ---------------------------------------------------------------------------
Set-AzContext -SubscriptionId $subsID
if (!$?) {
    Write-Host "Failed to set Azure subscription context. Exiting." -ForegroundColor Red
    exit 1
}

$ownername = (Get-AzContext).Account.Id

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------
$rgTags = @{
    owner    = $ownername
    BuiltBy  = $scriptName
    OSType   = "Windows"
    GitRepo  = $gitRemoteUrl
}
if ($description      -ne "") { $rgTags.Add("description",  $description) }
if ($smoketest)                { $rgTags.Add("smoketest",    "true") }
if ($DisableBastion)           { $rgTags.Add("BastionDisabled", "true") }

New-AzResourceGroup -Name $resgrp -Location $region -Tag $rgTags -Force

# ---------------------------------------------------------------------------
# Credential object
# ---------------------------------------------------------------------------
$securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword)

# ---------------------------------------------------------------------------
# Key Vault (Premium SKU required for CVM CMK)
# ---------------------------------------------------------------------------
Write-Host "`nCreating Azure Key Vault (Premium)..." -ForegroundColor Cyan
New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp `
    -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization `
    -SoftDeleteRetentionInDays 10 -EnablePurgeProtection

# Grant CVM orchestrator access
$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp `
    -ObjectId $cvmAgent.Id -PermissionsToKeys get,release

# Add CMK key using default CVM release policy
Add-AzKeyVaultKey -VaultName $akvname -Name $keyname -Size $KeySize `
    -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy

$encryptionKeyVaultId = (Get-AzKeyVault  -VaultName $akvname -ResourceGroupName $resgrp).ResourceId
$encryptionKeyURL     = (Get-AzKeyVaultKey -VaultName $akvname -KeyName $keyname).Key.Kid

# ---------------------------------------------------------------------------
# Disk Encryption Set
# ---------------------------------------------------------------------------
Write-Host "Creating Disk Encryption Set..." -ForegroundColor Cyan
$desConfig = New-AzDiskEncryptionSetConfig -Location $region -SourceVaultId $encryptionKeyVaultId `
    -KeyUrl $encryptionKeyURL -IdentityType SystemAssigned -EncryptionType $diskEncryptionType
New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname -DiskEncryptionSet $desConfig

$diskencset   = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname
$desIdentity  = $diskencset.Identity.PrincipalId

Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp `
    -ObjectId $desIdentity -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation

# ---------------------------------------------------------------------------
# Virtual Machine configuration
# ---------------------------------------------------------------------------
Write-Host "Configuring Confidential VM (Windows Server 2022)..." -ForegroundColor Cyan
$VirtualMachine = New-AzVMConfig -VMName $vmname -VMSize $vmSize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname `
    -Credential $cred -ProvisionVMAgent -EnableAutoUpdate
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine `
    -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' `
    -Skus '2022-datacenter-smalldisk-g2' -Version "latest"

# Networking
$subnet   = New-AzVirtualNetworkSubnetConfig -Name $vmsubnetname -AddressPrefix "10.0.0.0/24"
$vnet     = New-AzVirtualNetwork -Force -Name $vnetname -ResourceGroupName $resgrp `
    -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $subnet
$vnet     = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$subnetId = $vnet.Subnets[0].Id

$nic    = New-AzNetworkInterface -Force -Name $nicPrefix -ResourceGroupName $resgrp `
    -Location $region -SubnetId $subnetId
$nic    = Get-AzNetworkInterface -Name $nicPrefix -ResourceGroupName $resgrp
$nicId  = $nic.Id

$VirtualMachine = Add-AzVMNetworkInterface  -VM $VirtualMachine -Id $nicId
$VirtualMachine = Set-AzVMOSDisk           -VM $VirtualMachine `
    -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" `
    -SecurityEncryptionType $secureEncryptGuestState `
    -SecureVMDiskEncryptionSet $diskencset.Id
$VirtualMachine = Set-AzVmSecurityProfile  -VM $VirtualMachine -SecurityType $vmSecurityType
$VirtualMachine = Set-AzVmUefi             -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true
$VirtualMachine = Set-AzVMBootDiagnostic   -VM $VirtualMachine -Disable

Write-Host "Creating Confidential VM..." -ForegroundColor Cyan
New-AzVM -ResourceGroupName $resgrp -Location $region -Vm $VirtualMachine
$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname

# ---------------------------------------------------------------------------
# Azure Bastion (optional)
# ---------------------------------------------------------------------------
if (-not $DisableBastion) {
    Write-Host "Creating Azure Bastion..." -ForegroundColor Cyan
    $vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
    Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vnet `
        -AddressPrefix "10.0.99.0/26" | Set-AzVirtualNetwork
    $publicip = New-AzPublicIpAddress -ResourceGroupName $resgrp -Name $vnetipname `
        -Location $region -AllocationMethod Static -Sku Standard
    New-AzBastion -ResourceGroupName $resgrp -Name $bastionname `
        -PublicIpAddressRgName $resgrp -PublicIpAddressName $publicip.Name `
        -VirtualNetworkRgName $resgrp -VirtualNetworkName $vnetname -Sku "Basic"
} else {
    Write-Host "Bastion creation skipped (-DisableBastion). VM is accessible via private network only." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Recovery Services Vault + Backup Policy
# ---------------------------------------------------------------------------
Write-Host "`nCreating Recovery Services Vault for Azure Backup..." -ForegroundColor Cyan

# Create the Recovery Services Vault
New-AzRecoveryServicesVault -Name $rsvname -ResourceGroupName $resgrp -Location $region

$rsv = Get-AzRecoveryServicesVault -Name $rsvname -ResourceGroupName $resgrp
Set-AzRecoveryServicesVaultContext -Vault $rsv

# Build a daily backup schedule (02:00 UTC)
$schedulePolicy    = Get-AzRecoveryServicesBackupSchedulePolicyObject -WorkloadType AzureVM
$schedulePolicy.ScheduleRunTimes.Clear()
$schedulePolicy.ScheduleRunTimes.Add((Get-Date "2000-01-01 02:00:00Z").ToUniversalTime())

# Build a simple tiered retention policy
$retentionPolicy   = Get-AzRecoveryServicesBackupRetentionPolicyObject -WorkloadType AzureVM
$retentionPolicy.DailySchedule.DurationCountInDays = $backupRetentionDays

# Create (or update) the backup protection policy
$backupPolicy = New-AzRecoveryServicesBackupProtectionPolicy `
    -Name $backupPolicyName `
    -WorkloadType AzureVM `
    -RetentionPolicy $retentionPolicy `
    -SchedulePolicy $schedulePolicy

Write-Host "Enabling Azure Backup for the Confidential VM ($vmname)..." -ForegroundColor Cyan
Enable-AzRecoveryServicesBackupProtection `
    -ResourceGroupName $resgrp `
    -Name $vmname `
    -Policy $backupPolicy

Write-Host "`nAzure Backup enabled successfully." -ForegroundColor Green
Write-Host "Recovery Services Vault : $rsvname"
Write-Host "Backup Policy           : $backupPolicyName"
Write-Host "Daily retention         : $backupRetentionDays day(s)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "----------------------------------------------------------------------------------------------------------------"
Write-Host "Deployment complete. Resources created in resource group: $resgrp" -ForegroundColor Green
if (-not $DisableBastion) {
    Write-Host "Connect to the VM via Azure Bastion in the Azure portal (RDP)."
}
Write-Host "To clean up all resources manually, run:"
Write-Host "  Remove-AzResourceGroup -Name $resgrp -Force"
Write-Host "----------------------------------------------------------------------------------------------------------------"

# ---------------------------------------------------------------------------
# Smoketest cleanup
# ---------------------------------------------------------------------------
if ($smoketest) {
    Write-Host ""
    Write-Host "SMOKETEST MODE: Removing all created resources in 10 seconds..." -ForegroundColor Yellow
    Write-Host "Press any key to cancel deletion." -ForegroundColor Yellow

    $timeout   = 10
    $timer     = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = $false

    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            [Console]::ReadKey($true) | Out-Null
            $cancelled = $true
            break
        }
        Start-Sleep -Milliseconds 100
        $remaining = [math]::Ceiling($timeout - $timer.Elapsed.TotalSeconds)
        Write-Host "`rDeletion in $remaining second(s)... (Press any key to cancel)" -NoNewline -ForegroundColor Yellow
    }
    $timer.Stop()

    if ($cancelled) {
        Write-Host "`nDeletion cancelled. Resources remain in: $resgrp" -ForegroundColor Green
    } else {
        Write-Host "`nDeleting resource group $resgrp ..." -ForegroundColor Red
        try {
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob
            Write-Host "Resource group deletion initiated (running in background)."
        } catch {
            Write-Host "Error removing resource group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

$elapsed = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Output ("Execution time: {0} minutes and {1} seconds." -f $elapsed.Minutes, $elapsed.Seconds)
