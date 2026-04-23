# Deploy a Windows Confidential VM with Azure Backup (Enhanced – 4-hourly schedule)
# All resources are created in a single resource group in Korea Central.
# The VM sits on a private VNet with no public IP address (Bastion is not deployed).
# Azure Backup (Recovery Services Vault) uses the Enhanced policy with a 4-hour
# backup interval; an initial on-demand backup is triggered immediately after setup.
#
# April 2025
#
# Usage:
#   ./Deploy-CVMWithBackup.ps1 -subsID <SUBSCRIPTION_ID> -basename <BASENAME>
#       [-description <DESC>] [-region <AZURE_REGION>] [-vmsize <VM_SKU>]
#       [-backupRetentionDays <DAYS>] [-smoketest]
#
# Parameters:
#   basename           : Prefix for all resource names; a 5-digit numeric suffix is
#                        appended automatically (e.g. myvm12345).
#   description        : Optional tag added to the resource group.
#   region             : Azure region (defaults to koreacentral).
#                        Must support DCasv6 Confidential VMs.
#   vmsize             : VM SKU (defaults to Standard_DC2as_v6).
#                        Only DCasv6 / ECasv6 / ECadsv6 family (v6 CVM) SKUs are accepted.
#   backupRetentionDays: Daily backup retention in days (defaults to 30).
#   smoketest          : When set, all resources are removed after the initial backup
#                        completes (10-second cancellable countdown).
#
# Prerequisites:
#   - Azure PowerShell (Az module, latest):  Install-Module -Name Az -Force
#   - Logged in to Azure:                    Connect-AzAccount
#   - Confidential VM Orchestrator SP must exist in the tenant (run once per tenant):
#       Connect-MgGraph -Tenant <TENANT_ID> -Scopes Application.ReadWrite.All
#       New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 `
#           -DisplayName "Confidential VM Orchestrator"
#
# Use at your own risk, no warranties implied, test in a non-production environment first.

param (
    [Parameter(Mandatory)]         $subsID,
    [Parameter(Mandatory)]         $basename,
    [Parameter(Mandatory=$false)]  $description         = "",
    [Parameter(Mandatory=$false)]  $region              = "koreacentral",
    [Parameter(Mandatory=$false)]  $vmsize              = "Standard_DC2as_v6",
    [Parameter(Mandatory=$false)]  $backupRetentionDays = 30,
    [Parameter(Mandatory=$false)]  [switch]$smoketest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($subsID) -or [string]::IsNullOrWhiteSpace($basename)) {
    Write-Host "ERROR: -subsID and -basename are required." -ForegroundColor Red
    exit 1
}
if ($basename.Length -gt 12) {
    Write-Host "ERROR: -basename must be 12 characters or fewer (a 5-digit suffix will be appended)." -ForegroundColor Red
    exit 1
}
# Only v6 CVM SKUs are supported (DCasv6, ECasv6, ECadsv6 families)
if ($vmsize -notmatch '(?i)Standard_(DC|EC)\d+a?d?s_v6$') {
    Write-Host "ERROR: -vmsize '$vmsize' is not a supported v6 CVM SKU." -ForegroundColor Red
    Write-Host "       Accepted families: DCasv6, ECasv6, ECadsv6  (e.g. Standard_DC2as_v6, Standard_EC4as_v6)" -ForegroundColor Red
    exit 1
}

$startTime  = Get-Date
$scriptName = $MyInvocation.MyCommand.Name

# Detect git remote URL for resource tagging (best-effort)
try   { $gitRemoteUrl = (git remote get-url origin 2>$null) -replace "\.git$", "" }
catch { $gitRemoteUrl = "" }
if ([string]::IsNullOrWhiteSpace($gitRemoteUrl)) {
    $gitRemoteUrl = "https://github.com/vinfnet/confidential-computing"
}

# ---------------------------------------------------------------------------
# Resource names  (prefix + 5-character numeric string, e.g. "03729")
# Each position is independently drawn from 0-9, so leading zeros are possible.
# ---------------------------------------------------------------------------
$suffix           = -join (1..5 | ForEach-Object { Get-Random -Minimum 0 -Maximum 10 })
$basename         = $basename + $suffix

$resgrp           = $basename
$akvname          = $basename + "akv"
$desname          = $basename + "des"
$keyname          = $basename + "-cmk-key"
$vmname           = $basename
$vnetname         = $vmname  + "vnet"
$nicName          = $basename + "-nic"
$vmsubnetname     = $basename + "vmsubnet"
$rsvname          = $basename + "rsv"
$backupPolicyName = "CVM4HourBackupPolicy"

# VM settings
$vmusername              = "azureuser"
$vmadminpassword         = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*".ToCharArray() | Get-Random -Count 40)
$vmSize                  = $vmsize
$secureEncryptGuestState = "DiskWithVMGuestState"
$vmSecurityType          = "ConfidentialVM"
$KeySize                 = 3072
$diskEncryptionType      = "ConfidentialVmEncryptedWithCustomerKey"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host "================================================================================================================"
Write-Host " Windows Confidential VM + Azure Backup (4-hourly) | Korea Central"
Write-Host " Resource group : $resgrp"
Write-Host " VM name        : $vmname"
Write-Host " Region         : $region"
Write-Host " VM SKU         : $vmSize"
Write-Host " Backup policy  : Enhanced – every 4 hours | $backupRetentionDays-day daily retention"
if ($smoketest) { Write-Host " SMOKETEST MODE : resources will be removed after initial backup" -ForegroundColor Yellow }
Write-Host ""
Write-Host " VM admin username : $vmusername"
Write-Host " VM admin password : $vmadminpassword"
Write-Host " *** SAVE THE PASSWORD ABOVE NOW – it cannot be retrieved later ***" -ForegroundColor Yellow
Write-Host " Script            : $scriptName"
Write-Host " Repository        : $gitRemoteUrl"
Write-Host "================================================================================================================"

# ---------------------------------------------------------------------------
# Azure context
# ---------------------------------------------------------------------------
Write-Host "`n[1/9] Setting Azure context..." -ForegroundColor Cyan
Set-AzContext -SubscriptionId $subsID | Out-Null
$ownername = (Get-AzContext).Account.Id
Write-Host "      Logged in as: $ownername" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------
Write-Host "[2/9] Creating resource group: $resgrp ..." -ForegroundColor Cyan
$rgTags = @{
    owner    = $ownername
    BuiltBy  = $scriptName
    OSType   = "Windows"
    GitRepo  = $gitRemoteUrl
}
if ($description -ne "") { $rgTags["description"] = $description }
if ($smoketest)           { $rgTags["smoketest"]   = "true" }

New-AzResourceGroup -Name $resgrp -Location $region -Tag $rgTags -Force | Out-Null
Write-Host "      Resource group created." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Credential object
# ---------------------------------------------------------------------------
$securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword)

# ---------------------------------------------------------------------------
# Key Vault (Premium SKU required for CVM CMK)
# ---------------------------------------------------------------------------
Write-Host "[3/9] Creating Azure Key Vault (Premium): $akvname ..." -ForegroundColor Cyan
New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp `
    -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization `
    -SoftDeleteRetentionInDays 10 -EnablePurgeProtection | Out-Null

# Grant Confidential VM Orchestrator access
$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp `
    -ObjectId $cvmAgent.Id -PermissionsToKeys get,release | Out-Null

# Create the CMK key with the default CVM release policy (SEV-SNP validated)
Add-AzKeyVaultKey -VaultName $akvname -Name $keyname -Size $KeySize `
    -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM `
    -Exportable -UseDefaultCVMPolicy | Out-Null

$encryptionKeyVaultId = (Get-AzKeyVault    -VaultName $akvname -ResourceGroupName $resgrp).ResourceId
$encryptionKeyURL     = (Get-AzKeyVaultKey -VaultName $akvname -KeyName $keyname).Key.Kid
Write-Host "      Key Vault and CMK key created." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Disk Encryption Set
# ---------------------------------------------------------------------------
Write-Host "[4/9] Creating Disk Encryption Set: $desname ..." -ForegroundColor Cyan
$desConfig = New-AzDiskEncryptionSetConfig `
    -Location $region `
    -SourceVaultId $encryptionKeyVaultId `
    -KeyUrl $encryptionKeyURL `
    -IdentityType SystemAssigned `
    -EncryptionType $diskEncryptionType
New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname `
    -DiskEncryptionSet $desConfig | Out-Null

$diskencset  = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname
$desIdentity = $diskencset.Identity.PrincipalId

Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp `
    -ObjectId $desIdentity `
    -PermissionsToKeys wrapKey,unwrapKey,get `
    -BypassObjectIdValidation | Out-Null
Write-Host "      Disk Encryption Set created and linked to Key Vault." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Networking  (private VNet – NO public IP on the VM)
# ---------------------------------------------------------------------------
Write-Host "[5/9] Creating private VNet and NIC (no public IP)..." -ForegroundColor Cyan
$subnet   = New-AzVirtualNetworkSubnetConfig -Name $vmsubnetname -AddressPrefix "10.0.0.0/24"
$vnet     = New-AzVirtualNetwork -Force -Name $vnetname -ResourceGroupName $resgrp `
    -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $subnet
$vnet     = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$subnetId = $vnet.Subnets[0].Id

# NIC with no public IP address
$nic   = New-AzNetworkInterface -Force -Name $nicName -ResourceGroupName $resgrp `
    -Location $region -SubnetId $subnetId
$nic   = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $resgrp
$nicId = $nic.Id
Write-Host "      Private VNet and NIC created." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Confidential VM
# ---------------------------------------------------------------------------
Write-Host "[6/9] Deploying Windows Server 2022 Confidential VM: $vmname ..." -ForegroundColor Cyan
$VirtualMachine = New-AzVMConfig -VMName $vmname -VMSize $vmSize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows `
    -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine `
    -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' `
    -Skus '2022-datacenter-smalldisk-g2' -Version "latest"
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nicId
$VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine `
    -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" `
    -SecurityEncryptionType $secureEncryptGuestState `
    -SecureVMDiskEncryptionSet $diskencset.Id
$VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType
$VirtualMachine = Set-AzVmUefi            -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true
$VirtualMachine = Set-AzVMBootDiagnostic  -VM $VirtualMachine -Disable

New-AzVM -ResourceGroupName $resgrp -Location $region -Vm $VirtualMachine | Out-Null
$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname
Write-Host "      Confidential VM created: $($vm.Id)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Recovery Services Vault
# ---------------------------------------------------------------------------
Write-Host "[7/9] Creating Recovery Services Vault: $rsvname ..." -ForegroundColor Cyan
New-AzRecoveryServicesVault -Name $rsvname -ResourceGroupName $resgrp -Location $region | Out-Null
$rsv = Get-AzRecoveryServicesVault -Name $rsvname -ResourceGroupName $resgrp
Set-AzRecoveryServicesVaultContext -Vault $rsv

# Enable soft-delete for the vault (good practice; does not block CVM backup)
Set-AzRecoveryServicesVaultProperty -VaultId $rsv.ID -SoftDeleteFeatureState Enable | Out-Null
Write-Host "      Recovery Services Vault created." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Enhanced backup policy – 4-hour interval
# The Enhanced policy is required for sub-daily (hourly) backup schedules.
# ---------------------------------------------------------------------------
Write-Host "[8/9] Configuring Enhanced backup policy (every 4 hours)..." -ForegroundColor Cyan

$schedulePolicy = Get-AzRecoveryServicesBackupSchedulePolicyObject `
    -WorkloadType AzureVM -BackupManagementType AzureVM -PolicySubType Enhanced

# Set hourly schedule with a 4-hour interval covering the full 24-hour window
$backupWindowHours = 24   # full-day coverage so no backup window is missed
$schedulePolicy.ScheduleRunFrequency                    = "Hourly"
$schedulePolicy.HourlySchedule.Interval                = 4
$schedulePolicy.HourlySchedule.ScheduleWindowStartTime = `
    (Get-Date "2000-01-01 00:00:00Z").ToUniversalTime()
$schedulePolicy.HourlySchedule.ScheduleWindowDuration  = $backupWindowHours

# Retention: keep daily recovery points for $backupRetentionDays days
$retentionPolicy = Get-AzRecoveryServicesBackupRetentionPolicyObject `
    -WorkloadType AzureVM -BackupManagementType AzureVM -PolicySubType Enhanced
$retentionPolicy.DailySchedule.DurationCountInDays = $backupRetentionDays

# Create the policy
$backupPolicy = New-AzRecoveryServicesBackupProtectionPolicy `
    -Name $backupPolicyName `
    -WorkloadType AzureVM `
    -BackupManagementType AzureVM `
    -RetentionPolicy $retentionPolicy `
    -SchedulePolicy $schedulePolicy `
    -VaultId $rsv.ID

# Enable protection on the CVM
Enable-AzRecoveryServicesBackupProtection `
    -ResourceGroupName $resgrp `
    -Name $vmname `
    -Policy $backupPolicy `
    -VaultId $rsv.ID | Out-Null

Write-Host "      Enhanced 4-hourly backup policy applied to $vmname." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Trigger initial on-demand backup and wait for completion
# ---------------------------------------------------------------------------
Write-Host "[9/9] Triggering initial on-demand backup..." -ForegroundColor Cyan

# Give ARM a moment to register the protection before querying the item
Start-Sleep -Seconds 30

$container  = Get-AzRecoveryServicesBackupContainer `
    -ContainerType AzureVM -FriendlyName $vmname -VaultId $rsv.ID
$backupItem = Get-AzRecoveryServicesBackupItem `
    -Container $container -WorkloadType AzureVM -VaultId $rsv.ID

$backupJob = Backup-AzRecoveryServicesBackupItem -Item $backupItem -VaultId $rsv.ID

Write-Host "      Backup job started. Job ID: $($backupJob.JobId)" -ForegroundColor Green
Write-Host "      Waiting for initial backup to complete (this typically takes 10-30 minutes)..." -ForegroundColor Cyan

$maxWaitMinutes = 60                        # hard timeout
$maxWaitSeconds = $maxWaitMinutes * 60
$pollIntervalSeconds = 30                   # seconds between status polls
$elapsed        = 0

do {
    Start-Sleep -Seconds $pollIntervalSeconds
    $elapsed += $pollIntervalSeconds
    $job = Get-AzRecoveryServicesBackupJob -JobId $backupJob.JobId -VaultId $rsv.ID
    $mins = [math]::Floor($elapsed / 60)
    $secs = $elapsed % 60
    Write-Host ("      [{0:D2}:{1:D2}] Backup status: {2}" -f $mins, $secs, $job.Status)
} while ($job.Status -in @("InProgress", "NotStarted") -and $elapsed -lt $maxWaitSeconds)

if ($job.Status -eq "Completed") {
    Write-Host "      Initial backup COMPLETED successfully." -ForegroundColor Green
} elseif ($job.Status -eq "CompletedWithWarnings") {
    Write-Host "      Initial backup completed with warnings – check the RSV job log in the portal." -ForegroundColor Yellow
} elseif ($elapsed -ge $maxWaitSeconds) {
    Write-Host "      Timed out waiting for backup. Job is still running in the background." -ForegroundColor Yellow
    Write-Host "      Check job status in the portal: Vault '$rsvname' > Backup Jobs." -ForegroundColor Yellow
} else {
    Write-Host "      Backup ended with status: $($job.Status). Check the portal for details." -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Deployment summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================================================================================"
Write-Host " DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "================================================================================================================"
Write-Host " Resource group          : $resgrp"
Write-Host " Region                  : $region"
Write-Host " VM name                 : $vmname  (Windows Server 2022 CVM, AMD SEV-SNP)"
Write-Host " Confidential disk enc.  : DiskWithVMGuestState + Customer Managed Key"
Write-Host " Key Vault               : $akvname"
Write-Host " Disk Encryption Set     : $desname"
Write-Host " Recovery Services Vault : $rsvname"
Write-Host " Backup policy           : $backupPolicyName (every 4 hours, $backupRetentionDays-day retention)"
Write-Host " Initial backup job      : $($job.Status)"
Write-Host ""
Write-Host " The VM has NO public IP address."
Write-Host " Access via: Azure portal (Serial console), VPN, ExpressRoute, or a jump box in the same VNet."
Write-Host ""
Write-Host " To clean up all resources run:"
Write-Host "   Remove-AzResourceGroup -Name $resgrp -Force"
Write-Host "================================================================================================================"

# ---------------------------------------------------------------------------
# Smoketest cleanup
# ---------------------------------------------------------------------------
if ($smoketest) {
    Write-Host ""
    Write-Host "SMOKETEST: Removing all resources in 10 seconds – press any key to cancel." -ForegroundColor Yellow

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
        Write-Host ("`rDeleting in {0} second(s)... (any key to cancel)" -f $remaining) `
            -NoNewline -ForegroundColor Yellow
    }
    $timer.Stop()

    if ($cancelled) {
        Write-Host "`nDeletion cancelled – resources remain in '$resgrp'." -ForegroundColor Green
    } else {
        Write-Host "`nDeleting resource group '$resgrp' (background job)..." -ForegroundColor Red
        try {
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
            Write-Host "Resource group deletion initiated successfully."
        } catch {
            Write-Host "Error removing resource group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

$elapsed = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Output ("Total execution time: {0} minutes and {1} seconds." -f $elapsed.Minutes, $elapsed.Seconds)
