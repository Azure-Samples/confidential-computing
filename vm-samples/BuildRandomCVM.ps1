# Hands-off script to build a windows CVM and then make it do attestation by automating an attestation process /inside/ the VM
# VM will be created in a private vnet with no public IP and can only be accessed over the Internet via the Azure Bastion service
# Feb 2025 - ported to all native PowerShell code and re-implemented Azure Bastion code and added command line parameters rather than editing file
# April 2025 - attestation check now runs inside the VM using the WindowsAttest.ps1 script
# Tested on MacOS (PWSH 7.5) & Windows (7.4.6)
# 
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# based on https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-azure-cli
# 
# Clone this repo to a folder (relies on the WindowsAttest.ps1 script being in the same folder as this script)
#
# Usage: ./BuildRandomCVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> -osType <Windows|Windows11|Windows2019|Ubuntu|RHEL> [-description <OPTIONAL DESCRIPTION>] [-smoketest] [-region <AZURE REGION>] [-policyFilePath <PATH TO POLICY FILE>] [-DisableBastion] [-NoInternetAccess] [-SkipSkuPreflight]
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
# osType specifies which OS to deploy: Windows (Server 2022), Windows11 (Windows 11 Enterprise), Ubuntu (24.04), or RHEL (9.5)
# description is an optional parameter that will be added as a tag to the resource group
# smoketest is an optional switch that automatically removes all resources after completion (useful for testing)
# region is an optional parameter that specifies the Azure region (defaults to northeurope)
# policyFilePath is an optional parameter that specifies the path to a custom policy file for key vault key creation
# DisableBastion is an optional switch that skips the creation of Azure Bastion (VM will only be accessible via private network)
# NoInternetAccess is an optional switch that blocks outbound internet access from the CVM subnet by not attaching NAT Gateway egress
#
# You'll need to have the latest Azure PowerShell module installed as older versions don't have the parameters for AKV & ACC (update-module -force)
#

# TODO
# - look at the credential handling, it's not optimal

# handle command line parameters, mandatory, will force you to enter them
param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$basename,
    [Parameter(Mandatory)]
    [ValidateSet("Windows", "Windows11", "Windows2019", "Ubuntu", "RHEL")]
    $osType,
    [Parameter(Mandatory=$false)]$description = "",
    [Parameter(Mandatory=$false)][switch]$smoketest,
    [Parameter(Mandatory=$false)]$region = "northeurope",
    [Parameter(Mandatory=$false)]$vmsize = "Standard_DC2as_v5",
    [Parameter(Mandatory=$false)]$policyFilePath = "",
    [Parameter(Mandatory=$false)][switch]$DisableBastion,
    [Parameter(Mandatory=$false)][switch]$NoInternetAccess,
    [Parameter(Mandatory=$false)][switch]$SkipSkuPreflight
)

if ($subsID -eq "" -or $basename -eq "" -or $osType -eq "") {
    write-host "You must enter a subscription ID, basename, and OS type (Windows, Windows11, Ubuntu, or RHEL)"
    exit
}# exit if any of the parameters are empty

#---------Prerequisite Checks: PowerShell version and required Az modules-----------------------------------------------
function Test-PrerequisitesInstalled {
    param(
        [Parameter(Mandatory=$false)][switch]$StrictMode  # If true, fail on missing optional tools like Azure CLI
    )
    
    $missingPrereqs = @()
    
    # Check PowerShell version (need 7.0+)
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7) {
        $missingPrereqs += "PowerShell 7.0+ (currently running: $($psVersion.Major).$($psVersion.Minor).$($psVersion.Patch))"
    }
    
    # Check required Az modules
    $requiredModules = @("Az.Accounts", "Az.Compute", "Az.KeyVault", "Az.Network")
    foreach ($moduleName in $requiredModules) {
        $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue
        if (-not $module) {
            $missingPrereqs += "$moduleName (required)"
        }
    }
    
    # Check optional but recommended tools (just warnings, not errors)
    $optionalTools = @()
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCli) {
        $optionalTools += "Azure CLI 2.60+ (optional, used for enhanced queries and Bastion RDP tunneling)"
    }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        $optionalTools += "git (optional, used to auto-detect repository URL)"
    }
    
    # Display results
    write-host ""
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Prerequisite Check" -ForegroundColor Cyan
    write-host "----------------------------------------------------------------------------------------------------------------"
    
    # PowerShell version (OK)
    if ($psVersion.Major -ge 7) {
        write-host "✓ PowerShell $($psVersion.Major).$($psVersion.Minor).$($psVersion.Patch)" -ForegroundColor Green
    }
    
    # Required modules status
    foreach ($moduleName in $requiredModules) {
        $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue
        if ($module) {
            $version = $module.Version | Sort-Object -Descending | Select-Object -First 1
            write-host "✓ $moduleName (v$version)" -ForegroundColor Green
        }
    }
    
    # Optional tools (just info, don't block)
    if ($optionalTools.Count -gt 0) {
        write-host ""
        foreach ($tool in $optionalTools) {
            write-host "⚠ $tool" -ForegroundColor Yellow
        }
    }
    
    # Display errors and exit if critical prereqs missing
    if ($missingPrereqs.Count -gt 0) {
        write-host ""
        write-host "MISSING PREREQUISITES:" -ForegroundColor Red
        foreach ($prereq in $missingPrereqs) {
            write-host "✗ $prereq" -ForegroundColor Red
        }
        write-host ""
        write-host "Installation steps:" -ForegroundColor Yellow
        write-host "  PowerShell 7+: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Gray
        write-host "  Azure PowerShell: Update-Module -Name Az -Force" -ForegroundColor Gray
        write-host "  Azure CLI (optional): https://learn.microsoft.com/cli/azure/install-azure-cli" -ForegroundColor Gray
        write-host ""
        write-host "After installing, restart PowerShell and run this script again." -ForegroundColor Yellow
        write-host "----------------------------------------------------------------------------------------------------------------"
        exit 1
    }
    
    write-host "✓ All required prerequisites are installed" -ForegroundColor Green
    write-host "----------------------------------------------------------------------------------------------------------------"
}

# Run the prerequisite check
Test-PrerequisitesInstalled

# mark the start time of the script execution
$startTime = Get-Date
# get the name of the script so we can tag the resource group with it
$scriptName = $MyInvocation.MyCommand.Name

# Get GitHub repository URL from git remote - we use this to tag the resource group with the repo URL
$gitRemoteUrl = ""  
    $gitRemoteUrl = git remote get-url origin
    # Remove .git suffix if present
    $gitRemoteUrl = $gitRemoteUrl -replace "\.git$", ""
  
# If git remote didn't work, use fallback
if (-not $gitRemoteUrl) {
    $gitRemoteUrl = "[Originally from] https://github.com/Microsoft/confidential-computing"
}


# Set PowerShell variables to use in the script
$basename = $basename + -join ((97..122) | Get-Random -Count 5 | % {[char]$_}) # basename + 5 random lower-case letters
$vmusername = "azureuser" # you can adjust this if you want
$vmadminpassword = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40) # build a random password - note you can't get it back afterwards
$resgrp =  $basename # name of the resource group where all resources will be created, copied from $basename
$akvname = $basename + "akv"    #Name of the Azure Key Vault
$desname = $basename + "des"    #Name of the Disk Encryption Set
$keyname = $basename + "-cmk-key" #Name of the key in the Key Vault
$vmname = $basename # name of the VM, copied from $basename, or customise it here
$vnetname = $vmname + "vnet" # name of the VNET
$bastionname = $vnetname + "-bastion" # name of the bastion host
$vnetipname = $vnetname + "-pip"     #Name of the VNET IP
$natGatewayName = $vnetname + "-nat" # name of the NAT gateway used for outbound internet
$natPublicIpName = $vnetname + "-nat-pip" # name of the NAT gateway public IP
$nicPrefix = $basename + "-nic"    #Name of the NIC
$bastionsubnetName = "AzureBastionSubnet" # don't change this
$vmsubnetname = $basename + "vmsubnet" # don't change this
# region is now a command line parameter with default value of northeurope
$vmSize = $vmsize # Use the value from the command line parameter
$identityType = "SystemAssigned";
$secureEncryptGuestState = "DiskWithVMGuestState";
$vmSecurityType = "ConfidentialVM";
$KeySize = 3072
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey";

# Display region information
if ($region -eq "northeurope") {
    write-host "Using default region: $region (North Europe)" -ForegroundColor Cyan
    write-host "To use a different region, specify -region parameter. Ensure the region supports Confidential VMs." -ForegroundColor Cyan
} else {
    write-host "Using specified region: $region" -ForegroundColor Cyan
    write-host "Please ensure this region supports Confidential VMs and the selected VM SKU." -ForegroundColor Cyan
}

write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Building a Confidential Virtual Machine ($osType) in " $basename " in " $region
if ($smoketest) {
    write-host "SMOKETEST MODE: Resources will be automatically deleted after completion" -ForegroundColor Yellow
}
if ($DisableBastion) {
    write-host "BASTION DISABLED: VM will only be accessible via private network connectivity" -ForegroundColor Yellow
}
if ($NoInternetAccess) {
    write-host "INTERNET DISABLED: CVM subnet will not have outbound internet access" -ForegroundColor Yellow
} else {
    write-host "INTERNET ENABLED: CVM subnet will use NAT Gateway for outbound internet access" -ForegroundColor Cyan
}
write-host "IMPORTANT"
write-host "VM admin username is " $vmusername
write-host "randomly generated passsword for the VM is " $vmadminpassword " - save this now as you CANNOT retrieve it later"
write-host ""
write-host "Script: $scriptName"
write-host "Repository URL: $gitRemoteUrl"
write-host "----------------------------------------------------------------------------------------------------------------"

#Interactive login for PowerShell - uncomment if you want the script to prompt you
#If you are not logged in, or dont have the correct subscription selected you will need to do so 1st
#Connect-AzAccount -SubscriptionId $subsid -Tenant <ADD TENANT ID>

Set-AzContext -SubscriptionId $subsID
if (!$?) {
    write-host "Failed to connect to the Azure subscription " $subsID " extiting"
    exit
}

#Get username of logged-in Azure user so we can tag the resource group with it
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

#---------Pre-flight: SKU availability and quota check---------------------------------------------------------------
# Verify the chosen VM SKU is a Confidential VM SKU (AMD SEV-SNP or Intel TDX, NOT Intel SGX which is
# a different isolation model and not supported by this script), is offered in the chosen region and not
# restricted for this subscription, and that there's enough vCPU quota left in the SKU's family before
# we start creating resources.
# Note: Get-AzComputeResourceSku and Get-AzVMUsage have been observed to misreport NotAvailableForSubscription / 0 quota
# even when ARM accepts the deployment (e.g. Standard_DC*as_v6 in koreacentral). Use -SkipSkuPreflight to bypass.
if ($SkipSkuPreflight) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Pre-flight check SKIPPED (-SkipSkuPreflight). ARM will validate '$vmSize' in '$region' at deploy time." -ForegroundColor Yellow
    write-host "----------------------------------------------------------------------------------------------------------------"
}
else {
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Pre-flight check: confirming '$vmSize' is available in '$region' with sufficient quota..." -ForegroundColor Cyan

# Reject Intel SGX SKUs early - this script targets Confidential VMs (full-VM isolation),
# not SGX enclaves (per-process isolation). SGX SKUs use the DC*s_v3 / DC*s_v2 naming.
if ($vmSize -match '^Standard_DC\d+s_v[23]$') {
    write-host "ERROR: '$vmSize' is an Intel SGX SKU (application-enclave isolation), which is NOT supported by this script." -ForegroundColor Red
    write-host "This script provisions Confidential VMs (whole-VM hardware isolation) using either:" -ForegroundColor Yellow
    write-host "  - AMD SEV-SNP : DCa*/ECa*   (e.g. Standard_DC2as_v5, Standard_DC4as_v5)" -ForegroundColor Yellow
    write-host "  - Intel TDX   : DCe*/ECe*   (e.g. Standard_DC2es_v6, Standard_EC4es_v6)" -ForegroundColor Yellow
    write-host "For Intel SGX (DCsv3/DCsv2) workloads, see https://learn.microsoft.com/azure/confidential-computing/virtual-machine-solutions-sgx instead." -ForegroundColor Yellow
    exit 1
}

# Warn (but don't fail) if the SKU doesn't look like a known CVM SKU naming pattern.
if ($vmSize -notmatch '^Standard_(DC|EC)\d+[a-z]+_v\d+$' -or $vmSize -notmatch '_(DC|EC)\d+(a|e)') {
    write-host "Warning: '$vmSize' does not match a known Confidential VM SKU pattern (DCa*/ECa* for SEV-SNP, DCe*/ECe* for TDX). Continuing, but deployment may fail if this is not a CVM SKU." -ForegroundColor Yellow
}

$skuInfo = $null
try {
    $skuInfo = Get-AzComputeResourceSku -Location $region -ErrorAction Stop |
        Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -eq $vmSize } |
        Select-Object -First 1
} catch {
    write-host "Warning: could not query Get-AzComputeResourceSku for '$region': $($_.Exception.Message)" -ForegroundColor Yellow
}

function Show-QuotaHelp($sku, $region) {
    write-host ""
    write-host "To find regions where this SKU IS available to your subscription, try:" -ForegroundColor Yellow
    write-host "  Get-AzComputeResourceSku | Where-Object { `$_.ResourceType -eq 'virtualMachines' -and `$_.Name -eq '$sku' -and (-not `$_.Restrictions -or `$_.Restrictions.Count -eq 0) } | Select-Object Locations, Name" -ForegroundColor Gray
    write-host ""
    write-host "To list the Confidential VM SKUs offered in '$region' (SEV-SNP DCa*/ECa* and Intel TDX DCe*/ECe*):" -ForegroundColor Yellow
    write-host "  Get-AzComputeResourceSku -Location '$region' | Where-Object { `$_.ResourceType -eq 'virtualMachines' -and `$_.Name -match '_(DC|EC)\d+(a|e)' } | Select-Object Name, @{n='Restricted';e={`$_.Restrictions.Count -gt 0}}" -ForegroundColor Gray
    write-host ""
    write-host "To see your vCPU usage and limits in '$region':" -ForegroundColor Yellow
    write-host "  Get-AzVMUsage -Location '$region' | Where-Object { `$_.Name.Value -match 'DCa|DCe|ECa|ECe|cores' } | Format-Table -AutoSize" -ForegroundColor Gray
    write-host ""
    write-host "To request a quota increase, see: https://learn.microsoft.com/azure/quotas/quickstart-increase-quota-portal" -ForegroundColor Yellow
}

if ($null -eq $skuInfo) {
    write-host "ERROR: VM SKU '$vmSize' is not offered in region '$region'." -ForegroundColor Red
    Show-QuotaHelp $vmSize $region
    exit 1
}

# Check subscription-level restrictions (e.g. NotAvailableForSubscription)
$subRestriction = $skuInfo.Restrictions | Where-Object {
    $_.ReasonCode -eq 'NotAvailableForSubscription' -or
    ($_.RestrictionInfo -and $_.RestrictionInfo.Locations -contains $region) -or
    ($_.Values -contains $region)
}
if ($subRestriction) {
    $reason = ($skuInfo.Restrictions | ForEach-Object { $_.ReasonCode }) -join ', '
    write-host "ERROR: VM SKU '$vmSize' is restricted for this subscription in '$region' (reason: $reason)." -ForegroundColor Red
    Show-QuotaHelp $vmSize $region
    exit 1
}

# Determine vCPU count and family for the SKU
$skuVCpus = ($skuInfo.Capabilities | Where-Object { $_.Name -eq 'vCPUs' } | Select-Object -First 1).Value -as [int]
$skuFamily = $skuInfo.Family   # e.g. 'standardDCASv5Family'
if (-not $skuVCpus) { $skuVCpus = 2 }   # fall back to a sensible minimum

# Check vCPU quota for that family in this region
try {
    $usage = Get-AzVMUsage -Location $region -ErrorAction Stop |
        Where-Object { $_.Name.Value -eq $skuFamily } |
        Select-Object -First 1
    if ($usage) {
        $available = [int]$usage.Limit - [int]$usage.CurrentValue
        write-host ("Quota for {0} in {1}: {2}/{3} used, {4} vCPUs available, this SKU needs {5}." -f `
            $skuFamily, $region, $usage.CurrentValue, $usage.Limit, $available, $skuVCpus) -ForegroundColor Cyan
        if ($available -lt $skuVCpus) {
            write-host "ERROR: Insufficient vCPU quota in family '$skuFamily' in '$region' to deploy '$vmSize' ($skuVCpus vCPUs needed, $available available)." -ForegroundColor Red
            Show-QuotaHelp $vmSize $region
            exit 1
        }
    } else {
        write-host "Note: could not find VM usage entry for family '$skuFamily' in '$region' - proceeding without quota check." -ForegroundColor Yellow
    }
} catch {
    write-host "Warning: Get-AzVMUsage failed for '$region': $($_.Exception.Message). Proceeding without quota check." -ForegroundColor Yellow
}

write-host "Pre-flight check passed: '$vmSize' is available and within quota in '$region'." -ForegroundColor Green
write-host "----------------------------------------------------------------------------------------------------------------"
}

# Create Resource Group
$resourceGroupTags = @{
    owner = $ownername
    BuiltBy = $scriptName
    OSType = $osType
    GitRepo = $gitRemoteUrl
}

# Add description tag if provided
if ($description -ne "") {
    $resourceGroupTags.Add("description", $description)
}

# Add smoketest tag if running in smoketest mode
if ($smoketest) {
    $resourceGroupTags.Add("smoketest", "true")
}

# Add DisableBastion tag if running without Bastion
if ($DisableBastion) {
    $resourceGroupTags.Add("BastionDisabled", "true")
}

# Add NoInternetAccess tag if outbound internet is disabled
if ($NoInternetAccess) {
    $resourceGroupTags.Add("NoInternetAccess", "true")
}

New-AzResourceGroup -Name $resgrp -Location $region -Tag $resourceGroupTags -force

#create a credential object
$securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force # this could probably be done better inline rather than via a variable
$cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword);

# Create Key Vault
New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization -SoftDeleteRetentionInDays 10 -EnablePurgeProtection;

#TO DO - if the SP hasn't been created in this tenant yet - break here, or prompt to create it (code as follows)
#Connect-Graph -Tenant "your tenant ID" Application.ReadWrite.All
#New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 -DisplayName "Confidential VM Orchestrator"

$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0';
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $cvmAgent.id -PermissionsToKeys get,release;

# Add Key vault Key
if ($policyFilePath -ne "" -and (Test-Path $policyFilePath)) {
    Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -ReleasePolicyPath $policyFilePath;
} else {
    if ($policyFilePath -ne "" -and !(Test-Path $policyFilePath)) {
        Write-Host "Warning: Policy file path '$policyFilePath' does not exist. Using default CVM policy instead." -ForegroundColor Yellow
    }
    Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy;
}
        
# Capture Key Vault and Key details
$encryptionKeyVaultId = (Get-AzKeyVault -VaultName $akvname -ResourceGroupName $resgrp).ResourceId;
$encryptionKeyURL = (Get-AzKeyVaultKey -VaultName $akvname -KeyName $keyName).Key.Kid;

# Create new DES Config and Disk Encryption Set
$desConfig = New-AzDiskEncryptionSetConfig -Location $region -SourceVaultId $encryptionKeyVaultId -KeyUrl $encryptionKeyURL -IdentityType SystemAssigned -EncryptionType $diskEncryptionType;
New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName -DiskEncryptionSet $desConfig;
        
$diskencset = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName;
        
# Assign DES Access Policy to key vault
$desIdentity = (Get-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resgrp).Identity.PrincipalId;
        
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $desIdentity -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation;
        
$VirtualMachine = New-AzVMConfig -VMName $VMName -VMSize $vmSize;

# Configure OS based on the selected type
switch ($osType) {
    "Windows" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2022-datacenter-smalldisk-g2' -Version "latest";
        $VMIsLinux = $false
    }
    "Windows11" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'Windows-11' -Skus 'win11-23h2-ent' -Version "latest";
        $VMIsLinux = $false
    }
    "Windows2019" {
        # Windows Server 2019 Confidential VM image (G2)
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2019-datacenter-smalldisk-g2' -Version "latest";
        $VMIsLinux = $false
    }
    "Ubuntu" { # updated to use Ubuntu 24.04 LTS
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest";
        $VMIsLinux = $true
    }
    "RHEL" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'redhat' -Offer 'rhel-cvm' -Skus '9_5_cvm' -Version "latest";
        $VMIsLinux = $true
    }
}
        
$subnet = New-AzVirtualNetworkSubnetConfig -Name ($vmsubnetName) -AddressPrefix "10.0.0.0/24" -DefaultOutboundAccess $false;
$vnet = New-AzVirtualNetwork -Force -Name ($vnetname) -ResourceGroupName $resgrp -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $subnet;
$vnet = Get-AzVirtualNetwork -Name ($vnetname) -ResourceGroupName $resgrp;

# Configure outbound internet path for the VM subnet via NAT Gateway unless explicitly disabled.
if ($NoInternetAccess) {
    write-host "No NAT Gateway attached to VM subnet due to -NoInternetAccess. Outbound internet will be blocked." -ForegroundColor Yellow
}
else {
    write-host "Configuring NAT Gateway egress so the private CVM can access internet without a public IP..." -ForegroundColor Cyan
    $natPublicIp = New-AzPublicIpAddress -ResourceGroupName $resgrp -Name $natPublicIpName -Location $region -AllocationMethod Static -Sku Standard
    $natGateway = New-AzNatGateway -ResourceGroupName $resgrp -Name $natGatewayName -Location $region -IdleTimeoutInMinutes 10 -Sku Standard -PublicIpAddress $natPublicIp
    Set-AzVirtualNetworkSubnetConfig -Name ($vmsubnetName) -VirtualNetwork $vnet -AddressPrefix "10.0.0.0/24" -DefaultOutboundAccess $false -InputObject $natGateway | Set-AzVirtualNetwork | Out-Null
    $vnet = Get-AzVirtualNetwork -Name ($vnetname) -ResourceGroupName $resgrp
    write-host "NAT Gateway '$natGatewayName' attached to subnet '$vmsubnetname'." -ForegroundColor Green
}

$subnetId = $vnet.Subnets[0].Id;
#uncomment the below if you want to add a public IP address to the VM
#$pubip = New-AzPublicIpAddress -Force -Name ($pubIpPrefix + $resgrp) -ResourceGroupName $resgrp -Location $region -AllocationMethod Static -DomainNameLabel $domainNameLabel2;
#$pubip = Get-AzPublicIpAddress -Name ($pubIpPrefix + $resgrp) -ResourceGroupName $resgrp;
#$pubipId = $pubip.Id;

$nic = New-AzNetworkInterface -Force -Name ($nicPrefix) -ResourceGroupName $resgrp -Location $region -SubnetId $subnetId #-PublicIpAddressId $pubip.Id;
$nic = Get-AzNetworkInterface -Name ($nicPrefix) -ResourceGroupName $resgrp;
$nicId = $nic.Id;

$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nicId;

# Set VM SecurityType and connect to DES
if ($VMisLinux) {
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id -Linux;
} else {
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id;
}
$VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType;
$VirtualMachine = Set-AzVmUefi -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true;
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -disable #disable boot diagnostics, you can re-enable if required

New-AzVM -ResourceGroupName $resgrp -Location $region -Vm $VirtualMachine;
$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname;

# Create the Bastion to allow accessing the VM via the Azure portal (unless disabled)
if (-not $DisableBastion) {
    write-host "VM created, now enabling Bastion for the VM"
    $vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
    Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vnet -AddressPrefix "10.0.99.0/26" | Set-AzVirtualNetwork # you can make this subnet anything you like as long as it fits into the vnet address space
    $publicip = New-AzPublicIpAddress -ResourceGroupName $resgrp -name "VNet1-ip" -location $region -AllocationMethod Static -Sku Standard
    New-AzBastion -ResourceGroupName $resgrp -Name $bastionname -PublicIpAddressRgName $resgrp -PublicIpAddressName $publicIp.Name -VirtualNetworkRgName $resgrp -VirtualNetworkName $vnetname -Sku "Basic"
} else {
    write-host "VM created, Bastion creation skipped due to -DisableBastion parameter"
    write-host "VM is only accessible via private network connectivity (VPN, ExpressRoute, or peered networks)"
}

#---------Do attestation check inside the VM using Azure/cvm-attestation-tools-----------------------------------
# Downloads the latest pre-built attest CLI release from https://github.com/Azure/cvm-attestation-tools/releases
# and runs it inside the freshly deployed CVM, returning the output to the caller.

if ($NoInternetAccess) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Skipping in-VM attestation because -NoInternetAccess blocks outbound internet access required to download cvm-attestation-tools." -ForegroundColor Yellow
    write-host "Build complete (attestation skipped due to -NoInternetAccess)." -ForegroundColor Green
}
else {
    # Pick the right config based on the VM SKU's isolation type:
    #   AMD SEV-SNP: DCa*/DCad*/ECa*/ECad*  (e.g. Standard_DC2as_v5)  -> config_snp.json
    #   Intel TDX  : DCe*/DCed*/ECe*/ECed*  (e.g. Standard_DC2es_v5)  -> config_tdx.json
    if ($vmSize -match '_(DC|EC)\d+e[a-z]*_') {
        $attestConfig = "config_tdx.json"
        $isolationType = "Intel TDX"
    } else {
        $attestConfig = "config_snp.json"
        $isolationType = "AMD SEV-SNP"
    }

    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Running attestation inside the $osType VM using cvm-attestation-tools (isolation: $isolationType, config: $attestConfig)..." -ForegroundColor Cyan
    write-host "This downloads the latest release of attest from https://github.com/Azure/cvm-attestation-tools/releases inside the VM."

    if ($VMisLinux) {
    # Linux: download attest-lin.zip from the latest release, extract, run attest
    # Note: the zip extracts files at its root (no "attest-lin/" subfolder)
    $attestScript = @"
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
if ! command -v unzip >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    (apt-get update -y && apt-get install -y unzip jq) >/dev/null 2>&1 || \
        (dnf install -y unzip jq || yum install -y unzip jq) >/dev/null 2>&1
fi
WORKDIR=`$(mktemp -d)
cd "`$WORKDIR"
echo "Downloading latest attest-lin.zip from cvm-attestation-tools..."
curl -fsSL -o attest-lin.zip https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-lin.zip
unzip -q attest-lin.zip
chmod +x attest read_report 2>/dev/null || true
echo "--------- attest --c $attestConfig ---------"
./attest --c $attestConfig 2>&1 | tee attest.out || echo "attest exited with code `$?"

# Extract JWT (a single token of the form xxx.yyy.zzz with base64url chars)
# from the attest output and pretty-print header + payload claims using jq.
JWT=`$(grep -Eo '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' attest.out | awk '{ print length, `$0 }' | sort -nr | head -1 | cut -d' ' -f2-)
if [ -n "`$JWT" ] && command -v jq >/dev/null 2>&1; then
    echo ""
    echo "--------- Decoded JWT (via jq) ---------"
    b64d() { local s=`$1; local m=`$(( `${#s} % 4 )); if [ `$m -eq 2 ]; then s="`${s}=="; elif [ `$m -eq 3 ]; then s="`${s}="; fi; echo "`$s" | tr '_-' '/+' | base64 -d 2>/dev/null; }
    H=`$(echo "`$JWT" | cut -d. -f1)
    P=`$(echo "`$JWT" | cut -d. -f2)
    echo "--- header ---"
    b64d "`$H" | jq .
    echo "--- payload ---"
    b64d "`$P" | jq .
    echo "--- key MAA claims ---"
    b64d "`$P" | jq '{iss, "x-ms-attestation-type", "x-ms-compliance-status", "x-ms-isolation-tee": ."x-ms-isolation-tee"."x-ms-attestation-type", "x-ms-runtime-vm-configuration-secure-boot": ."x-ms-runtime"."vm-configuration"."secure-boot", "x-ms-runtime-vm-configuration-tpm-enabled": ."x-ms-runtime"."vm-configuration"."tpm-enabled"}'
else
    echo "(no JWT found in attest output to decode, or jq unavailable)"
fi

cd /
rm -rf "`$WORKDIR"
"@
        $runCommandId = 'RunShellScript'
    } else {
    # Windows: download attest-win.zip from the latest release, extract, run attest.exe
    # Note: the zip extracts files at its root (no "attest-win/" subfolder)
    $attestScript = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$work = Join-Path `$env:TEMP "cvm-attest-`$(Get-Random)"
New-Item -ItemType Directory -Path `$work -Force | Out-Null
Set-Location `$work
Write-Host "Downloading latest attest-win.zip from cvm-attestation-tools..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
`$downloadUrls = @('https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-win.zip')

# Try to discover the concrete asset URL as a fallback (often resolves to objects.githubusercontent.com)
try {
    `$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/Azure/cvm-attestation-tools/releases/latest' -Headers @{ 'User-Agent' = 'BuildRandomCVM' } -UseBasicParsing
    `$asset = `$release.assets | Where-Object { `$_.name -eq 'attest-win.zip' } | Select-Object -First 1
    if (`$asset -and `$asset.browser_download_url) {
        `$downloadUrls += `$asset.browser_download_url
    }
} catch {
    Write-Host "Warning: unable to query GitHub release API for fallback URL: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

`$downloaded = `$false
foreach (`$url in (`$downloadUrls | Select-Object -Unique)) {
    for (`$i = 1; `$i -le 3; `$i++) {
        try {
            Write-Host "Download attempt `$i/3: `$url"
            Invoke-WebRequest -Uri `$url -OutFile 'attest-win.zip' -UseBasicParsing -Headers @{ 'User-Agent' = 'BuildRandomCVM' }
            if ((Test-Path 'attest-win.zip') -and ((Get-Item 'attest-win.zip').Length -gt 0)) {
                `$downloaded = `$true
                break
            }
            throw "Downloaded file is missing or empty"
        } catch {
            Write-Host "Download failed on attempt `$i for `$url: `$(`$_.Exception.Message)" -ForegroundColor Yellow
            if (`$i -lt 3) { Start-Sleep -Seconds 10 }
        }
    }
    if (`$downloaded) { break }
}

if (-not `$downloaded) {
    throw "Failed to download attest-win.zip after retries. Ensure outbound internet to github.com and objects.githubusercontent.com is allowed from the CVM subnet."
}

Expand-Archive -Path 'attest-win.zip' -DestinationPath '.' -Force
Write-Host "--------- attest.exe --c $attestConfig ---------"

# attest.exe writes INFO logs to stderr; under `$ErrorActionPreference='Stop' that surfaces
# as a NativeCommandError even though the tool is working. Relax EAP for this single call,
# merge stderr into stdout, and rely on `$LASTEXITCODE for success/failure.
# Use a wide -Width on Out-String so the JWT (which can be ~1.5KB on a single line)
# is not wrapped at the default ~80-char console width - otherwise the regex below only
# matches a wrapped fragment and base64url decoding fails with "Invalid length".
`$prevEap = `$ErrorActionPreference
`$ErrorActionPreference = 'Continue'
if (`$PSVersionTable.PSVersion.Major -ge 7) { `$PSNativeCommandUseErrorActionPreference = `$false }
`$attestOut = (& .\attest.exe --c $attestConfig 2>&1 | Out-String -Width 16384)
`$attestExit = `$LASTEXITCODE
`$ErrorActionPreference = `$prevEap
Write-Host `$attestOut
if (`$attestExit -ne 0) { Write-Host "attest.exe exited with code `$attestExit" -ForegroundColor Yellow }

# Extract JWT (xxx.yyy.zzz, base64url) from the attest output and pretty-print
# header + payload claims using built-in PowerShell JSON support (no jq needed).
# Defensive: collapse the captured output to a single line so any stray CR/LF inside
# the token is removed, then anchor the regex to 'eyJ' (base64url of '{"') which is
# the canonical JWT header start. Without that anchor, the greedy 3-segment match
# can cross attest.exe's interleaved Python INFO log lines (which share '-' / '_'
# with base64url) and pick up a corrupted token, producing garbage on decode.
`$attestOutFlat = (`$attestOut -replace '\s+', '')
`$jwtMatch = [regex]::Matches(`$attestOutFlat, 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{50,}') | Sort-Object { `$_.Length } -Descending | Select-Object -First 1
if (`$jwtMatch) {
    function ConvertFrom-Base64Url(`$s) {
        `$s = (`$s -replace '\s', '').Replace('-', '+').Replace('_', '/')
        switch (`$s.Length % 4) { 2 { `$s += '==' } 3 { `$s += '=' } }
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$s))
    }
    `$parts = `$jwtMatch.Value.Split('.')
    Write-Host ""
    Write-Host '--------- Decoded JWT ---------'
    Write-Host '--- header ---'
    ConvertFrom-Base64Url `$parts[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
    Write-Host '--- payload ---'
    `$payload = ConvertFrom-Base64Url `$parts[1] | ConvertFrom-Json
    `$payload | ConvertTo-Json -Depth 10
    Write-Host '--- key MAA claims ---'
    [pscustomobject]@{
        iss                            = `$payload.iss
        'x-ms-attestation-type'        = `$payload.'x-ms-attestation-type'
        'x-ms-compliance-status'       = `$payload.'x-ms-compliance-status'
        'x-ms-isolation-tee'           = `$payload.'x-ms-isolation-tee'.'x-ms-attestation-type'
        'secure-boot'                  = `$payload.'x-ms-runtime'.'vm-configuration'.'secure-boot'
        'tpm-enabled'                  = `$payload.'x-ms-runtime'.'vm-configuration'.'tpm-enabled'
    } | Format-List
} else {
    Write-Host '(no JWT found in attest output to decode)'
}

Set-Location `$env:TEMP
Remove-Item -Recurse -Force `$work -ErrorAction SilentlyContinue
"@
        $runCommandId = 'RunPowerShellScript'
    }

    # Retry loop: Invoke-AzVMRunCommand can return 409 Conflict for several minutes
    # after VM creation while the run-command extension is still finalising. This is
    # especially common on TDX SKUs. Back off and retry on Conflict / "in progress".
    $output = $null
    $maxAttempts = 10
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            write-host "Attestation run-command attempt $attempt of $maxAttempts..." -ForegroundColor Cyan
            $output = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId $runCommandId -ScriptString $attestScript -ErrorAction Stop
            break
        } catch {
            $msg = $_.Exception.Message
            if ($attempt -lt $maxAttempts -and ($msg -like '*Conflict*' -or $msg -like '*in progress*' -or $msg -like '*409*')) {
                write-host "Run-command extension busy (409); waiting 60s before retry..." -ForegroundColor Yellow
                Start-Sleep -Seconds 60
            } else {
                throw
            }
        }
    }

    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "--------------Output from cvm-attestation-tools running inside the VM--------------"
    $attestationText = ""
    foreach ($entry in $output.Value) {
        if ($entry.Message) {
            write-host $entry.Message
            $attestationText += $entry.Message
        }
    }

    # Fail loudly if the in-VM script output clearly contains download/attestation errors.
    if ($attestationText -match 'Unable to connect to the remote server|Invoke-WebRequest\s*:|Failed to download attest-win\.zip|attest\.exe exited with code\s+[1-9]') {
        write-host "Attestation failed inside the VM. See output above for details." -ForegroundColor Red
        throw "In-VM attestation failed"
    }
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Build and attestation complete." -ForegroundColor Green
}


# Smoketest cleanup - automatically remove all resources if smoketest flag is used
if ($smoketest) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "SMOKETEST MODE: Automatically removing all created resources..."
    write-host "Removing resource group: $resgrp"
    if (-not $DisableBastion) {
        write-host "This will delete all resources including VM, Key Vault, Bastion, VNet, etc."
    } else {
        write-host "This will delete all resources including VM, Key Vault, VNet, etc."
    }
    write-host "WARNING: RESOURCES ARE NOT RECOVERABLE."  -ForegroundColor Red
    write-host "Press ANY KEY to cancel deletion, or wait 10 seconds to proceed..."  -ForegroundColor Yellow
    write-host "----------------------------------------------------------------------------------------------------------------"
    
    # Wait for 10 seconds or until a key is pressed
    $timeout = 10
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = $false
    
    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            [Console]::ReadKey($true) | Out-Null
            $cancelled = $true
            break
        }
        Start-Sleep -Milliseconds 100
        $remaining = [math]::Ceiling($timeout - $timer.Elapsed.TotalSeconds)
        Write-Host "`rDeletion in $remaining seconds... (Press any key to cancel)" -NoNewline -ForegroundColor Yellow
    }
    $timer.Stop()
    
    if ($cancelled) {
        write-host "`nDeletion cancelled by user. Resources remain in resource group: $resgrp" -ForegroundColor Green
        write-host "To clean up manually later, run: Remove-AzResourceGroup -Name $resgrp -Force"
    } else {
        write-host "`nProceeding with resource deletion..."
        try {
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob
            write-host "Resource group deletion initiated successfully (running in background)"
            write-host "All resources in resource group '$resgrp' are being removed"
        } catch {
            write-host "Error removing resource group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    write-host ""
    write-host "Resources created in resource group: $resgrp"
    write-host "To clean up manually, run: Remove-AzResourceGroup -Name $resgrp -Force"
}

# determine the execution time of the script
$myTimeSpan = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Output ("Execution time was {0} minutes and {1} seconds." -f $myTimeSpan.Minutes, $myTimeSpan.Seconds)
