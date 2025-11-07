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
# Usage: ./BuildRandomCVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> -osType <Windows|Windows11|Windows2019|Ubuntu|RHEL> [-description <OPTIONAL DESCRIPTION>] [-smoketest] [-region <AZURE REGION>] [-policyFilePath <PATH TO POLICY FILE>]
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
# osType specifies which OS to deploy: Windows (Server 2022), Windows11 (Windows 11 Enterprise), Ubuntu (24.04), or RHEL (9.5)
# description is an optional parameter that will be added as a tag to the resource group
# smoketest is an optional switch that automatically removes all resources after completion (useful for testing)
# region is an optional parameter that specifies the Azure region (defaults to northeurope)
# policyFilePath is an optional parameter that specifies the path to a custom policy file for key vault key creation
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
    [Parameter(Mandatory=$false)]$policyFilePath = ""
)

if ($subsID -eq "" -or $basename -eq "" -or $osType -eq "") {
    write-host "You must enter a subscription ID, basename, and OS type (Windows, Windows11, Ubuntu, or RHEL)"
    exit
}# exit if any of the parameters are empty

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
        
$subnet = New-AzVirtualNetworkSubnetConfig -Name ($vmsubnetName) -AddressPrefix "10.0.0.0/24";
$vnet = New-AzVirtualNetwork -Force -Name ($vnetname) -ResourceGroupName $resgrp -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $subnet;
$vnet = Get-AzVirtualNetwork -Name ($vnetname) -ResourceGroupName $resgrp;
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

# Create the Bastion to allow accesing the VM via the Azure portal
write-host "VM created, now enabling Bastion for the VM"
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vnet -AddressPrefix "10.0.99.0/26" | Set-AzVirtualNetwork # you can make this subnet anything you like as long as it fits into the vnet address space
$publicip = New-AzPublicIpAddress -ResourceGroupName $resgrp -name "VNet1-ip" -location $region -AllocationMethod Static -Sku Standard
New-AzBastion -ResourceGroupName $resgrp -Name $bastionname -PublicIpAddressRgName $resgrp -PublicIpAddressName $publicIp.Name -VirtualNetworkRgName $resgrp -VirtualNetworkName $vnetname -Sku "Basic"

# COMMENTED OUT FOR NOW, will be re-factored to use latest attestation code from https://github.com/Azure/cvm-attestation-tools 
#---------Do attestation check, kick off a script inside the VM to do the attestation check---------
# Run attestation based on OS type
<#
write-host "Running an attestation check inside the $osType VM, please wait for output..."

if ($osType -like 'Windows*' -and $osType -ne 'Windows11') {
    # Windows family (Server and other Windows SKUs except Windows11) - use PowerShell script
    $output = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId 'RunPowerShellScript' -ScriptPath .\WindowsAttest.ps1
} elseif ($osType -eq "Windows11") {
    # Windows 11 VM - use PowerShell script
    $output = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId 'RunPowerShellScript' -ScriptPath .\WindowsAttest.ps1
} else {
    # Linux VMs (Ubuntu/RHEL) - use shell script
    $attestScript = @"
#!/bin/bash
echo "Linux $osType CVM attestation check"
echo "Checking if running in a Confidential VM..."
if [ -d "/sys/kernel/security/tpm0" ]; then
    echo "TPM device detected"
else
    echo "No TPM device found"
fi
echo "For full attestation on Linux, additional tools and configuration may be required"
echo "This is a basic check - implement proper attestation logic for production use"
"@
    $output = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId 'RunShellScript' -ScriptString $attestScript
}
write-host "--------------Output from the script that ran inside the VM--------------"
write-host $output.Value.message # repeat the output from the script that ran inside the VM
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Build and validation complete, check the output above for the attestation status."
#>


# Smoketest cleanup - automatically remove all resources if smoketest flag is used
if ($smoketest) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "SMOKETEST MODE: Automatically removing all created resources..."
    write-host "Removing resource group: $resgrp"
    write-host "This will delete all resources including VM, Key Vault, Bastion, VNet, etc."
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
