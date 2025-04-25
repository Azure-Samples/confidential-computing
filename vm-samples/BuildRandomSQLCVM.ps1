# Hands-off script to build a windows CVM and then make it do attestation by automating an attestation process /inside/ the VM
# VM will be created in a private vnet with no public IP and can only be accessed over the Internet via the Azure Bastion service
# April 2025 - ported to all native PowerShell code and re-implemented Azure Bastion code and added command line parameters rather than editing file
# Tested on MacOS (PWSH 7.5) & Windows (7.4.6)
# 
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# based on https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-azure-cli
# and
# https://learn.microsoft.com/en-gb/azure/azure-sql/virtual-machines/windows/sql-vm-create-confidential-vm-how-to?view=azuresql
# 
# Clone this repo to a folder (relies on the WindowsAttest.ps1 script being in the same folder as this script)
#
# Usage: ./BuildRandomSQLCVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME>
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
#
# You'll need to have the latest Azure PowerShell module installed as older versions don't have the parameters for AKV & ACC (update-module -force)
#

# TODO
# - look at the credential handling, it's not optimal

# handle command line parameters, mandatory, will force you to enter them
param ([Parameter(Mandatory)]$subsID,[Parameter(Mandatory)]$basename)

if ($subsID -eq "" -or $basename -eq "") {
    write-host "You must enter a subscription ID and a basename"
    exit
}# exit if either of the parameters are empty


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
$region = "northeurope" #Makesure the region is supported for ACC
$vmSize = "Standard_DC2as_v5"; #Note AMD SEV-SNP based SKUs are DCa and ECa series VMs (Big 'C' for Confidential, small 'a' for AMD)
$identityType = "SystemAssigned";
$secureEncryptGuestState = "DiskWithVMGuestState";
$vmSecurityType = "ConfidentialVM";
$KeySize = 3072
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey";
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Building a Confidential Virtual Machine in " $basename " in " $region
write-host "IMPORTANT"
write-host "VM admin username is " $vmusername
write-host "randomly generated passsword for the VM is " $vmadminpassword " - save this now as you CANNOT retrieve it later"
write-host "----------------------------------------------------------------------------------------------------------------"

#Interactive login for PowerShell - uncomment if you want the script to prompt you
#If you are not logged in, or dont have the correct subscription selected you will need to do so 1st
#Connect-AzAccount -SubscriptionId $subsid -Tenant <ADD TENANT ID>

Set-AzContext -SubscriptionId $subsid
if (!$?) {
    write-host "Failed to connect to the Azure subscription " $subsid " extiting"
    exit
}

#Get username of logged-in Azure user so we can tag the resource group with it
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

# Create Resource Group

New-AzResourceGroup -Name $resgrp -Location $region -Tag @{owner=$ownername} -force

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
Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy;
        
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
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
#original line was
#$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2022-datacenter-smalldisk-g2' -Version "latest";
#modified to use the latest SQL Server 2022 image
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftSQLServer' -Offer 'SQL2022-WS2022' -Skus 'standard-gen2' -Version "latest";        


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
$VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id;
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

write-host "Bastion host created, now restarting the VM"
#optional - uncomment the following if you want to automatically remove the VM after the attestation check
#get-azresourceGroup -name $resgrp | Remove-AzResourceGroup   

