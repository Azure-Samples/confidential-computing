# This script creates a Disk Encryption Set (DES) and a Key Vault Key for use with Confidential VMs in Azure.
# if you want to use the ARM template to deploy the CVM, you need to create a DES and Key Vault Key first and get the resource ID for the DES for the ARM parameters file

$akvname = "<NAME OF YOUR KEY VAULT>"
$resgrp = "<NAME OF THE RESOURCE GROUP WHERE YOU WANT TO CREATE THE DES AND KEY VAULT KEY>"
$region = "<YOUR REGION>" # note CVM and keyvault must be in the same region due
$keyname = "<NAME OF YOUR ENCRYPTION KEY>"
$keysize = 2048
$desName = "<NAME OF YOUR DES>" # this is the name of the Disk Encryption Set
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey" # this is the type of encryption you want to use for the DES for a CVM with confidential disk encryption

#TO DO - if the SP hasn't been created in this tenant yet - break here, or prompt to create it (code as follows)
#Connect-Graph -Tenant "your tenant ID" Application.ReadWrite.All
#New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 -DisplayName "Confidential VM Orchestrator"

$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0';
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $cvmAgent.id -PermissionsToKeys get,release;

# Add Key vault Key, needs to be KeyType RSA and Destination HSM for a CVM
# Note: The key name must be unique in the Key Vault, so if you run this script multiple times, you may need to change the key name.
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
