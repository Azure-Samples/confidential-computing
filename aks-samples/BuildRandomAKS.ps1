# Script to build a random AKS cluster with a random name and enable CMK
# Currently a mix of AZ CLI and PowerShell, will be converted to all PowerShell in future but this is a good starting point
# based on https://learn.microsoft.com/en-us/azure/aks/azure-disk-customer-managed-keys
#  
# Tested on Windows (7.4.6)
# 
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# based on https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-azure-cli
# 
# Usage: ./BuildRandomAKS.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME>
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
#
# You'll need to have the latest Azure PowerShell module installed as older versions don't have the parameters for AKV & ACC (update-module -force)
#
# Ensure you are logged into your subscription with BOTH the AZ CLI and PowerShell (az login and connect-azaccount) before running script

# handle command line parameters, mandatory, will force you to enter them
param ([Parameter(Mandatory)]$subsID,[Parameter(Mandatory)]$basename)

if ($subsID -eq "" -or $basename -eq "") {
    write-host "You must enter a subscription ID and a basename"
    exit
}# exit if either of the parameters are empty

# Set PowerShell variables to use in the script
$basename = $basename + -join ((97..122) | Get-Random -Count 5 | % {[char]$_}) # basename + 5 random lower-case letters
$resgrp =  $basename # name of the resource group where all resources will be created, copied from $basename
$akvname = $basename + "akv"    #Name of the Azure Key Vault
$desname = $basename + "des"    #Name of the Disk Encryption Set
$keyname = $basename + "-cmk-key" #Name of the key in the Key Vault
$region = "northeurope" #Makesure the region is supported for ACC
$KeySize = 3072
#AKS specific
$aksclustername=$basename + "-aks"
$acrname=$basename + "acr"
$accnodepoolname="accpool" #needs to be short

az account set --subscription $subsid
if (!$?) {
    write-host "Failed to connect to the Azure subscription " $subsid " extiting"
    exit
}

if ($basename -like "*-*") {
    write-host "The basename cannot contain a hyphen (Azure Container Registry does not allow hyphens in the name)"
    exit
}

#Get username of logged-in Azure user so we can tag the resource group with it, there is a simpler way to do this
$tmp = Get-AzContext
$ownername = $tmp.Account.Id
$UPN = get-AzADUser -SignedIn

Set-AzContext -SubscriptionId $subsid

#Get username of logged-in Azure user so we can tag the resource group with it
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

write-host "Generating an AKS cluster with CMK enabled in : " $region " in subscription " $subsID " in resource group " $resgrp

# Create Resource Group
New-AzResourceGroup -Name $resgrp -Location $region -Tag @{owner=$ownername} -force

$keyvault=New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization -SoftDeleteRetentionInDays 10 -EnablePurgeProtection;
#wait for propagation just to be sure
start-sleep -seconds 45

#this step is missing from https://learn.microsoft.com/en-us/azure/aks/azure-disk-customer-managed-keys (or unclear as it's in previous step) translated to POSH
Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM

# Retrieve the Key Vault Id and store it in a variable
$keyVaultId=$(az keyvault show --name $akvname --query "[id]" -o tsv)

# Retrieve the Key Vault key URL and store it in a variable, there is a simpler way to do this
$tempkeyforurl = Get-AzKeyVaultKey -VaultName $akvname -name $keyName
$keyVaultKeyUrl=$tempkeyforurl.ID

# Create a DiskEncryptionSet
az disk-encryption-set create --name $desName --location $region --resource-group $resgrp --source-vault $keyVaultId --key-url $keyVaultKeyUrl

# Retrieve the DiskEncryptionSet value and set a variable
$desIdentity=$(az disk-encryption-set show --name $desName --resource-group $resgrp --query "[identity.principalId]" -o tsv)

# Update security policy settings to allow key release for CMK
az keyvault set-policy --name $akvname --resource-group $resgrp --object-id $desIdentity --key-permissions wrapkey unwrapkey get
$diskEncryptionSetId=$(az disk-encryption-set show --name $desName --resource-group $resgrp --query "[id]" -o tsv)

#ok, so all pre-reqs done, now create the AKS cluster
az aks create --name $aksclustername --resource-group $resgrp --node-osdisk-diskencryptionset-id $diskEncryptionSetId --generate-ssh-keys --node-osdisk-type Managed #--node-vm-size Standard_DC4as_v5 #seems to take a long time - working on ti

#now, add confidential nodes to the cluster
az aks nodepool add --cluster-name $aksclustername --resource-group $resgrp --name $accnodepoolname --node-osdisk-type Managed --node-vm-size Standard_DC4as_v5

#Create an Azure Container Registry (ACR) to store the container images
az acr create --resource-group $resgrp --name $acrname --sku Basic

#Attach the ACR to the AKS cluser
az aks update --name $aksclustername --resource-group $resgrp --attach-acr $acrname

#Set auto upgrade policy
az aks update --resource-group $resgrp --name $aksclustername --auto-upgrade-channel stable