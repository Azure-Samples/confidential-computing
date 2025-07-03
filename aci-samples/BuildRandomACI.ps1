# Hands-off script to build a simple Confidential Azure Container Instance
# April 2025 
# Tested on MacOS (PWSH 7.5) & Windows (7.4.6)
# 
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# Based on https://learn.microsoft.com/en-us/azure/container-instances/container-instances-quickstart-powershell
#
# Clone this repo to a folder
#
# Usage: ./BuildRandomACI.CVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME>
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
#
# You'll need to have the latest Azure PowerShell module installed as older versions don't have the parameters for AKV & ACC (update-module -force)
#
# TODO 
# 1) add confcom policy handling to block exec to container (default is allow)
# 2) more interesting container image
# 4) attestation
# 4) add CMK

# handle command line parameters, mandatory, will force you to enter them
param ([Parameter(Mandatory)]$subsID,[Parameter(Mandatory)]$basename)

if ($subsID -eq "" -or $basename -eq "") {
    write-host "You must enter a subscription ID and a basename"
    exit
}# exit if either of the parameters are empty

# Set PowerShell variables to use in the script
$basename = $basename + -join ((97..122) | Get-Random -Count 5 | % {[char]$_}) # basename + 5 random lower-case letters
$containerName = $basename + "aci" #Name of the Azure Container Instance
$containerGroupName = $basename + "group" #Name of the Azure Container Instance
$resgrp =  $basename # name of the resource group where all resources will be created, copied from $basename
$region = "northeurope" #Makesure the region is supported for ACC
$sku = "confidential" # SKU for the container, change this if you want a different SKU

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

$port = New-AzContainerInstancePortObject -Port 80 -Protocol TCP
# updated to use the latest helloworld image which displays attestation output
$container = New-AzContainerInstanceObject -Name $containerName -Image "mcr.microsoft.com/acc/samples/aci/helloworld:2.8"



$containerGroup = New-AzContainerGroup -ResourceGroupName $resgrp -Name $containerGroupName -Location $region -Container @($container) -OsType Linux -IpAddressDnsNameLabel ($basename + "dns") -IpAddressType Public -Sku confidential
Get-AzContainerGroup -ResourceGroupName $resgrp -Name $containerGroupName
$containerGroup | Format-Table InstanceViewState, IPAddressFqdn, IPAddressIP

#optional - clean up resources afterwards
#Remove-AzContainerGroup -ResourceGroupName $resgrp -Name $containerGroupName
#Get-azresourceGroup -name $resgrp | Remove-AzResourceGroup  