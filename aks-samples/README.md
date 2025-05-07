# Script to build a random AKS cluster with a random name and enable CMK

Currently a mix of AZ CLI and PowerShell, will be converted to all PowerShell in future but this is a good starting point
based on https://learn.microsoft.com/en-us/azure/aks/azure-disk-customer-managed-keys

Tested on Windows (7.4.6)

Usage: ./BuildRandomAKS.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME>

Basename is a prefix for all resources created, it's used to create unique names for the resources

You'll need to have the latest Azure PowerShell module installed as older versions don't have the parameters for AKV & ACC (update-module -force)

Ensure you are logged into your subscription with BOTH the AZ CLI and PowerShell (az login and connect-azaccount) before running script
