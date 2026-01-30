# Azure Attestation Samples

## Overview
This folder contains scripts and samples for working with Microsoft Azure Attestation (MAA), which provides remote attestation for Confidential Computing workloads.

## Files
- `createPrivateMAA.ps1` - PowerShell script to create a private Azure Attestation provider

## createPrivateMAA.ps1

### Description
Creates a private Microsoft Azure Attestation (MAA) provider in your Azure subscription. The script handles:
- Setting the correct Azure subscription context
- Creating the resource group if it doesn't exist
- Checking for existing attestation providers to avoid conflicts
- Creating the new attestation provider with proper error handling

### Prerequisites
- Azure PowerShell module installed (`Install-Module -Name Az`)
- Authentication to Azure (`Connect-AzAccount`)
- Appropriate permissions to create resource groups and attestation providers
- Valid Azure subscription with access to Azure Attestation service

### Usage
```powershell
.\createPrivateMAA.ps1 -Location <AZURE_REGION> -AttestationResourceGroup <RESOURCE_GROUP_NAME> -AttestationProviderName <PROVIDER_NAME> -SubscriptionId <SUBSCRIPTION_ID>