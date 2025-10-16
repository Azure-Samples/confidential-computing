# Azure Container Instances (ACI) Confidential Computing Sample

## Overview
This folder contains scripts for creating Confidential Azure Container Instances (ACIs) using Azure's confidential computing SKUs.

## Files
- `BuildRandomACI.ps1` - PowerShell script to create a confidential ACI with a hello-world container

## BuildRandomACI.ps1

### Description
Creates a confidential Azure Container Instance with:
- Confidential SKU (`confidential`)
- Hello-world container (`mcr.microsoft.com/azuredocs/aci-helloworld`)
- Public IP and DNS name
- Linux OS type
- Port 80 exposed (TCP)

### Prerequisites
- Azure PowerShell module installed (`Install-Module -Name Az`)
- Authentication to Azure (`Connect-AzAccount`)
- Subscription with access to confidential container instances
- Region that supports confidential ACIs (script defaults to `northeurope`)

### Usage
```powershell
.\BuildRandomACI.ps1 -subsID <YOUR_SUBSCRIPTION_ID> -basename <YOUR_BASENAME>
```
