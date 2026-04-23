# CVM Backup – Windows Confidential VM with Azure Backup

**Last Updated:** April 2025

## Overview

This example deploys a **Windows Server 2022 Confidential Virtual Machine (CVM)** protected by:

- **AMD SEV-SNP** hardware-based memory encryption
- **Customer Managed Keys (CMK)** via Azure Key Vault Premium and a Disk Encryption Set
- **Confidential Disk Encryption** (`DiskWithVMGuestState`) covering both the OS disk and VM guest state
- **Azure Backup** (Recovery Services Vault) with a configurable daily retention policy

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                  CVM Backup – Architecture Overview                           │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                  Confidential VM (Windows Server 2022)               │   │
│  │               AMD SEV-SNP  |  vTPM  |  Secure Boot                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│           │  encrypted disk snapshot                 │ CMK                  │
│           ▼                                          ▼                       │
│  ┌──────────────────────┐               ┌───────────────────────────────┐   │
│  │  Recovery Services   │               │  Azure Key Vault (Premium)    │   │
│  │  Vault               │               │  CMK  |  DES  |  Release      │   │
│  │  Daily backup policy │               │  Policy (SEV-SNP validated)   │   │
│  └──────────────────────┘               └───────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Private VNet  |  Azure Bastion (optional)  |  No public IP on VM   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell) (Az module, latest version)
- An Azure subscription with quota for **DCasv5-series** Confidential VMs
- The **Confidential VM Orchestrator** service principal must exist in your tenant:

  ```powershell
  # Run once per tenant if the service principal does not exist yet
  Connect-MgGraph -Tenant "<YOUR_TENANT_ID>" -Scopes Application.ReadWrite.All
  New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 `
      -DisplayName "Confidential VM Orchestrator"
  ```

## Script: `Deploy-CVMWithBackup.ps1`

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `subsID` | ✅ | — | Azure subscription ID |
| `basename` | ✅ | — | Prefix for all resource names (a 5-char suffix is appended) |
| `description` | ❌ | `""` | Optional tag added to the resource group |
| `region` | ❌ | `northeurope` | Azure region (must support Confidential VMs) |
| `vmsize` | ❌ | `Standard_DC2as_v5` | VM SKU |
| `backupRetentionDays` | ❌ | `30` | Daily backup retention in days |
| `smoketest` | ❌ | `$false` | Auto-delete all resources after deployment |
| `DisableBastion` | ❌ | `$false` | Skip Azure Bastion creation |

## Usage

```powershell
# Deploy a CVM with Azure Backup (30-day daily retention, Bastion enabled)
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "mybackupcvm"

# Specify a custom region and retention period
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "mybackupcvm" `
    -region "eastus" -backupRetentionDays 90

# Smoketest – deploy and auto-remove resources after 10 seconds
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "test" -smoketest

# Deploy without Bastion (VM only accessible via private network)
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "mybackupcvm" -DisableBastion
```

## What the Script Creates

| Resource | Notes |
|----------|-------|
| Resource Group | Tagged with owner, script name, and repository URL |
| Azure Key Vault (Premium) | Hosts the CMK; purge protection enabled (10-day retention) |
| Key Vault Key (RSA 3072) | Exportable HSM-backed key with default CVM release policy |
| Disk Encryption Set | Links the CMK to the CVM OS disk for confidential encryption |
| Virtual Network + Subnet | Private VNet (10.0.0.0/16), no public IP on the VM |
| Network Interface | Connected to the VM subnet |
| Windows Server 2022 CVM | `Standard_DC2as_v5` by default; Secure Boot + vTPM enabled |
| Azure Bastion (optional) | Allows RDP access via the Azure portal without a public IP |
| Recovery Services Vault | Azure Backup vault in the same region and resource group |
| Backup Protection Policy | Daily schedule at 02:00 UTC with configurable retention |

## Important Notes

- The script generates a **random VM admin password** that is printed once to the terminal. Copy it before the script finishes.
- Azure Key Vault **Premium** SKU is required for Confidential VM disk encryption.
- Azure Backup of CVMs creates encrypted snapshots; the CMK in Key Vault must remain accessible for restores.
- Check [Azure region availability](https://azure.microsoft.com/en-gb/explore/global-infrastructure/products-by-region/) to confirm CVM support before deploying.

## Clean-up

```powershell
Remove-AzResourceGroup -Name <RESOURCE_GROUP_NAME> -Force
```

> **Note:** The Key Vault has purge protection enabled with a 10-day soft-delete retention.  
> If you need to reuse the same vault name, wait for the retention period or purge it manually.
