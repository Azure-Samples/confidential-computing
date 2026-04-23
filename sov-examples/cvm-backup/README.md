# CVM Backup – Windows Confidential VM with Azure Backup (4-hourly, Korea Central)

**Last Updated:** April 2025

## Overview

This example deploys a **Windows Server 2022 Confidential Virtual Machine (CVM)** in **Korea Central** inside a single resource group, protected by:

- **AMD SEV-SNP** hardware-based memory encryption
- **Customer Managed Keys (CMK)** via Azure Key Vault Premium and a Disk Encryption Set
- **Confidential Disk Encryption** (`DiskWithVMGuestState`) covering both the OS disk and VM guest state
- **Private VNet with no public IP address** – the VM is only reachable via private connectivity
- **Azure Backup (Enhanced policy)** – every 4 hours with configurable daily retention, and an initial on-demand backup triggered immediately after deployment

```
┌──────────────────────────────────────────────────────────────────────────────┐
│         CVM Backup – Architecture (Korea Central)                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │          Confidential VM (Windows Server 2022)                       │   │
│  │          AMD SEV-SNP  |  vTPM  |  Secure Boot  |  No public IP      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│           │  encrypted disk snapshot                 │ CMK                  │
│           ▼                                          ▼                       │
│  ┌──────────────────────┐               ┌───────────────────────────────┐   │
│  │  Recovery Services   │               │  Azure Key Vault (Premium)    │   │
│  │  Vault               │               │  CMK  |  DES  |  Release      │   │
│  │  Enhanced policy:    │               │  Policy (SEV-SNP validated)   │   │
│  │  every 4 hours       │               └───────────────────────────────┘   │
│  │  + initial backup    │                                                    │
│  └──────────────────────┘                                                    │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Private VNet (10.0.0.0/16)  |  No Bastion  |  No public IP         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell) (Az module, latest version)
- An Azure subscription with quota for **DCasv6-series** (or ECasv6/ECadsv6) Confidential VMs in Korea Central
- The **Confidential VM Orchestrator** service principal must exist in your tenant (run once per tenant):

  ```powershell
  Connect-MgGraph -Tenant "<YOUR_TENANT_ID>" -Scopes Application.ReadWrite.All
  New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 `
      -DisplayName "Confidential VM Orchestrator"
  ```

## Script: `Deploy-CVMWithBackup.ps1`

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `subsID` | ✅ | — | Azure subscription ID |
| `basename` | ✅ | — | Prefix for resource names (≤ 12 chars); a **5-character numeric string** is appended (e.g. `myvm03729` — leading zeros are possible) |
| `description` | ❌ | `""` | Optional tag added to the resource group |
| `region` | ❌ | `koreacentral` | Azure region (must support DCasv6 / ECasv6 / ECadsv6 Confidential VMs) |
| `vmsize` | ❌ | `Standard_DC2as_v6` | VM SKU — **only v6 CVM SKUs are accepted** (DCasv6, ECasv6, ECadsv6 families) |
| `backupRetentionDays` | ❌ | `30` | Daily backup retention in days |
| `smoketest` | ❌ | `$false` | Auto-delete all resources after the initial backup completes |

## Usage

```powershell
# Deploy a CVM with 4-hourly Azure Backup in Korea Central (defaults)
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "mybackupcvm"

# Specify a different region and retention period
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "mybackupcvm" `
    -region "eastasia" -backupRetentionDays 90

# Smoketest – deploy, run initial backup, then auto-remove resources
./Deploy-CVMWithBackup.ps1 -subsID "your-subscription-id" -basename "test" -smoketest
```

## What the Script Creates

| # | Resource | Notes |
|---|----------|-------|
| 1 | Resource Group | All resources in one group; tagged with owner, script name, and repo URL |
| 2 | Azure Key Vault (Premium) | Hosts the CMK; purge protection enabled (10-day soft-delete retention) |
| 3 | Key Vault Key (RSA 3072) | Exportable HSM-backed key with default CVM SEV-SNP release policy |
| 4 | Disk Encryption Set | Links the CMK to confidential OS disk encryption (`DiskWithVMGuestState`) |
| 5 | Private VNet + Subnet | 10.0.0.0/16 — no public IP on the VM, no Bastion |
| 6 | Network Interface | Attached to VM subnet, no public IP |
| 7 | Windows Server 2022 CVM | AMD SEV-SNP, Secure Boot + vTPM, CMK-encrypted OS disk — **v6 SKU only** (DCasv6/ECasv6/ECadsv6) |
| 8 | Recovery Services Vault | Azure Backup vault in the same region and resource group |
| 9 | Enhanced Backup Policy | Every **4 hours** (24-hour window), configurable daily retention |
| 10 | Initial On-Demand Backup | Triggered immediately; script waits (up to 60 min) for completion |

## Backup Schedule Details

The script uses the **Enhanced policy** (required for sub-daily schedules):

- **Frequency**: every 4 hours
- **Window**: 00:00 – 24:00 UTC (full day)
- **Retention**: daily recovery points kept for `backupRetentionDays` days (default 30)
- **Initial backup**: on-demand backup triggered right after protection is enabled; the script polls every 30 seconds and reports when it completes

## Accessing the VM

The VM has **no public IP address** and no Azure Bastion. Connect via:

- **Azure Serial Console** (Azure portal → VM → Serial console) for emergency access
- **Azure VPN Gateway** or **ExpressRoute** from your on-premises network
- **A jump box / bastion host** deployed in the same or a peered VNet

## Important Notes

- The basename must be **12 characters or fewer** (a 5-digit numeric suffix is always appended).
- Only **v6 CVM SKUs** are accepted (`DCasv6`, `ECasv6`, `ECadsv6` families, e.g. `Standard_DC2as_v6`). The script exits with an error if a non-v6 SKU is supplied.
- Azure Key Vault **Premium** SKU is required for CVM disk encryption.
- Azure Backup of CVMs creates encrypted snapshots; the CMK in Key Vault must remain accessible for restores.
- Check [Azure region availability](https://azure.microsoft.com/en-gb/explore/global-infrastructure/products-by-region/) to confirm v6 CVM support in your target region.
- The VM admin password is generated randomly and printed once to the terminal – save it before the script finishes.

## Clean-up

```powershell
Remove-AzResourceGroup -Name <RESOURCE_GROUP_NAME> -Force
```

> **Note:** The Key Vault has purge protection enabled with a 10-day soft-delete retention.
> If you need to reuse the same vault name, wait for the retention period or purge it manually.
