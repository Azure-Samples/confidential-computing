# Sovereign Examples

This directory contains example scripts and configurations for deploying Azure Confidential Computing
resources in scenarios that require heightened data sovereignty, compliance, or backup/recovery controls.

## Available Examples

| Folder | Description |
|--------|-------------|
| [`cvm-backup/`](cvm-backup/README.md) | Deploy a Windows Confidential VM (CVM) with Azure Backup (Recovery Services Vault) and Customer Managed Key disk encryption |

## Common Themes

- All examples use **AMD SEV-SNP** hardware-based memory protection
- Customer Managed Keys (CMK) via **Azure Key Vault Premium** with confidential disk encryption
- Private VNet topology – no public IP on the VM; optional **Azure Bastion** for RDP access
- Resource tagging for ownership tracking and automation

## Prerequisites

- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell) (Az module, latest version)
- An Azure subscription with quota for DCasv5-series Confidential VMs
- The **Confidential VM Orchestrator** service principal registered in your tenant
