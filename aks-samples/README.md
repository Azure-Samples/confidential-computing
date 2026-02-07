# Azure Kubernetes Service (AKS) Confidential Computing Samples

**Last Updated:** February 2026

## Overview

Deploy Azure Kubernetes Service clusters with AMD SEV-SNP confidential node pools and Customer Managed Keys (CMK).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  AKS Cluster with Confidential Nodes              │
├─────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────────────┐   ┌───────────────────────────────────┐   │
│  │   System Node Pool  │   │   Confidential Node Pool (DCasv5)   │   │
│  │   (Standard VMs)    │   │   ┌─────────────────────────────┐   │   │
│  │                     │   │   │    AMD SEV-SNP TEE Pods     │   │   │
│  │  ┌───────────────┐   │   │   │  ┌────────┐ ┌───────────┐ │   │   │
│  │  │  CoreDNS       │   │   │   │  │ Pod A  │ │ Pod B     │ │   │   │
│  │  │  Metrics      │   │   │   │  │ (TEE)  │ │ (TEE)     │ │   │   │
│  │  │  Kube-Proxy   │   │   │   │  └────────┘ └───────────┘ │   │   │
│  │  └───────────────┘   │   │   └─────────────────────────────┘   │   │
│  └─────────────────────┘   └───────────────────────────────────┘   │
│                                                                    │
├─────────────────────────────────────────────────────────────────┤
│                     Azure Infrastructure                           │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────┐    │
│  │  Key Vault     │  │  Disk Encrypt  │  │  Managed Identity   │    │
│  │  (Premium)     │  │  Set (CMK)     │  │  (Node Pools)       │    │
│  └───────────────┘  └───────────────┘  └────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## BuildRandomAKS.ps1

Creates an AKS cluster with:
- **Customer Managed Keys (CMK)** - Encrypt etcd secrets and OS disks
- **Confidential Node Pool** - AMD SEV-SNP hardware (DCasv5 series)
- **Azure Key Vault Premium** - HSM-backed key storage
- **Disk Encryption Set** - Managed disk encryption with CMK

### Prerequisites

- Azure CLI (`az login`) - authenticated
- Azure PowerShell (`Connect-AzAccount`) - authenticated
- Latest Az PowerShell module (`Update-Module Az -Force`)
- Subscription with AKS Confidential Container support

### Usage

```powershell
./BuildRandomAKS.ps1 -subsID <YOUR_SUBSCRIPTION_ID> -basename <YOUR_BASENAME>
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-subsID` | Yes | Your Azure subscription ID |
| `-basename` | Yes | Prefix for all created resources |

### Example

```powershell
# Create AKS cluster with confidential nodes
./BuildRandomAKS.ps1 -subsID "your-subscription-id" -basename "myaks"
```

### Created Resources

| Resource | Type | Purpose |
|----------|------|--------|
| `<basename>-rg` | Resource Group | Contains all resources |
| `<basename>-akv` | Key Vault (Premium) | Stores CMK encryption key |
| `<basename>-des` | Disk Encryption Set | Encrypts node OS disks |
| `<basename>-aks` | AKS Cluster | Kubernetes cluster |
| `confpool` | Node Pool | Confidential node pool (DCasv5) |

## Deploying Confidential Workloads

After cluster creation, deploy workloads to the confidential node pool:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: confidential-workload
spec:
  nodeSelector:
    kubernetes.azure.com/security-type: ConfidentialVM
  containers:
  - name: app
    image: your-image:latest
```

## References

- [AKS with Confidential Computing](https://learn.microsoft.com/azure/aks/confidential-containers-overview)
- [Azure Disk Encryption with CMK](https://learn.microsoft.com/azure/aks/azure-disk-customer-managed-keys)
- [DCasv5 Series VMs](https://learn.microsoft.com/azure/virtual-machines/dcasv5-series)
