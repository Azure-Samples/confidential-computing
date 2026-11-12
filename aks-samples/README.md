# Azure Kubernetes Service (AKS) Confidential Computing Samples

**Last Updated:** November 2026

## Overview

Deploy Azure Kubernetes Service clusters with confidential CPU node pools or a
confidential NVIDIA H100 GPU worker. The CPU sample includes Customer Managed
Keys (CMK); the GPU sample follows the Azure confidential H100 onboarding guide.

## Choose a sample

| Sample | What it covers |
|---|---|
| [Confidential H100 GPU worker](aks-gpu-worker/README.md) | Single H100 worker on the latest offered AKS node image, guide-only GPU Operator installation, TensorFlow execution verified on GPU, and strict GPU attestation before and after the workload. |
| [Confidential CPU node pools with CMK](#buildrandomaksps1) | AMD SEV-SNP confidential node pools, Key Vault, and customer-managed encryption keys. |
| [AKS virtual nodes](virtual%20nodes/README.md) | Virtual nodes backed by ACI, hello-world scheduling validation, and a confidential ACI follow-on manifest. |

### Start with the confidential H100 worker

See the [H100 worker guide](aks-gpu-worker/README.md) for prerequisites,
preflight and deployment commands, redacted attestation output, and cleanup.
The sample was revalidated in West Europe using an Azure-FDE kernel at least
`6.8.0-1071-azure-fde`. Successful execution on a newer AKS image is not
Microsoft/NVIDIA support certification; the guide explains that boundary.
GPU attestation is not a separate CPU/whole-VM attestation claim.

The worker sample stops newly created compute automatically, but does **not**
delete resources. Delete its resource group when finished to remove retained
disks, IPs, and other potentially billable resources.

## Architecture

The following architecture describes the confidential CPU node-pool/CMK sample.
For the H100 configuration, use the [GPU worker guide](aks-gpu-worker/README.md).

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
