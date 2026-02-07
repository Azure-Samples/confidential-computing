# Azure Attestation Samples

**Last Updated:** February 2026

## Overview

Scripts and samples for working with Microsoft Azure Attestation (MAA), which provides remote attestation for Confidential Computing workloads.

## Attestation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 Remote Attestation Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                    │
│   ┌───────────────────────┐    1️⃣ Request      ┌─────────────────┐   │
│   │  Confidential         │   Attestation   │  Azure          │   │
│   │  Workload             │─────────────────▶│  Attestation    │   │
│   │  (CVM/ACI/AKS)        │                 │  (MAA)          │   │
│   │                       │                 │                 │   │
│   │  ┌─────────────────┐   │                 │  - Validates    │   │
│   │  │ AMD SEV-SNP     │   │                 │    hardware     │   │
│   │  │ Hardware        │   │                 │  - Signs JWT    │   │
│   │  │ Report          │   │                 │  - Returns      │   │
│   │  └─────────────────┘   │   2️⃣ JWT Token   │    claims       │   │
│   │                       │◀─────────────────│                 │   │
│   └───────────────────────┘                 └─────────────────┘   │
│              │                                                      │
│              │ 3️⃣ Present JWT                                      │
│              ▼                                                      │
│   ┌───────────────────────┐                                        │
│   │  Relying Party        │   4️⃣ Verify JWT signature             │
│   │  (Key Vault, App,     │   5️⃣ Check attestation claims          │
│   │   Service)            │   6️⃣ Release secrets/grant access      │
│   └───────────────────────┘                                        │
└─────────────────────────────────────────────────────────────────┘
```

## Attestation Provider Types

| Type | Endpoint Pattern | Use Case |
|------|-----------------|----------|
| **Shared (Regional)** | `shared<region>.<region>.attest.azure.net` | Default, no setup required |
| **Private** | `<name>.<region>.attest.azure.net` | Custom policies, compliance |

## Files

| File | Description |
|------|-------------|
| `createPrivateMAA.ps1` | Create a private Azure Attestation provider |
| `release.json` | Sample key release policy template |

## createPrivateMAA.ps1

### Description

Creates a private Microsoft Azure Attestation (MAA) provider for scenarios requiring:
- Custom attestation policies
- Compliance requirements (data residency)
- Isolated attestation infrastructure

### Prerequisites

- Azure PowerShell module (`Install-Module -Name Az`)
- Authentication to Azure (`Connect-AzAccount`)
- Appropriate permissions to create attestation providers

### Usage

```powershell
.\createPrivateMAA.ps1 -Location <AZURE_REGION> `
    -AttestationResourceGroup <RESOURCE_GROUP_NAME> `
    -AttestationProviderName <PROVIDER_NAME> `
    -SubscriptionId <SUBSCRIPTION_ID>
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Location` | Yes | Azure region (e.g., `eastus`) |
| `-AttestationResourceGroup` | Yes | Resource group name |
| `-AttestationProviderName` | Yes | Name for the attestation provider |
| `-SubscriptionId` | Yes | Azure subscription ID |

### Example

```powershell
.\createPrivateMAA.ps1 -Location "eastus" `
    -AttestationResourceGroup "myattest-rg" `
    -AttestationProviderName "myattestation" `
    -SubscriptionId "your-subscription-id"
```

## Key Release Policy

The `release.json` file contains a sample key release policy for Azure Key Vault integration:

```json
{
  "version": "1.0.0",
  "anyOf": [{
    "authority": "https://<maa-endpoint>",
    "allOf": [{
      "claim": "x-ms-attestation-type",
      "equals": "sevsnpvm"
    }]
  }]
}
```

## References

- [Azure Attestation Overview](https://learn.microsoft.com/azure/attestation/overview)
- [Azure Attestation Policy Grammar](https://learn.microsoft.com/azure/attestation/author-sign-policy)
- [Confidential Computing Attestation](https://learn.microsoft.com/azure/confidential-computing/attestation-solutions)
