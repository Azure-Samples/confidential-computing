# Azure Container Instances (ACI) Confidential Computing Samples

**Last Updated:** February 2026

## Overview

Scripts and samples for creating Confidential Azure Container Instances (ACIs) using Azure's confidential computing SKUs with AMD SEV-SNP hardware protection.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Confidential ACI Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                    │
│   ┌────────────────────────────────────────────────────────┐   │
│   │           Azure Container Instance (Confidential SKU)        │   │
│   │  ┌────────────────────────────────────────────────────┐  │   │
│   │  │              Combined Container (supervisord)            │  │   │
│   │  │  ┌───────────────────┐     ┌─────────────────────┐       │  │   │
│   │  │  │  Flask Web App    │     │  SKR Service        │       │  │   │
│   │  │  │  (Port 80)        │◀───▶│  (Port 8080)        │       │  │   │
│   │  │  │                   │     │  mcr.microsoft.com/ │       │  │   │
│   │  │  │  - Attestation UI │     │  aci/skr:2.13       │       │  │   │
│   │  │  │  - Key Release    │     │                     │       │  │   │
│   │  │  │  - Encryption     │     └──────────┬──────────┘       │  │   │
│   │  │  └───────────────────┘              │                  │  │   │
│   │  └─────────────────────────────────┬──────────────────┘  │   │
│   │                                    │                          │   │
│   │            AMD SEV-SNP TEE         │                          │   │
│   │         (Hardware Memory Encryption)│                          │   │
│   └─────────────────────────────────────┬──────────────────┘   │
│                                        │                              │
│                                        ▼                              │
│   ┌───────────────────┐  ┌─────────────────┐  ┌──────────────────┐  │
│   │  Azure Key Vault   │  │  Azure            │  │  Azure Container │  │
│   │  (Premium HSM)     │  │  Attestation      │  │  Registry (ACR)  │  │
│   │                   │  │  (MAA)            │  │                  │  │
│   └───────────────────┘  └─────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Samples

| Sample | Description |
|--------|-------------|
| `BuildRandomACI.ps1` | PowerShell script to create a confidential ACI with a hello-world container |
| [Visual Attestation Demo](visual-attestation-demo/README.md) | Interactive web application demonstrating remote attestation via Microsoft Azure Attestation (MAA) |

---

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

---

## Visual Attestation Demo

An interactive Flask web application that demonstrates Azure Container Instances with AMD SEV-SNP confidential computing and remote attestation.

### Features
- **Single Container Architecture** - Combined Flask app and SKR attestation service
- **Interactive Web UI** - Modern interface with real-time attestation controls
- **Remote Attestation** - Request JWT tokens from Microsoft Azure Attestation (MAA)
- **Secure Key Release (SKR)** - Release keys only to verified confidential containers
- **Real-time Encryption** - Encrypt text using released SKR keys (RSA-OAEP-SHA256)
- **Hardware Security** - AMD SEV-SNP memory encryption and isolation
- **Security Policy Enforcement** - Cryptographic verification of container configuration
- **Multi-Stage Docker Build** - Extracts SKR binary from Microsoft's sidecar image
- **Side-by-Side Comparison** - Deploy Confidential and Standard containers simultaneously
- **Live Diagnostics** - Service logs and `/dev/sev-guest` device detection on failure

### Quick Start
```powershell
cd visual-attestation-demo

# Build container image
.\Deploy-AttestationDemo.ps1 -Build

# Deploy with confidential computing
.\Deploy-AttestationDemo.ps1 -Deploy

# Or deploy without TEE for testing
.\Deploy-AttestationDemo.ps1 -Deploy -NoAcc

# Compare both side-by-side
.\Deploy-AttestationDemo.ps1 -Compare
```

See [visual-attestation-demo/README.md](visual-attestation-demo/README.md) for complete documentation.
