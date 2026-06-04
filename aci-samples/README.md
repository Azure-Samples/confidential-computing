# Azure Container Instances (ACI) Confidential Computing Samples

**Last Updated:** June 2026

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
| [Visual Attestation Demo](visual-attestation-demo/README.md) | Interactive web application demonstrating remote attestation via Microsoft Azure Attestation (MAA) using the SKR sidecar |
| [Visual Attestation Demo v2](visual-attestation-demo-v2/README.md) 🆕 | Simplified ACI port that calls MAA **directly** from the Flask app via the upstream `get-snp-report` tool (no SKR sidecar). Side-by-side Confidential vs Standard SKU deployment to demonstrate falsifiability. |
| [App + PostgreSQL Finance Demo](app-and-postgreSQL-demo/README.md) 🆕 | Confidential ACI with DCa/ECa AMD PostgreSQL, 5,000 financial transactions, Application Gateway, and 9 threat scenarios |

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

---

## Visual Attestation Demo v2 (direct MAA, no SKR sidecar)

A simpler ACI port of the AKS visual attestation sample. The Flask app calls Microsoft Azure Attestation **directly** from inside a single container — no SKR sidecar — by invoking the upstream [`get-snp-report`](https://github.com/microsoft/confidential-sidecar-containers/tree/main/tools/get-snp-report) tool against `/dev/sev-guest`, then POSTing the SNP report plus THIM cert chain and UVM endorsements to `https://<maa>/attest/SevSnpVm`.

### Features
- **No SKR sidecar** — single container, single process tree
- **Direct MAA call** from Python with `get-snp-report` baked into the image (multi-stage build)
- **Side-by-side Confidential vs Standard SKU** via `-Compare` — same image, deterministic Standard-SKU failure (`/dev/sev-guest` absent) proves the success case really came from AMD silicon
- **CCE policy** auto-generated with `az confcom acipolicygen` on Confidential deploys
- Renders the decoded MAA JWT with `x-ms-sevsnpvm-*` claims and the raw hardware evidence

### Quick Start
```powershell
cd visual-attestation-demo-v2

# Build, deploy both SKUs side-by-side, and open both URLs in the browser
.\Deploy-VisualAttestationV2.ps1 -Compare

# Or step-by-step
.\Deploy-VisualAttestationV2.ps1 -Build
.\Deploy-VisualAttestationV2.ps1 -Deploy           # Confidential SKU
.\Deploy-VisualAttestationV2.ps1 -Deploy -NoAcc    # Standard SKU

# Tear everything down
.\Deploy-VisualAttestationV2.ps1 -Cleanup
```

See [visual-attestation-demo-v2/README.md](visual-attestation-demo-v2/README.md) for the full flow, screenshots of both SKUs, and a feature comparison with the AKS sample.
