# Multi-Party Samples

Secure multi-party computation demonstrations using Azure Confidential Containers with AMD SEV-SNP hardware protection.

## 🤖 AI-Generated Content

> **Note:** These multi-party demonstration samples were **entirely created using AI-assisted development** with GitHub Copilot powered by Claude. This showcases the capabilities of modern AI models for developing complex security-focused applications, including:
>
> - Infrastructure-as-code (ARM templates, PowerShell deployment scripts)
> - Cryptographic implementations (AES-256-GCM encryption/decryption)
> - Web applications (Flask backend, interactive HTML/CSS/JavaScript frontend)
> - Security architecture design
> - Documentation and diagrams
>
> **While functional, AI-generated code should always be reviewed by qualified security professionals before use in production scenarios.**

## Available Samples

### [Advanced App](advanced-app/README.md) ⭐ RECOMMENDED

A comprehensive 4-container demonstration with **partner analytics** capabilities:

![Multi-Party Topology](advanced-app/MultiPartyTopology.svg)

| Container | Type | Purpose |
|-----------|------|---------|
| **Contoso** | Confidential (AMD SEV-SNP) | Enterprise data provider with 50 encrypted employee records |
| **Fabrikam Fashion** | Confidential (AMD SEV-SNP) | Online retailer with 50 encrypted customer records |
| **Woodgrove Bank** | Confidential (AMD SEV-SNP) | Analytics partner with cross-company key access |
| **Snooper** | Standard (No TEE) | Attacker view - demonstrates failed key access |

#### Key Features

- 🔐 **Hardware-Based Security** - AMD SEV-SNP memory encryption at CPU level
- 🛡️ **Remote Attestation** - Cryptographic proof via Microsoft Azure Attestation (MAA)
- 🔑 **Secure Key Release (SKR)** - HSM keys only released to attested TEE containers
- 🏦 **Partner Analytics** - Woodgrove Bank performs cross-company demographic analysis
- 📊 **Real-time Progress** - Server-Sent Events (SSE) streaming with progress bars
- 🌍 **Demographics Analysis** - Top 10 countries with top 3 cities, generations, salary averages
- 👁️ **Attacker Visualization** - See what malicious actors observe (encrypted data only)
- 🔓 **TEE-Only Decryption** - Data decrypted only inside hardware-protected memory

#### Architecture

![Architecture Diagram](advanced-app/MultiPartyArchitecture.svg)

#### Encrypted Data Flow

![Data Flow Diagram](advanced-app/DataFlowDiagram.svg)

**Key Insight:** Data remains encrypted in storage and transit. Decryption **only** occurs inside the AMD SEV-SNP TEE, where memory is hardware-encrypted. Even infrastructure operators cannot access plaintext.

#### Quick Start

```powershell
cd advanced-app
.\Deploy-MultiParty.ps1 -Build -Deploy
```

See the [full documentation](advanced-app/README.md) for detailed instructions.

---

### [Demo App](demo-app/README-MultiParty.md)

A simpler 3-container demonstration without partner analytics:

| Container | Type | Purpose |
|-----------|------|---------|
| **Contoso** | Confidential (AMD SEV-SNP) | Enterprise with access to own encryption key |
| **Fabrikam Fashion** | Confidential (AMD SEV-SNP) | Online retailer with access to own encryption key |
| **Snooper** | Standard (No TEE) | Attacker view - cannot access any keys |

#### Quick Start

```powershell
cd demo-app
.\Deploy-MultiParty.ps1 -Build -Deploy
```

## Prerequisites

- **Azure CLI** (v2.50+) with `confcom` extension
- **Docker Desktop** - Required for security policy generation
- **Azure subscription** with Confidential Container support
- **PowerShell** 5.1+ (PowerShell 7+ recommended)

### Install Azure CLI Extension

```powershell
az extension add --name confcom --upgrade
```

## ⚠️ Disclaimer

This code is provided for **educational and demonstration purposes only**.

- **No Warranty:** Provided "AS IS" without warranty of any kind
- **Not Production-Ready:** Requires thorough review before production use
- **User Responsibility:** Users are responsible for:
  - Security review of all code
  - Compliance with organizational policies
  - Validating cryptographic implementations
  - Proper key management

## Related Resources

- [Azure Confidential Computing](https://azure.microsoft.com/solutions/confidential-compute/)
- [AMD SEV-SNP Technology](https://www.amd.com/en/developer/sev.html)
- [Azure Container Instances - Confidential Containers](https://docs.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Microsoft Azure Attestation](https://learn.microsoft.com/azure/attestation/overview)
