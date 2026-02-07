# Multi-Party Confidential Computing Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** February 2026

## 🤖 AI-Generated Content

> **Note:** This entire multi-party demonstration was **created using AI-assisted development** with GitHub Copilot powered by Claude. This showcases the capabilities of modern AI models for developing complex security-focused applications. While functional, AI-generated code should always be reviewed by qualified security professionals before use in production scenarios.

This demonstration shows how Azure Confidential Containers enable secure multi-party computation where each party's data remains protected, even from other parties and infrastructure operators.

## Architecture Overview

![Multi-Party Architecture](MultiPartyArchitecture.svg)

## Encrypted Data Flow

![Data Flow Diagram](DataFlowDiagram.svg)

**Key Insight:** Data remains encrypted at rest and in transit. Decryption **only** occurs inside the AMD SEV-SNP Trusted Execution Environment (TEE), where memory is hardware-encrypted at the CPU level.

## Overview

The demo deploys **two containers** running identical code, demonstrating how hardware-based security provides protection that software alone cannot achieve:

| Container | SKU | Hardware | Can Attest? | Can Get Keys? | Can Decrypt Data? |
|-----------|-----|----------|-------------|---------------|-------------------|
| **Contoso** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | ✅ Own data only |
| **Fabrikam Fashion** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | ✅ Own data only |

## Key Concepts

### Why This Matters

In traditional cloud computing, infrastructure operators (cloud providers, IT admins) can potentially access data in memory. Confidential computing solves this by:

1. **Hardware Isolation**: AMD SEV-SNP encrypts memory at the CPU level
2. **Remote Attestation**: Cryptographic proof that code is running in a genuine TEE
3. **Secure Key Release (SKR)**: Keys are only released to attested environments
4. **Company Isolation**: Each company's key is bound to their container identity

### Cross-Company Isolation

Even between trusted parties (Contoso and Fabrikam Fashion):
- Each company has a **separate Key Vault key** with its own release policy
- Contoso's key is bound to Contoso's container identity
- Fabrikam Fashion cannot access Contoso's key, and vice versa
- Shared storage contains encrypted data from both, but each can only decrypt their own

## Traffic Flow

### Successful Attestation & Key Release (Contoso/Fabrikam Fashion)

```
User Browser → Flask App (:80) → SKR Sidecar (:8080)
                                        ↓
                              Microsoft Azure Attestation
                                        ↓
                              JWT Token (signed attestation)
                                        ↓
                              Azure Key Vault (Premium HSM)
                                        ↓
                              Private Key → TEE Memory
                                        ↓
                              Encrypt/Decrypt Operations
```

### Data Protection Flow

The following diagram shows how encrypted data flows from storage to the TEE where it is decrypted:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        UNTRUSTED ZONE                                    │
│  (Data always encrypted - attackers see only ciphertext)                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────┐         ┌─────────────────┐                       │
│   │   contoso.csv   │         │  fabrikam.csv   │                       │
│   │   (9 records)   │         │   (9 records)   │                       │
│   └────────┬────────┘         └────────┬────────┘                       │
│            │                           │                                 │
│            ▼                           ▼                                 │
│   ┌─────────────────┐         ┌─────────────────┐                       │
│   │ Encrypt with    │         │ Encrypt with    │                       │
│   │ Contoso Key     │         │ Fabrikam Key    │                       │
│   │ (RSA-OAEP-256)  │         │ (RSA-OAEP-256)  │                       │
│   └────────┬────────┘         └────────┬────────┘                       │
│            │                           │                                 │
│            └─────────────┬─────────────┘                                │
│                          ▼                                               │
│              ┌───────────────────────┐                                  │
│              │  consolidated-        │                                  │
│              │  records-{rg}.json    │                                  │
│              │  (Azure Blob Storage) │                                  │
│              │  Mixed encrypted data │                                  │
│              └───────────┬───────────┘                                  │
│                          │                                              │
└──────────────────────────┼──────────────────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────────────────┐
│                          │     TRUSTED ZONE (AMD SEV-SNP TEE)           │
│  (Data decrypted ONLY here - hardware-encrypted memory)                 │
├──────────────────────────┼──────────────────────────────────────────────┤
│                          ▼                                               │
│              ┌───────────────────────┐                                  │
│              │  1️⃣ Fetch encrypted   │                                  │
│              │     data from blob    │                                  │
│              └───────────┬───────────┘                                  │
│                          │                                               │
│                          ▼                                               │
│              ┌───────────────────────┐      ┌─────────────────────┐     │
│              │  2️⃣ Request           │─────▶│  Azure Attestation  │     │
│              │     attestation       │      │  (MAA)              │     │
│              └───────────────────────┘      │  Verify TEE         │     │
│                          │                  │  Issue JWT          │     │
│                          │◀─────────────────└─────────────────────┘     │
│                          ▼                                               │
│              ┌───────────────────────┐      ┌─────────────────────┐     │
│              │  3️⃣ Request key       │─────▶│  Azure Key Vault    │     │
│              │     with JWT token    │      │  (HSM)              │     │
│              └───────────────────────┘      │  Verify JWT         │     │
│                          │                  │  Release Key        │     │
│                          │◀─────────────────└─────────────────────┘     │
│                          ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  4️⃣ DECRYPTION HAPPENS HERE (in TEE-protected memory)            │  │
│  │     🔓 Key exists only in encrypted memory                        │  │
│  │     🔓 Plaintext exists only in encrypted memory                  │  │
│  │     🔓 Even hypervisor cannot read TEE memory                     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                          │                                               │
│                ┌─────────┴─────────┐                                   │
│                │                   │                                   │
│                ▼                   ▼                                   │
│            Contoso         Fabrikam Fashion                            │
│           Decrypts            Decrypts                                  │
│           own data            own data                                  │
│           inside TEE          inside TEE                                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Azure CLI (v2.60+) with `confcom` extension (`az extension add --name confcom --upgrade`)
- Docker Desktop (for security policy generation)
- Azure subscription with Confidential Container support
- PowerShell 7.0+ recommended

### Deploy

```powershell
# Build the container image (first time only)
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build

# Deploy all 2 containers
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Deploy

# Or build and deploy in one command
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build -Deploy
```

> **Note:** Replace `<yourcode>` with a short unique identifier (3-8 chars) like your initials or team code.

### Clean Up

```powershell
# Delete all Azure resources (containers, Key Vault keys, blob data)
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Cleanup
```

## What You'll See

After deployment, a browser opens with a 2-pane view:

```
+---------------------------+---------------------------+
|        CONTOSO            |    FABRIKAM FASHION       |
|    (Confidential TEE)     |    (Confidential TEE)     |
|          🏢               |           👗              |
|  ✅ Attestation: Success  |  ✅ Attestation: Success  |
|  ✅ Key Release: Works    |  ✅ Key Release: Works    |
|  ✅ Encryption: Works     |  ✅ Encryption: Works     |
|  ✅ CSV Auto-Import       |  ✅ CSV Auto-Import       |
+---------------------------+---------------------------+
```

## Demo Script

### Basic Attestation Demo

1. **Show Contoso**: Click "Get Raw Report" - attestation succeeds (🏢)
2. **Show Fabrikam Fashion**: Same result - both can attest (👗)

### Secure Key Release Demo

3. **Release Key on Contoso**: Expand "Secure Key Release" section, click release
4. **Cross-Company Test**: Contoso tries to access Fabrikam Fashion's key - denied

### Data Protection Demo

5. **Expand "Protect Data"**: Section auto-imports CSV records
6. **Show encrypted storage**: Records encrypted with company-specific keys
7. **Decrypt Toggle**: Press "Decrypt" to see plaintext (only for own data)

## Security Model

### Per-Company Key Vault Keys

```
Azure Key Vault: kv<registry>a (Contoso)
├── Key: contoso-secret-key
├── Type: RSA-HSM (4096-bit)
├── Exportable: true (for SKR)
└── Release Policy: sevsnpvm + Contoso container identity

Azure Key Vault: kv<registry>b (Fabrikam Fashion)
├── Key: fabrikam-secret-key
├── Type: RSA-HSM (4096-bit)
├── Exportable: true (for SKR)
└── Release Policy: sevsnpvm + Fabrikam container identity
```

### Release Policy Example

```json
{
  "version": "1.0.0",
  "anyOf": [{
    "authority": "https://sharedeus.eus.attest.azure.net",
    "allOf": [{
      "claim": "x-ms-attestation-type",
      "equals": "sevsnpvm"
    }]
  }]
}
```

This means:
- Only containers with `x-ms-attestation-type: sevsnpvm` can release the key
- Non-TEE containers cannot fake this claim - it's verified by AMD hardware
- Each company's key has its own policy tied to their container

## Files

| File | Description |
|------|-------------|
| `Deploy-MultiParty.ps1` | Main deployment script with -Build, -Deploy, -Cleanup |
| `app.py` | Flask application with all API endpoints |
| `Dockerfile` | Multi-stage build with SKR sidecar |
| `templates/index.html` | Interactive web UI with all demo features |
| `contoso-data.csv` | Sample data for Contoso |
| `fabrikam-data.csv` | Sample data for Fabrikam Fashion |
| `deployment-template-original.json` | ARM template for Confidential SKU |
| `deployment-template-standard.json` | ARM template for Standard SKU |
| `multiparty-view.html` | 2-pane view for side-by-side comparison |
| `MultiPartyArchitecture.svg` | High-level architecture diagram |
| `DataFlowDiagram.svg` | Encrypted data flow showing TEE decryption model |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web UI |
| `/attest/maa` | POST | Request MAA attestation token |
| `/attest/raw` | POST | Get raw attestation report |
| `/skr/release` | POST | Release company's SKR key |
| `/skr/release-other` | POST | Attempt cross-company key access |
| `/skr/config` | GET | Get SKR configuration |
| `/encrypt` | POST | Encrypt data with released key |
| `/decrypt` | POST | Decrypt data with released key |
| `/company/info` | GET | Get company identity |
| `/company/save` | POST | Save encrypted record to blob |
| `/company/populate` | POST | Import CSV and encrypt to blob |
| `/company/list` | GET | List company's encrypted records |
| `/storage/config` | GET | Get blob storage configuration |
| `/storage/list` | GET | List all blobs in storage |
| `/container/info` | GET | Get container metadata |
| `/health` | GET | Health check endpoint |

## Troubleshooting

### Docker Not Running
```
Error: Docker is not running. Required for security policy generation.
```
Start Docker Desktop before running with `-Deploy`.

### Containers Not Starting
Check container logs:
```powershell
az container logs -g <resource-group> -n <container-name>
```

### Key Release Fails on Confidential Container
Verify the managed identity has Key Vault permissions:
```powershell
az keyvault show --name <vault-name> --query "properties.accessPolicies"
```

### Cross-Company Key Access Not Denied
Ensure each container has a unique managed identity and the Key Vault keys have proper release policies bound to specific identities.

## Related Documentation

- [Azure Confidential Computing Overview](https://azure.microsoft.com/solutions/confidential-compute/)
- [AMD SEV-SNP Technical Details](https://www.amd.com/en/developer/sev.html)
- [Azure Container Instances Confidential Containers](https://docs.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Azure Key Vault Secure Key Release](https://docs.microsoft.com/azure/key-vault/keys/about-keys-details)
- [Microsoft Azure Attestation](https://docs.microsoft.com/azure/attestation/)
