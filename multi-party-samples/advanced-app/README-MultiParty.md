# Multi-Party Confidential Computing Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** February 2026

This demonstration shows how Azure Confidential Containers enable secure multi-party computation where each party's data remains protected, even from other parties and infrastructure operators.

## Architecture Overview

![Multi-Party Architecture](MultiPartyArchitecture.svg)

## Encrypted Data Flow

![Data Flow Diagram](DataFlowDiagram.svg)

**Key Insight:** Data remains encrypted at rest and in transit. Decryption **only** occurs inside the AMD SEV-SNP Trusted Execution Environment (TEE), where memory is hardware-encrypted at the CPU level.

## Overview

The demo deploys **four containers** running identical code, demonstrating how hardware-based security provides protection that software alone cannot achieve:

| Container | SKU | Hardware | Can Attest? | Can Get Keys? | Can Decrypt Data? |
|-----------|-----|----------|-------------|---------------|-------------------|
| **Contoso** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | ✅ Own data only |
| **Fabrikam** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | ✅ Own data only |
| **Woodgrove Bank** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own + Partner | ✅ Partner data |
| **Snooper** | Standard | None | ❌ No | ❌ No keys | ❌ No data |

## Key Concepts

### Why This Matters

In traditional cloud computing, infrastructure operators (cloud providers, IT admins) can potentially access data in memory. Confidential computing solves this by:

1. **Hardware Isolation**: AMD SEV-SNP encrypts memory at the CPU level
2. **Remote Attestation**: Cryptographic proof that code is running in a genuine TEE
3. **Secure Key Release (SKR)**: Keys are only released to attested environments
4. **Company Isolation**: Each company's key is bound to their container identity

### The Snooper Problem

The `snooper` container represents:
- A malicious container trying to intercept data
- An infrastructure operator trying to peek at secrets
- A compromised container without TEE protection

**Even though snooper runs the same code**, it cannot:
- Generate valid attestation tokens (no `/dev/sev-guest` device)
- Release cryptographic keys from Azure Key Vault
- Decrypt data protected by SKR-released keys

### Woodgrove Bank: Trusted Partner Analytics

Woodgrove Bank demonstrates a **trusted third-party analytics** scenario:
- Operates as a financial analytics partner for Contoso and Fabrikam
- Both companies explicitly grant Woodgrove access to their Key Vaults
- Woodgrove must still pass TEE attestation to release partner keys
- Enables aggregate demographic analysis while maintaining cryptographic guarantees

**Key differences from Snooper:**
- Woodgrove runs in a **Confidential** container (can attest)
- Woodgrove has **explicit permission** from partners (Key Vault access policies)
- All access is **audited** in Azure for compliance

### Cross-Company Isolation

Even between trusted parties (Contoso and Fabrikam):
- Each company has a **separate Key Vault key** with its own release policy
- Contoso's key is bound to Contoso's container identity
- Fabrikam cannot access Contoso's key, and vice versa
- Shared storage contains encrypted data from both, but each can only decrypt their own

**Woodgrove exception:**
- Woodgrove can access both keys because partners **explicitly granted** access
- This is not a security bypass - it's intentional delegation

## Traffic Flow

### Successful Attestation & Key Release (Contoso/Fabrikam/Woodgrove)

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

### Woodgrove Partner Key Release

```
Woodgrove Container → SKR Sidecar (:8080)
                              ↓
                    Microsoft Azure Attestation
                              ↓
                    JWT Token (Woodgrove TEE)
                              ↓
          ┌─────────────────────────────────────────┐
          ↓                                         ↓
  Contoso Key Vault                        Fabrikam Key Vault
  (Woodgrove has access)                   (Woodgrove has access)
          ↓                                         ↓
  contoso-secret-key                       fabrikam-secret-key
          ↓                                         ↓
          └─────────────────────────────────────────┘
                              ↓
                    Partner Data Analysis
```

### Failed Attestation (Snooper)

```
User Browser → Flask App (:80) → SKR Sidecar (:8080)
                                        ↓
                              ❌ No /dev/sev-guest device
                              ❌ Cannot generate TEE evidence
                              ❌ Attestation fails
                              ❌ No JWT token
                              ❌ Key Vault denies access
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
│              │  consolidated-        │        ┌──────────────┐          │
│              │  records-{rg}.json    │◄───────│   Snooper    │          │
│              │  (Azure Blob Storage) │        │  Can READ    │          │
│              │  Mixed encrypted data │        │  but NOT     │          │
│              └───────────┬───────────┘        │  DECRYPT ❌  │          │
│                          │                    └──────────────┘          │
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
│            ┌─────────────┼─────────────┬─────────────┐                  │
│            │             │             │             │                   │
│            ▼             ▼             ▼             ▼                   │
│        Contoso       Fabrikam      Woodgrove      Snooper               │
│       Decrypts      Decrypts      Decrypts       ❌ Cannot              │
│       own 9         own 9         Partner        attest                 │
│       records       records       Data           ❌ No key              │
│                                                  ❌ No decrypt          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Azure CLI with `confcom` extension (`az extension add --name confcom`)
- Docker Desktop (for security policy generation)
- Azure subscription with Confidential Container support
- PowerShell 5.1 or later

### Deploy

```powershell
# Build the container image (first time only)
.\Deploy-MultiParty.ps1 -Build

# Deploy all 4 containers
.\Deploy-MultiParty.ps1 -Deploy

# Or build and deploy in one command
.\Deploy-MultiParty.ps1 -Build -Deploy
```

### Clean Up

```powershell
# Delete all Azure resources (containers, Key Vault keys, blob data)
.\Deploy-MultiParty.ps1 -Cleanup
```

## What You'll See

After deployment, a browser opens with a 4-pane side-by-side view:

```
+------------------+------------------+------------------+------------------+
|     CONTOSO      |     FABRIKAM     |  WOODGROVE BANK  |     SNOOPER      |
| (Confidential)   | (Confidential)   |  (Confidential)  |  (Standard)      |
|                  |                  |                  |                  |
| ✅ Attestation   | ✅ Attestation   | ✅ Attestation   | ❌ Attestation   |
| ✅ Key Release   | ✅ Key Release   | ✅ Key Release   | ❌ Key Release   |
| ✅ Own data      | ✅ Own data      | ✅ Partner data  | 👁️ Encrypted    |
+------------------+------------------+------------------+------------------+
```

### Woodgrove Bank Features

- **Green bank branding** with 🏦 logo
- **Partner Demographic Analysis** section
- **Progress indicators** for Contoso and Fabrikam key release
- **Real-time analysis log**

## Demo Script

### Basic Attestation Demo

1. **Show Contoso**: Click "Get Raw Report" - attestation succeeds
2. **Show Fabrikam**: Same result - both can attest
3. **Show Woodgrove**: Attestation succeeds with green bank theme
4. **Show Snooper**: Click "Get Raw Report" - fails with error message

### Secure Key Release Demo

5. **Release Key on Contoso**: Expand "Secure Key Release" section, click release
6. **Try on Snooper**: Same action fails - no attestation = no key
7. **Cross-Company Test**: Contoso tries to access Fabrikam's key - denied

### Partner Analysis Demo (Woodgrove Only)

8. **Open Woodgrove Bank pane**: Notice green bank branding
9. **Expand "Partner Demographic Analysis"** section
10. **Click "Start Partner Demographic Analysis"**
11. **Watch progress**: Contoso ✅ → Fabrikam ✅
12. **Review log**: Shows both partner keys released successfully

### Data Protection Demo

13. **Expand "Protect Data"**: Section auto-imports CSV records
14. **Show encrypted storage**: Records encrypted with company-specific keys
15. **Decrypt Toggle**: Press "Decrypt" to see plaintext (only for own data)
16. **Switch to Snooper**: Show auto-refreshing attacker view with encrypted blobs

## Security Model

### Per-Company Key Vault Keys

```
Azure Key Vault: kv<registry>a (Contoso)
├── Key: contoso-secret-key
├── Type: RSA-HSM (4096-bit)
├── Exportable: true (for SKR)
└── Release Policy: sevsnpvm + Contoso container identity

Azure Key Vault: kv<registry>b (Fabrikam)
├── Key: fabrikam-secret-key
├── Type: RSA-HSM (4096-bit)
├── Exportable: true (for SKR)
└── Release Policy: sevsnpvm + Fabrikam container identity

Azure Key Vault: kv<registry>c (Woodgrove Bank)
├── Key: woodgrove-secret-key
├── Type: RSA-HSM (4096-bit)
├── Exportable: true (for SKR)
├── Release Policy: sevsnpvm + Woodgrove container identity
└── Cross-Company: Access to kv<registry>a and kv<registry>b
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
- The snooper container cannot fake this claim - it's verified by AMD hardware
- Each company's key has its own policy tied to their container
- Woodgrove has access to partner keys via explicit Key Vault permissions

## Files

| File | Description |
|------|-------------|
| `Deploy-MultiParty.ps1` | Main deployment script with -Build, -Deploy, -Cleanup |
| `app.py` | Flask application with all API endpoints |
| `Dockerfile` | Multi-stage build with SKR sidecar |
| `templates/index.html` | Interactive web UI with all demo features |
| `contoso-data.csv` | Sample data for Contoso (9 records) |
| `fabrikam-data.csv` | Sample data for Fabrikam (9 records) |
| `deployment-template-original.json` | ARM template for Confidential SKU |
| `deployment-template-woodgrove-base.json` | ARM template for Woodgrove with partner env vars |
| `deployment-template-standard.json` | ARM template for Standard SKU |
| `multiparty-view.html` | 4-pane view for side-by-side comparison |
| `MultiPartyArchitecture.svg` | High-level architecture diagram |
| `DataFlowDiagram.svg` | Encrypted data flow showing TEE decryption model |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web UI |
| `/attest/maa` | POST | Request MAA attestation token |
| `/attest/raw` | POST | Get raw attestation report |
| `/skr/release` | POST | Release company's SKR key |
| `/skr/release-other` | POST | Attempt cross-company key access (Contoso/Fabrikam) |
| `/skr/release-partner` | POST | Release partner key (Woodgrove only) |
| `/skr/config` | GET | Get SKR configuration |
| `/encrypt` | POST | Encrypt data with released key |
| `/decrypt` | POST | Decrypt data with released key |
| `/company/info` | GET | Get company identity |
| `/company/save` | POST | Save encrypted record to blob |
| `/company/populate` | POST | Import CSV and encrypt to blob |
| `/company/list` | GET | List company's encrypted records |
| `/storage/config` | GET | Get blob storage configuration |
| `/storage/list` | GET | List all blobs (for snooper view) |
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

### Partner Key Release Fails (Woodgrove)
Ensure Woodgrove container was deployed with partner environment variables:
- `PARTNER_CONTOSO_AKV_ENDPOINT`
- `PARTNER_FABRIKAM_AKV_ENDPOINT`

### Cross-Company Key Access Not Denied
Ensure each container has a unique managed identity and the Key Vault keys have proper release policies bound to specific identities.

## Related Documentation

- [Azure Confidential Computing Overview](https://azure.microsoft.com/solutions/confidential-compute/)
- [AMD SEV-SNP Technical Details](https://www.amd.com/en/developer/sev.html)
- [Azure Container Instances Confidential Containers](https://docs.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Azure Key Vault Secure Key Release](https://docs.microsoft.com/azure/key-vault/keys/about-keys-details)
- [Microsoft Azure Attestation](https://docs.microsoft.com/azure/attestation/)
