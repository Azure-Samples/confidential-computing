# Multi-Party Confidential Computing Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** February 2026

This demonstration shows how Azure Confidential Containers enable secure multi-party computation where each party's data remains protected, even from other parties and infrastructure operators.

## Architecture Overview

![Multi-Party Architecture](MultiPartyArchitecture.svg)

## Overview

The demo deploys **three containers** running identical code, demonstrating how hardware-based security provides protection that software alone cannot achieve:

| Container | SKU | Hardware | Can Attest? | Can Get Keys? | Can Decrypt Data? |
|-----------|-----|----------|-------------|---------------|-------------------|
| **Contoso** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | ✅ Own data only |
| **Fabrikam** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | ✅ Own data only |
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

### Cross-Company Isolation

Even between trusted parties (Contoso and Fabrikam):
- Each company has a **separate Key Vault key** with its own release policy
- Contoso's key is bound to Contoso's container identity
- Fabrikam cannot access Contoso's key, and vice versa
- Shared storage contains encrypted data from both, but each can only decrypt their own

## Traffic Flow

### Successful Attestation & Key Release (Contoso/Fabrikam)

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

```
┌─────────────────┐         ┌─────────────────┐
│   contoso.csv   │         │  fabrikam.csv   │
│   (9 records)   │         │   (9 records)   │
└────────┬────────┘         └────────┬────────┘
         │                           │
         ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│ Encrypt with    │         │ Encrypt with    │
│ Contoso Key     │         │ Fabrikam Key    │
│ (RSA-OAEP-256)  │         │ (RSA-OAEP-256)  │
└────────┬────────┘         └────────┬────────┘
         │                           │
         └─────────────┬─────────────┘
                       ▼
           ┌───────────────────────┐
           │  consolidated-        │
           │  records.json         │
           │  (Azure Blob Storage) │
           │  Mixed encrypted data │
           └───────────┬───────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
     Contoso       Fabrikam       Snooper
    Decrypts      Decrypts       Sees only
    own 9         own 9          encrypted
    records       records        gibberish
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

# Deploy all 3 containers
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

After deployment, a browser opens with a 3-pane view:

```
+---------------------------+---------------------------+
|        CONTOSO            |        FABRIKAM           |
|    (Confidential TEE)     |    (Confidential TEE)     |
|                           |                           |
|  ✅ Attestation: Success  |  ✅ Attestation: Success  |
|  ✅ Key Release: Works    |  ✅ Key Release: Works    |
|  ✅ Encryption: Works     |  ✅ Encryption: Works     |
|  ✅ CSV Auto-Import       |  ✅ CSV Auto-Import       |
+---------------------------+---------------------------+
|                 SNOOPER                               |
|              (Standard - No TEE)                      |
|                                                       |
|  ❌ Attestation: FAILED (no TEE hardware)            |
|  ❌ Key Release: DENIED (not attested)               |
|  👁️ Attacker View: Sees encrypted data only          |
|  🔄 Auto-refresh: Monitors blob for new records      |
+-------------------------------------------------------+
```

## Demo Script

### Basic Attestation Demo

1. **Show Contoso**: Click "Get Raw Report" - attestation succeeds
2. **Show Fabrikam**: Same result - both can attest
3. **Show Snooper**: Click "Get Raw Report" - fails with error message

### Secure Key Release Demo

4. **Release Key on Contoso**: Expand "Secure Key Release" section, click release
5. **Try on Snooper**: Same action fails - no attestation = no key
6. **Cross-Company Test**: Contoso tries to access Fabrikam's key - denied

### Data Protection Demo

7. **Expand "Protect Data"**: Section auto-imports CSV records
8. **Show encrypted storage**: Records encrypted with company-specific keys
9. **Decrypt Toggle**: Press "Decrypt" to see plaintext (only for own data)
10. **Switch to Snooper**: Show auto-refreshing attacker view with encrypted blobs

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

## Files

| File | Description |
|------|-------------|
| `Deploy-MultiParty.ps1` | Main deployment script with -Build, -Deploy, -Cleanup |
| `app.py` | Flask application with all API endpoints |
| `Dockerfile` | Multi-stage build with SKR sidecar |
| `templates/index.html` | Interactive web UI with all demo features |
| `contoso-data.csv` | Sample data for Contoso (9 records) |
| `fabrikam-data.csv` | Sample data for Fabrikam (9 records) |
| `deployment-template-contoso.json` | ARM template for Contoso (Confidential) |
| `deployment-template-fabrikam.json` | ARM template for Fabrikam (Confidential) |
| `deployment-template-snooper.json` | ARM template for Snooper (Standard) |
| `multiparty-view.html` | 3-pane view for side-by-side comparison |
| `MultiPartyArchitecture.svg` | Architecture diagram |

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

### Cross-Company Key Access Not Denied
Ensure each container has a unique managed identity and the Key Vault keys have proper release policies bound to specific identities.

## Related Documentation

- [Azure Confidential Computing Overview](https://azure.microsoft.com/solutions/confidential-compute/)
- [AMD SEV-SNP Technical Details](https://www.amd.com/en/developer/sev.html)
- [Azure Container Instances Confidential Containers](https://docs.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Azure Key Vault Secure Key Release](https://docs.microsoft.com/azure/key-vault/keys/about-keys-details)
- [Microsoft Azure Attestation](https://docs.microsoft.com/azure/attestation/)
