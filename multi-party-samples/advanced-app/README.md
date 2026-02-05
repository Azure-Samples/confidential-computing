
# Multi-Party Confidential Computing Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** February 2026

A demonstration of Azure Confidential Container Instances (ACI) with AMD SEV-SNP hardware protection, showing how multiple parties can securely collaborate while protecting their data from each other and from infrastructure operators.

## Overview

This project deploys **four containers** running identical code to demonstrate multi-party confidential computing:

| Container | SKU | Hardware | Can Attest? | Can Release Keys? | Special Features |
|-----------|-----|----------|-------------|-------------------|------------------|
| **Contoso** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | Data provider |
| **Fabrikam** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own key only | Data provider |
| **Woodgrove Bank** | Confidential | AMD SEV-SNP TEE | ✅ Yes | ✅ Own + Partner keys | Analytics partner |
| **Snooper** | Standard | None | ❌ No | ❌ No keys | Attacker view |

### Key Features

- **Multi-Party Isolation** - Each company has separate Key Vault keys bound to their container identity
- **Partner Analytics** - Woodgrove Bank can access Contoso and Fabrikam keys for aggregate analysis
- **Hardware-Based Security** - AMD SEV-SNP memory encryption at the CPU level
- **Remote Attestation** - Cryptographic proof via Microsoft Azure Attestation (MAA)
- **Secure Key Release (SKR)** - Keys only released to attested confidential containers
- **Cross-Company Protection** - Contoso cannot access Fabrikam's key, and vice versa
- **Attacker Visualization** - Snooper container shows what an attacker sees (encrypted data only)
- **Interactive Web UI** - Real-time demonstration of attestation and encryption
- **Unique Per-Deployment Storage** - Each deployment uses `consolidated-records-{resource_group}.json`

## Architecture

![Multi-Party Architecture](MultiPartyArchitecture.svg)

The demo deploys:
- **3 Confidential Containers** (Contoso, Fabrikam, Woodgrove Bank) - Running on AMD SEV-SNP hardware with TEE protection
- **1 Standard Container** (Snooper) - Running without TEE hardware to demonstrate attack scenarios
- **3 Key Vaults** - Separate Premium HSM-backed vaults for each company's encryption keys
- **Shared Blob Storage** - Contains encrypted data from all parties

## Encrypted Data Flow

![Data Flow Diagram](DataFlowDiagram.svg)

### How It Works

1. **Encrypted Data at Rest** - All company data is stored encrypted in Azure Blob Storage
2. **Attestation First** - Before decryption, the container must prove it's running in a genuine AMD SEV-SNP TEE
3. **Key Release** - Azure Key Vault only releases the decryption key after verifying the attestation JWT
4. **Decryption Inside TEE** - The key is released directly into TEE-protected memory; decryption happens inside the hardware-isolated enclave
5. **Plaintext Never Leaves TEE** - Decrypted data exists only in encrypted memory, protected from even infrastructure operators

### Woodgrove Bank Partner Analysis

Woodgrove Bank demonstrates **trusted multi-party analytics**:
- Contoso and Fabrikam explicitly grant Woodgrove access to their Key Vaults
- Woodgrove can release partner keys after passing TEE attestation
- Enables aggregate demographic analysis across partner datasets
- All access is logged in Azure for compliance and audit

### Why Attackers Cannot Decrypt

| Attack Vector | Protection |
|--------------|------------|
| **Compromise Storage** | Data is encrypted; no key available outside TEE |
| **Compromise Network** | TLS + encrypted payloads; key never transmitted |
| **Compromise Container** | Standard containers cannot attest; no key release |
| **Compromise Hypervisor** | SEV-SNP encrypts memory at CPU level |
| **Infrastructure Operator** | Cannot read TEE memory; attestation blocks access |

## Prerequisites

- **Azure CLI** (v2.50+) - [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Azure Subscription** - With permissions to create Container Instances, Container Registry, and Key Vault
- **Docker Desktop** - [Download Docker Desktop](https://www.docker.com/products/docker-desktop/) (required for confidential container policy generation)
- **PowerShell** - Version 5.1 or later ([PowerShell 7+ recommended](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell))

### Azure CLI Extensions

```powershell
# Install or update the confcom extension (required for security policy generation)
az extension add --name confcom --upgrade

# Verify installation
az confcom --help
```

## Quick Start

### Step 1: Build the Container Image

```powershell
.\Deploy-MultiParty.ps1 -Build
```

This creates:
- **Azure Resource Group** - Named `sgall<registryname>-rg` in East US
- **Azure Container Registry (ACR)** - Basic SKU with admin enabled
- **Contoso Key Vault** - Premium HSM with `contoso-secret-key`
- **Fabrikam Key Vault** - Premium HSM with `fabrikam-secret-key`
- **Woodgrove Bank Key Vault** - Premium HSM with `woodgrove-secret-key`
- **Managed Identities** - Separate identity for each company's container
- **Cross-Company Access** - Woodgrove granted access to Contoso and Fabrikam Key Vaults
- **Container Image** - Built and pushed to ACR

### Step 2: Deploy All Containers

```powershell
.\Deploy-MultiParty.ps1 -Deploy
```

Deploys four containers:
- **Contoso** - Confidential SKU with AMD SEV-SNP TEE
- **Fabrikam** - Confidential SKU with AMD SEV-SNP TEE  
- **Woodgrove Bank** - Confidential SKU with AMD SEV-SNP TEE and partner access
- **Snooper** - Standard SKU (no TEE hardware)

> ⚠️ **Requires Docker to be running** for security policy generation.

### Combined Build and Deploy

```powershell
.\Deploy-MultiParty.ps1 -Build -Deploy
```

### Cleanup All Resources

```powershell
.\Deploy-MultiParty.ps1 -Cleanup
```

## Command Reference

| Parameter | Description |
|-----------|-------------|
| `-Build` | Build and push container image to ACR (creates RG, ACR, Key Vaults) |
| `-Deploy` | Deploy all 4 containers (Contoso, Fabrikam, Woodgrove Bank, Snooper) |
| `-Cleanup` | Delete all Azure resources in the resource group |
| `-SkipBrowser` | Don't open Microsoft Edge browser after deployment |
| `-RegistryName <name>` | Custom ACR name (default: random 8-character string) |

**Note:** Run the script without parameters to see usage help and current configuration.

### Examples

```powershell
# Show help and current configuration
.\Deploy-MultiParty.ps1

# Build with custom registry name
.\Deploy-MultiParty.ps1 -Build -RegistryName "myregistry"

# Deploy and skip browser
.\Deploy-MultiParty.ps1 -Deploy -SkipBrowser

# Full workflow: build and deploy
.\Deploy-MultiParty.ps1 -Build -Deploy

# Delete all resources
.\Deploy-MultiParty.ps1 -Cleanup
```

## What You'll See

After deployment, a browser opens with a 4-pane side-by-side comparison view:

```
+------------------+------------------+------------------+------------------+
|     CONTOSO      |     FABRIKAM     |  WOODGROVE BANK  |     SNOOPER      |
| (Confidential)   | (Confidential)   |  (Confidential)  |  (Standard)      |
|                  |                  |                  |                  |
| ✅ Attestation   | ✅ Attestation   | ✅ Attestation   | ❌ Attestation   |
| ✅ Key Release   | ✅ Key Release   | ✅ Key Release   | ❌ Key Release   |
| ✅ Encryption    | ✅ Encryption    | ✅ Partner Keys  | ❌ Encryption    |
| ✅ Own data      | ✅ Own data      | ✅ Partner data  | 👁️ Encrypted    |
+------------------+------------------+------------------+------------------+
```

### Woodgrove Bank Special Features

- **Custom branding** - Green bank theme with 🏦 logo
- **Partner Analysis System** - Dedicated section for cross-company key release
- **Progress tracking** - Visual indicators for Contoso and Fabrikam key release
- **Analysis log** - Real-time log of partner key release operations

## Demo Script

### Basic Attestation Demo

1. **Show Contoso**: Expand "Remote Attestation" → Click "Get Raw Report" → Success
2. **Show Fabrikam**: Same actions → Also succeeds
3. **Show Woodgrove Bank**: Same actions → Also succeeds (green bank theme)
4. **Show Snooper**: Same actions → Fails with detailed error

### Secure Key Release Demo

5. **Release Key on Contoso**: Expand "Secure Key Release" → Click release → Key obtained
6. **Try on Snooper**: Same actions → Key release denied
7. **Cross-Company Test**: On Contoso, expand "Cross-Company Key Access" → Shows cannot access Fabrikam's key

### Partner Analysis Demo (Woodgrove Bank)

8. **Open Woodgrove Bank**: Notice custom green bank branding
9. **Expand "Partner Demographic Analysis"**: Click "Start Partner Demographic Analysis"
10. **Watch Progress**: Contoso key release ✅, then Fabrikam key release ✅
11. **Review Log**: Shows attestation passed for each partner

### Data Protection Demo

12. **Expand "Protect Data"**: CSV automatically imported and encrypted
13. **List Records**: Shows encrypted data in table
14. **Press Decrypt**: Own company data decrypts successfully
15. **View Snooper**: Shows attacker view with all data encrypted

## Security Model

### Per-Company Key Vault Keys

Each company has a separate Key Vault with an SKR-protected key:

```
Contoso Key Vault: kv<registry>a
├── Key: contoso-secret-key (RSA-HSM, exportable)
└── Release Policy: sevsnpvm attestation required

Fabrikam Key Vault: kv<registry>b  
├── Key: fabrikam-secret-key (RSA-HSM, exportable)
└── Release Policy: sevsnpvm attestation required

Woodgrove Bank Key Vault: kv<registry>c
├── Key: woodgrove-secret-key (RSA-HSM, exportable)
├── Release Policy: sevsnpvm attestation required
└── Cross-Company Access: Can also release Contoso and Fabrikam keys
```

### Woodgrove Partner Access

Woodgrove Bank's managed identity is granted explicit access to partner Key Vaults:

```powershell
# Granted during Build phase
az keyvault set-policy --name $ContosoKeyVault --object-id $WoodgroveIdentity --key-permissions get release
az keyvault set-policy --name $FabrikamKeyVault --object-id $WoodgroveIdentity --key-permissions get release
```

### Release Policy

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

This ensures:
- Only containers with valid AMD SEV-SNP attestation can release keys
- Snooper cannot fake attestation (hardware-enforced)
- Each company's key has its own policy
- Woodgrove can access partner keys only because of explicit Key Vault access grants

## Files

| File | Description |
|------|-------------|
| `Deploy-MultiParty.ps1` | Main deployment script |
| `app.py` | Flask application with all API endpoints |
| `Dockerfile` | Multi-stage build with SKR sidecar |
| `templates/index.html` | Interactive web UI |
| `contoso-data.csv` | Sample data for Contoso (9 records) |
| `fabrikam-data.csv` | Sample data for Fabrikam (9 records) |
| `deployment-template-original.json` | ARM template for Confidential SKU |
| `deployment-template-woodgrove-base.json` | ARM template for Woodgrove with partner env vars |
| `deployment-template-standard.json` | ARM template for Standard SKU |
| `MultiPartyArchitecture.svg` | High-level architecture diagram |
| `DataFlowDiagram.svg` | Encrypted data flow diagram showing TEE decryption |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web UI |
| `/attest/maa` | POST | Request MAA attestation token |
| `/attest/raw` | POST | Get raw attestation report |
| `/skr/release` | POST | Release company's SKR key |
| `/skr/release-other` | POST | Attempt cross-company key access |
| `/skr/release-partner` | POST | Release partner key (Woodgrove only) |
| `/skr/config` | GET | Get SKR configuration |
| `/encrypt` | POST | Encrypt data with released key |
| `/decrypt` | POST | Decrypt data with released key |
| `/company/info` | GET | Get company identity |

## Troubleshooting

### Docker not running
```
ERROR: Docker is not running. Required for security policy generation.
```
**Solution:** Start Docker Desktop before running `-Deploy`.

### Policy generation fails
```
Failed to generate security policy
```
**Solution:** Ensure Docker is running and you're logged into ACR.

### No configuration found
```
acr-config.json not found. Run with -Build first.
```
**Solution:** Run `.\Deploy-MultiParty.ps1 -Build` before deploying.

### Attestation fails on confidential container
```
Attestation failed with status 500
```
**Solution:** Check container logs for detailed error messages:
```powershell
az container logs -g <resource-group> -n <container-name>
```

### Key release denied
**Solution:** Verify the managed identity has Key Vault permissions and the container is running on Confidential SKU.

### Partner key release fails (Woodgrove)
```
SKR sidecar not available
```
**Solution:** Ensure the Woodgrove container is deployed with the correct template that includes partner Key Vault environment variables.

## Additional Documentation

- [ATTESTATION.md](ATTESTATION.md) - Technical details about attestation
- [README-MultiParty.md](README-MultiParty.md) - Comprehensive multi-party demo documentation

## References

- [Azure Confidential Container Samples](https://github.com/Azure-Samples/confidential-container-samples)
- [Azure Container Instances - Confidential Containers](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)
- [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview)
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [az confcom Extension](https://learn.microsoft.com/en-us/cli/azure/confcom)

## License

MIT License
