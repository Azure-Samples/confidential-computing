# Azure Confidential Container Attestation Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** January 2026

A demonstration of Azure Container Instances (ACI) with AMD SEV-SNP confidential computing and remote attestation via Microsoft Azure Attestation (MAA).

## Overview

This project deploys a Python Flask web application to Azure Container Instances with optional hardware-based Trusted Execution Environment (TEE) protection. When deployed in confidential mode, the container runs on AMD SEV-SNP hardware and can request cryptographic attestation tokens that prove the container's integrity.

### Features

- **Interactive Web UI** - Modern interface demonstrating attestation capabilities with real-time status indicators
- **Remote Attestation** - Request JWT tokens from Microsoft Azure Attestation (MAA)
- **Hardware Security** - AMD SEV-SNP memory encryption and isolation
- **Security Policy Enforcement** - Cryptographic verification of container configuration with layer hash validation
- **Sidecar Pattern** - Uses Azure's attestation sidecar container (`mcr.microsoft.com/aci/skr:2.7`)
- **Key Vault Integration** - Secure credential storage using Azure Key Vault
- **Live Diagnostics** - Real-time attestation status and error reporting

## Prerequisites

- **Azure CLI** (v2.50+) - [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Azure Subscription** - With permissions to create Container Instances, Container Registry, and Key Vault
- **Docker Desktop** - Required for confidential mode (policy generation pulls and analyzes images)
- **PowerShell** - Version 5.1 or later (PowerShell 7+ recommended)

### Azure CLI Extensions

The confidential mode requires the `confcom` extension for security policy generation:

```powershell
# Install or update the confcom extension
az extension add --name confcom --upgrade

# Verify installation
az confcom --help
```

## Quick Start

All operations are performed using a single script: `Deploy-AttestationDemo.ps1`

### Step 1: Build the Container Image

```powershell
.\Deploy-AttestationDemo.ps1 -Build
```

This creates:
- **Azure Resource Group** - Named `sgall<registryname>-rg` in East US
- **Azure Container Registry (ACR)** - Basic SKU with admin enabled
- **Azure Key Vault** - Stores ACR credentials securely (username and password)
- **Container Image** - Built and pushed to ACR using `az acr build`
- **Configuration File** - `acr-config.json` with registry details (no secrets stored locally)

### Step 2: Deploy to Azure Container Instances

#### Confidential Mode (Default)

```powershell
.\Deploy-AttestationDemo.ps1 -Deploy
```

Deploys with:
- **Confidential SKU** - AMD SEV-SNP hardware protection with encrypted memory
- **Attestation Sidecar** - `mcr.microsoft.com/aci/skr:2.7` provides attestation endpoints
- **Security Policy** - Generated via `az confcom` with `--disable-stdio` (blocks shell access)
- **Hardened Configuration** - No elevated privileges, no stack dumps, encrypted scratch storage
- **Layer Hash Validation** - Each container layer hash is verified against the policy

> ⚠️ **Requires Docker to be running** for security policy generation. The `az confcom` tool pulls container images locally to analyze their layers.

#### Non-Confidential Mode (Testing/Development)

```powershell
.\Deploy-AttestationDemo.ps1 -Deploy -NoAcc
```

Deploys with:
- **Standard SKU** - No hardware TEE protection
- **Faster Deployment** - No Docker or policy generation required
- **Sidecar Included** - Attestation endpoint available but returns detailed error diagnostics
- **Full Diagnostics** - Deployment shows sidecar logs and `/info` endpoint status

> ℹ️ **Use this mode for testing the UI and understanding attestation failures.** The web application provides detailed error messages explaining why attestation fails without AMD SEV-SNP hardware.

### Combined Build and Deploy

```powershell
.\Deploy-AttestationDemo.ps1 -Build -Deploy
```

### Cleanup All Resources

```powershell
.\Deploy-AttestationDemo.ps1 -Cleanup
```

> 💡 **Interactive Cleanup**: After deployment, the script prompts for cleanup options:
> - `d` - Delete container only (preserve ACR and Key Vault for future deployments)
> - `a` - Delete ALL resources (entire resource group)
> - `k` - Keep everything running

## Command Reference

| Parameter | Description |
|-----------|-------------|
| `-Build` | Build and push container image to ACR (creates RG, ACR, Key Vault) |
| `-Deploy` | Deploy container to ACI (requires prior `-Build`) |
| `-Cleanup` | Delete all Azure resources in the resource group |
| `-NoAcc` | Use Standard SKU (faster, no Docker required, attestation will fail) |
| `-SkipBrowser` | Don't open Microsoft Edge browser after deployment |
| `-RegistryName <name>` | Custom ACR name (default: random 8-character string) |

**Note:** Run the script without parameters to see usage help and current configuration.

### Examples

```powershell
# Show help and current configuration
.\Deploy-AttestationDemo.ps1

# Build with custom registry name
.\Deploy-AttestationDemo.ps1 -Build -RegistryName "myregistry"

# Deploy and skip browser
.\Deploy-AttestationDemo.ps1 -Deploy -SkipBrowser

# Full workflow: build, deploy confidential, cleanup when done
.\Deploy-AttestationDemo.ps1 -Build -Deploy
```

## Architecture

### Confidential Mode

```
┌─────────────────────────────────────────────────────────┐
│                Azure Container Instance                  │
│                   (Confidential SKU)                     │
│  ┌─────────────────────┐  ┌─────────────────────────┐   │
│  │   Flask Web App     │  │   Attestation Sidecar   │   │
│  │     (Port 80)       │  │      (Port 8080)        │   │
│  │                     │  │                         │   │
│  │  /attest/maa ──────────► /attest/maa             │   │
│  │  /attest/raw ──────────► /attest/raw             │   │
│  └─────────────────────┘  └───────────┬─────────────┘   │
│                                       │                  │
│              AMD SEV-SNP TEE          │                  │
└───────────────────────────────────────┼─────────────────┘
                                        │
                                        ▼
                          ┌─────────────────────────┐
                          │  Microsoft Azure        │
                          │  Attestation (MAA)      │
                          │  sharedeus.eus.attest.  │
                          │  azure.net              │
                          └─────────────────────────┘
```

### Standard Mode

```
┌─────────────────────────────────────────────────────────┐
│                Azure Container Instance                  │
│                    (Standard SKU)                        │
│  ┌─────────────────────┐  ┌─────────────────────────┐   │
│  │   Flask Web App     │  │   Attestation Sidecar   │   │
│  │     (Port 80)       │  │      (Port 8080)        │   │
│  │                     │  │                         │   │
│  │  /attest/maa ──────────► /attest/maa             │   │
│  └─────────────────────┘  └───────────┬─────────────┘   │
│                                       │                  │
│              No TEE (Standard)        │                  │
└───────────────────────────────────────┼─────────────────┘
                                        │
                                        ▼
                          ┌─────────────────────────┐
                          │  Attestation Fails      │
                          │  (No SNP hardware)      │
                          └─────────────────────────┘
```

## Project Structure

```
├── Deploy-AttestationDemo.ps1      # Main script (build, deploy, cleanup)
├── app.py                          # Flask web application
├── Dockerfile                      # Container image definition
├── requirements.txt                # Python dependencies
├── templates/
│   └── index.html                  # Web UI template
├── deployment-template-original.json   # ARM template (confidential)
├── deployment-template-standard.json   # ARM template (standard)
└── acr-config.json                 # Generated config (no secrets)
```

## Web Application Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Interactive demo UI with real-time attestation controls |
| `/attest/maa` | POST | Request MAA attestation token (forwards to sidecar on port 8080) |
| `/attest/raw` | POST | Request raw AMD SEV-SNP attestation report |
| `/sidecar/status` | GET | Check attestation sidecar availability |
| `/info` | GET | Live deployment info with attestation status and diagnostics |
| `/health` | GET | Health check endpoint for container monitoring |

## Attestation Token Claims

When attestation succeeds, the JWT token includes claims such as:

| Claim | Description |
|-------|-------------|
| `x-ms-isolation-tee` | TEE isolation details |
| `x-ms-sevsnpvm-is-debuggable` | Debug mode status (should be false) |
| `x-ms-compliance-status` | Azure compliance status |
| `x-ms-sevsnpvm-hostdata` | Security policy hash |
| `x-ms-sevsnpvm-vmpl` | Virtual Machine Privilege Level |

## Security

- **No secrets in code** - ACR credentials stored in Azure Key Vault
- **Hardware isolation** - AMD SEV-SNP encrypts memory
- **Policy enforcement** - Container configuration cryptographically verified
- **Attestation** - Prove workload integrity to remote parties

## Troubleshooting

### Docker not running
```
ERROR: Docker is not running. Required for security policy generation.
```
**Solution:** Start Docker Desktop, or use `-NoAcc` mode for testing without security policy generation.

### Policy generation fails
```
Failed to generate security policy
```
**Solution:** Ensure Docker is running and you're logged into ACR. Try running `docker login <registry>.azurecr.io` manually.

### Attestation returns error
```
Attestation failed with status 500
```
**Solution:** This is expected in `-NoAcc` mode. The sidecar response will show details about why attestation failed (no SNP hardware). Check the `/info` endpoint for detailed diagnostics.

### No configuration found
```
acr-config.json not found. Run with -Build first.
```
**Solution:** Run `.\Deploy-AttestationDemo.ps1 -Build` before deploying.

### Sidecar connection refused
```
Attestation sidecar not available. Connection refused.
```
**Solution:** Wait for the container group to fully start (can take 1-3 minutes). Check logs with:
```powershell
az container logs -g <resource-group> -n <container-name> --container-name attestation-sidecar
```

### Container not responding
```
Container did not respond within 3 minutes
```
**Solution:** Check container state and logs in the Azure Portal. Verify the security policy allows the container to start.

## Additional Documentation

For detailed technical information about attestation, see [ATTESTATION.md](ATTESTATION.md).

## References

- [Azure Confidential Container Samples](https://github.com/Azure-Samples/confidential-container-samples)
- [Azure Container Instances - Confidential Containers](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)
- [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview)
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [az confcom Extension Documentation](https://learn.microsoft.com/en-us/cli/azure/confcom)
- [Confidential Computing on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/)

## License

MIT License
