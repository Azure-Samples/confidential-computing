# Attestation Technical Details

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** February 2026

> **Note:** See [README.md](README.md) for the main project documentation.

This document provides additional technical details about the attestation features in this demo.

## Attestation Overview

Remote attestation allows a relying party to verify that:

1. **The workload runs in a genuine TEE** - AMD SEV-SNP hardware
2. **The workload hasn't been tampered with** - Security policy enforcement
3. **The environment is properly configured** - No debugging, correct firmware

## Encrypted Data Flow

![Data Flow Diagram](DataFlowDiagram.svg)

The key security principle: **data is encrypted at rest and in transit; decryption ONLY happens inside the TEE**.

| Zone | Data State | Who Can Access |
|------|-----------|----------------|
| **Blob Storage** | Encrypted (RSA-OAEP-256) | Anyone (but useless without key) |
| **Network Transit** | Encrypted (TLS + payload encryption) | Cannot be decrypted |
| **Standard Container** | Encrypted (no key access) | Cannot decrypt - attestation fails |
| **TEE Memory** | Decrypted (hardware-protected) | Only the TEE workload |

### Why TEE Decryption is Secure

1. **Hardware Memory Encryption**: AMD SEV-SNP encrypts all memory at the CPU level
2. **Key Isolation**: Decryption keys exist only in TEE-protected memory
3. **Attestation Binding**: Keys are only released after hardware attestation proves TEE integrity
4. **Hypervisor Excluded**: Even the cloud infrastructure cannot read TEE memory

### Attestation Flow

The demo uses a single container with both Flask and SKR (Secure Key Release) services managed by supervisord.

```
┌──────────────┐     ┌─────────────────────────────────────────────┐
│   Browser    │     │           Combined Container                 │
│              │     │  ┌─────────────────┐  ┌─────────────────┐   │
└──────┬───────┘     │  │   Flask App     │  │  SKR Service    │   │
       │             │  │   (Port 80)     │  │  (Port 8080)    │   │
       │             │  └────────┬────────┘  └────────┬────────┘   │
       │             └───────────┼────────────────────┼────────────┘
       │                         │                    │
       │  POST /attest/maa       │                    │
       │────────────────────────►│                    │
       │                         │  POST /attest/maa  │
       │                         │───────────────────►│
       │                         │                    │
       │                         │    ┌───────────────┼─────────────────┐
       │                         │    │               ▼                 │
       │                         │    │  ┌─────────────────────────┐    │
       │                         │    │  │   AMD SEV-SNP Hardware  │    │
       │                         │    │  │   Generate SNP Report   │    │
       │                         │    │  └────────────┬────────────┘    │
       │                         │    │               │                 │
       │                         │    │               ▼                 │
       │                         │    │  ┌─────────────────────────┐    │
       │                         │    │  │   Microsoft Azure       │    │
       │                         │    │  │   Attestation (MAA)     │    │
       │                         │    │  │   Verify & Sign JWT     │    │
       │                         │    │  └────────────┬────────────┘    │
       │                         │    │               │                 │
       │                         │    └───────────────┼─────────────────┘
       │                         │                    │
       │                         │◄───────────────────│
       │                         │    JWT Token       │
       │◄────────────────────────│                    │
       │   Display Token         │                    │
       │   & Claims              │                    │
```

## JWT Token Structure

The attestation token is a signed JWT with three parts:

### Header
```json
{
  "alg": "RS256",
  "jku": "https://sharedeus.eus.attest.azure.net/certs",
  "kid": "<key-id>",
  "typ": "JWT"
}
```

### Payload Claims

| Claim | Description |
|-------|-------------|
| `x-ms-isolation-tee` | TEE type and configuration |
| `x-ms-sevsnpvm-is-debuggable` | Debug mode (must be `false` for production) |
| `x-ms-sevsnpvm-vmpl` | Virtual Machine Privilege Level |
| `x-ms-sevsnpvm-hostdata` | SHA256 of security policy |
| `x-ms-sevsnpvm-guestsvn` | Guest Security Version Number |
| `x-ms-compliance-status` | Azure compliance status |
| `x-ms-ver` | Attestation service version |
| `iss` | Issuer (MAA endpoint) |
| `exp` | Token expiration |
| `iat` | Issued at timestamp |
| `jti` | Unique token ID |

### Signature

The token is signed by MAA using RSA-256. The public key can be retrieved from the JKU (JSON Web Key URL) in the header.

## Security Policy

> **📄 Full annotated example:** See [SECURITY-POLICY.md](SECURITY-POLICY.md) for a complete decoded ccePolicy with detailed explanations of every section, environment variable rules, capability analysis, and the multi-party trust chain.

The security policy (`ccePolicy`) is generated by `az confcom` and includes:

- **Allowed container images** - Exact image IDs (registry/image:tag)
- **Image layer hashes** - SHA256 hashes of each layer (must match exactly)
- **Allowed commands** - Entry points and arguments
- **Environment variables** - Allowed env var patterns
- **Mount points** - Allowed filesystem mounts
- **Capabilities** - Linux capabilities
- **Stdio access** - Disabled to prevent interactive shell access
- **Exec processes** - Empty list (no exec allowed)

The policy is base64-encoded Rego and embedded in the ARM template.

### Container Image Enforcement

Each container in the policy specifies:
- `id` - The exact image reference (e.g., `myacr.azurecr.io/aci-attestation-demo:latest`)
- `layers` - Array of SHA256 hashes for each image layer

**Only containers with matching image IDs AND layer hashes can run.** If an attacker modifies any layer, the hash won't match and the container will be rejected.

Example from the policy:
```json
{
  "id": "myacr.azurecr.io/aci-attestation-demo:latest",
  "layers": [
    "ffeb5c88c5667f9edaa3b8380636b4c3c9057dd53d11e78f691f4fc3497e57d7",
    "a6d080858cb2a978e86257b184dc8b8610a5d0a42c0392122033d89a93351f64",
    ...
  ]
}
```

### Security Hardening

The policy is generated with the `--disable-stdio` flag which:
- Sets `allow_stdio_access` to `false` for all containers
- Prevents `az container exec` and shell access
- Blocks interactive debugging into the TEE
- Ensures container contents remain confidential

Additional hardening settings:
| Setting | Value | Effect |
|---------|-------|--------|
| `allow_elevated` | `false` | No root privilege escalation |
| `allow_dump_stacks` | `false` | No debug stack dumps |
| `allow_runtime_logging` | `false` | No runtime logging |
| `allow_unencrypted_scratch` | `false` | All scratch storage encrypted |
| `exec_processes` | `[]` | No additional processes can be executed |

### Generating the Policy

```powershell
az confcom acipolicygen -a deployment-template.json --parameters deployment-params.json --disable-stdio
```

This:
1. Pulls container images locally
2. Analyzes image layers and configuration
3. Generates Rego policy
4. Encodes and injects into template

## SKR Service (Secure Key Release)

The SKR binary is extracted from `mcr.microsoft.com/aci/skr:2.13` during the Docker multi-stage build and runs alongside Flask via supervisord. It provides the following endpoints on port 8080:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/attest/maa` | POST | Request MAA attestation token |
| `/attest/raw` | POST | Get raw SNP attestation report |
| `/key/release` | POST | Release a key from Azure Key Vault |
| `/status` | GET | SKR service health status |

### How Secure Key Release Works

SKR is a cryptographic protocol that allows Azure Key Vault to release encryption keys **only** to containers that can prove they are running in a genuine hardware TEE. The process involves:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Container     │     │  SKR Sidecar    │     │  Azure MAA      │     │  Azure Key Vault│
│   (app.py)      │     │  (port 8080)    │     │                 │     │  (Premium HSM)  │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │                       │
         │  POST /key/release    │                       │                       │
         │──────────────────────>│                       │                       │
         │                       │                       │                       │
         │                       │  Get SNP Report       │                       │
         │                       │  (AMD Hardware)       │                       │
         │                       │──────────┐            │                       │
         │                       │          │            │                       │
         │                       │<─────────┘            │                       │
         │                       │                       │                       │
         │                       │  POST /attest/maa     │                       │
         │                       │──────────────────────>│                       │
         │                       │                       │                       │
         │                       │  JWT Token (signed)   │                       │
         │                       │<──────────────────────│                       │
         │                       │                       │                       │
         │                       │  POST /keys/{name}/release                    │
         │                       │  (with MAA JWT)       │                       │
         │                       │──────────────────────────────────────────────>│
         │                       │                       │                       │
         │                       │                       │    Verify JWT claims  │
         │                       │                       │    Check policy hash  │
         │                       │                       │    Match hostdata     │
         │                       │                       │                       │
         │                       │                       │    Released Key (JWE) │
         │                       │<──────────────────────────────────────────────│
         │                       │                       │                       │
         │  Decrypted Key (RSA)  │                       │                       │
         │<──────────────────────│                       │                       │
```

### Policy Hash Binding

**Critical**: The `x-ms-sevsnpvm-hostdata` claim in the MAA JWT contains a hash that identifies the container's security policy. Azure Key Vault compares this against the hash specified in the key's release policy.

The policy hash is computed by `az confcom acipolicygen` and output to stdout as a 64-character hex string. **This is NOT the same as SHA256 of the base64-encoded policy!**

```powershell
# Correct way to get the policy hash (from confcom output)
$output = az confcom acipolicygen -a template.json --parameters params.json --disable-stdio 2>&1
$policyHash = ($output | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -Last 1).Trim()

# This is WRONG - produces different hash:
# $policyBase64 = $template.properties.confidentialComputeProperties.ccePolicy
# $wrongHash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyBase64))).Replace("-","").ToLower()
```

### MAA Request Format

```json
{
  "maa_endpoint": "sharedeus.eus.attest.azure.net",
  "runtime_data": "<base64-encoded-data>"
}
```

### MAA Response

```json
{
  "token": "<jwt-attestation-token>"
}
```

### Key Release Request Format

```json
{
  "maa_endpoint": "sharedeus.eus.attest.azure.net",
  "akv_endpoint": "mykeyvault.vault.azure.net",
  "kid": "my-secret-key"
}
```

### Key Release Response (Success)

```json
{
  "key": {
    "kty": "RSA",
    "n": "<modulus>",
    "e": "AQAB",
    "d": "<private-exponent>",
    "key_ops": ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  }
}
```

## Dynamic Security Features UI

The web UI dynamically updates security feature indicators based on attestation results:

| Feature | Verified When |
|---------|---------------|
| AMD SEV-SNP TEE | Token contains `x-ms-isolation-tee` |
| Memory Encryption | Token contains `x-ms-sevsnpvm-vmpl` |
| Data Confidentiality | Compliance status is `azure-compliant-cvm` |
| Security Policy | Token contains `x-ms-sevsnpvm-hostdata` |
| Remote Attestation | Valid token received |
| Runtime Protection | `x-ms-sevsnpvm-is-debuggable` is `false` |

## Files Reference

| File | Purpose |
|------|---------|
| `Deploy-MultiParty.ps1` | Main script for build, deploy, cleanup || `SECURITY-POLICY.md` | Annotated ccePolicy (Rego) with real example and security analysis || `app.py` | Flask routes, forwards attestation requests to SKR |
| `supervisord.conf` | Process supervisor config for Flask + SKR |
| `templates/index.html` | Interactive UI with JavaScript for attestation |
| `deployment-template-original.json` | ARM template with Confidential SKU |
| `deployment-template-standard.json` | ARM template with Standard SKU |
| `Dockerfile` | Multi-stage build (Flask + SKR binary) |
| `requirements.txt` | Python dependencies (Flask, requests) |
| `acr-config.json` | Generated configuration (no secrets, created by `-Build`) |

## Troubleshooting Attestation

### Debug API Endpoints

The Flask application exposes several debugging endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/debug/attestation-claims` | GET | Get MAA attestation and decode JWT claims - **critical for debugging SKR failures** |
| `/skr/config` | GET | View SKR configuration (endpoints, key names, policy hashes) |
| `/skr/key-status` | GET | Check if a key has been released |
| `/skr/release` | POST | Attempt Secure Key Release |
| `/info` | GET | Full container info with live attestation test |
| `/health` | GET | Simple health check |

### Using `/debug/attestation-claims`

This is the **most important debugging endpoint** for SKR failures. It shows:
- The **actual** `x-ms-sevsnpvm-hostdata` from hardware attestation
- The **expected** policy hash from deployment configuration
- Whether they **match** (if not, SKR will fail with 403)

```powershell
# Test attestation claims
Invoke-RestMethod -Uri "http://contoso-YYYYMMDD.eastus.azurecontainer.io/debug/attestation-claims" | ConvertTo-Json -Depth 10
```

**Example response (mismatch detected):**
```json
{
  "status": "success",
  "comparison": {
    "actual_hostdata": "49ca0663a1f128f90a4e7f58db9bf9dedb374f52491826e3480845ec7ccbe4a7",
    "expected_policy_hash": "a3d2e479...",
    "match": false,
    "attestation_type": "sevsnpvm"
  },
  "diagnosis": {
    "problem": "MISMATCH - The actual hostdata does not match the expected policy hash!",
    "solution": "The policy hash computed during deployment does not match what Azure puts in x-ms-sevsnpvm-hostdata. Check the hash computation method."
  }
}
```

### Using `/skr/release`

Test key release directly:

```powershell
# Test SKR
Invoke-RestMethod -Uri "http://contoso-YYYYMMDD.eastus.azurecontainer.io/skr/release" -Method POST -ContentType "application/json" -Body "{}" | ConvertTo-Json -Depth 5
```

**Success response:**
```json
{
  "status": "success",
  "message": "Secure Key Release successful!",
  "key": { "kty": "RSA", "n": "...", "e": "AQAB", ... },
  "release_policy": {
    "maa_endpoint": "https://sharedeus.eus.attest.azure.net",
    "required_claims": [
      { "claim": "x-ms-attestation-type", "value": "sevsnpvm" },
      { "claim": "x-ms-sevsnpvm-hostdata", "value": "49ca0663..." }
    ]
  }
}
```

**Error response (403 - policy mismatch):**
```json
{
  "status": "error",
  "message": "Secure Key Release failed with status 403",
  "failure_reason": "Forbidden - attestation failed to meet key release policy requirements",
  "diagnosis": {
    "likely_cause": "The x-ms-sevsnpvm-hostdata claim does not match the key's release policy"
  }
}
```

### Using `/skr/config`

View the current SKR configuration:

```powershell
Invoke-RestMethod -Uri "http://contoso-YYYYMMDD.eastus.azurecontainer.io/skr/config" | ConvertTo-Json
```

### Common SKR Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| **403 Forbidden** | Policy hash mismatch | Use `/debug/attestation-claims` to compare hashes. The policy hash in the key's release policy must match `x-ms-sevsnpvm-hostdata` from attestation |
| **500 Internal Error** | No TEE hardware | Container deployed with Standard SKU. Redeploy with Confidential SKU |
| **Connection refused** | SKR sidecar not running | Check container logs; wait for full startup |
| **401 Unauthorized** | Key Vault permissions | Grant container identity access to Key Vault keys |
| **404 Not Found** | Key doesn't exist | Check key name matches what's in Key Vault |

### Root Cause: Policy Hash Computation

The most common SKR failure is a 403 due to policy hash mismatch. The `x-ms-sevsnpvm-hostdata` claim is set by Azure from the security policy hash computed by `az confcom acipolicygen`.

**Important**: This hash is output to stdout by confcom - it is NOT the SHA256 of the base64-encoded policy string!

```powershell
# CORRECT: Capture hash from confcom output
$output = az confcom acipolicygen -a template.json --parameters params.json --disable-stdio 2>&1
$policyHash = ($output | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -Last 1).Trim()
Write-Host "Use this hash in release policy: $policyHash"
```

### "Connection refused" error

The SKR service is not running. Check container logs to verify supervisord started both processes:
```powershell
az container logs -g <resource-group> -n <container-name> --container-name attestation-demo
```

### "400 Bad Request" from MAA

Check the MAA endpoint format. It should be just the hostname without `https://`:
```
sharedeus.eus.attest.azure.net
```

### Token parsing fails

The token may be malformed. Check the raw response in the browser console.

### Claims show unexpected values

Verify the container is running on confidential hardware:
```powershell
az container show --name <name> --resource-group <rg> --query "sku"
# Should return "Confidential"
```

### Attestation fails on Snooper container

This is expected. The Snooper container is deployed with Standard SKU (no TEE hardware), so attestation will fail. The error response from the SKR service will be displayed in the UI, demonstrating what happens when a non-confidential container attempts to access protected resources.

## Complete API Reference

### Flask Application Endpoints (Port 80)

| Endpoint | Method | Description | Use Case |
|----------|--------|-------------|----------|
| `/` | GET | Main web UI | Interactive demo |
| `/health` | GET | Health check | Load balancer probes |
| `/info` | GET | Deployment info with live attestation test | Debugging container state |
| `/attest/maa` | POST | Get MAA attestation token | Verify TEE status |
| `/attest/raw` | POST | Get raw SNP attestation report | Low-level debugging |
| `/skr/release` | POST | Release key from Azure Key Vault | Main SKR operation |
| `/skr/config` | GET | View SKR configuration | Check setup |
| `/skr/key-status` | GET | Check if key is released | Verify key availability |
| `/skr/release-partner` | POST | Release partner company's key (Woodgrove only) | Multi-party analytics |
| `/debug/attestation-claims` | GET | **Decode attestation JWT and compare hashes** | **Critical for SKR debugging** |
| `/encrypt-data` | POST | Encrypt data using released key | Demo encryption |
| `/decrypt-data` | POST | Decrypt data using released key | Demo decryption |

### SKR Sidecar Endpoints (Port 8080 - Internal)

These endpoints are called by the Flask app, not directly by users:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/attest/maa` | POST | Request MAA JWT token |
| `/attest/raw` | POST | Get raw SNP report |
| `/key/release` | POST | Release key from Key Vault |
| `/status` | GET | Sidecar health status |

### Quick Debugging Commands

```powershell
# Check if container is confidential
az container show --name <name> --resource-group <rg> --query "sku"

# View container logs
az container logs -g <rg> -n <name> --container-name attestation-demo

# Test attestation claims (most important for SKR debugging)
Invoke-RestMethod -Uri "http://<fqdn>/debug/attestation-claims" | ConvertTo-Json -Depth 10

# Test SKR
Invoke-RestMethod -Uri "http://<fqdn>/skr/release" -Method POST -Body "{}" -ContentType "application/json"

# Check SKR config
Invoke-RestMethod -Uri "http://<fqdn>/skr/config" | ConvertTo-Json

# Full deployment info
Invoke-RestMethod -Uri "http://<fqdn>/info" | ConvertTo-Json -Depth 5
```

## References

- [ACI Confidential Containers Overview](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)
- [Azure Attestation Overview](https://learn.microsoft.com/en-us/azure/attestation/overview)
- [AMD SEV-SNP Technical Documentation](https://www.amd.com/en/developer/sev.html)
- [az confcom Extension](https://learn.microsoft.com/en-us/cli/azure/confcom)
