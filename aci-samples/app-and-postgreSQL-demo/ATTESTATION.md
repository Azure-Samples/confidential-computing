# Attestation Technical Details

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** March 2026

> **Note:** See [README.md](README.md) for the main project documentation.

This document provides additional technical details about the attestation and confidential computing features in this PostgreSQL finance demo.

## Attestation Overview

Remote attestation allows a relying party to verify that:

1. **The workload runs in a genuine TEE** — AMD SEV-SNP hardware
2. **The workload hasn't been tampered with** — Security policy enforcement via ccePolicy hash
3. **The environment is properly configured** — No debugging, correct firmware version

## Architecture Security Layers

```
┌──────────────────────────────────────────────────────────────┐
│  Application Gateway (Layer 7)                                │
│  - Public IP entry point                                      │
│  - Health probes to /health endpoint                          │
│  - Routes traffic to ACI private IP                           │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  AMD SEV-SNP Trusted Execution Environment                    │
│  ┌──────────────────────────────────────────────────────────┐│
│  │  Confidential ACI Container (Private VNet)               ││
│  │                                                           ││
│  │  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐   ││
│  │  │  Nginx   │──│ Flask/Gunicorn│──│  SKR Sidecar     │   ││
│  │  │  :80/:443│  │  :8000       │  │  :8080           │   ││
│  │  └──────────┘  └──────┬───────┘  └────────┬─────────┘   ││
│  │                       │                    │              ││
│  │                       │                    │              ││
│  └───────────────────────┼────────────────────┼──────────────┘│
│                          │                    │               │
│  Hardware Memory Encryption (CPU-level)       │               │
└──────────────────────────┼────────────────────┼───────────────┘
                           │                    │
                ┌──────────▼────────┐  ┌───────▼────────────┐
                │  PostgreSQL       │  │  Azure Attestation  │
                │  Flexible Server  │  │  (MAA)              │
                │  DC-series (CC)   │  │                     │
                │  TLS connection   │  │  Validates SNP      │
                └───────────────────┘  │  report, issues JWT │
                                       └────────┬────────────┘
                                                 │
                                       ┌─────────▼───────────┐
                                       │  Azure Key Vault     │
                                       │  (Premium, HSM)      │
                                       │                      │
                                       │  Release key only if │
                                       │  policy hash matches │
                                       └──────────────────────┘
```

## Attestation Flow

The demo uses a single container with Flask, Nginx, and SKR services managed by supervisord.

### 1. Container Startup

```
supervisord
├── SKR Sidecar (priority 1, startsecs=2)
│   └── Listens on port 8080 for attestation requests
├── Flask/Gunicorn (priority 10, startsecs=5)
│   └── Listens on port 8000, connects to PostgreSQL
└── Nginx (priority 20, startsecs=2)
    └── Listens on ports 80/443, proxies to Flask
```

### 2. MAA Attestation Request

```
Browser                Flask App              SKR Sidecar           MAA Service
   │                      │                      │                      │
   │  POST /attest/maa    │                      │                      │
   │─────────────────────►│                      │                      │
   │                      │  POST /attest/maa    │                      │
   │                      │─────────────────────►│                      │
   │                      │                      │                      │
   │                      │                      │  GET SNP Report      │
   │                      │                      │  (from CPU hardware) │
   │                      │                      │                      │
   │                      │                      │  POST /attest        │
   │                      │                      │─────────────────────►│
   │                      │                      │                      │
   │                      │                      │  JWT Token           │
   │                      │                      │◄─────────────────────│
   │                      │  JWT + Claims        │                      │
   │                      │◄─────────────────────│                      │
   │  Claims + Decoded JWT│                      │                      │
   │◄─────────────────────│                      │                      │
```

### 3. Secure Key Release

```
Flask App              SKR Sidecar           MAA Service         Key Vault
   │                      │                      │                   │
   │  POST /key/release   │                      │                   │
   │─────────────────────►│                      │                   │
   │                      │  SNP Attestation     │                   │
   │                      │─────────────────────►│                   │
   │                      │  JWT (with claims)   │                   │
   │                      │◄─────────────────────│                   │
   │                      │                      │                   │
   │                      │  Release Key (JWT)   │                   │
   │                      │──────────────────────────────────────────►│
   │                      │                      │                   │
   │                      │                      │  Verify:           │
   │                      │                      │  - attestation-type│
   │                      │                      │    = "sevsnpvm"    │
   │                      │                      │  - hostdata        │
   │                      │                      │    = policy hash   │
   │                      │                      │                   │
   │                      │  Released Key        │                   │
   │                      │◄──────────────────────────────────────────│
   │  Key Material        │                      │                   │
   │◄─────────────────────│                      │                   │
```

## Key Attestation Claims

When MAA validates the SNP report, the JWT contains these critical claims:

| Claim | Description | Example Value |
|-------|-------------|---------------|
| `x-ms-attestation-type` | Type of attestation | `sevsnpvm` |
| `x-ms-sevsnpvm-hostdata` | SHA256 of container security policy | `a1b2c3...` (64 hex chars) |
| `x-ms-sevsnpvm-is-debuggable` | Whether debugging is enabled | `false` |
| `x-ms-sevsnpvm-vmpl` | Virtual Machine Privilege Level | `0` (most privileged) |
| `x-ms-compliance-status` | Security compliance status | `azure-compliant-cvm` |
| `x-ms-sevsnpvm-snpfw-svn` | SNP firmware security version | Version number |

## Security Policy Binding

The `x-ms-sevsnpvm-hostdata` claim is critical — it contains the SHA256 hash of the container's security policy (ccePolicy). This policy hash is:

1. **Generated by `az confcom`** — From the ARM deployment template and parameters
2. **Embedded in the ARM template** — As the `ccePolicy` base64-encoded Rego policy
3. **Verified by MAA** — During attestation, the hardware-reported hash must match
4. **Required by Key Vault** — The release policy requires this exact hash value

This creates a **cryptographic binding** between the container code and the encryption keys — only a container with the exact approved code can release the keys.

## PostgreSQL DCa/ECa-Series AMD Protection

The DCa/ECa-series AMD PostgreSQL Flexible Server adds database-level confidential computing (note: `eds` SKUs are Intel TDX and do NOT support PostgreSQL CC — only AMD `ads` SKUs like DC2ads_v5 and EC2ads_v5 are supported):

- **Memory Encryption** — Database query processing occurs in encrypted memory
- **TLS Connections** — All connections between ACI and PostgreSQL use TLS (sslmode=require)
- **Firewall Rules** — Limited to Azure services + deployer IP during setup
- **No Plaintext Exposure** — Data flows encrypted from database → ACI TEE memory

## Why Attackers Cannot Access Data

This architecture protects against specific, real-world threat scenarios through multiple overlapping security layers:

| Attack Vector | Protection | How It Works |
|--------------|------------|-------------|
| **Intercept Network** | TLS encryption on all connections | `sslmode=require` on PostgreSQL; HTTPS between browser and App Gateway |
| **Compromise ACI Host** | AMD SEV-SNP memory encryption at CPU level | Hardware enforces memory isolation — hypervisor cannot read TEE memory even with root access |
| **Compromise Database Host** | DCa/ECa AMD confidential computing protection | PostgreSQL query processing occurs in encrypted memory on AMD SEV-SNP hardware |
| **Deploy Rogue Container** | Attestation fails — different policy hash | `x-ms-sevsnpvm-hostdata` contains SHA256 of ccePolicy; any container modification produces a different hash |
| **Disable Attestation** | Key Vault requires valid attestation JWT | SKR release policy mandates `attestation-type=sevsnpvm` and matching `hostdata` hash |
| **Access from Internet** | ACI is on private VNet, no public IP | Container subnet `10.0.1.0/24` has no public route; only App Gateway can reach it |
| **Compromise App Gateway** | Only routes traffic, cannot access TEE memory | App Gateway is a Layer 7 proxy — it never sees decrypted application data inside the TEE |
| **Modify Container Image** | Policy hash changes, attestation fails | Docker image layers are included in the confcom policy hash computation |
| **Insider Threat (Cloud Operator)** | SEV-SNP TEE boundary prevents access | Even privileged Azure operators cannot read memory inside the hardware-protected TEE |
| **Attach Debugger** | `is-debuggable=false` enforced by attestation | MAA verifies the TEE is non-debuggable; SKR policy rejects debuggable VMs |

### PostgreSQL-Specific Protections

The DCa/ECa-series AMD PostgreSQL Flexible Server provides database-level confidential computing beyond standard encryption:

1. **Query Processing in Encrypted Memory** — SQL operations (joins, aggregations, filtering) execute in SEV-SNP protected memory. A DBA or cloud operator cannot inspect intermediate query results.
2. **TLS-Encrypted Connections** — All data in transit between the ACI container and PostgreSQL uses TLS (`sslmode=require`). Certificate validation prevents MITM attacks.
3. **Firewall Rules** — PostgreSQL is not exposed to the public internet. Access is limited to Azure services and the deployer's IP (temporarily, during setup).
4. **No Plaintext Exposure** — The data path from database storage → query engine → network → ACI TEE is encrypted at every stage. Plaintext only exists inside the respective TEE boundaries.

> ⚠️ **Important SKU distinction:** `eds` SKUs (e.g., DC2eds_v5) are **Intel TDX** and do **NOT** support PostgreSQL confidential computing. Only AMD `ads` SKUs (e.g., DC2ads_v5, EC2ads_v5) are supported for PostgreSQL CC.

## Container Services

| Service | Port | Purpose |
|---------|------|---------|
| SKR Sidecar | 8080 | AMD SEV-SNP attestation + key release |
| Flask/Gunicorn | 8000 | Web application + PostgreSQL analytics |
| Nginx | 80, 443 | Reverse proxy + TLS termination |
| supervisord | — | Process management and health monitoring |

## Related Documentation

- [Azure Confidential Computing](https://learn.microsoft.com/azure/confidential-computing/)
- [Confidential Containers on ACI](https://learn.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Microsoft Azure Attestation](https://learn.microsoft.com/azure/attestation/)
- [Secure Key Release](https://learn.microsoft.com/azure/confidential-computing/concept-skr-attestation)
- [PostgreSQL Flexible Server](https://learn.microsoft.com/azure/postgresql/flexible-server/)
