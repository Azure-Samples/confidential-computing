# Confidential ACI + PostgreSQL Finance Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** March 2026

## 🤖 AI-Generated Content

> **Note:** This demonstration was **created using AI-assisted development** with GitHub Copilot powered by Claude. While functional, AI-generated code should always be reviewed by qualified security professionals before use in production scenarios.

A demonstration of Azure Confidential Container Instances (ACI) connected to a PostgreSQL Flexible Server using DC-series confidential computing SKUs, showing how financial analytics can be performed inside a hardware-protected Trusted Execution Environment (TEE) with data stored in a confidential database.

## Overview

This project deploys a **single confidential container** connected to a **confidential PostgreSQL database** to demonstrate end-to-end confidential computing for financial analytics:

| Component | Type | Security | Purpose |
|-----------|------|----------|---------|
| **ACI Container** | Confidential (AMD SEV-SNP TEE) | Hardware memory encryption | Runs Flask analytics dashboard |
| **PostgreSQL Flexible Server** | DCa/ECa-series AMD (Confidential Computing) | Encrypted processing | Stores 5000 financial transactions |
| **Application Gateway** | Standard_v2 (Layer 7) | Public entry point | Routes traffic to private ACI container |
| **Virtual Network** | Private (10.0.0.0/16) | Network isolation | Isolates ACI container from public internet |

### Key Features

- **Confidential ACI Container** — AMD SEV-SNP memory encryption at the CPU level
- **DCa/ECa-Series PostgreSQL** — AMD confidential computing SKUs for database-level protection
- **Private VNet** — ACI container runs on a private IP, accessible only through Application Gateway
- **Remote Attestation** — Cryptographic proof via Microsoft Azure Attestation (MAA)
- **Secure Key Release (SKR)** — Keys only released to attested confidential containers
- **Financial Dashboard** — Interactive Chart.js analytics with 6 chart types, KPI cards, and data tables
- **Health Monitoring** — Real-time endpoint health checks with latency tracking (auto-refreshes every 30 seconds)
- **SSE Progress** — Server-Sent Events streaming for analytics loading with progress indicators

## Architecture

```
Internet
    │
    ▼
┌──────────────────────────────────┐
│  Application Gateway             │
│  (Public IP, Standard_v2)        │
│  Health Probe: /health           │
└──────────────┬───────────────────┘
               │ HTTP (port 80)
               ▼
┌──────────────────────────────────┐     ┌──────────────────────────────┐
│  ACI Container (Confidential)    │     │  PostgreSQL Flexible Server   │
│  ┌──────────┐  ┌──────────────┐  │     │  (DC-series, TLS)            │
│  │ Nginx    │  │ Flask/Gunicorn│  │────►│                              │
│  │ (port 80)│  │ (port 8000)  │  │     │  Database: financedemo       │
│  └──────────┘  └──────────────┘  │     │  5000 transactions           │
│  ┌──────────────────────────────┐│     └──────────────────────────────┘
│  │ SKR Sidecar (port 8080)     ││
│  └──────────────────────────────┘│
│  AMD SEV-SNP TEE (Private VNet)  │
│  Subnet: 10.0.1.0/24            │
└──────────────────────────────────┘

VNet: 10.0.0.0/16
├── aci-subnet:   10.0.1.0/24 (delegated: Microsoft.ContainerInstance)
└── appgw-subnet: 10.0.2.0/24
```

## Prerequisites

- **Azure CLI** with `confcom` and `rdbms-connect` extensions
- **Docker Desktop** (required for security policy generation)
- **Azure subscription** with access to:
  - Confidential ACI (AMD SEV-SNP)
  - PostgreSQL Flexible Server DCa/ECa-series AMD SKUs
- **Microsoft Edge** (optional, for auto-opening demo)

## Quick Start

### 1. Build

```powershell
.\Deploy-PostgreSQLDemo.ps1 -Prefix "sg01" -Build
```

This creates:
- Resource Group with all resources
- Azure Container Registry (ACR)
- Key Vault (Premium SKU for HSM-backed keys)
- Managed identity with Key Vault access
- Builds and pushes the Docker container image

### 2. Deploy

```powershell
.\Deploy-PostgreSQLDemo.ps1 -Prefix "sg01" -Deploy
```

This deploys:
1. **Virtual Network** with ACI and Application Gateway subnets
2. **PostgreSQL Flexible Server** (DCa/ECa AMD series) with firewall rules
3. **Database** created and seeded with 5000 financial transactions
4. **Confidential Computing security policy** generated via `az confcom`
5. **SKR key** created with policy hash binding
6. **ACI container** deployed to private VNet
7. **Application Gateway** created with health probe routing to ACI

### 3. Build + Deploy (Combined)

```powershell
.\Deploy-PostgreSQLDemo.ps1 -Prefix "sg01" -Build -Deploy
```

### 4. Cleanup

```powershell
.\Deploy-PostgreSQLDemo.ps1 -Cleanup
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Prefix` | Yes (Build/Deploy) | — | Unique 3-8 char identifier (e.g., "sg01") |
| `-Build` | No | — | Build and push container image |
| `-Deploy` | No | — | Deploy all infrastructure |
| `-Cleanup` | No | — | Delete all Azure resources |
| `-SkipBrowser` | No | — | Don't open Edge after deployment |
| `-RegistryName` | No | Random | Custom ACR name |
| `-Location` | No | `uaenorth` | Azure region (UAE North for DCa/ECa AMD SKU availability) |
| `-Description` | No | — | Optional resource group description tag |

## Dashboard Features

### Financial Analytics
- **Category Spend** — Horizontal bar chart of spending by merchant category
- **Hourly Transactions** — Line chart showing transaction patterns throughout the day
- **Grocery Hours** — Bar chart highlighting peak grocery shopping times
- **Day-of-Week** — Bar chart of transaction volume by day
- **Age Groups** — Dual-axis bar chart with transaction counts and average amounts by age bracket
- **Country Spending** — Horizontal bar chart of spending by country

### KPI Cards
- Total transactions, data source (PostgreSQL DC-series), query time, unique categories
- Average mortgage/car loan/student loan amounts, peak grocery hour

### Health Monitoring
The bottom section provides real-time health monitoring with 30-second auto-refresh:
- **TEE Status** — AMD SEV-SNP hardware attestation availability
- **Sidecar Status** — SKR sidecar service health
- **SKR Configuration** — Secure Key Release service configuration
- **Database Connection** — PostgreSQL connectivity and row count
- **Average DB Latency** — Rolling average from 3 ping measurements
- **API Endpoints** — Status of all REST API endpoints

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard (HTML) |
| `/health` | GET | Simple health check (for Application Gateway probes) |
| `/health/endpoints` | GET | Comprehensive health with latency measurements |
| `/db/status` | GET | Database connectivity, latency, row count |
| `/db/analytics` | GET | Full financial analytics from PostgreSQL |
| `/db/analytics-stream` | GET | SSE-based analytics with progress updates |
| `/attest/maa` | POST | MAA attestation via SKR sidecar |
| `/attest/raw` | POST | Raw SNP attestation report |
| `/sidecar/status` | GET | SKR sidecar service status |
| `/skr/release` | POST | Secure Key Release operation |
| `/skr/config` | GET | SKR configuration details |
| `/security/policy` | GET | Container security policy (ccePolicy) |
| `/info` | GET | Container and environment information |

## Security Model

### Defense in Depth

| Layer | Protection |
|-------|-----------|
| **Application Gateway** | Layer 7 load balancing, health probes |
| **Private VNet** | ACI container has no public IP |
| **AMD SEV-SNP** | Hardware memory encryption at CPU level |
| **DCa/ECa-Series PostgreSQL** | AMD confidential compute-enabled database |
| **TLS/SSL** | Encrypted database connections (sslmode=require) |
| **MAA Attestation** | Cryptographic proof of TEE integrity |
| **SKR** | Keys bound to specific container security policy hash |
| **Managed Identity** | No credentials stored in code |

### Attestation Flow

1. Container starts in AMD SEV-SNP TEE
2. SKR sidecar becomes available on port 8080
3. Flask app can request attestation via sidecar
4. MAA validates the SNP report and issues JWT
5. JWT contains claims including `x-ms-sevsnpvm-hostdata` (policy hash)
6. Key Vault releases keys only if policy hash matches

> **📄 Attestation Details:** See [ATTESTATION.md](ATTESTATION.md) for the full technical details of the attestation flow.

## Threat Scenarios

This architecture specifically protects against the following threat scenarios:

| # | Threat Scenario | Attack Description | Mitigation | Component |
|---|----------------|--------------------|-----------:|-----------|
| 1 | **Data-in-use exposure** | Malicious host OS or hypervisor operator reads application memory while data is being processed | AMD SEV-SNP encrypts all VM memory at the CPU level — the hypervisor cannot read TEE memory even with root access | ACI (SEV-SNP) |
| 2 | **Unauthorized container substitution** | Attacker deploys a rogue container on the same infrastructure to intercept data or impersonate the real workload | Security policy hash (`ccePolicy`) is verified by MAA during attestation — a different container produces a different hash, and SKR denies key release | MAA + SKR |
| 3 | **Database memory inspection** | Cloud operator or DBA inspects PostgreSQL query results in memory while queries execute | DCa/ECa AMD PostgreSQL Flexible Server encrypts query processing memory using AMD SEV-SNP | PostgreSQL (DCa/ECa) |
| 4 | **Network interception (MITM)** | Attacker intercepts traffic between the ACI container and PostgreSQL database | All database connections use TLS (`sslmode=require`); ACI and PostgreSQL are on the same VNet | TLS + VNet |
| 5 | **Key theft / unauthorized decryption** | Attacker obtains encryption keys to decrypt protected data at rest | HSM-backed keys in Azure Key Vault are only released via SKR to containers that pass MAA attestation with the correct policy hash | Key Vault + SKR |
| 6 | **Supply chain attack (image tampering)** | Attacker modifies the Docker container image to exfiltrate data or inject malicious code | Any image modification changes the security policy hash, causing attestation to fail and SKR to deny key release | confcom policy |
| 7 | **Insider threat (cloud operator)** | Privileged cloud operator attempts to read VM memory or attach a debugger | SEV-SNP TEE boundary prevents host-level access; `x-ms-sevsnpvm-is-debuggable` must be `false` for attestation to succeed | SEV-SNP + MAA |
| 8 | **Privilege escalation from host** | Compromised host OS kernel attempts to access guest VM memory | SEV-SNP hardware enforcement prevents host-to-guest memory access regardless of host OS privilege level | SEV-SNP hardware |
| 9 | **Direct internet access to container** | Attacker attempts to directly connect to the container from the public internet | ACI container runs on a private VNet subnet with no public IP — only accessible via Application Gateway | VNet + AppGw |

> **Note:** No single component provides complete protection. The architecture uses **defense in depth** — multiple overlapping security layers that collectively protect data at rest, in transit, and in use.

## File Structure

```
app-and-postgreSQL-demo/
├── Deploy-PostgreSQLDemo.ps1       # Main deployment script
├── Dockerfile                      # Multi-stage build (SKR + Python + Nginx)
├── app.py                          # Flask application (~600 lines)
├── deployment-template.json        # ARM template for confidential ACI
├── generate_transactions.py        # Generates 5000 transaction seed data
├── seed-data.sql                   # Pre-generated SQL seed file (~789 KB)
├── nginx.conf                      # Nginx reverse proxy configuration
├── supervisord.conf                # Process manager (SKR → Flask → Nginx)
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── ATTESTATION.md                  # Attestation technical details
├── .gitignore                      # Git ignore rules
└── templates/
    └── index.html                  # Chart.js dashboard template
```

## Troubleshooting

### DCa/ECa-Series SKU Not Available
If `Standard_DC2ads_v5` (AMD) is not available in your region, the script falls back to `Standard_EC2ads_v5`, then to `Standard_D2ds_v5` (non-confidential). Note: `eds` SKUs are Intel TDX and do NOT work with PostgreSQL confidential computing — only AMD (`ads`) SKUs are supported. For full confidential computing, deploy to a region with DCa/ECa AMD SKU availability (e.g., UAE North, East US, West Europe).

### Database Seeding Fails
The script attempts seeding via `az postgres flexible-server execute` (requires `rdbms-connect` extension). If that fails, it falls back to `psql` CLI. Ensure at least one of these is available.

### Application Gateway 502 Error
After deployment, the Application Gateway may take 1-2 minutes to detect the backend as healthy. Wait and refresh. Check the health probe is configured:
```powershell
az network application-gateway probe show --resource-group <rg> --gateway-name <appgw> --name health-probe
```

### Container Not Starting
Check container logs:
```powershell
az container logs --resource-group <rg> --name <container-name>
```

## Region Availability

| Region | Confidential ACI | DCa/ECa AMD PostgreSQL |
|--------|-----------------|------------------------|
| UAE North | ✅ | ✅ (DC2ads_v5, EC2ads_v5) |
| East US | ✅ | ✅ |
| West Europe | ✅ | ✅ |
| UK South | ✅ | Check availability |

> Default region is `uaenorth` which has both confidential ACI and DCa/ECa AMD PostgreSQL availability.
> **Important:** `eds` SKUs (e.g., DC2eds_v5) are Intel TDX and do NOT support PostgreSQL confidential computing. Only AMD `ads` SKUs (e.g., DC2ads_v5, EC2ads_v5) are supported.
