# Confidential ACI — Norland Citizen Registry Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** April 2026

## 🤖 AI-Generated Content

> **Note:** This demonstration was **created using AI-assisted development** with GitHub Copilot powered by Claude. While functional, AI-generated code should always be reviewed by qualified security professionals before use in production scenarios.

A demonstration of Azure Confidential Container Instances (ACI) running a fictional government citizen registry for the **Republic of Norland**, connected to SQL Server hosted on an AMD-based Confidential VM (DCasv6 family). Backend traffic stays on a private VNet while frontend access is exposed through a public Application Gateway IP.

## Overview

This project deploys a **confidential container with a private IP** behind a public Application Gateway, connected to a **SQL Server instance running on an AMD Confidential VM** over a private VNet:

| Component | Type | Security | Purpose |
|-----------|------|----------|---------|
| **Application Gateway** | Public entrypoint | Internet-facing frontend only | Routes HTTP traffic to private ACI |
| **ACI Container** | Confidential (AMD SEV-SNP TEE) | Hardware memory encryption + ccepolicy | Runs Flask citizen registry CRUD app on private subnet |
| **SQL Server on CVM** | `Standard_DC2ads_v6` (or higher DCads v6) | Confidential VM memory encryption + TLS | Stores citizen registry records |
| **SKR Sidecar** | Secure Key Release | Attestation-backed key release | Cryptographic proof of TEE |

### Key Features

- **Confidential ACI Container** — AMD SEV-SNP memory encryption at the CPU level
- **Confidential SQL Host** — SQL Server runs on an AMD Confidential VM (`DCads_v6` family)
- **Private Backend Connectivity** — ACI and SQL VM communicate over private VNet addressing only
- **Public Frontend Access** — Application Gateway provides internet-facing access to the private ACI app
- **Security Policy (ccepolicy)** — Enforces container integrity via `az confcom acipolicygen`
- **Citizen Registry CRUD** — Full create, read, update, delete for citizen records
- **Fictional Dataset** — 100 auto-generated records for the Republic of Norland (5 regions, 15 municipalities)
- **Health Monitoring** — `/health` and `/db/status` endpoints
- **Owner Tagging** — All resources tagged with the UPN of the person executing the deployment
- **Secure Key Release (SKR)** — SKR sidecar for attestation-backed key release

## Architecture

```
Internet
    │
    ▼
┌──────────────────────────────────┐
│  Application Gateway (Public)    │
│  Public IP frontend              │
└──────────────────────────────────┘
                │
                │ Private VNet
                ▼
┌──────────────────────────────────┐     ┌──────────────────────────────┐
│  ACI Container (Confidential)    │     │  SQL Database (Confidential) │
│  Private IP (no public backend)  │     │  AMD DCasv6 SEV-SNP TEE      │
│  ┌──────────┐  ┌──────────────┐  │     │                              │
│  │ Nginx    │  │ Flask/Gunicorn│  │     │  Database: citizendb         │
│  │ (80/443) │→ │ (port 8000)  │  │────►│  Table: citizen_registry     │
│  └──────────┘  └──────────────┘  │     │  Auth: SQL login             │
│  ┌──────────────────────────────┐│     │  Encryption: TDE + HW TEE    │
│  │ SKR Sidecar (port 8080)      ││     │                              │
│  └──────────────────────────────┘│     │  Private subnet only         │
│  AMD SEV-SNP TEE                │     │                              │
└──────────────────────────────────┘     └──────────────────────────────┘
```

## Prerequisites

- **Azure CLI** with `confcom` extension
- **Docker Desktop** (required for security policy generation)
- **Python 3.10+** (for data seeding)
- **Azure subscription** with access to Confidential ACI (AMD SEV-SNP)

## Quick Start

### 1. Build

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Build
```

Builds the container image using ACR Tasks and pushes to a new Azure Container Registry.

### 2. Deploy

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Deploy
```

Creates an AMD confidential VM (`DCads_v6` family), installs SQL Server, seeds 100 citizen records, generates the ccepolicy, and deploys the Confidential ACI container group.

### 3. Build + Deploy (combined)

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Build -Deploy
```

### 4. Cleanup

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Cleanup
```

Deletes the resource group and all contained resources.

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Prefix` | Yes (Build/Deploy) | — | Short unique identifier (3-12 lowercase alphanumeric) for resource naming |
| `-Build` | No | — | Build and push the container image to ACR |
| `-Deploy` | No | — | Deploy database, generate ccepolicy, deploy Confidential ACI |
| `-Cleanup` | No | — | Delete all Azure resources |
| `-Location` | No | `koreacentral` | Azure region for ACI deployment |
| `-DbLocation` | No | Same as `-Location` | Azure region for SQL CVM |

Deploy credential behavior:

- SQL SA and app-login passwords are generated randomly on each deploy run.
- Credentials are passed to Azure deployment in an ephemeral temp params file and deleted immediately after use.
- No secret-bearing deployment params file is written under the repository path.

## Operational Fix Notes

The following reliability fixes are now built into the deployment and app paths:

- SQL bootstrap convergence: deployment SQL initialization now enforces login default database and user-login rebinding to prevent `4060` and orphaned principal cases.
- Demo self-heal for missing database: the app retries `4060` by creating `citizendb`, login, user mapping, roles, and `dbo.citizen_registry` before reconnecting.
- Confidential policy drift handling: deployment pins image by digest and regenerates `securityPolicyHash` for each effective image change.
- App Gateway race handling: backend pool updates now retry transient `CanceledAndSupersededDueToAnotherOperation` responses.

## Fresh End-to-End Validation

Use this sequence for a clean validation run:

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Cleanup
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Build
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Deploy
```

Then validate:

```powershell
$cfg = Get-Content .\citizen-registry-config.json -Raw | ConvertFrom-Json
curl.exe -sS -i ("http://" + $cfg.fqdn + "/health")
curl.exe -sS -i ("http://" + $cfg.fqdn + "/db/status")
```

Expected results:

- `/health` returns HTTP `200` with `{"status":"ok"}`
- `/db/status` returns HTTP `200` with `{"status":"connected"}`

## Application Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Citizen registry list (paginated, 50 per page) |
| `/citizen/new` | Add a new citizen record |
| `/citizen/<id>/edit` | Edit an existing citizen |
| `/citizen/<id>/delete` | Delete a citizen record |
| `/health` | Health check (`{"status": "ok"}`) |
| `/db/status` | Database connectivity check (`{"status": "connected"}`) |

## Citizen Record Fields

Each citizen record includes: National ID, First Name, Last Name, Date of Birth, Sex, Region, Municipality, Address, Postal Code, Household Size, Marital Status, Employment Status, Tax Bracket, Registered Voter.

## Files

| File | Purpose |
|------|---------|
| `app.py` | Flask CRUD application |
| `Dockerfile` | Multi-stage build with SKR sidecar + Python + Nginx |
| `deployment-template.json` | ARM template for Confidential ACI (with ccepolicy) |
| `nginx.conf` | Reverse proxy (ports 80/443) |
| `supervisord.conf` | Process manager for SKR, Flask/Gunicorn, Nginx |
| `generate_citizen_data.py` | Generates fictional Republic of Norland citizen data |
| `seed-data.sql` | SQL seed file (generated by the deploy script) |
| `requirements.txt` | Python dependencies |
| `templates/index.html` | Paginated citizen list page |
| `templates/citizen_form.html` | Add/edit citizen form |

## To Do

- [ ] **Enhanced monitoring** — Add Application Insights integration for telemetry, traces, and performance analysis
- [ ] **Audit logging** — Track citizen record changes (create, update, delete) with timestamp and operator identity
