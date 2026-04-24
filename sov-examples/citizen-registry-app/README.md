# Confidential ACI — Norland Citizen Registry Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security  
**Last Updated:** April 2026

## 🤖 AI-Generated Content

> **Note:** This demonstration was **created using AI-assisted development** with GitHub Copilot powered by Claude. While functional, AI-generated code should always be reviewed by qualified security professionals before use in production scenarios.

A demonstration of Azure Confidential Container Instances (ACI) running a fictional government citizen registry for the **Republic of Norland**, connected to Azure SQL Database with DC-series confidential computing SKU. The application and database both run inside hardware-protected Trusted Execution Environments (TEEs) with AMD SEV-SNP memory encryption. Authentication uses Azure AD managed identity—no static credentials.

## Overview

This project deploys a **single confidential container** with a public IP, connected to a **SQL Database with DC-series hardware**, to demonstrate end-to-end confidential computing for sensitive citizen data:

| Component | Type | Security | Purpose |
|-----------|------|----------|---------|
| **ACI Container** | Confidential (AMD SEV-SNP TEE) | Hardware memory encryption + ccepolicy | Runs Flask citizen registry CRUD app |
| **SQL Database** | DC-series (AMD SEV-SNP TEE) | Hardware-encrypted database, TLS, Entra-only auth | Stores citizen registry records |
| **Managed Identity** | User-Assigned (Azure AD) | RBAC roles (db_datareader, db_datawriter) | Secure auth without passwords |
| **SKR Sidecar** | Secure Key Release | Attestation-backed key release | Cryptographic proof of TEE |

### Key Features

- **Confidential ACI Container** — AMD SEV-SNP memory encryption at the CPU level
- **Confidential SQL Database** — DC-series SQL with AMD SEV-SNP TEE for hardware-protected data
- **Managed Identity Auth** — Azure AD managed identity for secure database access; no static credentials stored
- **Entra-Only Authentication** — SQL Server configured for Azure AD authentication only
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
┌──────────────────────────────────┐     ┌──────────────────────────────┐
│  ACI Container (Confidential)    │     │  SQL Database (Confidential) │
│  Public IP + DNS label           │     │  DC-series AMD SEV-SNP TEE   │
│  ┌──────────┐  ┌──────────────┐  │     │                              │
│  │ Nginx    │  │ Flask/Gunicorn│  │     │  Database: citizendb         │
│  │ (80/443) │→ │ (port 8000)  │  │────►│  Table: citizen_registry     │
│  └──────────┘  └──────────────┘  │     │  Auth: Entra-only (MI)       │
│  ┌──────────────────────────────┐│     │  Encryption: TDE + HW TEE    │
│  │ SKR Sidecar (port 8080)     ││     │                              │
│  │ Managed Identity Client ID   ││     │  Firewall: Azure services +  │
│  └──────────────────────────────┘│     │           Deployer IP       │
│  AMD SEV-SNP TEE                 │     │                              │
└──────────────────────────────────┘     └──────────────────────────────┘
          │
          │ Authenticates via Managed Identity
          │ (No static credentials in container)
          │
       Azure AD
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

Creates the Azure SQL Database with DC-series confidential computing, creates a managed identity for secure auth, seeds 100 citizen records, generates the ccepolicy, and deploys the Confidential ACI container group.

### 3. Build + Deploy (combined)

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Build -Deploy
```

### 4. Cleanup

```powershell
.\Deploy-CitizenRegistry.ps1 -Prefix "myprefix" -Cleanup
```

Deletes the container group, SQL Database, managed identity, and resource group.

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Prefix` | Yes (Build/Deploy) | — | Short unique identifier (3-12 lowercase alphanumeric) for resource naming |
| `-Build` | No | — | Build and push the container image to ACR |
| `-Deploy` | No | — | Deploy database, generate ccepolicy, deploy Confidential ACI |
| `-Cleanup` | No | — | Delete all Azure resources |
| `-Location` | No | `uaenorth` | Azure region for ACI deployment |
| `-DbLocation` | No | `eastus` | Azure region for Azure SQL Database |

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
