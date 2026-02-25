# Secure Key Release (SKR) Example

This example deploys a single **Azure Confidential VM** (AMD SEV-SNP) and demonstrates
**Secure Key Release** — the ability for a VM to prove its hardware identity to Azure
Key Vault and receive an encryption key that cannot be accessed any other way.

## What It Does

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Deployment Overview                             │
│                                                                     │
│  1. Resource Group with random suffix                               │
│  2. VNet + Public IP + NSG (SSH locked to deployer's IP)            │
│  3. Azure Key Vault Premium (HSM-backed)                            │
│       └─ Key: "fabrikam-totally-top-secret-key"                     │
│            └─ Release policy: AMD SEV-SNP CVM only                  │
│  4. User-Assigned Managed Identity → KV get + release               │
│  5. DiskEncryptionSet → confidential OS disk (CMK)                  │
│  6. Ubuntu 24.04 Confidential VM (DCas_v5)                          │
│       └─ SSH key auth (ephemeral key pair, no password)             │
│  7. SSH into CVM: attest via vTPM → MAA token → key release         │
│  8. Result streamed directly to your console                        │
│  9. Auto-cleanup: resource group deleted, SSH keys removed          │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```powershell
# Deploy, run SKR, display result, and auto-clean up (~10 minutes)
.\Deploy-SKRExample.ps1 -Prefix "skrdemo"
```

The script deploys all resources, SSHs into the CVM to perform secure key release,
displays the result, then automatically deletes the resource group and SSH keys.

To clean up a previous deployment manually (e.g. if the script was interrupted):

```powershell
.\Deploy-SKRExample.ps1 -Cleanup
```

### Parameters

| Parameter  | Required | Default             | Description                                    |
|------------|----------|---------------------|------------------------------------------------|
| `-Prefix`  | Yes*     | —                   | 3-8 char prefix for resource names             |
| `-Location`| No       | `northeurope`       | Azure region (must support DCas_v5)            |
| `-VMSize`  | No       | `Standard_DC2as_v5` | Confidential VM SKU                            |
| `-Cleanup` | No       | —                   | Remove all resources from previous deployment  |

\* Required for deployment. Omit all params to see usage + current deployment status.

## The SKR Release Policy Explained

The key `fabrikam-totally-top-secret-key` is created with an HSM-enforced release policy.
The key material is stored in the Key Vault HSM and **cannot be exported** unless the
caller provides a **Microsoft Azure Attestation (MAA) token** that satisfies the policy.

### Policy Structure

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedneu.neu.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-compliance-status",
          "equals": "azure-compliant-cvm"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        }
      ]
    }
  ]
}
```

### What Each Part Means

| Element | Purpose |
|---------|---------|
| **`anyOf`** | Array of acceptable attestation authorities. We specify the shared MAA endpoint for the deployment region. You could add multiple regions or private MAA instances. |
| **`authority`** | The MAA endpoint URL. Key Vault will only accept tokens issued by this authority. The shared MAA endpoint is operated by Microsoft and validates attestation evidence against AMD's key distribution server (KDS). |
| **`allOf`** | All claims in this array must be present AND match. This is an AND condition — both claims are required. |
| **Claim 1:** `x-ms-isolation-tee.x-ms-compliance-status` = `azure-compliant-cvm` | MAA checked the AMD SEV-SNP attestation report, verified the VCEK certificate chain against AMD's root of trust, validated the firmware measurements, and confirmed this is a compliant Azure CVM. |
| **Claim 2:** `x-ms-isolation-tee.x-ms-attestation-type` = `sevsnpvm` | The attestation evidence came from an AMD SEV-SNP guest VM — confirming hardware memory encryption is active and memory integrity protection is enforced. |

### Why Nested Claims?

The claims use the **nested path** `x-ms-isolation-tee.x-ms-attestation-type` rather than
the top-level path `x-ms-attestation-type`. This is important because:

- MAA tokens for CVM attestation place SEV-SNP-specific claims **inside** the
  `x-ms-isolation-tee` object (the Trusted Execution Environment section)
- The top-level `x-ms-attestation-type` may contain a different value or be absent
- Using the wrong claim path causes the release policy to fail silently

> **Note:** `Add-AzKeyVaultKey -UseDefaultCVMPolicy` uses the correct nested paths
> for the disk CMK. We use the REST API for the application key to demonstrate how
> to construct a custom policy with these paths explicitly.

### What Gets Blocked

| Scenario | Result | Why |
|----------|--------|-----|
| Standard VM (no SEV-SNP) | ❌ Blocked | Cannot produce vTPM attestation with SEV-SNP evidence |
| CVM with debug enabled | ❌ Blocked | MAA will not issue `azure-compliant-cvm` for debug VMs |
| CVM that fails firmware check | ❌ Blocked | Compliance status won't be `azure-compliant-cvm` |
| CVM in wrong region (different MAA) | ❌ Blocked | Token authority won't match the policy |
| CVM without the managed identity | ❌ Blocked | Can't authenticate to Key Vault at all |
| Genuine Azure CVM (SEV-SNP) with correct identity | ✅ Released | All conditions met |

## How It Works (Flow)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  1. VM boots on AMD SEV-SNP hardware                                     │
│     └─ AMD CPU generates attestation report (SNP_REPORT)                 │
│        └─ Signed by VCEK (chip-unique key from AMD KDS)                  │
│                                                                          │
│  2. Script SSHs into the VM and runs the bootstrap                       │
│     └─ Reads SNP report from vTPM (/dev/tpmrm0)                         │
│        └─ cvm-attestation-tools sends evidence to MAA                    │
│                                                                          │
│  3. MAA validates the evidence                                           │
│     ├─ Verifies VCEK signature chain → AMD root of trust                 │
│     ├─ Checks firmware measurements against known-good values            │
│     ├─ Confirms no debug flags are set                                   │
│     └─ Issues JWT token with claims:                                     │
│        ├─ x-ms-isolation-tee.x-ms-compliance-status: azure-compliant-cvm │
│        └─ x-ms-isolation-tee.x-ms-attestation-type: sevsnpvm             │
│                                                                          │
│  4. Bootstrap calls AKV /keys/{name}/{version}/release                   │
│     ├─ Auth: Managed identity bearer token (proves KV access)            │
│     └─ Body: { "target": "<MAA JWT token>" }                            │
│                                                                          │
│  5. AKV HSM evaluates the release policy                                 │
│     ├─ Validates MAA token signature                                     │
│     ├─ Checks token issuer matches policy authority                      │
│     ├─ Checks all claims match policy allOf conditions                   │
│     └─ If all pass → wraps key material in JWS and returns it            │
│                                                                          │
│  6. Bootstrap decodes the JWS to extract the JWK (key material)          │
│     └─ Output streams directly to your console via SSH                   │
│                                                                          │
│  7. Script auto-cleans up (deletes resource group + SSH keys)            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Two Layers of Trust

The security of this example relies on **two independent layers**:

### Layer 1: Hardware Attestation (AMD SEV-SNP → MAA → Release Policy)
The Key Vault HSM will not release the key unless it receives an MAA token proving
the caller is a genuine AMD SEV-SNP Confidential VM that passed all compliance checks.
This is enforced by the HSM — even Microsoft cannot bypass it.

### Layer 2: Identity Authorization (Managed Identity → KV Access Policy)
Even if another CVM passes attestation, it cannot release the key unless its managed
identity has `get` + `release` permissions on the Key Vault. This ensures only the
**intended** CVM can access the key, not just any CVM in the subscription.

Both layers must pass for key release to succeed.

## Resources Created

| Resource | Name Pattern | Purpose |
|----------|-------------|---------|
| Resource Group | `{prefix}{suffix}-skr-rg` | Contains all resources |
| Virtual Network | `{prefix}{suffix}-vnet` | Private network (10.0.0.0/16) |
| Public IP | `{prefix}{suffix}-pip` | SSH access to VM |
| NSG | `{prefix}{suffix}-nsg` | SSH locked to deployer's IP |
| VM NIC | `{prefix}{suffix}-cvm-nic` | Public + private IP (10.0.1.4) |
| Confidential VM | `{prefix}{suffix}-cvm` | Ubuntu 24.04, DCas_v5, SSH key auth |
| Key Vault | `{prefix}{suffix}kv` | Premium (HSM), soft-delete |
| User Identity | `{prefix}{suffix}-id` | VM identity for KV access |
| Disk Encryption Set | `{prefix}{suffix}-des` | Confidential OS disk CMK |
| KV Key: `disk-cmk` | — | RSA-HSM 3072, disk encryption |
| KV Key: `fabrikam-totally-top-secret-key` | — | RSA-HSM 2048, exportable, SKR |

All resources are automatically deleted after the SKR result is displayed.

## Prerequisites

- **Azure PowerShell** (`Az` module) — `Install-Module -Name Az -Force`
- **SSH client** — pre-installed on macOS/Linux; on Windows use OpenSSH or Git Bash
- **Azure subscription** with Confidential VM quota for `DCas_v5` series
- **Logged in** — `Connect-AzAccount`

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| "No shared MAA endpoint for region" | Region doesn't have a shared MAA endpoint | Use a supported region (see script) |
| CMK creation fails repeatedly | Key Vault not fully provisioned | Script retries 6 times automatically |
| Bootstrap shows "No vTPM device" | VM not running as CVM | Check VM SKU is DCas_v5 or similar |
| Key release returns 403 | Identity doesn't have KV permissions | Check access policy includes `get` + `release` |
| Key release returns policy error | MAA token claims don't match policy | Verify VM is SEV-SNP (not TDX), check claim paths |
| SSH connection times out | NSG or VM not ready | Script waits up to 5 min; check NSG allows your IP |
| "Enter passphrase for key" | SSH key generated with passphrase | Delete `.ssh/` folder and re-run; uses `-P ""` for no passphrase |
| Resources left after interruption | Script was killed before auto-cleanup | Run `.\Deploy-SKRExample.ps1 -Cleanup` |
