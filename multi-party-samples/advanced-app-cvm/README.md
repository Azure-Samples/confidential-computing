# Multi-Party Confidential Computing on Confidential VMs

This sample deploys the multi-party confidential computing demo on **Ubuntu 24.04 Confidential Virtual Machines** (AMD SEV-SNP hardware, DCas_v5 series) instead of ACI confidential containers.

Three companies — **Contoso**, **Fabrikam**, and **Woodgrove** — each get their own Confidential VM with:

- **AMD SEV-SNP** hardware-based attestation via vTPM
- **Two-layer key isolation** — hardware attestation release policy + per-VM Key Vault access policies (managed identity)
- **Confidential OS disk encryption** (DiskWithVMGuestState) with customer-managed keys
- **No public IP** — VMs are only accessible via a shared private VNet
- **Network Security Group** blocking all inbound except HTTP 80 (AppGw), HTTPS 443 (inter-VM), and SSH 22 (only with `-DEBUG`)
- **Application Gateway WAF_v2** providing a single public IP with per-company port routing
- **Random credentials** generated per-VM, hidden from the operator unless `-DEBUG` is specified

## Architecture

```
                    ┌─────────────────────────────────┐
                    │   Application Gateway WAF_v2    │
                    │        (Single Public IP)        │
                    │                                   │
                    │  :80 → Woodgrove    (10.0.1.6)   │
                    │  :8080 → Contoso   (10.0.1.4)   │
                    │  :8081 → Fabrikam  (10.0.1.5)   │
                    └───────────┬──────────────────────┘
                                │
                    ┌───────────┴──────────────────────┐
                    │     VNet 10.0.0.0/16              │
                    │                                    │
    ┌───────────────┼───────────────────────────────────┤
    │  VMSubnet 10.0.1.0/24                              │
    │                                                     │
    │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐│
    │  │ Contoso CVM  │  │ Fabrikam CVM │  │Woodgrove   ││
    │  │ 10.0.1.4     │  │ 10.0.1.5     │  │CVM         ││
    │  │              │  │              │  │10.0.1.6    ││
    │  │ ┌──────────┐ │  │ ┌──────────┐ │  │┌──────────┐││
    │  │ │SKR Shim  │ │  │ │SKR Shim  │ │  ││SKR Shim  │││
    │  │ │:8080     │ │  │ │:8080     │ │  ││:8080     │││
    │  │ ├──────────┤ │  │ ├──────────┤ │  │├──────────┤││
    │  │ │Flask App │ │  │ │Flask App │ │  ││Flask App │││
    │  │ │:8000     │ │  │ │:8000     │ │  ││:8000     │││
    │  │ ├──────────┤ │  │ ├──────────┤ │  │├──────────┤││
    │  │ │nginx     │ │  │ │nginx     │ │  ││nginx     │││
    │  │ │:80 :443  │ │  │ │:80 :443  │ │  ││:80 :443  │││
    │  │ └──────────┘ │  │ └──────────┘ │  │└──────────┘││
    │  └──────────────┘  └──────────────┘  └────────────┘│
    └─────────────────────────────────────────────────────┘
```

## Compensating Controls for Removing Interactive Access

In the ACI version, each container's `ccePolicy` cryptographically prevents interactive access — `docker exec`, SSH, and shell commands are blocked at the hardware level by the security policy hash embedded in the attestation evidence. CVMs do not have an equivalent container-level policy enforcement, so this deployment applies **compensating controls** across multiple layers to achieve the same outcome: **no operator can interactively access a running CVM**.

### Layer 1 — OS-Level: SSH Disabled at Boot

The `setup-vm.sh` bootstrap script unconditionally disables the SSH service on every CVM unless the deployment was created with `-EnableDebug`:

```bash
if [[ "$ENABLE_DEBUG" != "true" ]]; then
    systemctl stop ssh && systemctl disable ssh
fi
```

With SSH stopped and disabled, there is no listening daemon to accept connections — even if network access were available.

### Layer 2 — Network: No Public IP + NSG Deny-All

Every CVM is assigned a **private IP only** (10.0.1.x) within a VNet. The Network Security Group on the VM subnet enforces:

| Priority | Rule | Source | Destination | Ports | Action |
|----------|------|--------|-------------|-------|--------|
| 100 | Allow-AppGw-HTTP | AppGw subnet (10.0.2.0/24) | VM subnet (10.0.1.0/24) | 80 | Allow |
| 110 | Allow-InterVM-HTTPS | VM subnet | VM subnet | 443 | Allow |
| 120 | Allow-Bastion-SSH (**DEBUG only**) | Bastion subnet (10.0.99.0/26) | VM subnet | 22 | Allow |
| 4000 | Deny-All-Other-Inbound | VirtualNetwork | VirtualNetwork | * | **Deny** |

In a standard (non-debug) deployment, there is **no SSH rule at all** — the deny-all rule at priority 4000 blocks every port except HTTP 80 from the Application Gateway and HTTPS 443 between VMs.

### Layer 3 — No Bastion Unless Debug

Azure Bastion (the only service that could proxy SSH through the Azure control plane) is **not deployed** in standard mode. Without Bastion, there is no path to reach port 22 even if SSH were somehow re-enabled inside the VM.

### Layer 4 — Credentials Hidden from Operator

Each VM is provisioned with a randomly generated 12-character username and 40-character password. In a standard deployment these credentials are **never displayed** to the operator — they exist only in Azure's internal provisioning pipeline and are not stored anywhere accessible.

### Layer 5 — Hardware Isolation (AMD SEV-SNP)

The AMD SEV-SNP hardware encrypts all VM memory with a per-VM key managed by the CPU's Secure Processor. Even if an attacker had physical access to the host, or compromised the hypervisor, they **cannot read or modify CVM memory**. This is the same hardware protection that backs ACI confidential containers.

### Layer 6 — Confidential OS Disk Encryption

Each CVM's OS disk uses `DiskWithVMGuestState` encryption with a customer-managed key (CMK) stored in the company's own Key Vault. The disk encryption key can only be released via attestation (`UseDefaultCVMPolicy`), so even detaching the disk and mounting it elsewhere would not reveal its contents.

### Layer 7 — Application Gateway WAF

The only public-facing endpoint is the Application Gateway with WAF_v2 (OWASP 3.2 rules). Port-based routing exposes only HTTP traffic — there is no path from the internet to any management port on the VMs.

### Summary: Defence in Depth

```
                    Internet
                       │
          ┌────────────▼────────────┐
          │  Application Gateway    │  Layer 7 — WAF filtering
          │  (WAF_v2, single IP)    │
          └────────────┬────────────┘
                       │ HTTP 80 only
          ┌────────────▼────────────┐
          │  NSG (Deny-All default) │  Layer 2 — Network isolation
          └────────────┬────────────┘
                       │
   ┌───────────────────┼───────────────────┐
   │ ┌─────────────┐ ┌┴─────────────┐ ┌───┴─────────┐
   │ │ Contoso CVM │ │ Fabrikam CVM │ │Woodgrove CVM│
   │ │             │ │              │ │             │
   │ │ SSH: OFF    │ │ SSH: OFF     │ │ SSH: OFF    │  Layer 1 — SSH disabled
   │ │ No pub IP   │ │ No pub IP    │ │ No pub IP   │  Layer 2 — Private only
   │ │ Creds: ???  │ │ Creds: ???   │ │ Creds: ???  │  Layer 4 — Hidden creds
   │ │ SEV-SNP  🔒 │ │ SEV-SNP  🔒  │ │ SEV-SNP 🔒  │  Layer 5 — HW isolation
   │ │ CMK disk 🔐 │ │ CMK disk 🔐  │ │ CMK disk 🔐 │  Layer 6 — Disk encrypt
   │ └─────────────┘ └──────────────┘ └─────────────┘
   │         No Bastion deployed (Layer 3)           │
   └─────────────────────────────────────────────────┘
```

These seven layers collectively ensure that **no operator or external party can gain interactive access to a production CVM**, matching the security posture of ACI's container-level policy enforcement with defence-in-depth controls.

## Key Differences from ACI Version

| Aspect | ACI (`advanced-app/`) | CVM (`advanced-app-cvm/`) |
|--------|----------------------|--------------------------|
| **TEE** | ACI confidential containers | Ubuntu 24.04 CVM (DCas_v5) |
| **Attestation** | ACI SKR sidecar binary (`/usr/local/bin/skr`) | CVM SKR shim (`skr_shim.py`) using vTPM + guest attestation client |
| **Key Release Claims** | `x-ms-sevsnpvm-hostdata` (per-container policy hash) | `azure-compliant-cvm` + `sevsnpvm` attestation type (hardware attestation; per-VM scoping via KV access policies) |
| **Multi-Party Isolation** | ccePolicy hash binds keys to specific container images | KV access policies bind keys to specific managed identities + hardware attestation proves CVM |
| **Interactive Access Prevention** | ccePolicy blocks `exec`, SSH, shell at hardware level | SSH disabled + NSG deny-all + no Bastion + hidden credentials (see [Compensating Controls](#compensating-controls-for-removing-interactive-access)) |
| **Disk Encryption** | N/A (ephemeral containers) | ConfidentialVmEncryptedWithCustomerKey (CMK via DES) |
| **Networking** | Per-container public FQDN | Private VNet + Application Gateway WAF |
| **NSG** | N/A (ACI managed networking) | Deny-all inbound except AppGw HTTP, inter-VM HTTPS, Bastion SSH (DEBUG only) |
| **Public Access** | Direct container FQDN | Single WAF IP with port-based routing |
| **Credentials** | N/A (managed identity only) | Random per-VM, hidden unless `-EnableDebug` |
| **Remote Access** | Blocked by ccePolicy | Azure Bastion (only with `-EnableDebug`); otherwise none |

### Trust Model

In the ACI version, each container's security policy (`ccePolicy`) is hashed to produce a unique `x-ms-sevsnpvm-hostdata` value. Key release policies bind keys to these specific hashes, ensuring only the exact container code can access the key.

In the CVM version, key isolation uses a **two-layer trust model**:

**Layer 1 — Release Policy (hardware attestation)**

Each key's release policy requires two claims from the MAA guest attestation token:
- `x-ms-isolation-tee.x-ms-compliance-status` = `azure-compliant-cvm` (proves the VM is an Azure CVM running on SEV-SNP hardware)
- `x-ms-isolation-tee.x-ms-attestation-type` = `sevsnpvm` (proves AMD SEV-SNP attestation)

This ensures keys can only be released to genuine Azure Confidential VMs that pass MAA guest attestation. The release policy is shared across all keys — it proves the *class* of environment (CVM on SEV-SNP) but does not identify a specific VM instance.

> **Note:** AKV Secure Key Release does not support `x-ms-runtime.*` claims (including `vm-configuration.vmUniqueId`) in release policies. Although the MAA token contains `vmUniqueId` under `x-ms-runtime.vm-configuration`, AKV only evaluates top-level and `x-ms-isolation-tee.*` claims during release policy matching. Per-VM scoping must therefore use Key Vault access policies.

**Layer 2 — Key Vault Access Policies (identity-based)**

Per-VM managed identities restrict which VMs can call the release API at all:

| Key | Authorised Managed Identities | Reason |
|-----|-------------------------------|--------|
| `contoso-secret-key` | Contoso MI + Woodgrove MI | Contoso owns the data; Woodgrove aggregates |
| `fabrikam-secret-key` | Fabrikam MI + Woodgrove MI | Fabrikam owns the data; Woodgrove aggregates |
| `woodgrove-secret-key` | Woodgrove MI only | Woodgrove's own data is private |

This provides per-VM scoping: even though any CVM could satisfy the release policy claims, only the managed identity assigned to a specific VM has permission to call the release API on a given Key Vault.

**Combined isolation:**
- **Hardware attestation**: The AKV release policy ensures the caller is a genuine Azure CVM (not an arbitrary VM or local machine)
- **Identity-based access**: Key Vault access policies restrict which managed identities can call the release API at all
- **No interactive access**: Compensating controls (SSH disabled, NSG deny-all, no Bastion, hidden credentials, confidential OS disk encryption) prevent any operator from gaining shell access to the running VM — see [Compensating Controls](#compensating-controls-for-removing-interactive-access) above

Compared to ACI:
- **ACI**: Single-layer cryptographic binding of code to keys (code identity via ccePolicy hash) + ccePolicy blocks interactive access at the hardware level
- **CVM**: Two-layer model — hardware attestation (proves CVM class) + identity-based access (proves specific VM) + defence-in-depth compensating controls to prevent interactive access

## Prerequisites

- **Azure PowerShell** (`Az` module) — `Install-Module -Name Az -Force`
- **Azure subscription** with:
  - DCas_v5 quota in the target region
  - Contributor role (or equivalent) on the subscription
  - Application Gateway v2 (WAF_v2) available in the region
- **Logged in** — `Connect-AzAccount`

## Usage

### Standard Deployment (credentials hidden)

```powershell
.\Deploy-MultiPartyCVM.ps1 -Prefix "demo"
```

This creates all resources with default settings (North Europe, Standard_DC2as_v5). All [compensating controls](#compensating-controls-for-removing-interactive-access) are active: SSH is disabled, no Bastion is deployed, NSG blocks all management traffic, and VM credentials are randomly generated and **not displayed** — the operator has no path to interactively access any CVM.

### Debug Deployment (credentials shown + Bastion)

```powershell
.\Deploy-MultiPartyCVM.ps1 -Prefix "demo" -EnableDebug
```

Same as above, but the compensating controls for interactive access prevention are **relaxed** for debugging purposes:
- **SSH remains enabled** on each CVM (not stopped/disabled in `setup-vm.sh`)
- **Azure Bastion** (Basic SKU) is deployed for SSH access via the Azure Portal
- **NSG rule** added to allow SSH (port 22) from the Bastion subnet
- The random **username and password** for each VM are printed at the end of the script

> **Warning:** Debug mode weakens the interactive access controls. Use only in development/testing environments.

### Custom Region and VM Size

```powershell
.\Deploy-MultiPartyCVM.ps1 -Prefix "demo" -Location "eastus" -VMSize "Standard_DC4as_v5"
```

### Cleanup

```powershell
.\Deploy-MultiPartyCVM.ps1 -Cleanup
```

Removes the entire resource group and all deployed resources.

## Files

| File | Purpose |
|------|---------|
| `Deploy-MultiPartyCVM.ps1` | Main deployment script (PowerShell) |
| `skr_shim.py` | CVM SKR shim — replaces ACI SKR sidecar, exposes same `localhost:8080` API |
| `setup-vm.sh` | VM bootstrap — called by CustomScriptExtension after file delivery |
| `app.py` | Flask web application (unchanged from ACI version) |
| `nginx.conf` | Reverse proxy (HTTP :80 + HTTPS :443) |
| `requirements.txt` | Python dependencies |
| `templates/index.html` | Web UI for Contoso/Fabrikam |
| `templates/index-woodgrove.html` | Web UI for Woodgrove (with partner analytics) |
| `contoso-data.csv` | Sample Contoso demographic data |
| `fabrikam-data.csv` | Sample Fabrikam demographic data |
| `generate_data.py` | Regenerate sample CSV data |

## SKR Shim (`skr_shim.py`)

The SKR shim is a lightweight Flask service that runs on `localhost:8080` inside each CVM, exposing the same three endpoints that the ACI SKR sidecar provides:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health/status check |
| `/attest/maa` | POST | Get MAA attestation token via vTPM |
| `/key/release` | POST | Release a key from AKV using MAA attestation |

### Attestation Flow (CVM)

1. The **vTPM** in the CVM contains the AMD SEV-SNP attestation report
2. The **guest attestation client** (`/opt/azguestattestation/AttestationClient`) extracts a TPM quote and sends it to the specified MAA endpoint
3. **MAA** validates the evidence and returns a signed JWT with CVM claims
4. The shim uses the MAA JWT + a **managed identity token** (from IMDS) to call the **AKV key release API**
5. AKV validates the MAA token against the key's release policy, and if the claims match, returns the key material wrapped in a JWS
6. The shim decodes the JWS and returns the key JWK to `app.py`

Since `app.py` only interacts with `localhost:8080`, it requires **zero code changes** when migrating from ACI to CVM.

## Deployment Timeline

A typical deployment takes approximately:

| Phase | Duration | Description |
|-------|----------|-------------|
| Phase 1 | ~2 min | Resource group, VNet, storage account, file upload |
| Phase 2 | ~4 min | 3× Key Vaults, identities, CMK keys, DES |
| Phase 3 | ~12 min | 3× CVM creation, VmId retrieval, per-VM app keys, bootstrap |
| Phase 4 | ~8 min | Application Gateway WAF_v2 |
| Phase 5 | ~5 min | Azure Bastion (only with `-DEBUG`) |
| **Total** | **~25–30 min** | Full deployment |
