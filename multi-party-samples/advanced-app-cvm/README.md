# Multi-Party Confidential Computing on Confidential VMs

This sample deploys the multi-party confidential computing demo on **Ubuntu 24.04 Confidential Virtual Machines** (AMD SEV-SNP hardware, DCas_v5 series) instead of ACI confidential containers.

Three companies — **Contoso**, **Fabrikam**, and **Woodgrove** — each get their own Confidential VM with:

- **AMD SEV-SNP** hardware-based attestation via vTPM
- **Per-VM key binding** — each key's release policy includes the target VM's `vmUniqueId`
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

## Key Differences from ACI Version

| Aspect | ACI (`advanced-app/`) | CVM (`advanced-app-cvm/`) |
|--------|----------------------|--------------------------|
| **TEE** | ACI confidential containers | Ubuntu 24.04 CVM (DCas_v5) |
| **Attestation** | ACI SKR sidecar binary (`/usr/local/bin/skr`) | CVM SKR shim (`skr_shim.py`) using vTPM + guest attestation client |
| **Key Release Claim** | `x-ms-sevsnpvm-hostdata` (per-container policy hash) | `vmUniqueId` (per-VM) + `azure-compliant-cvm` |
| **Multi-Party Isolation** | ccePolicy hash binds keys to specific container images | Per-VM `vmUniqueId` in release policy + KV access policies |
| **Disk Encryption** | N/A (ephemeral containers) | ConfidentialVmEncryptedWithCustomerKey (CMK via DES) |
| **Networking** | Per-container public FQDN | Private VNet + Application Gateway WAF |
| **NSG** | N/A (ACI managed networking) | Deny-all inbound except AppGw HTTP, inter-VM HTTPS, Bastion SSH (DEBUG) |
| **Public Access** | Direct container FQDN | Single WAF IP with port-based routing |
| **Credentials** | N/A (managed identity only) | Random per-VM, hidden unless `-DEBUG` |
| **Remote Access** | N/A | Azure Bastion (only with `-DEBUG`) |

### Trust Model

In the ACI version, each container's security policy (`ccePolicy`) is hashed to produce a unique `x-ms-sevsnpvm-hostdata` value. Key release policies bind keys to these specific hashes, ensuring only the exact container code can access the key.

In the CVM version, each key's release policy binds to the **specific VM instance** that is authorised to release it, using the `vmUniqueId` claim from the MAA attestation token. The deployment script:

1. Creates all three CVMs first
2. Retrieves each VM's unique identifier (`Get-AzVM ... .VmId`)
3. Creates application keys with release policies that require **both**:
   - `x-ms-isolation-tee.x-ms-compliance-status` = `azure-compliant-cvm` (proves the VM is an Azure CVM running on SEV-SNP hardware)
   - `x-ms-isolation-tee.x-ms-runtime.vm-configuration.vmUniqueId` = `<specific-vm-guid>` (proves the request comes from a specific VM)

The key access matrix defines which VMs can release which keys:

| Key | Authorised VMs | Reason |
|-----|---------------|--------|
| `contoso-secret-key` | Contoso VM + Woodgrove VM | Contoso owns the data; Woodgrove aggregates |
| `fabrikam-secret-key` | Fabrikam VM + Woodgrove VM | Fabrikam owns the data; Woodgrove aggregates |
| `woodgrove-secret-key` | Woodgrove VM only | Woodgrove's own data is private |

This provides **two layers of isolation**:
- **Hardware attestation + per-VM binding**: The AKV release policy ensures only the specific CVM instance (by `vmUniqueId`) running on attested AMD SEV-SNP hardware can release the key
- **Identity-based access**: Key Vault access policies restrict which managed identities can call the release API at all

Compared to ACI:
- **ACI**: Cryptographic binding of code to keys (code identity via ccePolicy hash)
- **CVM**: Cryptographic binding of VM instance to keys (`vmUniqueId`) + hardware attestation (proves CVM) + identity-based access (managed identity)

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

This creates all resources with default settings (North Europe, Standard_DC2as_v5). VM credentials are randomly generated and **not displayed** — the operator cannot SSH into the VMs.

### Debug Deployment (credentials shown + Bastion)

```powershell
.\Deploy-MultiPartyCVM.ps1 -Prefix "demo" -DEBUG
```

Same as above, but:
- **Azure Bastion** (Basic SKU) is deployed for SSH access via the Azure Portal
- The random **username and password** for each VM are printed at the end of the script

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
