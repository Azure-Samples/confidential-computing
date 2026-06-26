# Multi-Party Samples

Secure multi-party computation demonstrations using Azure Confidential Computing
with AMD SEV-SNP hardware protection — available as **ACI confidential containers**
and as **Confidential Virtual Machines (CVMs)**.

Each sample shows multiple organizations collaborating on shared analytics while
keeping their raw data encrypted at rest, decrypted only inside a TEE, and
cryptographically isolated from each other and the cloud operator.

## Available Samples

| Sample | Parties | TEE | Highlight |
|--------|---------|-----|-----------|
| [`advanced-app-federated/`](advanced-app-federated/README-MultiParty.md) ⭐ **NEW** | 4 (Contoso, Fabrikam, Wingtip, Woodgrove) | ACI confidential | **Federated** analytics — only aggregates leave each TEE |
| [`advanced-app/`](advanced-app/README.md) | 3 (Contoso, Fabrikam, Woodgrove) | ACI confidential (+ optional AKS virtual nodes) | Cross-company partner analytics with delegated key access |
| [`advanced-app-cvm/`](advanced-app-cvm/README.md) | 3 (Contoso, Fabrikam, Woodgrove) | Ubuntu 24.04 CVM (DCas_v5) | Same scenario, but on Confidential VMs with App Gateway / WAF |
| [`advanced-app-finance-openAI/`](advanced-app-finance-openAI/README.md) | 3 (Contoso, Fabrikam, Woodgrove) | ACI confidential | Adds an Azure OpenAI chat assistant over **aggregate** results |
| [`demo-app/`](demo-app/README-MultiParty.md) | 2 (Contoso, Fabrikam) | ACI confidential | Minimal 2-party intro — encrypted-data-in-untrusted-storage |

All samples share the same trust model: a per-party HSM key in Azure Key Vault
released only to a TEE that passes Microsoft Azure Attestation
(`x-ms-attestation-type: sevsnpvm`), with the CCE policy hash
(or CVM platform hash) baked into the release policy.

---

### advanced-app-federated/ — Federated Multi-Party (4 parties) ⭐

![Federated Demo Slide](advanced-app-federated/Federated%20Mutli%20Party%20Demo%201-Slide.svg)

Four independent parties — **Contoso**, **Fabrikam**, **Wingtip Toys**, and
**Woodgrove Bank** — each run the same image with their own data, identity, and
Key Vault. Woodgrove orchestrates a federated analysis: each partner decrypts
its own data **inside its own TEE**, computes aggregates locally, and returns
only counts / averages / percentages. **No PII ever leaves a partner's TEE.**

Key features:

- 4-way side-by-side UI; Woodgrove's pane gets the full architecture diagram
  and federated-analysis controls.
- Live RSA-OAEP-SHA256 encryption panel after key release.
- Cross-company key-access denial demo (Contoso trying Fabrikam's key fails).
- Operator-lockout demo (`exec`, SSH, shell-spawn all blocked by CCE policy).
- Demographics dashboard combining 750 records into country/city/generation/
  blood-type/medical-condition aggregates with a salary world map.

Quick start:

```powershell
cd advanced-app-federated
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build -Deploy
```

See [`advanced-app-federated/README-MultiParty.md`](advanced-app-federated/README-MultiParty.md)
and [`DEMO-SCRIPT.md`](advanced-app-federated/DEMO-SCRIPT.md).

---

### advanced-app/ — Partner Analytics (3 parties)

![Multi-Party Topology](advanced-app/MultiPartyTopology.svg)

Woodgrove acts as a trusted analytics partner with **delegated** Key Vault
access to Contoso and Fabrikam. Demonstrates centralized cross-company
analytics inside a TEE (rather than the federated model above).

Quick start:

```powershell
cd advanced-app

# Direct ACI
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build -Deploy

# Or AKS confidential virtual nodes
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build -Deploy -AKS
```

See [`advanced-app/README.md`](advanced-app/README.md).

---

### advanced-app-cvm/ — Confidential VM Edition (3 parties)

The 3-party scenario from `advanced-app/` deployed on Ubuntu 24.04
Confidential VMs (DCas_v5) instead of containers.

| Aspect | ACI (`advanced-app/`) | CVM (`advanced-app-cvm/`) |
|--------|----------------------|--------------------------|
| TEE | ACI confidential containers | Ubuntu 24.04 CVM (DCas_v5) |
| Attestation | ACI SKR sidecar | CVM SKR shim via vTPM + guest attestation |
| Key binding | Per-container CCE policy hash | Hardware attestation (`azure-compliant-cvm` + `sevsnpvm`) + KV access policies |
| Operator lockout | Enforced by CCE policy | Compensating controls (SSH off, NSG deny-all, no Bastion) |
| Networking | Per-container public FQDN | Private VNet + Application Gateway WAF_v2 |
| Disk encryption | N/A (ephemeral) | Confidential OS disk with CMK |

Quick start:

```powershell
cd advanced-app-cvm
.\Deploy-MultiPartyCVM.ps1 -Prefix <yourcode>
.\Deploy-MultiPartyCVM.ps1 -Prefix <yourcode> -EnableDebug   # SSH + Bastion for triage
```

See [`advanced-app-cvm/README.md`](advanced-app-cvm/README.md).

---

### advanced-app-finance-openAI/ — Finance + AI (3 parties)

![Finance + OpenAI Topology](advanced-app-finance-openAI/MultiPartyTopology.svg)

5,000+ synthetic financial transactions across Contoso and Fabrikam, with an
Azure OpenAI (gpt-4o-mini) chat assistant on the Woodgrove side that can
answer natural-language questions over the **aggregate** analytics — the LLM
never sees raw rows.

Quick start:

```powershell
cd advanced-app-finance-openAI
.\Deploy-MultiFinanceAI.ps1 -Prefix <yourcode> -Build -Deploy
```

See [`advanced-app-finance-openAI/README.md`](advanced-app-finance-openAI/README.md).

---

### demo-app/ — Minimal 2-Party Intro

![Demo App Topology](demo-app/demo-app-topology.jpg)

Two confidential containers (Contoso, Fabrikam) each holding their own
SKR-protected key. The simplest entry point — no partner analytics, no
federation. Useful as a "hello world" for SKR + attestation.

Quick start:

```powershell
cd demo-app
.\Deploy-SimpleDemo.ps1 -Prefix <yourcode> -Build -Deploy
```

See [`demo-app/README-MultiParty.md`](demo-app/README-MultiParty.md).

---

## Choosing a Sample

```
Just learning SKR + attestation?           →  demo-app/
Want partner analytics on containers?      →  advanced-app/
Same scenario, but VM-based?               →  advanced-app-cvm/
Want LLM-over-private-data on top?         →  advanced-app-finance-openAI/
Need true federation (no raw data shared)? →  advanced-app-federated/  ⭐
```

## Prerequisites

### For ACI samples (`advanced-app`, `advanced-app-federated`, `advanced-app-finance-openAI`, `demo-app`)

- Azure CLI 2.60+ with `confcom` extension:
  ```powershell
  az extension add --name confcom --upgrade
  ```
- Docker Desktop (for security-policy generation)
- Azure subscription with Confidential Container quota
- PowerShell 7.0+ recommended

### For the CVM sample (`advanced-app-cvm`)

- Azure PowerShell (`Az` module): `Install-Module -Name Az -Force`
- Subscription with DCas_v5 quota in the target region
- Contributor on the subscription, signed in via `Connect-AzAccount`

## AI-Generated Content

These samples were authored with heavy AI assistance (GitHub Copilot, Claude,
GPT). They are intended for **demonstration and education**. Review carefully —
especially the cryptographic and attestation paths — before adapting to
production.

## Disclaimer

Provided **AS IS**, without warranty of any kind. Users are responsible for:

- Security review of all code
- Compliance with organizational policy
- Validating cryptographic and attestation flows
- Proper key management

## Related Resources

- [Azure Confidential Computing](https://azure.microsoft.com/solutions/confidential-compute/)
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [Confidential Containers on ACI](https://learn.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Azure Confidential VMs (DCas_v5)](https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview)
- [Microsoft Azure Attestation](https://learn.microsoft.com/azure/attestation/overview)
- [Azure Key Vault Secure Key Release](https://learn.microsoft.com/azure/key-vault/keys/policy-grammar)
- [AKS Virtual Nodes](https://learn.microsoft.com/azure/aks/virtual-nodes)
- [CVM Attestation Tools](https://github.com/Azure/cvm-attestation-tools)
