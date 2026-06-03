# Federated Multi-Party Confidential Computing Demo

**Author:** Simon Gallagher, Senior Technical Program Manager, Azure Compute Security
**Last Updated:** June 2026

This demo shows four organizations collaborating on shared analytics **without ever
exposing raw data to each other or to the cloud infrastructure**. Each company's
records stay encrypted at rest, are decrypted only inside an AMD SEV-SNP TEE, and
only **aggregate statistics** ever leave the trust boundary.

> Companion docs: [`DEMO-SCRIPT.md`](DEMO-SCRIPT.md) (3-minute live walkthrough),
> [`SECURITY-POLICY.md`](SECURITY-POLICY.md) (CCE policy notes),
> [`ATTESTATION.md`](ATTESTATION.md) (attestation claim reference).

## Architecture

![Multi-Party Architecture](MultiPartyArchitecture.svg)

![Encrypted Data Flow](DataFlowDiagram.svg)

Four confidential containers run the **same image** with different identities,
data files, and Key Vaults:

| Container        | Role                | Own Data | Partner Data       | Key Vault      |
|------------------|---------------------|----------|--------------------|----------------|
| **Contoso**      | Data provider       | 250 PII records | — (own only)        | `kv<id>a`      |
| **Fabrikam**     | Data provider       | 250 PII records | — (own only)        | `kv<id>b`      |
| **Wingtip Toys** | Data provider       | 250 PII records | — (own only)        | `kv<id>d`      |
| **Woodgrove Bank** | Federated orchestrator | — | Aggregate results only | `kv<id>c`      |

Each Key Vault holds an HSM-backed RSA key with a **release policy bound to
`x-ms-attestation-type: sevsnpvm`** — only an attested SEV-SNP TEE can obtain it.

## Federated Privacy Model

Unlike a centralized data-pooling architecture, **raw records never leave a partner's
TEE**. Woodgrove Bank's analysis works like this:

1. Woodgrove attests, releases its own key, then asks each partner for an analysis.
2. Each partner attests independently, releases its own key, decrypts its own
   data **inside its own TEE**, and computes aggregates locally.
3. Each partner returns only counts, averages, and percentages — no names,
   IDs, salaries, or PHI.
4. Woodgrove combines the aggregates and renders the dashboard.

What's shared across the boundary: record counts, salary min/avg/max, generation
buckets, blood-type distribution, medical-condition counts, country/city counts.
What's never shared: the 18 PII fields listed in [DEMO-SCRIPT.md](DEMO-SCRIPT.md#sensitive-fields-in-each-companys-dataset-18-fields).

## Quick Start

### Prerequisites

- Azure CLI 2.60+ with `confcom` extension (`az extension add --name confcom --upgrade`)
- Docker Desktop running (used for security-policy generation)
- Subscription with Confidential ACI quota (East US recommended)
- PowerShell 7.0+

### Deploy

```powershell
# Build image + create ACR/Key Vaults/identities, then deploy all four containers
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build -Deploy

# Or run the phases separately
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build
.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Deploy
```

`<yourcode>` is a 3-8 char `[a-z0-9]` tag (e.g. initials, team code) used to
prefix all resources.

### Optional flags

| Flag | Effect |
|------|--------|
| `-AKS` | Deploy via AKS confidential virtual nodes instead of direct ACI |
| `-RegistryName <name>` | Reuse / pin a specific ACR name |
| `-Location <region>` | Override default `eastus` |
| `-SkipBrowser` | Don't auto-open endpoints after deploy |
| `-Description <text>` | Tag the resource group |

### Clean Up

```powershell
.\Deploy-MultiParty.ps1 -Cleanup
```

Reads `acr-config.json` and deletes the resource group (containers, Key Vaults,
identities, ACR).

## What You See

After `-Deploy`, four FQDNs are printed and (unless `-SkipBrowser`) opened side-by-side:

- **Woodgrove Bank** — green bank theme, federated orchestrator UI with the
  full architecture diagram and partner-analysis controls.
- **Contoso / Fabrikam / Wingtip** — provider UI with attestation, SKR, live
  encryption, cross-company key-access denial, and per-company demographics.

Run through [DEMO-SCRIPT.md](DEMO-SCRIPT.md) for the recommended 3-minute path.

## Security Model

### Per-company keys with attestation-bound release policies

```
kv<id>a  contoso-secret-key   RSA-HSM 4096   policy: sevsnpvm + Contoso identity
kv<id>b  fabrikam-secret-key  RSA-HSM 4096   policy: sevsnpvm + Fabrikam identity
kv<id>d  wingtip-secret-key   RSA-HSM 4096   policy: sevsnpvm + Wingtip identity
kv<id>c  woodgrove-secret-key RSA-HSM 4096   policy: sevsnpvm + Woodgrove identity
```

Cross-company key access is **denied by Key Vault RBAC** — Contoso's identity
has no permission on Fabrikam's vault and vice versa. Try it from the
"🚫 Attempt to Use Key from Other Company" panel.

### Release policy (all keys)

```json
{
  "version": "1.0.0",
  "anyOf": [{
    "authority": "https://sharedeus.eus.attest.azure.net",
    "allOf": [{
      "claim": "x-ms-attestation-type",
      "equals": "sevsnpvm"
    }]
  }]
}
```

Combined with the **CCE policy hash** burned into the SEV-SNP attestation
report (`x-ms-sevsnpvm-hostdata`), this means: change one byte of the image
or its environment variables and Key Vault stops releasing the key.

### Operator lockout

The CCE policy generated by `az confcom acipolicygen` blocks `az container exec`,
shell spawn, and any container modification. Demonstrated live by the
"🖥️ Try to Access Container OS" panel.

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI (Woodgrove vs. provider variant chosen by company role) |
| `/health` | GET | Liveness probe |
| `/info` | GET | Container/role metadata |
| `/company/info` | GET | Branding + role + key vault endpoint |
| `/company/init-status` | GET | Whether SKR + data init has completed |
| `/attest/maa` | POST | MAA-issued JWT (used by SKR) |
| `/attest/raw` | POST | Raw SEV-SNP attestation report |
| `/sidecar/status` | GET | SKR sidecar health |
| `/skr/config` | GET | Effective SKR config (vault + key + MAA) |
| `/skr/release` | POST | Release this container's own key |
| `/skr/release-other` | POST | Try to release a peer company's key (expected to fail) |
| `/skr/key-status` | GET | Whether the key is currently held in TEE memory |
| `/encrypt` | POST | RSA-OAEP-SHA256 encrypt with released key |
| `/decrypt` | POST | RSA-OAEP-SHA256 decrypt with released key |
| `/security/policy` | GET | CCE policy hash + summary |
| `/debug/attestation-claims` | GET | Pretty-printed MAA claims |
| `/container/info` | GET | Hostname, OS, SEV-SNP device, file checksums |
| `/container/access-test` | POST | Demonstrate that exec/SSH/shell are blocked |
| `/partner/federated-analysis` | GET | **Woodgrove only.** SSE stream that runs the federated analysis across partners |

## Files

| File | Purpose |
|------|---------|
| `Deploy-MultiParty.ps1` | End-to-end build / deploy / cleanup |
| `app.py` | Flask app shared by all four containers |
| `Dockerfile` | App + SKR sidecar (multi-stage) |
| `nginx.conf`, `supervisord.conf` | Reverse proxy + process supervision |
| `templates/index.html` | Provider UI (Contoso / Fabrikam / Wingtip) |
| `templates/index-woodgrove.html` | Woodgrove orchestrator UI |
| `contoso-data.csv`, `fabrikam-data.csv`, `wingtip-data.csv` | 250 PII records each (encrypted at rest in image) |
| `generate_data.py` | Regenerate the synthetic CSVs |
| `deployment-template-original.json` | Generic ACI confidential template (providers) |
| `deployment-template-woodgrove-base.json`, `deployment-template-wingtip.json` | Role-specific templates |
| `deployment-params-*.json` | Per-company parameter files |
| `MultiPartyArchitecture.svg`, `MultiPartyTopology.svg`, `DataFlowDiagram.svg` | Diagrams |
| `Federated Mutli Party Demo 1-Slide.svg` | Single-slide overview |
| `DEMO-SCRIPT.md` | 3-minute demo walkthrough |
| `SECURITY-POLICY.md` | CCE policy notes |
| `ATTESTATION.md` | MAA claim reference |

## Troubleshooting

**Build fails with "registry context cancelled" / ACR run failed.** Re-run
`.\Deploy-MultiParty.ps1 -Prefix <yourcode> -Build`. ACR Tasks occasionally
abort on cold start; the script is idempotent.

**Docker is not running.** Start Docker Desktop — `az confcom acipolicygen`
needs it to inspect the image.

**Container stuck `Pending` / `Waiting`.** Check the CCE policy mount denies:
```powershell
az container logs -g <rg> -n <container> --container-name aci-attestation-demo
```
Most often caused by an image digest mismatch — re-run `-Build -Deploy` so the
policy hash matches the image you actually pushed.

**SKR returns 403 / `release_key denied`.** The release policy hash on the key
doesn't match the running container's CCE policy. Easiest fix: re-run
`-Deploy`; the script updates the key's release policy in place (no key
recreation needed, so it works in subscriptions without `purge` permission).

**Cross-company key access *succeeds* (it shouldn't).** Verify each container
has its own user-assigned identity and that only its own identity is on the
vault's access policy:
```powershell
az keyvault show --name <vault> --query "properties.accessPolicies"
```

**Woodgrove federated analysis hangs on a partner.** Hit that partner's
`/health` and `/skr/key-status` directly. A partner that never released its key
will never produce aggregates; check its SKR panel and logs.

## Related Reading

- [Azure Confidential Computing](https://azure.microsoft.com/solutions/confidential-compute/)
- [Confidential Containers on ACI](https://learn.microsoft.com/azure/container-instances/container-instances-confidential-overview)
- [Azure Key Vault Secure Key Release](https://learn.microsoft.com/azure/key-vault/keys/policy-grammar)
- [Microsoft Azure Attestation](https://learn.microsoft.com/azure/attestation/)
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
