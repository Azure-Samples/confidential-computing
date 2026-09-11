# Secure Key Release (SKR) Example — Trusted Launch (no Confidential Computing)

This example is the **Trusted Launch** counterpart to [`Deploy-SKRExample.ps1`](./Deploy-SKRExample.ps1).
It demonstrates that **Secure Key Release is a feature of Azure Key Vault Premium / Managed HSM**,
not of Confidential Computing. A **Trusted Launch** VM (Gen2, Secure Boot + vTPM) is *not* a
Confidential VM, yet it produces a Microsoft Azure Attestation (MAA) token that a Key Vault
**release policy** can gate on — so the key is released only to a genuine, attested VM.

> The official policy grammar confirms this: a release policy validates a signed MAA token that
> conforms to the expected structure and claims, independent of the compute type. See
> [Azure Key Vault secure key release policy grammar](https://learn.microsoft.com/azure/key-vault/keys/policy-grammar).

## CVM vs. Trusted Launch — what actually differs

| | Confidential VM (`Deploy-SKRExample.ps1`) | Trusted Launch (this example) |
|---|---|---|
| Hardware | AMD SEV-SNP / Intel TDX | Gen2 VM with Secure Boot + vTPM |
| MAA claims used in policy | `x-ms-isolation-tee.x-ms-compliance-status`, `x-ms-isolation-tee.x-ms-attestation-type` | `secureboot`, `x-ms-azurevm-attested-pcr-values.pcrN` |
| Protects asset from the **subscription owner** | Yes | Yes |
| Protects asset from the **host / hypervisor** | Yes (memory encryption) | No (accepted risk) |
| SKU / GPU / region breadth | Narrower (confidential SKUs + quota) | Broad (any Gen2 SKU) |
| Confidential OS disk (DES/CMK) | Required | Not used |

Choose Trusted Launch when your threat model is the VM/subscription owner and you need broad SKU,
GPU, and region availability at standard cost. Choose a Confidential VM when the host itself must
be distrusted (memory encryption).

## What it does

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Deployment Overview                             │
│                                                                     │
│  1. Resource Group with random suffix                               │
│  2. VNet + Public IP + NSG (SSH locked to deployer's IP)            │
│  3. Azure Key Vault Premium (HSM-backed), two exportable keys:      │
│       ├─ "<prefix>-protected-key"          → policy: secureboot     │
│       └─ "<prefix>-protected-key-mismatch" → policy: bogus PCR4     │
│  4. User-Assigned Managed Identity → KV get + release               │
│  5. Ubuntu 24.04 Gen2 TRUSTED LAUNCH VM (Secure Boot + vTPM)        │
│  6. SSH into VM: build AzureAttestSKR → attest via vTPM →           │
│       ├─ SUCCESS: release + unwrap the protected key               │
│       └─ NEGATIVE: mismatch key returns AccessDenied               │
│  7. Result streamed to your console                                 │
│  8. Auto-cleanup: resource group deleted, SSH keys removed          │
└─────────────────────────────────────────────────────────────────────┘
```

The success and negative cases use the canonical **`AzureAttestSKR`** tool from
[`Azure/confidential-computing-cvm-guest-attestation`](https://github.com/Azure/confidential-computing-cvm-guest-attestation)
(`cvm-securekey-release-app`), which already supports Trusted Launch VMs. The bootstrap builds it
on the VM, then wraps/unwraps against the protected key (success) and attempts the mismatch key
(expected `AccessDenied`).

## Quick start

```bash
# Deploy, run SKR (success + mismatch), display result, and auto-clean up
./deploy-skr-trusted-launch.sh --prefix skrtl
```

Clean up a previous deployment manually (for example, if the script was interrupted):

```bash
./deploy-skr-trusted-launch.sh --cleanup
```

### Parameters

| Parameter    | Required | Default            | Description                                     |
|--------------|----------|--------------------|-------------------------------------------------|
| `--prefix`   | Yes*     | —                  | 3-8 char lowercase alphanumeric prefix for resource names |
| `--location` | No       | `northeurope`      | Azure region                                    |
| `--vm-size`  | No       | `Standard_D2s_v5`  | Any Gen2 SKU that supports Trusted Launch       |
| `--cleanup`  | No       | —                  | Remove all resources from a previous deployment |

\* Required for deployment. Omit all parameters to see usage + current deployment status.

## The Trusted Launch release policy explained

The protected key is created with an HSM-enforced release policy. The key material stays in the
Key Vault HSM and **cannot be exported** unless the caller presents an MAA token that satisfies
the policy.

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://<maa-endpoint>",
      "allOf": [
        { "claim": "secureboot", "equals": true }
      ]
    }
  ]
}
```

| Element | Purpose |
|---|---|
| **`authority`** | The MAA endpoint. Key Vault accepts only tokens issued by this authority. |
| **`secureboot` = `true`** | MAA issues this claim only for a VM that booted with Secure Boot enabled and whose vTPM quote validated. A non-Trusted-Launch VM, or one with Secure Boot off, cannot obtain it. |

### Pin the exact image with PCR claims (recommended for production)

`secureboot` proves the platform is a genuine, Secure-Boot Trusted Launch VM but does **not** pin
*which* image booted. To bind release to your specific, unmodified image, add PCR constraints:

```json
{ "claim": "x-ms-azurevm-attested-pcr-values.pcr4", "equals": "<BASE64_PCR4>" },
{ "claim": "x-ms-azurevm-attested-pcr-values.pcr7", "equals": "<BASE64_PCR7>" }
```

Read the expected values from a known-good attestation first — the MAA token returned during a
successful run contains `x-ms-azurevm-attested-pcr-values.pcr0` through `pcr7`. `pcr4` typically
covers the boot loader/kernel and `pcr7` the Secure Boot state; a tampered, reimaged, or
disk-swapped VM measures different values and is rejected.

The **mismatch key** in this example pins a deliberately-wrong `pcr4` to show that path:

### What gets blocked

| Scenario | Result | Why |
|---|---|---|
| Standard (non-Trusted-Launch) VM | ❌ Blocked | No `secureboot` claim from MAA |
| Trusted Launch VM, Secure Boot off | ❌ Blocked | `secureboot` is not `true` |
| Wrong region (different MAA) | ❌ Blocked | Token authority won't match the policy |
| Tampered/reimaged image (when PCRs pinned) | ❌ Blocked | PCR values won't match |
| VM without the managed identity | ❌ Blocked | Can't authenticate to Key Vault |
| Genuine Trusted Launch VM + correct identity | ✅ Released | Policy satisfied |

## How it works (flow)

```
1. VM boots as Trusted Launch (Secure Boot measures the boot chain into vTPM PCRs)
2. Script SSHs in and builds AzureAttestSKR (cvm-securekey-release-app)
3. AzureAttestSKR obtains an MAA token via the vTPM (contains secureboot + PCR claims)
4. It calls AKV /keys/{name}/release with the MAA token + managed-identity bearer token
5. AKV HSM validates the token signature, authority, and claims against the release policy
      ├─ protected-key  → policy satisfied → key wrapped and returned → unwrap round-trip
      └─ mismatch-key   → bogus PCR fails  → AccessDenied
6. Script auto-cleans up (deletes resource group + SSH keys)
```

## Two layers of trust

- **Layer 1 — Attestation gate.** The HSM releases the key only when the MAA token satisfies the
  release policy (`secureboot`, optionally pinned PCRs). Enforced by the HSM.
- **Layer 2 — Identity authorization.** Even an attested VM cannot release the key unless its
  managed identity has `get` + `release` on the vault. This ensures only the *intended* VM
  gets the key. The identity is **not** the security boundary — attestation is.

## Prerequisites

- **Azure CLI** (`az`) — [install](https://learn.microsoft.com/cli/azure/install-azure-cli); sign in with `az login`
- **`jq`** — JSON processor used to parse `az` output
- **SSH client** (`ssh`, `ssh-keygen`, `scp`) — pre-installed on macOS/Linux; on Windows use OpenSSH or Git Bash
- **Azure subscription** with quota for a Gen2 general-purpose SKU (for example, `Dsv5`)

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| "No shared MAA endpoint for region" | Region has no shared MAA endpoint | Use a supported region (see script) |
| Bootstrap shows "No vTPM device" | VM not deployed as Trusted Launch | Confirm `--security-type TrustedLaunch` and a Gen2 image |
| Success key returns 403 / policy error | Identity lacks KV permission, or authority mismatch | Check access policy `get`+`release`; verify the MAA authority matches the region |
| Mismatch key unexpectedly succeeds | PCR pin not applied | Confirm the mismatch key's release policy contains the bogus PCR claim |
| SSH connection times out | NSG or VM not ready | Script waits up to 5 min; check NSG allows your IP |
| Resources left after interruption | Script killed before auto-cleanup | Run `./deploy-skr-trusted-launch.sh --cleanup` |

## See also

- [Azure Key Vault secure key release policy grammar](https://learn.microsoft.com/azure/key-vault/keys/policy-grammar)
- [Secure Key Release with Azure Key Vault and Azure Confidential Computing](https://learn.microsoft.com/azure/confidential-computing/concept-skr-attestation)
- [`cvm-securekey-release-app`](https://github.com/Azure/confidential-computing-cvm-guest-attestation/tree/main/cvm-securekey-release-app) — the `AzureAttestSKR` tool used here
- [Trusted Launch for Azure VMs](https://learn.microsoft.com/azure/virtual-machines/trusted-launch)
