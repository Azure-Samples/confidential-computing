# Confidential Virtual Machines

**Last Updated:** June 2026

## Overview

Deploy Confidential Virtual Machines (CVMs) with AMD SEV-SNP or Intel TDX hardware protection, **Confidential OS disk encryption bound to a Customer Managed Key (CMK)**, and automated attestation. The script auto-detects the isolation type from the chosen VM SKU and runs the matching attestation flow inside the freshly deployed VM using the latest [Azure/cvm-attestation-tools](https://github.com/Azure/cvm-attestation-tools) release.

> 📚 New to Azure Confidential Computing? Start at [`https://aka.ms/accdocs`](https://aka.ms/accdocs) for the full product documentation, including [Confidential VM overview](https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview) and [Confidential OS disk encryption](https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview#confidential-os-disk-encryption).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Confidential VM Architecture                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Confidential VM (DCasv5)                       │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │                  Guest OS (Windows/Linux)                   │  │   │
│  │  │  ┌─────────────────┐    ┌─────────────────────────────┐   │  │   │
│  │  │  │  Application    │    │  Attestation Agent          │   │  │   │
│  │  │  │  Workload       │    │  (Proves TEE Integrity)     │   │  │   │
│  │  │  └─────────────────┘    └──────────────┬──────────────┘   │  │   │
│  │  └────────────────────────────────────────┼───────────────────┘  │   │
│  │                                           │                       │   │
│  │              AMD SEV-SNP TEE              │                       │   │
│  │         (Memory Encrypted at CPU)         │                       │   │
│  └───────────────────────────────────────────┼───────────────────────┘   │
│                                              │                           │
│                                              ▼                           │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     Azure Infrastructure                          │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │  │
│  │  │  Key Vault      │  │  Azure          │  │  Azure Bastion  │   │  │
│  │  │  (Premium HSM)  │  │  Attestation    │  │  (Secure RDP/   │   │  │
│  │  │                 │  │  (MAA)          │  │  SSH Access)    │   │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Available Scripts

| Script | Description | Status |
|--------|-------------|--------|
| `BuildRandomCVM.ps1` | Deploy CVM with Confidential OS disk encryption + CMK and Bastion | **Stable** |
| `BuildRandomSQLCVM.ps1` | SQL Server 2022 on Confidential VM | **Stable** |

---

## BuildRandomCVM.ps1

Builds a CVM with **Confidential OS disk encryption bound to a Customer Managed Key** (see [What is Confidential OS disk encryption?](#what-is-confidential-os-disk-encryption-with-cmk) below) and a private VNet (no public IP), and optionally deploys Azure Bastion for remote access. Once the VM is up, the script downloads the latest pre-built `attest` binary from [Azure/cvm-attestation-tools](https://github.com/Azure/cvm-attestation-tools/releases/latest) inside the VM, runs it against the matching SNP/TDX config, and streams the attestation JWT and claims back to the caller via `Invoke-AzVMRunCommand` (with a 60s backoff retry loop to absorb the transient 409 Conflict that the run-command extension can return immediately after VM provisioning).

Supported images: Windows Server 2022, Windows Server 2019, Windows 11 Enterprise, Ubuntu 24.04 LTS, and RHEL 9.5 CVM. The script tags the resource group with the GitHub repo URL (auto-detected from git remote) for traceability.

### Pre-flight checks (before any resources are created)

To save you a half-built deployment in a region or subscription that can't actually host the VM, the script runs the following checks **before** creating the resource group, Key Vault, DES, VNet or VM:

1. **Confidential VM SKU type** — confirms `-vmsize` is an AMD SEV-SNP (`DCa*`/`ECa*`) or Intel TDX (`DCe*`/`ECe*`) SKU. **Intel SGX SKUs (`DC*s_v3` / `DC*s_v2`) are explicitly rejected** because they use a different isolation model (per-process enclaves, not full-VM); the script prints a clear error and points at the [SGX VM solutions docs](https://learn.microsoft.com/azure/confidential-computing/virtual-machine-solutions-sgx) instead.
2. **SKU availability in the chosen region** — calls `Get-AzComputeResourceSku -Location <region>` and verifies the SKU is offered there and is not blocked for your subscription (e.g. `NotAvailableForSubscription`).
3. **vCPU quota** — calls `Get-AzVMUsage -Location <region>`, locates the SKU's family (e.g. `standardDCASv5Family`, `standardDCESv6Family`) and confirms there are at least enough free vCPUs left to deploy the requested size.

If any check fails the script aborts immediately with a clear error and prints the helper commands you can run yourself to find a region with availability or check your quota, e.g.:

```powershell
# Regions where this SKU is available to your subscription
Get-AzComputeResourceSku | Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -eq '<SKU>' -and (-not $_.Restrictions -or $_.Restrictions.Count -eq 0) } | Select-Object Locations, Name

# All Confidential VM SKUs offered in <region>
Get-AzComputeResourceSku -Location '<region>' | Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -match '_(DC|EC)\d+(a|e)' } | Select-Object Name, @{n='Restricted';e={$_.Restrictions.Count -gt 0}}

# Your current vCPU usage and limits in <region>
Get-AzVMUsage -Location '<region>' | Where-Object { $_.Name.Value -match 'DCa|DCe|ECa|ECe|cores' } | Format-Table -AutoSize
```

Use at your own risk, no warranties implied.

## Usage

Clone this repo locally.  
Basename is a prefix assigned to all resources created by the script and will be given a 5 char suffix - for example: myCVM-sdfrw.  
The script will generate a random complex password and output it to the terminal once; make sure you copy it if you want to login to the CVM.

```powershell
./BuildRandomCVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> -osType <Windows|Windows11|Windows2019|Ubuntu|RHEL> [-description <OPTIONAL DESCRIPTION>] [-smoketest] [-region <AZURE REGION>] [-vmsize <VM SIZE SKU>] [-policyFilePath <PATH>] [-DisableBastion]
```

## Parameters:
- **subsID**: Your Azure subscription ID (required)
- **basename**: A prefix for all resources created by the script (required)
- **osType**: The operating system to deploy (required)
- **description**: Optional description added as a tag to the resource group
- **smoketest**: Optional switch that automatically removes all resources after completion (useful for testing)
- **region**: Optional Azure region (defaults to `northeurope`)
- **vmsize**: Optional VM size SKU (defaults to `Standard_DC2as_v5`). Use SEV-SNP SKUs like `Standard_DC4as_v5` or Intel TDX SKUs like `Standard_DC2es_v6` — the script picks the matching attestation config automatically.
- **policyFilePath**: Optional path to a custom key release policy JSON (defaults to `-UseDefaultCVMPolicy`)
- **DisableBastion**: Optional switch that skips Azure Bastion creation; the VM will only be reachable via private network connectivity (VPN, ExpressRoute, peering)

## OS Type Options:
- **Windows**: Windows Server 2022 Datacenter (RDP via Bastion)
- **Windows2019**: Windows Server 2019 Datacenter (RDP via Bastion)
- **Windows11**: Windows 11 Enterprise 24H2 (RDP via Bastion)
- **Ubuntu**: Ubuntu 24.04 LTS CVM (SSH via Bastion)
- **RHEL**: Red Hat Enterprise Linux 9.5 CVM (SSH via Bastion)

## Example:
```powershell
# Deploy Ubuntu CVM with a larger VM size
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myubuntu" -osType "Ubuntu" -vmsize "Standard_DC4as_v5"
```

## Examples:
```powershell
# Deploy Windows Server CVM (resources remain)
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Windows"

# Deploy Windows 11 Enterprise CVM
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "mywin11" -osType "Windows11"

# Deploy Ubuntu CVM with description
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Ubuntu" -description "Development testing environment"

# Deploy RHEL CVM for testing (automatically cleaned up)
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "test" -osType "RHEL" -smoketest

# Deploy Windows 11 CVM in a specific region
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Windows11" -region "eastus"

# Smoketest with Windows 11 for CI/CD pipeline
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "ci" -osType "Windows11" -description "Automated testing pipeline" -smoketest
```

## Intel TDX Examples

The script auto-detects the isolation type from the VM SKU and runs the matching attestation flow inside the VM:

- **AMD SEV-SNP** SKUs (`DCa*` / `DCad*` / `ECa*` / `ECad*`, e.g. `Standard_DC2as_v5`) → uses `config_snp.json`, expect `x-ms-attestation-type: sevsnpvm`.
- **Intel TDX** SKUs (`DCe*` / `DCed*` / `ECe*` / `ECed*`, e.g. `Standard_DC2es_v6`) → uses `config_tdx.json`, expect `x-ms-attestation-type: tdxvm`.

Intel TDX SKUs are available in a subset of regions (e.g. `westeurope`, `westus3`, `northeurope`). Verify with:

```powershell
Get-AzComputeResourceSku -Location westeurope |
    Where-Object { $_.Name -match '^Standard_(DC|EC)\d+e' -and $_.ResourceType -eq 'virtualMachines' } |
    Select-Object Name, @{N='Restrictions';E={ $_.Restrictions.ReasonCode -join ',' }}
```

```powershell
# Deploy Ubuntu 24.04 Intel TDX CVM in West Europe
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "mytdx" -osType "Ubuntu" -region "westeurope" -vmsize "Standard_DC2es_v6" -DisableBastion -description "ubuntu tdx attestation"

# Deploy Windows Server 2022 Intel TDX CVM
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "wintdx" -osType "Windows" -region "westeurope" -vmsize "Standard_DC2es_v6"

# Smoketest a TDX deployment
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "tdxci" -osType "Ubuntu" -region "westus3" -vmsize "Standard_DC4es_v6" -smoketest
```

The script automatically tags the resource group with:
- **owner**: Your Azure user principal name
- **BuiltBy**: The script name that created the resources
- **OSType**: The operating system type deployed
- **GitRepo**: The GitHub repository URL where the script was cloned from
- **description**: Optional description if provided
- **smoketest**: Set to "true" when running in smoketest mode

## Smoketest Mode:
The `-smoketest` parameter is perfect for:
- **Automated testing**: CI/CD pipelines that need to validate deployments
- **Quick validation**: Testing that the script works without leaving resources behind
- **Demonstrations**: Show functionality without manual cleanup
- **Cost management**: Ensures test resources are automatically removed

### Interactive Safety Features:
- **Real-time countdown**: Shows exactly how many seconds remain before deletion
- **Easy cancellation**: Press any key during the 10-second countdown to cancel deletion
- **Clear warnings**: Bold red warnings that resources cannot be recovered
- **Flexible operation**: Works in both interactive and automated environments

When using `-smoketest`, the script will:
1. Deploy and configure the CVM as normal
2. Run attestation checks
3. Display a 10-second interactive countdown with real-time timer
4. Allow cancellation by pressing any key during the countdown
5. Automatically remove all created resources (VM, Key Vault, Bastion, VNet, etc.) if not cancelled
6. Provide confirmation of successful cleanup or cancellation status

## What is Confidential OS disk encryption with CMK?

A standard Azure VM with a customer-managed key (CMK) protects the **disk blob at rest in Azure Storage** with your key — but the OS disk is still decrypted by the Azure host before being presented to the guest, so the host (and anyone with privileged access to it) can in principle read OS disk contents in the clear.

**Confidential OS disk encryption** (also called *Confidential Disk Encryption with Customer-Managed Keys*) goes further: it provisions the OS disk with `SecurityEncryptionType = DiskWithVMGuestState`, which means:

- The OS disk and the **VM Guest State (VMGS)** blob (which holds vTPM state and Secure Boot keys) are **encrypted with a key that lives in your Azure Key Vault Premium / Managed HSM** and never leaves it in clear form.
- Decryption happens **inside the AMD SEV-SNP or Intel TDX trusted execution environment**, not on the Azure host. The host fabric, hypervisor admin, datacenter operator, and even Microsoft cannot read the decrypted OS disk content.
- The CMK is wrapped by an Azure-managed *CVM orchestrator* identity that is itself gated by an **attestation-bound key release policy** (`-UseDefaultCVMPolicy` in this script): the key is only unwrapped after Microsoft Azure Attestation (MAA) verifies the platform really is a genuine SEV-SNP / TDX CVM running the expected firmware and Secure Boot configuration.
- The vTPM state inside VMGS is also protected, so things like BitLocker keys (Windows) or LUKS volume keys (Linux) sealed to the vTPM stay confidential to the guest.

Why this matters:

| Capability | Standard VM + CMK | Confidential VM + CMK + Confidential OS disk encryption |
|---|---|---|
| Disk-at-rest encrypted with your key | ✅ | ✅ |
| Customer holds key in AKV/HSM | ✅ | ✅ |
| Key release gated by **hardware attestation** | ❌ | ✅ |
| OS disk decrypted **inside TEE**, not on host | ❌ | ✅ |
| Host admin / hypervisor blocked from reading OS disk | ❌ | ✅ |
| vTPM + Secure Boot state encrypted with same CMK | ❌ | ✅ (via VMGS) |

In short, this is the strongest "my data, my key, my hardware boundary" posture available for an Azure VM today: the cloud operator runs the VM but cannot see inside it, and the disk cannot be decrypted anywhere except inside an attested confidential VM you own. See the official docs for details: [Confidential OS disk encryption](https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview#confidential-os-disk-encryption), [How to create a CVM with CMK (Azure CLI)](https://learn.microsoft.com/azure/confidential-computing/quick-create-confidential-vm-azure-cli), and the umbrella docs at [`https://aka.ms/accdocs`](https://aka.ms/accdocs).

## Key Release Policy

If the `-policyFilePath` parameter is not specified when running `BuildRandomCVM.ps1`, the script uses the default CVM key release policy (`-UseDefaultCVMPolicy`), which points at the shared attestation endpoint serving the region where the CVM is created. This provides out-of-the-box attestation-gated key release without requiring custom configuration. For background on attestation-bound key release see the [Azure Key Vault SKR docs](https://learn.microsoft.com/azure/key-vault/keys/policy-grammar) and [`https://aka.ms/accdocs`](https://aka.ms/accdocs).

## Important Notes:
Note this will deploy an Azure Keyvault *Premium* SKU [pricing](https://azure.microsoft.com/en-gb/pricing/details/key-vault/#pricing) & enables purge protection for 10 days (you can adjust the purge protection period but AKV Premium with HSM-backed RSA-3072 keys is required for CVMs with **Confidential OS disk encryption** — see [`https://aka.ms/accdocs`](https://aka.ms/accdocs) for the full requirements).

By default the script will create resources in North Europe - you can specify a different region using the `-region` parameter. Make sure to check availability of CVMs in your chosen region first.

There is a similar concept to build an AKS cluster with CMK enabled on the worker nodes.


# SQL Server on Confidential Computing

The BuildRandomSQLCVM.ps1 script builds on the CVM script but deploys the specific SQL image to give you a SQL 2022 build running on Windows Server 2022 [official docs](https://learn.microsoft.com/en-gb/azure/azure-sql/virtual-machines/windows/sql-vm-create-confidential-vm-how-to?view=azuresql)


# ARM Template (currently a work-in-progress)
Create a simple CVM with CMK enabled using an Azure Resource Manager (ARM) template

You'll need to pre-create a disk encryption set and encryption key (use Azure Keyvault Premium) and replace the relevant values in the parameter file, see 'snippet-createDES.ps1' for an automated way to do this in an existing Azure Key Vault _Premium_ instance - in future will try to do this in the ARM template itself, seems complex to get the resource ID for the DES and pass it in the same ARM template (or, at-least I haven't figured out how to do it yet)

To deploy from the command line:

New-AzResourceGroupDeployment -Name DeployLocalTemplate -ResourceGroupName "<YOUR_RESOURCE_GROUP>" -TemplateFile ./cvm-cmk.json  -TemplateParameterFile ./cvm-cmk-params.json -Verbose


# Automated Attestation

[Attestation](https://learn.microsoft.com/en-us/azure/confidential-computing/attestation-solutions) is how you prove you are running on a Confidential VM based on evidence signed by the CPU and validated by Microsoft Azure Attestation (MAA).

> **Recommended tooling:** [Azure/cvm-attestation-tools](https://github.com/Azure/cvm-attestation-tools)
>
> Pre-built `attest` binaries for Linux (`attest-lin.zip`) and Windows (`attest-win.zip`), with ready-made configs for AMD SEV-SNP (`config_snp.json`) and Intel TDX (`config_tdx.json`). See the [project README](https://github.com/Azure/cvm-attestation-tools/blob/main/README.md) and the [latest release](https://github.com/Azure/cvm-attestation-tools/releases/latest) for additional examples and the source. `BuildRandomCVM.ps1` in this repo runs that flow automatically inside the freshly deployed CVM.

## In-VM attestation via cvm-attestation-tools

`BuildRandomCVM.ps1` selects the right config from the VM SKU and executes the matching binary inside the VM via `Invoke-AzVMRunCommand`:

| Isolation | Example SKUs | Binary | Config | Expected `x-ms-attestation-type` |
|---|---|---|---|---|
| AMD SEV-SNP | `Standard_DC2as_v5`, `Standard_EC4as_v5` | `attest` / `attest.exe` | `config_snp.json` | `sevsnpvm` |
| Intel TDX | `Standard_DC2es_v6`, `Standard_EC4es_v6` | `attest` / `attest.exe` | `config_tdx.json` | `tdxvm` |

A successful run prints the JWT plus parsed claims and ends with `Attested Platform Successfully!!` and `x-ms-compliance-status: azure-compliant-cvm`.

## Running attestation manually against an existing CVM

From an authenticated PowerShell session you can re-run attestation against an already-deployed CVM by reusing the same payload `BuildRandomCVM.ps1` injects. Replace `<RG>` and `<VM>` with your values, and switch the config filename for the isolation type of the target VM.

Linux (Ubuntu / RHEL) target:

```powershell
$attest = @'
#!/bin/bash
set -e
command -v unzip >/dev/null || (apt-get update -y && apt-get install -y unzip) >/dev/null 2>&1 || (dnf install -y unzip || yum install -y unzip) >/dev/null 2>&1
W=$(mktemp -d); cd "$W"
curl -fsSL -o a.zip https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-lin.zip
unzip -q a.zip
chmod +x attest 2>/dev/null || true
./attest --c config_snp.json   # use config_tdx.json for Intel TDX SKUs
cd /; rm -rf "$W"
'@
Invoke-AzVMRunCommand -ResourceGroupName <RG> -VMName <VM> -CommandId 'RunShellScript' -ScriptString $attest
```

Windows (Server 2019 / 2022 / Windows 11) target:

```powershell
$attest = @'
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
$w = Join-Path $env:TEMP "cvm-attest-$(Get-Random)"; New-Item -ItemType Directory -Path $w -Force | Out-Null; Set-Location $w
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri 'https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-win.zip' -OutFile 'a.zip' -UseBasicParsing
Expand-Archive -Path 'a.zip' -DestinationPath '.' -Force
& .\attest.exe --c config_snp.json   # use config_tdx.json for Intel TDX SKUs
'@
Invoke-AzVMRunCommand -ResourceGroupName <RG> -VMName <VM> -CommandId 'RunPowerShellScript' -ScriptString $attest
```

You can also SSH/RDP into the VM and run the binary directly; the same `attest --c <config>` invocation works interactively.

## Deprecated: WindowsAttest.ps1

[`WindowsAttest.ps1`](WindowsAttest.ps1) is the previous-generation, Windows-only check (uses `cvm-platform-checker-exe` against the West Europe shared MAA endpoint, SEV-SNP only). It is retained for historical reference but is **no longer recommended** — use [Azure/cvm-attestation-tools](https://github.com/Azure/cvm-attestation-tools) instead, which is cross-platform and supports both SEV-SNP and Intel TDX.

For more information on Azure Confidential Computing see the [public docs](https://aka.ms/accdocs).


# TURBO Charged Versions

These scripts are useful for step by step learning or exploring, but one of our colleagues has a turbo-charged version of this script with detailed error handing, Managed HSM support and much more - check it out - [GitHub Link](https://github.com/RZomermanMS/CVM)
