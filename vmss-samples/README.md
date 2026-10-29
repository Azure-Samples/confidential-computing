# Confidential VM Scale Sets

**Last Updated:** August 2026

## Overview

Deploy a **Confidential Virtual Machine Scale Set** (AMD SEV-SNP by default) running a small web application, fronted by an **Application Gateway**, with **CPU-based autoscale** capped at 5 instances. A companion load-generation script runs from your own machine and drives enough CPU load to make the scale set grow, then shrink again when the load stops.

The scale set instances have **no public IP**. The only public entry point is the Application Gateway; outbound internet (if enabled) goes through a NAT Gateway; optional Azure Bastion provides SSH access to individual instances.

> 📚 New to Azure Confidential Computing? Start at [`https://aka.ms/accdocs`](https://aka.ms/accdocs), including the [Confidential VM overview](https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview).

```
                    Internet
                        │
                        ▼
        ┌───────────────────────────────┐
        │  Application Gateway v2       │  public IP, HTTP :80
        │  probe /health, backend :8080 │  appgw-subnet 10.0.1.0/24
        └───────────────┬───────────────┘
                        │  (only allowed inbound path)
    ┌───────────────────▼────────────────────────────────────┐
    │  Confidential VM Scale Set - vmss-subnet 10.0.0.0/24    │
    │  no public IPs, autoscale 2 → 5 on CPU                  │
    │                                                         │
    │   ┌───────────────┐  ┌───────────────┐  ┌────────────┐ │
    │   │ Instance 0    │  │ Instance 1    │  │ Instance n │ │
    │   │ Ubuntu 24.04  │  │ Ubuntu 24.04  │  │    ...     │ │
    │   │ CVM image     │  │ CVM image     │  │            │ │
    │   │ demo web app  │  │ demo web app  │  │            │ │
    │   │ AMD SEV-SNP   │  │ AMD SEV-SNP   │  │            │ │
    │   └───────────────┘  └───────────────┘  └────────────┘ │
    └───────────────────┬─────────────────────────────────────┘
                        │ outbound only
                        ▼
                 ┌─────────────┐
                 │ NAT Gateway │
                 └─────────────┘
```

## Files

| File | Description |
|------|-------------|
| `BuildRandomCVMSS.ps1` | Builds the resource group, network, Application Gateway, Confidential VMSS and autoscale rules |
| `Start-VmssLoad.ps1` | Generates load from your machine and reports the live instance count |
| `cloud-init-webapp.yaml` | cloud-init that installs the demo web app on every instance |

---

## BuildRandomCVMSS.ps1

Creates a resource group named `<basename>` + 5 random lower-case letters, so you can run it repeatedly without name collisions, and tags the group with your identity, the script name and the git remote URL.

What it deploys:

- **Confidential VM Scale Set** — Ubuntu 24.04 LTS `cvm` image, `Standard_DC2as_v5` (AMD SEV-SNP), vTPM and Secure Boot enabled, Uniform orchestration
- **Application Gateway Standard_v2** — public HTTP frontend on port 80, health probe on `/health`, backend on port 8080, with the scale set wired into its backend pool
- **Autoscale** — scale out +1 when average CPU > 60% over 5 minutes; scale in −1 when average CPU < 30% over 5 minutes; 5 minute cooldown; range 2–5 instances
- **NAT Gateway** — outbound internet without any public IP on the instances (skip with `-NoInternetAccess`)
- **NSGs** — the scale set subnet accepts port 8080 only from the Application Gateway subnet
- **Azure Bastion** — optional, with `-EnableBastion`

### Prerequisites

- **Azure subscription** with Contributor or Owner rights
- **PowerShell 7.0+**
- **Azure PowerShell** modules `Az.Accounts`, `Az.Compute`, `Az.Network`, `Az.Resources` (Az 9.0 or later) — `Update-Module -Name Az -Force`
- **Confidential VM quota** in the target region for `maxInstances × vCPUs` (10 vCPUs with the defaults). The script pre-flights both SKU availability and quota, and stops with guidance if either is short.

### Usage

```powershell
# Defaults: northeurope, Standard_DC2as_v5, start at 2 instances, autoscale 2-5
./BuildRandomCVMSS.ps1 -subsID <SUBSCRIPTION ID> -basename mydemo

# Larger SKU, different region, wider scale range, plus Bastion for SSH access
./BuildRandomCVMSS.ps1 -subsID <SUBSCRIPTION ID> -basename mydemo `
    -region westeurope -vmsize Standard_DC4as_v5 -minInstances 2 -maxInstances 5 -EnableBastion

# Build and tear straight back down again (CI smoke test)
./BuildRandomCVMSS.ps1 -subsID <SUBSCRIPTION ID> -basename mydemo -smoketest
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-subsID` | *(required)* | Target subscription ID |
| `-basename` | *(required)* | Resource name prefix; 5 random letters are appended |
| `-region` | `northeurope` | Must offer your chosen Confidential VM SKU |
| `-vmsize` | `Standard_DC2as_v5` | AMD SEV-SNP (`DCa*`/`ECa*`) or Intel TDX (`DCe*`/`ECe*`). Intel SGX SKUs are rejected |
| `-instanceCount` | `2` | Starting and default capacity |
| `-minInstances` | `2` | Autoscale floor |
| `-maxInstances` | `5` | Autoscale ceiling |
| `-description` | *(none)* | Added as a resource group tag |
| `-EnableBastion` | off | Deploy Azure Bastion for SSH into instances |
| `-NoInternetAccess` | off | Do not attach the NAT Gateway |
| `-SkipSkuPreflight` | off | Skip the SKU/quota pre-flight check |
| `-smoketest` | off | Delete the resource group when the script finishes |

When the build completes the script prints the app URL, the generated admin password (which cannot be retrieved later), and the exact `Start-VmssLoad.ps1` command to run.

---

## The demo application

`cloud-init-webapp.yaml` installs a small Python service as a systemd unit on port 8080. It uses only the Python 3 standard library that already ships in the Ubuntu CVM image, so it still starts when the subnet has no outbound internet access.

| Endpoint | Purpose |
|----------|---------|
| `/` | HTML page showing the instance name, detected isolation type, vCPU count and requests served |
| `/health` | Application Gateway health probe |
| `/info` | Same details as JSON |
| `/burn?seconds=N` | Consumes N CPU-seconds (capped at 120) and returns JSON including the instance name |

The isolation type comes from `systemd-detect-virt --cvm`, which reports `sev-snp` or `tdx` and works without root. If neither is reported the page says so — a quick confirmation that you really are inside a Confidential VM. Note that the `/dev/sev-guest` device node is **not** present on the Azure Ubuntu CVM image, so it is only used as a fallback for other distributions.

`/burn` hashes a 4 KB buffer in a loop. `hashlib` releases the Python GIL for buffers that size, so concurrent requests spread across the instance's vCPUs and actually move the `Percentage CPU` metric that autoscale watches.

---

## Start-VmssLoad.ps1

Runs from your machine and only needs outbound HTTP to the Application Gateway. It starts a pool of parallel workers calling `/burn`, prints progress every 30 seconds, and — if you pass the subscription, resource group and scale set names — polls and prints the live instance count.

```powershell
# Command printed at the end of the build
./Start-VmssLoad.ps1 -Target http://<APPGW-IP> -subsID <SUB> -ResourceGroup <RG> -VmssName <VMSS>

# Heavier load, and keep watching for 20 minutes afterwards to see the scale-in
./Start-VmssLoad.ps1 -Target http://<APPGW-IP> -Concurrency 32 -DurationMinutes 20 -CooldownMinutes 20 `
    -subsID <SUB> -ResourceGroup <RG> -VmssName <VMSS>
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Target` | *(required)* | Application Gateway URL or IP |
| `-Concurrency` | `16` | Parallel workers; raise this if CPU never crosses the threshold |
| `-DurationMinutes` | `15` | How long to sustain the load |
| `-BurnSeconds` | `20` | CPU-seconds consumed per request |
| `-CooldownMinutes` | `0` | Keep watching, with no load, to observe the scale-in |
| `-subsID`, `-ResourceGroup`, `-VmssName` | *(none)* | Supply all three to display live instance counts |

### What to expect

1. The first 5 minutes produce **no scaling** — autoscale averages CPU over a 5 minute window.
2. Around **5–10 minutes** in, capacity increases by 1. Further increases follow at 5 minute cooldown intervals up to `maxInstances`.
3. New instances take a few minutes to boot, run cloud-init and pass the gateway health probe before they start answering. The "instances answering" counter reflects this.
4. After the load stops, CPU has to average below 30% for 5 minutes before the first scale-in, then one instance is removed per cooldown period until `minInstances`.

Allow roughly 40–60 minutes end to end to watch a full scale-out and scale-in cycle. If CPU never reaches the threshold, increase `-Concurrency`.

---

## Verifying it worked

```powershell
# Current capacity
(Get-AzVmss -ResourceGroupName <RG> -VMScaleSetName <VMSS>).Sku.Capacity

# Per-instance view
Get-AzVmssVM -ResourceGroupName <RG> -VMScaleSetName <VMSS> | Select-Object InstanceId, Name, ProvisioningState

# Confirm the confidential security profile is applied
(Get-AzVmss -ResourceGroupName <RG> -VMScaleSetName <VMSS>).VirtualMachineProfile.SecurityProfile

# Application Gateway backend health
Get-AzApplicationGatewayBackendHealth -ResourceGroupName <RG> -Name <APPGW>

# Autoscale actions taken
Get-AzLog -ResourceGroupName <RG> -StartTime (Get-Date).AddHours(-2) |
    Where-Object { $_.OperationName.Value -like '*Autoscale*' } |
    Select-Object EventTimestamp, Status, Description
```

Browsing to the app URL and refreshing repeatedly shows different instance names as the Application Gateway round-robins across the backend pool.

## Cleaning up

Everything lives in one resource group:

```powershell
Remove-AzResourceGroup -Name <RG> -Force
```

The Application Gateway, NAT Gateway and (if deployed) Azure Bastion are billed hourly whether or not traffic flows, so delete the group as soon as you are done. Use `-smoketest` for unattended runs.

## Notes and limitations

- **Disk encryption**: instances use `VMGuestStateOnly`, which protects the VM guest state with a platform-managed key and requires no Key Vault. For **Confidential OS disk encryption bound to a customer managed key**, see [`../vm-samples/BuildRandomCVM.ps1`](../vm-samples/README.md).
- **No attestation step**: unlike the single-VM sample, this one focuses on scaling behaviour. The app reports the isolation type from the guest device, but does not perform a full MAA attestation flow. See [`../vm-samples`](../vm-samples/README.md) and [`../attestation-samples`](../attestation-samples/README.md) for that.
- **Uniform orchestration** is used because it keeps the autoscale and Application Gateway backend-pool wiring straightforward. Flexible orchestration is the general recommendation for new production scale sets.
- **HTTP only**: the gateway listener is plain HTTP to keep the sample self-contained. Put TLS in front of anything real — see [`../automotive-machine-vision`](../automotive-machine-vision/README.md) for a certificate-based example.
- **Password authentication** is enabled on the instances with a randomly generated password, matching the other samples in this repo. Because there is no public IP, access requires Bastion or private connectivity.
