# Latest-image confidential H100 AKS worker

Automates the [Azure confidential H100 AKS onboarding guide](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/docs/Confidential-GPU-H100-AKS-Onboarding.md)
using **only its GPU Operator driver installation path**:
GPU Operator **v25.3.1**, open kernel modules, and
`nvcr.io/nvidia/driver:580-<running-kernel>-ubuntu24.04`.
There is no signed-package fallback, generic driver installation, manual host
kernel change, or Secure Boot bypass.

## What "latest kernel" means

The script selects the latest **AKS-managed node image offered to the new pool**
in the selected region, updates the pool if necessary, then reads the actual
worker kernel from Kubernetes. It requires `azure-fde` and a numeric version at
least **6.8.0-1071-azure-fde**. It does not select an arbitrary Ubuntu apt kernel:
AKS controls the kernel in its managed image. The default Kubernetes version is
the newest patch of the region's non-preview default minor; it is recorded with
the image versions.

**Support boundary:** the linked guide explicitly validates Ubuntu 24.04.3 and
kernel `6.8.0-1041-azure-fde`. Following its installation method on a newer image
does not independently establish Microsoft/NVIDIA support for that combination.
The result always records `VendorSupportValidated: false`. If the exact branch
580 image is missing, the script records `BlockedMissingGuideDriver`, stops
the disposable cluster, and exits nonzero. It does not substitute another branch
or repeatedly allocate workers for the same missing image.

## Run

Prerequisites: PowerShell 7.2+, authenticated Azure CLI, kubectl, Helm 3,
OpenSSH `ssh-keygen`, registered `Ubuntu2404Preview`, and permissions/quota to
create AKS and its managed resources. Preflight checks the actual regional SKU
restrictions, NCC family quota, system-family quota and total core quota using
the included [preflight helper](Preflight.ps1). Quota does not guarantee capacity.
Run these commands from this sample directory.

```powershell
.\Deploy.ps1 -SubscriptionId '<subscription-guid>' -PreflightOnly

.\Deploy.ps1 -SubscriptionId '<subscription-guid>' `
    -ResourceGroup 'rg-aks-gpu-worker-unique' `
    -ClusterName 'aks-gpu-worker-unique' `
    -Location westeurope -StopExistingNcc
```

`-StopExistingNcc` explicitly authorizes stopping **all existing NCC compute in
the selected subscription and region**, including whole AKS clusters that own
NCC pools (their system nodes also stop). Standalone NCC VMs/VMSS are deallocated.
Non-NCC compute and other regions are not changed. Without the switch, running
NCC compute is an error; `-PreflightOnly` never stops or creates compute.
Other regions can be selected explicitly; West Europe is the default.

Uses a fresh resource group, one `Standard_D4ds_v6` system node and one
`Standard_NCC40ads_H100_v5` worker (44 total vCPUs). Both pools use Ubuntu2404
instead of the guide's older Ubuntu2204 system pool; the confidential GPU pool,
disabled automatic driver and GPU taint match the guide. Autoscaling is omitted
to stay within the single-GPU quota/cost envelope. Automatic image/Kubernetes
upgrades are disabled for reproducible testing. CLI extensions and kubeconfig
are isolated per run without changing shared CLI defaults or kubeconfig.

After confirming ConfidentialVM, Secure Boot and vTPM, the script gates Helm on
a real registry manifest lookup. Authentication, rate-limit and network errors
are failures, not missing-image evidence. If installation can proceed, it
requires one allocatable GPU, CC ON/PRODUCTION/Ready, successful strict GPU
attestation, the guide's TensorFlow matrix multiplication job, and successful
strict attestation again. The TensorFlow workload retains the guide's image
and computation, but explicitly selects GPU 0, disables CPU fallback, and checks
the result tensor's actual device. Its runtime and retries are bounded, and it
uses the NVIDIA runtime on the GPU pool. The guide's attestation manifest is
pinned to the revision linked above;
it retains the guide's latest onboarding archive download, with strict OCSP,
bounded runtime and scheduling onto the GPU pool added. This is GPU attestation,
not a separate CPU/whole-VM attestation claim.

The newly created cluster is stopped in `finally`, including after failure.
Bounded readiness waits allow AKS background addon/pool operations to settle
before subsequent provisioning, configuration checks and shutdown.
If an addon operation starts between readiness and shutdown, AKS stop retries
only `OperationNotAllowed` errors identifying an in-progress operation, for up
to 20 minutes. Retries emit warnings; other errors fail immediately. The same
shutdown helper is used for existing NCC AKS clusters.
Stop and VMSS instance deallocation are verified. `-KeepRunning` explicitly
disables this cost safeguard. Failed provisioning can prevent AKS stop; such
cleanup errors are surfaced and require immediate attention. Existing compute
stopped at the beginning is not automatically restarted.

Run evidence is in ignored `.local/<cluster>-<timestamp>/`: kernel, node image,
VMSS security, registry response, result and (when reached) workload/attestation
logs. Failed job pod status and redacted logs are captured before shutdown when
available; diagnostic collection errors are surfaced. Attestation tokens are
omitted from persisted logs. This directory also
contains a dedicated kubeconfig and SSH private key: **do not commit or share it**.
No resources are automatically deleted. Stopped AKS retains disks/IPs and other
resources that may still incur charges; delete its resource group when finished.

## Offline validation

```powershell
.\tests\Test-Sample.ps1
```

Exercises numeric kernel floors, non-preview patch selection, genuine missing
images versus registry failures, digest validation, NCC-only shutdown scope,
explicit subscription propagation, real SSH key generation/error propagation,
guide workload GPU-placement guards and PowerShell parsing.
Also tests AKS background-operation readiness, failure and timeout handling.
Shutdown tests cover operation conflicts, nonretryable failures, deadline
exhaustion and explicit target/subscription propagation. Preflight tests check
read-only command scope, quota and registration failures, and saved evidence.

## West Europe live validation

On 2026-11-12, a fresh single-H100 deployment exited zero with
`Status: Succeeded`. It used Kubernetes
1.36.5, Ubuntu 24.04.5 LTS, the latest offered GPU image
`AKSUbuntu-2404gen2CVMcontainerd-202610.30.1`, kernel
`6.8.0-1071-azure-fde`, and the exact guide branch-580 driver image.
ConfidentialVM, Secure Boot, vTPM, CC ON/PRODUCTION/Ready and one allocatable
GPU checks passed. Strict GPU attestation passed before and after the workload.

Actual TensorFlow output (informational/startup warnings omitted):

```text
TensorFlow version: 2.15.0
GPU Available: [PhysicalDevice(name='/physical_device:GPU:0', device_type='GPU')]
Running GPU matmul...
GPU matmul device: /job:localhost/replica:0/task:0/device:GPU:0
Elapsed: 4.1502110958099365 sec
```

TensorFlow logged duplicate CUDA factory registration messages and a compute
capability 9.0 PTX JIT warning, but the job completed with explicit GPU placement.
Both redacted attestation logs reported `GPU Attestation is Successful.` for
the same worker GPU.

Automatic shutdown completed in this run without manual recovery:
`FinalPowerState: Stopped`, `ComputeDeallocated: true`. An independent Azure
check at 14:43:14 UTC confirmed AKS Stopped/Succeeded and capacity zero / zero
instances in both the GPU and system scale sets.
The AKS identity's Contributor role was verified on exactly its managed node
resource group.
The vendor-support caveat above still applies; retained disks/IPs can still cost money.

### Redacted GPU attestation example

The verifier output below is from that successful run. GPU identifiers and
attestation tokens have been removed; package-installation noise is omitted.
Both the pre-workload and post-workload checks passed for the same GPU.
**Version numbers and exact output may change** as AKS images, drivers, firmware
and the upstream verifier evolve. This demonstrates GPU attestation only.

```text
== Run attestation ==
Generating random nonce in the local GPU Verifier ..
Number of GPUs available : 1
Fetching GPU 0 information from GPU driver.
All GPU Evidences fetched successfully
-----------------------------------
Verifying GPU: <redacted-gpu-uuid>
    Driver version fetched : 580.178.04
    VBIOS version fetched : 96.00.9f.00.04
    Validating GPU certificate chains.
        The firmware ID in the device certificate chain is matching with the one in the attestation report.
        GPU attestation report certificate chain validation successful.
            The certificate chain revocation status verification successful.
    Authenticating attestation report
        The nonce in the SPDM GET MEASUREMENT request message is matching with the generated nonce.
        Driver version fetched from the attestation report : 580.178.04
        VBIOS version fetched from the attestation report : 96.00.9f.00.04
        Attestation report signature verification successful.
        Attestation report verification successful.
    Authenticating the RIMs.
        Authenticating Driver RIM
            Fetching the driver RIM from the RIM service.
            RIM Schema validation passed.
            driver RIM certificate chain verification successful.
            The certificate chain revocation status verification successful.
            driver RIM signature verification successful.
            Driver RIM verification successful
        Authenticating VBIOS RIM.
            Fetching the VBIOS RIM from the RIM service.
            RIM Schema validation passed.
            vbios RIM certificate chain verification successful.
            The certificate chain revocation status verification successful.
            vbios RIM signature verification successful.
            VBIOS RIM verification successful
    Comparing measurements (runtime vs golden)
            The runtime measurements are matching with the golden measurements.
        GPU is in expected state.
    GPU 0 with UUID <redacted-gpu-uuid> verified successfully.
    GPU Ready State is already READY
GPU Attestation is Successful.

[Attestation token omitted]
```
