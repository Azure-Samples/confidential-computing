# AKS confidential H100 worker

## Current workaround - UNSUPPORTED

> **UNSUPPORTED - experimental diagnostic workaround only.**
> This recipe is not a Microsoft/NVIDIA-supported AKS configuration or a
> production-managed driver installation. Successful workload and attestation
> tests do not establish vendor support. It requires a privileged pod with
> host access and does not survive node lifecycle changes automatically.

**Tested end to end on two fresh workers on 2026-11-10.** Exact-kernel,
Canonical-signed Ubuntu NVIDIA `615.71.09` packages loaded on
`6.8.0-1071-azure-fde` with Secure Boot enabled. Starting UVM persistence
**before the first GPU query**, then exposing the extracted driver tree to GPU
Operator with its driver installer disabled, produced one allocatable H100.
A GPU-only CUDA vector-add Job passed, strict GPU attestation passed before
and after that workload, and a separate Azure CPU/CVM attestation returned
`sevsnpvm` and `azure-compliant-cvm` claims.

### Use this path, not the failed driver-container recipes

Follow the [tested Azure CLI walkthrough](Confidential-GPU-H100-AKS-Onboarding.md)
for the complete commands. The working sequence is:

1. Provision the disposable system pool and confidential H100 worker with
   automatic GPU driver installation disabled. Verify the actual host kernel,
   ConfidentialVM, Secure Boot and vTPM before proceeding.
2. Install GPU Operator `v26.7.2` with **`driver.enabled=false`**. Keep the
   toolkit/runtime and device plugin; do not use its failing driver installer.
3. Apply [the privileged probe](signed-driver-probe.yaml) on a fresh worker and
   run [the exact-package installer](Install-SignedDriver.sh). It extracts
   Canonical-signed NVIDIA `615.71.09` modules for
   `6.8.0-1071-azure-fde` plus matching firmware and libraries, without changing
   the host kernel, disabling Secure Boot or replacing AKS-managed containerd.
4. The installer preloads the crypto dependencies and starts
   `nvidia-persistenced --uvm-persistence-mode` **before the first GPU query**,
   sets GPU ready state, and exposes the driver tree at `/run/nvidia/driver`.
   Require `SIGNED_DRIVER_LOADED=1`, CC ON / PRODUCTION / Ready and one
   allocatable `nvidia.com/gpu`.
5. Run [strict GPU attestation](Test-GpuAttestation.sh), then
   [the one-GPU CUDA Job](gpu-smoke-test.yaml), then GPU attestation again.
   Require zero exits, positive verdicts for the actual GPU UUID, and
   `Test PASSED`; no CPU fallback is supplied.
6. Run [separate CPU/CVM attestation](Test-CvmAttestation.sh). The probe mounts
   host securityfs read-only for TPM evidence; require the successful MAA
   request and `sevsnpvm` / `azure-compliant-cvm` claims.
7. Preserve evidence locally, remove only the probe-owned firmware and test
   resources, and stop the cluster using the walkthrough's cleanup commands.

**Limits:** the probe holds persistence for at most four hours. Deleting it ends
persistence; `/run/nvidia/driver` is ephemeral. Reboots, replacement nodes and
image/kernel upgrades require fresh validation and setup. Do not apply these
exact packages to another kernel. Optional DCGM exporter readiness remained
`0/1`, and the workload/probe persistence displays differed; neither issue is
claimed resolved. Full attestation logs may contain tokens: keep them local and
gitignored.

The original missing registry tags and generic-driver failure remain
reproducible. [Appendix: everything tried](#appendix-everything-tried) preserves
the failed attempts, alternatives investigated, fixes and verification evidence.

## Implementation steps - UNSUPPORTED

The steps below follow the [source guide's section order](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/docs/Confidential-GPU-H100-AKS-Onboarding.md):
CLI configuration, cluster creation, setup validation, driver installation,
confidential mode, workload and attestation. They replace only the parts that
failed in this reproduction. **This entire procedure is unsupported**, including
the exact OS/kernel/driver combination that passed the tests.

### 1. Prerequisites and Helm installation

Use Bash on Linux/WSL with Azure CLI (tested: 2.92.0), Helm and kubectl already
installed. Run all blocks in the **same Bash session from this sample directory**,
with its supplied manifests and scripts present. PowerShell users can use the
alternative provisioning commands below, but must not paste Bash blocks into
PowerShell.

Use a disposable cluster, permission to provision AKS, 40 available
`StandardNCCads2023Family` vCPUs plus four system-node vCPUs, and sufficient West
Europe allocation capacity. Allow HTTPS egress to Azure, Ubuntu repositories,
GitHub, NGC and the verifier's certificate/RIM/OCSP services. Do not run this
privileged diagnostic on shared production nodes.

```bash
set -euo pipefail
az version
helm version --short
kubectl version --client
```

### 2. Azcli configurations

Use an explicitly authorized subscription and a new resource group name.
Keep the sample-local extension directory empty: the tested core CLI avoids the
observed `aks-preview` incompatibility without changing shared extensions.
Keep the dedicated kubeconfig rather than overwriting the workstation default.

```bash
subscription='<authorized-subscription-id>'
location=westeurope
resourceGroup=rg-aks-gpu-worker-example
clusterName=aks-gpu-worker-example
mkdir -p .local/cli-extensions-core
export AZURE_EXTENSION_DIR="$PWD/.local/cli-extensions-core"
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no
export KUBECONFIG="$PWD/.local/kubeconfig"
az login
az account show --subscription "$subscription" --query '{name:name,state:state}'
az aks get-versions --subscription "$subscription" --location "$location" -o table
az feature register --subscription "$subscription" \
  --namespace Microsoft.ContainerService --name Ubuntu2404Preview
az feature show --subscription "$subscription" \
  --namespace Microsoft.ContainerService --name Ubuntu2404Preview \
  --query properties.state -o tsv
```

Registration is asynchronous. Wait until the feature reports `Registered`,
rerunning the show command as needed, then propagate registration:

```bash
test "$(az feature show --subscription "$subscription" \
  --namespace Microsoft.ContainerService --name Ubuntu2404Preview \
  --query properties.state -o tsv)" = Registered
az provider register --subscription "$subscription" \
  --namespace Microsoft.ContainerService
```

### 3. Create AKS cluster with CGPU nodepool

These commands create **one system node plus one confidential GPU worker** and
incur charges. Both pools use Ubuntu2404; autoscaling is not enabled. Disabling
automatic upgrades is only for this short-lived controlled experiment.

```bash
az group create --subscription "$subscription" --name "$resourceGroup" \
  --location "$location" --tags sample=aks-gpu-worker
az aks create --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --location "$location" --kubernetes-version 1.36.5 --tier free \
  --nodepool-name sysnp --node-count 1 --node-vm-size Standard_D4ds_v6 \
  --os-sku Ubuntu2404 --node-osdisk-type Managed --node-osdisk-size 128 \
  --enable-managed-identity --generate-ssh-keys \
  --auto-upgrade-channel none --node-os-upgrade-channel None \
  --tags sample=aks-gpu-worker
az aks get-credentials --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --file "$KUBECONFIG" --overwrite-existing
az aks nodepool add --subscription "$subscription" \
  --resource-group "$resourceGroup" --cluster-name "$clusterName" \
  --name gpunp --mode User --node-count 1 \
  --node-vm-size Standard_NCC40ads_H100_v5 --os-sku Ubuntu2404 \
  --gpu-driver None --node-osdisk-type Managed --node-osdisk-size 128 \
  --node-taints sku=gpu:NoSchedule
```

For the retained stopped sample, skip creation, set the variables to its verified
identity, and use `az aks start` instead. Starting it does not restore the
ephemeral driver installation. Do not create additional pools on an unrelated
existing cluster.

### 4. Setup validation

```bash
kubectl wait --for=condition=Ready node --all --timeout=600s
kubectl get nodes -o wide
test "$(kubectl get nodes -o name | wc -l)" -eq 2
test "$(kubectl get nodes -l agentpool=gpunp -o name | wc -l)" -eq 1
gpu_node_name=$(kubectl get nodes -l agentpool=gpunp \
  -o 'jsonpath={.items[0].metadata.name}')
kernel_version=$(kubectl get node "$gpu_node_name" \
  -o 'jsonpath={.status.nodeInfo.kernelVersion}')
test "$kernel_version" = 6.8.0-1071-azure-fde
az aks nodepool list --subscription "$subscription" \
  --resource-group "$resourceGroup" --cluster-name "$clusterName" \
  --query '[].{Name:name,NodeImageVersion:nodeImageVersion}' -o table
nodeResourceGroup=$(az aks show --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --query nodeResourceGroup -o tsv)
az vmss list --subscription "$subscription" --resource-group "$nodeResourceGroup" \
  --query "[?sku.name=='Standard_NCC40ads_H100_v5'].{name:name,count:sku.capacity,security:virtualMachineProfile.securityProfile}"
test "$(az vmss list --subscription "$subscription" --resource-group "$nodeResourceGroup" \
  --query "[?sku.name=='Standard_NCC40ads_H100_v5' && sku.capacity==\`1\` && virtualMachineProfile.securityProfile.securityType=='ConfidentialVM' && virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled==\`true\` && virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled==\`true\`] | length(@)" -o tsv)" = 1
```

The tested worker reported:

```text
OS-IMAGE: Ubuntu 24.04.5 LTS
KERNEL-VERSION: 6.8.0-1071-azure-fde
NODE-IMAGE: AKSUbuntu-2404gen2CVMcontainerd-202610.30.1
```

These are observations, **not an AKS image pin or supported combination**.
Stop if the kernel or effective ConfidentialVM/Secure Boot/vTPM checks differ.
Do not substitute 1041 modules, replace the host kernel or disable security.

### 5. Driver installation

Unlike the source guide, disable the GPU Operator driver operand. Use its toolkit
and device plugin with the separately extracted signed driver tree.

```bash
helm upgrade --install gpu-operator gpu-operator \
  --repo https://helm.ngc.nvidia.com/nvidia --version v26.7.2 \
  --namespace gpu-operator --create-namespace \
  --values gpu-operator-experimental-values.yaml --set driver.enabled=false
kubectl apply -f signed-driver-probe.yaml
kubectl wait --for=condition=Ready pod/signed-driver-load --timeout=300s
tr -d '\r' < Install-SignedDriver.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/signed-driver.log
grep -Fx 'SIGNED_DRIVER_LOADED=1' .local/signed-driver.log
```

The [installer](Install-SignedDriver.sh) verifies Secure Boot, exact kernel,
module-deb checksum, and five module signers/versions/vermagic values. It extracts
`linux-modules-nvidia-615-open-6.8.0-1071-azure-fde=6.8.0-1071.78` and coherent
`615.71.09` firmware/libraries, loads NVIDIA/UVM, starts UVM persistence **before
querying the GPU**, sets readiness, then copies the tree into `/run/nvidia/driver`.
It does not install a moving kernel metapackage or replace AKS containerd.

Keep the probe alive. It refuses already-loaded or partially populated nodes:
after failure, inspect and recycle the disposable node rather than repeatedly
unloading/reloading modules or deleting/recreating the persistence pod.

### 6. Enable confidential GPU mode and verify readiness

The installer already sets ready state after persistence starts. Confirm CC is
ON and PRODUCTION rather than trying to bypass a failed confidential-mode check:

```bash
kubectl exec signed-driver-load -- bash -c 'set -euo pipefail
export LD_LIBRARY_PATH=/tmp/signed-driver/root/usr/lib/x86_64-linux-gnu
smi=/tmp/signed-driver/root/usr/bin/nvidia-smi
kill -0 "$(cat /var/run/nvidia-persistenced/nvidia-persistenced.pid)"
"$smi" conf-compute -f | grep -Fx "CC status: ON"
"$smi" conf-compute -e | grep -Fx "CC Environment: PRODUCTION"
"$smi" conf-compute -q | grep -E "CC GPUs Ready State[[:space:]]*: Ready$"'
kubectl wait --for=jsonpath='{.status.allocatable.nvidia\.com/gpu}'=1 \
  node -l agentpool=gpunp --timeout=600s
kubectl get pods -n gpu-operator -o wide
```

Require one allocatable GPU. Node Ready and Helm `deployed` alone are insufficient.
The Operator CUDA validator completed during the tested runs; optional DCGM
exporter readiness remained `0/1`.

### 7. Sample workload

First attest the GPU so the workload is bracketed by successful checks:

```bash
tr -d '\r' < Test-GpuAttestation.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/gpu-attestation-before.log
grep -Fx 'GPU_ATTESTATION_VALIDATED=1' .local/gpu-attestation-before.log
kubectl apply -f gpu-smoke-test.yaml
kubectl wait --for=condition=Complete job/confidential-gpu-smoke --timeout=240s
kubectl logs job/confidential-gpu-smoke | tee .local/gpu-smoke.log
grep -Fx 'Test PASSED' .local/gpu-smoke.log
```

The [nonprivileged Job](gpu-smoke-test.yaml) requests and limits one GPU, uses
runtime class `nvidia`, and validates CUDA vector addition of 50,000 elements.
No CPU fallback is supplied.

### 8. GPU attestation and separate CPU/CVM attestation

```bash
tr -d '\r' < Test-GpuAttestation.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/gpu-attestation-after.log
grep -Fx 'GPU_ATTESTATION_VALIDATED=1' .local/gpu-attestation-after.log
tr -d '\r' < Test-CvmAttestation.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/cvm-attestation-summary.log
grep -Fx 'CVM_ATTESTATION_VALIDATED=1' .local/cvm-attestation-summary.log
```

Require zero pipeline exits throughout. [GPU verification](Test-GpuAttestation.sh)
uses checksum-pinned V4.5.1 verifier `2.3.0`, Python 3.12, strict OCSP and a fresh
nonce; it requires `GPU Attestation is Successful.` and verification of the
actual GPU UUID. [CVM verification](Test-CvmAttestation.sh) independently makes
the MAA request and requires returned `sevsnpvm` / `azure-compliant-cvm` claims,
not an additional independent JWT signature validator.

The probe's read-only securityfs mount supplies the TPM event log needed by MAA.
Keep full logs in the pod or ignored, access-controlled local storage: they may
contain tokens. Preserve needed evidence before cleanup; do not commit it.

### 9. Troubleshooting and cleanup

Do not continue after a failed gate. Use the
[investigation appendix](#appendix-everything-tried) for the observed failure
signatures. After a successful run, remove only the four probe-owned firmware
files and test resources, then promptly stop the cluster:

```bash
kubectl delete job confidential-gpu-smoke --ignore-not-found
kubectl exec signed-driver-load -- bash -c 'set -eu
rm -- /lib/firmware/nvidia/615.71.09/gsp_ga10x.bin \
  /lib/firmware/nvidia/615.71.09/gsp_tu10x.bin \
  /lib/firmware/nvidia/615.71.09/ucodes_ga10x.bin \
  /lib/firmware/nvidia/615.71.09/ucodes_tu10x.bin
rmdir /lib/firmware/nvidia/615.71.09'
kubectl delete pod signed-driver-load
az aks stop --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName"
az aks show --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --query '{power:powerState.code,state:provisioningState}'
az vmss list --subscription "$subscription" --resource-group "$nodeResourceGroup" \
  --query '[].{name:name,capacity:sku.capacity}' -o table
```

Require **Stopped / Succeeded** and **both VMSS capacities zero**. If setup failed,
still run `az aks stop`; inspect which exact probe-owned files exist before
cleaning them rather than allowing a cleanup failure to leave compute running.
Stopping retains potentially billable disks/networking. Explicit group deletion
is described in [Cleanup](#cleanup).

## Deployment plan and scope

Create a disposable development cluster in West Europe with Kubernetes 1.36.5,
one Ubuntu 24.04 system node (`Standard_D4ds_v6`), and exactly one Ubuntu 24.04
confidential GPU user node (`Standard_NCC40ads_H100_v5`). AKS requires a system
pool: this is **two nodes total**, not a one-node cluster. Disable automatic
driver installation, autoscaling, and automatic upgrades during the experiment.
Use the existing signed-in Azure subscription only when explicitly supplied.
Do not overwrite other clusters, change the workstation's default subscription
or kubeconfig, downgrade AKS node images, or bypass confidential-computing checks.

The Azure CLI recipe follows the
[onboarding guide](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/docs/Confidential-GPU-H100-AKS-Onboarding.md).
The scripts are PowerShell 7 equivalents with quota checks, bounded waits,
native-command error handling, and registry compatibility gates.
This is not a production architecture or a claim of a supported new OS/driver combination.
Unlike the guide's Ubuntu 22.04 system pool, both pools use Ubuntu 24.04 because
the AKS documentation warns against mixed OS versions with GPU Operator.

## PowerShell alternative prerequisites

- PowerShell 7.2+, Azure CLI, `kubectl`, and Helm for subsequent GPU Operator setup.
  The guide uses `aks-preview`; alternatively, `-UseCoreCli` uses built-in AKS
  commands (verified with Azure CLI 2.92.0) without loading installed extensions.
- `az login`, permissions to create AKS and its managed resources, and an enabled
  subscription with regional and VM-family quota. One H100 worker needs 40
  `StandardNCCads2023Family` vCPUs, plus four system-node vCPUs.
- `Ubuntu2404Preview` registered in `Microsoft.ContainerService` as required by
  the linked guide. Registration may need subscription-owner assistance.
- HTTPS access to Azure, GitHub, NVIDIA NGC, and the Kubernetes API.

Azure CLI on Windows is also detected at its standard installation path when
the current terminal's PATH has not been refreshed.

## PowerShell alternative provisioning

Run from this directory. The supplied resource group must be new unless resuming
this sample's deployment. Resource creation incurs charges.

```powershell
$subscription = '<subscription-id>'
$resourceGroup = 'rg-aks-gpu-worker-20261110'
$cluster = 'aks-gpu-worker-20261110'

.\Deploy.ps1 -SubscriptionId $subscription -ResourceGroup $resourceGroup `
    -ClusterName $cluster -UseCoreCli -PreflightOnly

# Registers the documented preview if necessary, with a 20-minute timeout.
.\Deploy.ps1 -SubscriptionId $subscription -ResourceGroup $resourceGroup `
    -ClusterName $cluster -UseCoreCli -RegisterPreview
```

For a partial deployment, inspect the resources and rerun with `-Resume`.
Keep the same system-node SKU and `-UseCoreCli` selection when resuming.
Resume validates sample ownership and existing pool configuration before cloud
mutations, and quota checks count only pools still to be created.
Use `-GpuZone` only with a zone reported as available to the subscription.
Quota and SKU listings do not guarantee physical allocation capacity.
No alternate subscription, region, VM family, or kernel is silently substituted.

The deployment saves local evidence and a dedicated kubeconfig in `.local/`
(gitignored). Do not commit credentials or raw cloud/Kubernetes dumps.
The development cluster follows the guide's authentication model; protect its
API access and kubeconfig. Use Entra RBAC, restricted API access and a resilient
system pool for production. Automatic upgrades are disabled only for this
short-lived experiment, not as a long-term security policy.

## Exact-kernel container compatibility gate

This gate diagnoses the original **container-image path**. It is expected to
fail on the tested 1071 kernel and is not an acceptance gate for the unsupported
signed-package workaround above. A successful signed-package run does not
change the missing-image result.

```powershell
.\Test-DriverCompatibility.ps1 -KubeConfig .\.local\kubeconfig -RequireAvailable
```

The worker's **actual** kernel determines the image tag. Selecting Kubernetes
1.36.5 and `Ubuntu2404` does not select an AKS node-image build or kernel.
An unavailable exact-kernel image is an external blocker, not a reason to use
1041 modules on a 1071 kernel. Do not disable Secure Boot, change the host kernel,
or install unsigned modules to get past it.

The script also verifies the underlying H100 scale set has exactly one instance,
`securityType: ConfidentialVM`, Secure Boot enabled and vTPM enabled. Inspect the
VM scale-set security profile rather than assuming the AKS pool's generic
security flags describe the confidential VM's effective settings.

## Resource status

The retained deployment is named `aks-gpu-worker-20261110` in
`rg-aks-gpu-worker-20261110`, West Europe. Resources are retained for inspection.
After the final successful published-script replay, the probe-owned firmware
files, test Job and probe pod were removed. `az aks stop` succeeded: the cluster
reported **Stopped / Succeeded**, and both node scale sets were verified at
capacity **zero**. Full attestation evidence was preserved only in ignored
local storage before the probe was removed.
Stopping AKS deallocates compute but retained disks, networking and other
resources can still incur charges; stopping is not deletion.

## Local regression checks

```powershell
.\tests\Test-Sample.ps1
```

These dependency-free tests mock registry and node responses. They check
authentication and OCI/Docker Accept headers, missing tags versus other HTTP
failures, digest validation, compatibility-report shape, the exact pool topology,
effective confidential VM security, and native-process failures. They do not
establish cloud capacity or GPU support.

## Cleanup

Resources are deliberately retained for inspection, including after failure.
Review the group and delete it explicitly when finished; this removes the
cluster and its managed node resources and stops their ongoing charges.

```powershell
az group show --subscription $subscription --name $resourceGroup
az group delete --subscription $subscription --name $resourceGroup --yes
```

## References

- [Confidential GPU AKS onboarding](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/docs/Confidential-GPU-H100-AKS-Onboarding.md)
- [AKS confidential GPU documentation](https://learn.microsoft.com/azure/aks/use-confidential-gpus)
- [AKS node image upgrades](https://learn.microsoft.com/azure/aks/node-image-upgrade)

## Appendix: everything tried

This appendix retains the investigation history, including unsuccessful recipes.
It is **not the current installation procedure**. Use the unsupported workaround
at the top and its linked walkthrough for the tested sequence.

### Registry-failure reproduction without an Azure cluster

```powershell
.\Test-DriverCompatibility.ps1 -KernelVersion '6.8.0-1071-azure-fde'
.\Test-DriverCompatibility.ps1 -KernelVersion '6.8.0-1041-azure-fde'
.\Test-DriverCompatibility.ps1 -KernelVersion '6.8.0-1063-azure-fde'
```

The JSON distinguishes missing manifests from authentication/network failures.
Add `-RequireAvailable` to fail when neither exact-kernel image exists.
`SupportValidated: false` is intentional: a published image alone does not prove
Microsoft/NVIDIA support, module loading, confidential mode, or attestation.

### Initial blockers and investigation results

Live checks on 2026-11-10:

| Check | Result | Interpretation / action |
|---|---|---|
| West Europe H100 SKU | Listed without subscription restrictions; zone 3 advertised; one worker allocated successfully without an explicit zone | Capacity was sufficient for this attempt, not a future guarantee. |
| H100 quota | 40 available family vCPUs; 140 available regional vCPUs | Sufficient for one worker and the system node. |
| Kubernetes 1.36.5 | Offered | The requested API version can be selected; this does not pin the kernel. |
| System node `Standard_D4ds_v5` | `NotAvailableForSubscription` in West Europe | Changed only the system node to unrestricted `Standard_D4ds_v6`, with 100 family vCPUs available. |
| `Ubuntu2404Preview` | Initially `NotRegistered`; registration succeeded | Registered before cluster creation. |
| Azure CLI 2.92.0 with `aks-preview` 18.0.0b17 | `ManagedCluster` has no attribute `hosted_system_profile` | Client-side failure; retry with `-UseCoreCli`, an empty sample-local extension directory, and dynamic extension installation disabled. The shared extension installation is unchanged. |
| AKS cluster and node pools | Provisioned; exactly one system node and one H100 user node, both Kubernetes `v1.36.5` and Ready | The control-plane/system-pool and H100 allocation stages succeeded. Node Ready is not GPU readiness. |
| Actual H100 node image | `AKSUbuntu-2404gen2CVMcontainerd-202610.30.1` | Matches the reported image build. |
| Actual worker OS / kernel / runtime | Ubuntu `24.04.5 LTS` / `6.8.0-1071-azure-fde` / `containerd://2.3.7-4` | The current provisioning recipe does not produce the guide's documented Ubuntu 24.04.3 / kernel 1041 combination. |
| Effective H100 VM security | `ConfidentialVM`; Secure Boot and vTPM both enabled | Verified on the underlying VM scale set; no security bypass was applied. |
| `580-6.8.0-1041-azure-fde-ubuntu24.04` | HTTP 200 | Published; the guide explicitly describes this kernel. |
| `580-6.8.0-1063-azure-fde-ubuntu24.04` | HTTP 200 with OCI Accept headers | Published; support for this combination has not been established. |
| `580-6.8.0-1071-azure-fde-ubuntu24.04` | HTTP 404, `MANIFEST_UNKNOWN`, `manifest unknown` | Reported missing image reproduced directly. |
| `595-6.8.0-1071-azure-fde-ubuntu24.04` | HTTP 404, `MANIFEST_UNKNOWN`, `manifest unknown` | Changing the driver branch does not fix this missing tag. |

Unauthenticated registry requests return HTTP 401 even for existing images.
Authenticate using the public anonymous bearer-token flow. Also request both
OCI and Docker manifest media types: otherwise an existing OCI image can return
a misleading HTTP 404 (`OCI manifest found, but accept header does not support
OCI manifests`). Neither error should be classified as an absent tag.

**Initial outcome: cluster provisioned; exact-kernel container path blocked.** The
exact-kernel compatibility gate deliberately exits with an error after saving
the evidence. This is not a failed H100 allocation: it is a reproducible missing
driver-image blocker on the actual provisioned worker.

The initial reproduction stopped before GPU Operator installation. The subsequent
generic-driver experiment below did install GPU Operator and attempt driver
loading, unsuccessfully. The later signed-package experiment succeeded through
a different installation path. The 1041 and 1063 images remain positive controls,
not substitutes for 1071.

To unblock, obtain a Microsoft/NVIDIA-supported pairing for the actual Ubuntu
24.04.5 / Azure-FDE kernel: a published, compatible signed driver image and
confirmation of its support, or an officially supported AKS provisioning path
that yields a compatible OS/kernel. Neither a Kubernetes-version selection nor
`--os-sku Ubuntu2404` pins the node-image build. This reproduction found no
supported way to select the guide's old kernel through these commands, and did
not attempt an unsupported node-image downgrade or host-kernel replacement.

Once an approved pairing is available, rerun the compatibility gate and follow
the pinned guide's GPU Operator `v25.3.1` steps with the exact driver version.
The worker has `sku=gpu:NoSchedule`: add that toleration to GPU Operator operands
and node-feature-discovery workers before installation. Then verify the signed
module loads, `nvidia-smi` confidential mode/readiness, one allocatable GPU, a
GPU-only workload that fails rather than falling back to CPU, and GPU attestation.
Those are separate acceptance stages, not consequences of a manifest returning
HTTP 200.

### Latest-image / generic-driver experiment

This is an **experimental reproduction, not a supported onboarding recipe**.
It preserves the original exact-kernel compatibility gate; generic image
publication does not satisfy that gate.

On 2026-11-10, the AKS node-pool upgrade API offered
`AKSUbuntu-2404gen2CVMcontainerd-202610.30.1`, identical to the existing image.
Restarting the cluster restored exactly one system node and one H100 worker,
both Ready. The worker still used Ubuntu 24.04.5 and
`6.8.0-1071-azure-fde`. The underlying H100 scale set retained ConfidentialVM,
Secure Boot and vTPM. No pool scaling or image upgrade was needed.

| Attempt | Observed result |
|---|---|
| GPU Operator `v26.7.2`, default driver `595.91.07`, open modules | Generic `595.91.07-ubuntu24.04` image pulled successfully. Driver initialization failed before module installation. |
| GPU Operator `v26.7.2`, newer published driver `615.71.09`, open modules | Generic `615.71.09-ubuntu24.04` image pulled successfully. The same initialization failure reproduced. |
| Exact-kernel `615-6.8.0-1071-azure-fde-ubuntu24.04` | HTTP 404 / `MANIFEST_UNKNOWN`. |
| Worker GPU resources after generic-container attempts | No `nvidia.com/gpu` allocatable resource; GPU Operator operands remained in initialization. |
| Attestation at this stage | Not run: the generic-container driver prerequisite failed. See the successful signed-package follow-up below. |

Both generic driver containers successfully obtained the **matching kernel
headers**. They then downloaded the Ubuntu kernel packages and failed with:

```text
Generating Linux kernel version string...
ls: cannot access 'boot/vmlinuz-*': No such file or directory
Could not locate Linux kernel version string
```

The container's `/usr/local/bin/nvidia-driver` expects `boot/vmlinuz-*` after
extracting `linux-image-${KERNEL_VERSION}`. Inspection of the actual Azure-FDE
package showed `usr/lib/linux/efi/kernel.efi-6.8.0-1071-azure-fde` instead.
This is a distinct generic-container packaging/layout blocker, **not missing
kernel headers**, and occurs before NVIDIA modules are built or loaded.

The Ubuntu package index also lists exact-kernel NVIDIA module packages,
including `linux-modules-nvidia-615-open-6.8.0-1071-azure-fde`
(`6.8.0-1071.78`), with dependency on NVIDIA `615.71.09`.
The signed-package follow-up below tests that route separately; publication is
not proof of a supported AKS integration or successful attestation.
The matching generic NVIDIA image exists (digest
`sha256:0ed39c3e75c219954ba81be558c9aa0e6abbfa838c0f60d61bf9a139776fa186`).
Simply selecting it does not make GPU Operator consume Ubuntu's module packages.

### Reusing the standalone VM signed-package approach

The existing [VM deployment script](../../vm-samples/BuildRandomCVM.ps1) was
inspected but **not modified**. Its H100 path forces a confidential Ubuntu
22.04 VM, downloads the checksum-pinned V4.3.3 onboarding archive, prepares a
snapshot kernel, and reboots. Its non-GPU Ubuntu choices do not establish an
AKS confidential GPU image choice. Do not copy its kernel preparation, moving
kernel metapackage, reboot sequence or Docker installation onto a managed AKS
node.

The reusable part is the **signed module package**, selected for the running
kernel, with coherent firmware and user-space libraries. On 2026-11-10, a
disposable Ubuntu 24.04 pod on the actual H100 worker downloaded and extracted:

| Exact Ubuntu package | Package version | Module driver version | Inspection |
|---|---|---|---|
| `linux-modules-nvidia-595-server-open-6.8.0-1071-azure-fde` | `6.8.0-1071.78` | `595.91.07` | Five prebuilt modules; correct kernel vermagic; Canonical signer. |
| `linux-modules-nvidia-615-open-6.8.0-1071-azure-fde` | `6.8.0-1071.78` | `615.71.09` | Five prebuilt modules; correct kernel vermagic; Canonical signer. |

Both trees reported `Canonical Ltd. Kernel Module Signing`, signing-key ID
`E9:DF:13:0F:92:92:A9:B7`, SHA-512 signatures, and vermagic
`6.8.0-1071-azure-fde SMP mod_unload modversions`. Metadata alone does not prove
the node accepts a signature. A subsequent privileged probe **did load the
615 NVIDIA and UVM modules with guest Secure Boot enabled**. The first
`nvidia-smi` identified an NVIDIA H100 NVL and driver `615.71.09`.

The probe downloaded exact packages and extracted them, rather than installing
the full VM driver metapackage onto the host. A clean-container `apt-get -s`
simulation of that metapackage also selected DKMS, kernel and X11 packages.
It is therefore not a safe managed-AKS installation recipe. Only the matching
615 firmware directory was temporarily copied into the host firmware path;
the host kernel and its module tree were not replaced.

Initial GPU detection was **not sustained readiness**: persistence was not
started before the first short-lived query. The next CC query returned
`No devices were found` (exit 6). Kernel logs reported:

```text
kgspCheckGspRmCcCleanup_GH100: CC secret cleanup failed due to timeout!
RmInitAdapter: osInitNvMapping failed, bailing out of RmInitAdapter
RmInitAdapter failed! (0x22:0x56:904)
```

Unloading and reloading the same signed module then failed with `No such device`.
This moves the investigation past the generic container's kernel-layout error
to GPU lifecycle/persistence initialization. It does not establish that
persistence ordering is the sole cause, that 615 is supported for this AKS image,
or that attestation succeeds. The clean persistence-first retry below supplies
the sustained-readiness and attestation evidence missing from this first attempt.

### Successful persistence-first retry

A fresh-node retry used the same exact signed `615.71.09` packages, preloaded
`ecdsa_generic`, `ecdh` and `ecc`, loaded NVIDIA/UVM, and started
`nvidia-persistenced --uvm-persistence-mode` **before** invoking `nvidia-smi`.
It then set confidential-compute ready state and copied the coherent extracted
driver tree into `/run/nvidia/driver`. GPU Operator `v26.7.2`, installed with
`driver.enabled=false`, supplied the toolkit/runtime and device plugin without
replacing AKS-managed containerd.

| Acceptance check | Live result |
|---|---|
| Current worker | Ubuntu 24.04.5, AKS image `AKSUbuntu-2404gen2CVMcontainerd-202610.30.1`, kernel `6.8.0-1071-azure-fde`. |
| Trusted driver loading | Canonical-signed NVIDIA/UVM `615.71.09` accepted by the running Secure Boot kernel; H100 NVL detected. |
| Confidential GPU | `CC status: ON`, `CC Environment: PRODUCTION`, `CC GPUs Ready State: Ready`; persistence daemon alive. |
| Kubernetes integration | Exactly one allocatable `nvidia.com/gpu`; Operator CUDA validator passed. |
| Independent GPU workload | Nonprivileged Job requested/limited one GPU using runtime class `nvidia`; vector addition of 50,000 elements returned `Test PASSED`. No CPU fallback. |
| GPU attestation before/after workload | V4.5.1 archive, verifier `2.3.0`, strict OCSP; exit zero, expected GPU UUID verified, exact `GPU Attestation is Successful.` verdict on both runs. |
| Sustained readiness | Three repeated post-workload CC queries succeeded and persistence remained alive. |
| Separate CPU/CVM attestation | Checksum-verified Azure guest CLI `v0.1.0`, MAA provider; exit zero and decoded `sevsnpvm` / `azure-compliant-cvm` claims. |

The published installer, probe manifest, workload and both attestation scripts
were then replayed unchanged on another fresh worker. The installer emitted
`SIGNED_DRIVER_LOADED=1`; GPU attestation emitted
`GPU_ATTESTATION_VALIDATED=1` before and after the Job's `Test PASSED`;
CVM attestation emitted `CVM_ATTESTATION_VALIDATED=1`. The GPU UUID was
discovered dynamically and differed from the previous allocation. The worker
still had ConfidentialVM, Secure Boot and vTPM enabled, with one allocatable GPU.
All nine Bash blocks in the CLI walkthrough passed syntax checks. Re-running
the installer on the initialized worker failed at its already-loaded-module
guard before mutation, while the existing persistence daemon and GPU remained
ready. Optional DCGM exporter readiness remained `0/1`; monitoring health is
not claimed by these workload and attestation results.

This comparison supports persistence-first initialization as the useful remedy
for this reproduction, not proof of the sole cause or of vendor support.
The workload container's `nvidia-smi` displayed Persistence Off while the probe
reported Enabled with its UVM persistence daemon alive. That display discrepancy
was not conclusively explained; repeated readiness, CUDA and attestation checks
passed. Do not equate any single persistence display with attestation.

CPU attestation initially failed with MAA HTTP 400, `TcgLogs is empty in
attestation request`. Mounting host `/sys/kernel/security` read-only exposed
the TPM event log and resolved that failure. Its sysfs stat size is zero despite
containing readable data: use `wc -c`, not `test -s`, to check it. GPU attestation
and CPU/CVM attestation are separate results; the latter records the successful
MAA request and returned claims, not an additional independent JWT verifier.

The reusable artifacts are [the probe manifest](signed-driver-probe.yaml),
[exact-package installer](Install-SignedDriver.sh),
[GPU-only workload](gpu-smoke-test.yaml),
[strict GPU attestation](Test-GpuAttestation.sh), and
[CPU/CVM attestation](Test-CvmAttestation.sh). The verifier warns of future
deprecation in favour of `nvattest`; that migration has not been tested here.
Full attestation logs can include tokens and must remain local, not in Git.

**Lifecycle boundary:** the privileged probe holds the persistence daemon and
expires after four hours. Deleting it ends persistence; `/run/nvidia/driver` is
ephemeral. Reboot, node replacement or a new image/kernel requires fresh matching
package validation and setup. The installer intentionally rejects an already
initialized node rather than guessing how to reconcile it. No DKMS, host kernel
replacement, unsigned modules, key enrollment or Secure Boot bypass was used.

### Clues from the full upstream onboarding flow

The [full upstream repository](https://github.com/Azure/az-cgpu-onboarding/tree/136262ef00ad75b8e0bc789563f043006fb68f4c),
not just its AKS page, provides several useful distinctions:

- **Signed exact-ABI modules:** the V4.3.3 VM installer uses
  `nvidia-driver-595-server-open` with a moving
  `linux-modules-nvidia-595-server-open-azure-fde` metapackage. Reuse the
  packaging principle, not the unmodified host installer or its moving kernel
  selection.
- **Crypto dependencies:** the
  [driver installer](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/src/step-1-install-gpu-driver.sh)
  preloads `ecdsa_generic` and `ecdh`; the inspected NVIDIA module also depends
  on `ecc`. The live signed-module probe loaded these before NVIDIA.
- **Persistence before validation:** the
  [persistence override](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/src/nvidia-persistenced.override.conf)
  enables `--uvm-persistence-mode`, then sets GPU ready state with
  `nvidia-smi conf-compute -srs 1`. The
  [attestation script](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/src/step-2-attestation.sh)
  waits for persistence and checks that it is enabled. A single successful
  `nvidia-smi` invocation is not an adequate substitute.
- **Runtime integration is separate:** the
  [VM tools installer](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/src/step-3-install-gpu-tools.sh)
  installs Docker/containerd and configures the Docker NVIDIA runtime. Do not
  overwrite AKS-managed containerd with that installer. A functioning module
  still needs AKS-compatible toolkit, device-plugin and GPU scheduling checks.
- **Standalone VM alternative:** the root README recommends a prebuilt
  community-gallery VM image with drivers, CUDA, Docker and verifier included.
  The current automatic VM onboarding also has an Ubuntu 24.04 path. These
  are alternatives if AKS is not mandatory, not AKS node-image selections or
  evidence of a working confidential AKS configuration.
- **Different failures need different fixes:** the
  [FAQ](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/Frequently-Asked-Questions.md)
  describes driver/library mismatches after updates; that is distinct from
  the initial generic-container `vmlinuz` extraction failure. The FAQ also
  explains the Azure vTPM CPU attestation route; absence of `/dev/sev-guest`
  alone is not proof that an Azure SNP VM lacks confidential protection.
- **Verifier alternatives do not fix drivers:** the optional preview
  `nvattest` path is a verifier choice, not a way around missing modules,
  failed GPU initialization or the requirement for positive attestation.

### Newer Ubuntu node OS availability

Checked on 2026-11-10 against the published AKS documentation and the existing
West Europe confidential H100 pool's node-image upgrade API:

| Ubuntu version | Published AKS availability | Applicability to this reproduction |
|---|---|---|
| 25.x | Not listed as a supported AKS node OS. | No documented AKS node OS option established. |
| 26.04 | Preview for Kubernetes 1.36 and later, using OS SKU `Ubuntu2604` and feature flag `Ubuntu2604Preview`. Requires Generation 2 VMs; Confidential VM, Trusted Launch and FIPS are explicitly unsupported. | Not a supported replacement for the confidential H100 worker, even though this cluster uses Kubernetes 1.36.5. |
| 24.04 | Supported Ubuntu family for AKS Confidential VM node images. | The existing pool's latest offered image remains `AKSUbuntu-2404gen2CVMcontainerd-202610.30.1`; the worker observed during the experiment used Ubuntu 24.04.5. |

Sources: [AKS OS version support and Ubuntu 26.04 preview restrictions](https://learn.microsoft.com/azure/aks/upgrade-os-version#migrate-to-ubuntu-2604-preview)
and [AKS node-image variants](https://learn.microsoft.com/azure/aks/node-images).
General AKS preview availability is distinct from support for a confidential
GPU node and does not prove availability for every VM size or region. Likewise,
the existing pool's upgrade response describes that pool's image track, not all
AKS OS SKUs.

Ubuntu 26.04 is therefore not a documented workaround for this driver blocker.
A standard, non-confidential node would not validate the required environment.
Changing a workload container's Ubuntu base image would not change the managed
host kernel or resolve the driver container's Azure-FDE package-layout failure.
This availability check was read-only; the cluster remained stopped.

### Reproduce the failed generic-container stage with Azure CLI

Use the existing subscription, resource group and cluster from the deployment
stage. Keep the sample kubeconfig separate from the default context. These Bash
commands follow the upstream guide's Azure CLI style; they resume billable nodes.
The local values file adds both GPU-taint tolerations and open-module selection.
**This block deliberately reenables the failed generic installer. Do not run it
over a successful signed-package probe.** Use the updated walkthrough for the
working experimental route.

```bash
az aks nodepool get-upgrades --subscription "$subscription" \
  --resource-group "$resourceGroup" --cluster-name "$clusterName" \
  --nodepool-name gpunp

az aks start --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName"

az aks get-credentials --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --file .local/kubeconfig --overwrite-existing

export KUBECONFIG="$PWD/.local/kubeconfig"
kubectl get nodes -o wide

helm upgrade --install gpu-operator gpu-operator \
  --repo https://helm.ngc.nvidia.com/nvidia --version v26.7.2 \
  --namespace gpu-operator --create-namespace \
  --values gpu-operator-experimental-values.yaml --set driver.enabled=true

kubectl --namespace gpu-operator get pods -o wide
kubectl --namespace gpu-operator logs \
  --selector app=nvidia-driver-daemonset --container nvidia-driver-ctr \
  --tail=150
# After a container restart, inspect the failed attempt:
kubectl --namespace gpu-operator logs \
  --selector app=nvidia-driver-daemonset --container nvidia-driver-ctr \
  --previous --tail=150
kubectl get nodes --selector agentpool=gpunp \
  -o 'jsonpath={.items[0].status.allocatable}'

az aks stop --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName"
az aks show --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --query '{power:powerState.code,state:provisioningState}'
```

Do not treat Helm's `deployed` status as GPU readiness. In this experiment Helm
succeeded, but the driver did not. Do not work around the layout failure by
replacing the managed host kernel, disabling Secure Boot, installing unsigned
modules, or inventing a driver-ready state. Resolution needs a compatible,
trusted installation path for this Azure-FDE image. The signed-package route
above bypasses the broken container entrypoint without changing the host kernel.

### Attestation acceptance after driver enablement

The existing [VM GPU attestation flow](../../vm-samples/BuildRandomCVM.ps1)
provides a reusable checksum-pinned verifier and explicit positive-verdict
checks. Its host-kernel installation and reboot steps do **not** apply to AKS.
Before adapting the verifier Job, require:

1. A loaded, trusted NVIDIA module and working `nvidia-smi`.
2. `CC status: ON`, `CC Environment: PRODUCTION`, and one allocatable H100 GPU.
3. A GPU-targeted workload that fails rather than falling back to CPU.
4. A checksum-verified, version-pinned verifier, zero exit status, the exact
   `GPU Attestation is Successful.` verdict, and successful verification of the
   expected GPU UUID. A Completed pod alone is insufficient.

For the newer reviewed Azure verifier V4.5.1, the release archive SHA-256 is
`075ee785f6d65799d99ae18102fb88bdab4afe31540bf16673a27545c0ba80e8`.
Its Python package requires Python 3.12. Use strict OCSP validation
(`--ocsp_attestation_settings strict`) rather than permissive defaults, and
preserve the verifier evidence. GPU attestation is separate from CPU/CVM
attestation; both have now passed separately through the signed-package route.
The [updated onboarding walkthrough](Confidential-GPU-H100-AKS-Onboarding.md)
preserves the Azure CLI workflow while clearly labeling this experimental path.
