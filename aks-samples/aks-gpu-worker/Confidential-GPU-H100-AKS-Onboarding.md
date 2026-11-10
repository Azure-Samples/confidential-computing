# Confidential H100 on AKS: tested signed-package workaround

This companion to the [upstream AKS onboarding page](https://github.com/Azure/az-cgpu-onboarding/blob/136262ef00ad75b8e0bc789563f043006fb68f4c/docs/Confidential-GPU-H100-AKS-Onboarding.md)
retains its Azure CLI, GPU Operator and workload-validation workflow, but uses
exact-kernel Ubuntu signed packages instead of the failing driver-container
entrypoint. See [investigation history](README.md) for the original blockers.

**Experimental diagnostic recipe, not a supported production configuration.**
It runs a privileged pod with host devices and firmware access. Do not use on
shared production nodes. The pod holds UVM persistence for at most four hours;
this is not a reconciled installation across reboots, image upgrades or node
replacement. Keep Secure Boot, vTPM and confidential mode enabled.

## Tested configuration

Observed in West Europe on 2026-11-10:

| Component | Observed value |
|---|---|
| Topology | One system node plus one confidential GPU worker (two nodes total) |
| System node | `Standard_D4ds_v6`, Ubuntu2404 |
| GPU worker | `Standard_NCC40ads_H100_v5`, H100 NVL, Ubuntu2404 |
| Kubernetes | `1.36.5` |
| AKS GPU node image | `AKSUbuntu-2404gen2CVMcontainerd-202610.30.1` |
| GPU node OS / kernel | Ubuntu 24.04.5 LTS / `6.8.0-1071-azure-fde` |
| Runtime | `containerd://2.3.7-4` |
| Security | ConfidentialVM, Secure Boot and vTPM enabled; GPU CC ON / PRODUCTION |
| GPU Operator | `v26.7.2`, **driver operand disabled** |
| NVIDIA signed package | `linux-modules-nvidia-615-open-6.8.0-1071-azure-fde=6.8.0-1071.78` |
| NVIDIA driver / matching libraries | `615.71.09` / `615.71.09-0ubuntu0.24.04.2` |
| GPU verifier | Checksum-pinned Azure archive V4.5.1, package `2.3.0`, strict OCSP |
| CPU/CVM verifier | Checksum-pinned Azure guest CLI `v0.1.0`, MAA |

These are observed versions, not an AKS image pin. AKS may provision a different
kernel later; the installer must fail rather than load mismatched modules.
Ubuntu 26.04 preview explicitly excludes ConfidentialVM; changing container
Ubuntu versions does not change the host kernel.

## 1. Prerequisites and isolated context

Use Azure CLI (tested: 2.92.0), kubectl, Helm and Bash. Run the Bash blocks from
this sample directory in a Linux/WSL shell with those tools configured.
The local shell does not need NVIDIA or Python. HTTPS egress is needed for Azure,
Ubuntu repositories, GitHub, NGC and the verifier's certificate/RIM/OCSP services.
Use an authorized subscription with 40 free H100-family vCPUs plus four system
vCPUs and sufficient physical allocation capacity.

```bash
set -euo pipefail
subscription='<authorized-subscription-id>'
location=westeurope
resourceGroup=rg-aks-gpu-worker-example
clusterName=aks-gpu-worker-example
mkdir -p .local/cli-extensions-core
export AZURE_EXTENSION_DIR="$PWD/.local/cli-extensions-core"
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no
export KUBECONFIG="$PWD/.local/kubeconfig"
az account show --subscription "$subscription" --query '{name:name,state:state}'
az aks get-versions --subscription "$subscription" --location "$location" -o table
```

Keep the extension directory empty. This avoids the observed `aks-preview`
18.0.0b17 / core CLI 2.92.0 `hosted_system_profile` client incompatibility without
modifying shared extensions or the default subscription/kubeconfig.
The development authentication model follows the original sample; use Entra
RBAC and restricted API access for production.

If needed, register the feature from the upstream guide and wait until it is
`Registered` before creation:

```bash
az feature register --subscription "$subscription" \
  --namespace Microsoft.ContainerService --name Ubuntu2404Preview
az feature show --subscription "$subscription" \
  --namespace Microsoft.ContainerService --name Ubuntu2404Preview \
  --query properties.state -o tsv
az provider register --subscription "$subscription" --namespace Microsoft.ContainerService
```

Registration is asynchronous. Do not proceed while the feature is registering.
For automated quota/topology/ownership checks and bounded registration waits,
use [Deploy.ps1](Deploy.ps1) with `-UseCoreCli` as described in the README.

## 2. Create the disposable cluster and confidential worker

Use a **new** resource group. These commands incur charges. Automatic upgrades
are disabled only to control this short-lived reproduction, not as a security
policy. AKS requires a system pool; the confidential worker is a user pool.

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
az aks nodepool add --subscription "$subscription" \
  --resource-group "$resourceGroup" --cluster-name "$clusterName" \
  --name gpunp --mode User --node-count 1 \
  --node-vm-size Standard_NCC40ads_H100_v5 --os-sku Ubuntu2404 \
  --gpu-driver None --node-osdisk-type Managed --node-osdisk-size 128 \
  --node-taints sku=gpu:NoSchedule
```

For this sample's existing stopped cluster, skip creation and instead use
`az aks start --subscription "$subscription" --resource-group "$resourceGroup"
--name "$clusterName"`. Verify its identity and topology before resuming.

```bash
az aks get-credentials --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" \
  --file "$KUBECONFIG" --overwrite-existing
kubectl wait --for=condition=Ready node --all --timeout=600s
kubectl get nodes -o wide
test "$(kubectl get nodes -o name | wc -l)" -eq 2
test "$(kubectl get nodes -l agentpool=gpunp -o name | wc -l)" -eq 1
test "$(kubectl get nodes -l agentpool=gpunp \
  -o 'jsonpath={.items[0].status.nodeInfo.kernelVersion}')" = 6.8.0-1071-azure-fde
az aks nodepool get-upgrades --subscription "$subscription" \
  --resource-group "$resourceGroup" --cluster-name "$clusterName" \
  --nodepool-name gpunp
nodeResourceGroup=$(az aks show --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$clusterName" --query nodeResourceGroup -o tsv)
az vmss list --subscription "$subscription" --resource-group "$nodeResourceGroup" \
  --query "[?sku.name=='Standard_NCC40ads_H100_v5'].{name:name,count:sku.capacity,security:virtualMachineProfile.securityProfile}"
test "$(az vmss list --subscription "$subscription" --resource-group "$nodeResourceGroup" \
  --query "[?sku.name=='Standard_NCC40ads_H100_v5' && sku.capacity==\`1\` && virtualMachineProfile.securityProfile.securityType=='ConfidentialVM' && virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled==\`true\` && virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled==\`true\`] | length(@)" -o tsv)" = 1
```

Do not continue if effective ConfidentialVM/Secure Boot/vTPM or the kernel differ.
Neither Kubernetes version nor Ubuntu2404 selects the guide's old 1041 image.

## 3. Install GPU Operator without its broken driver installer

```bash
helm upgrade --install gpu-operator gpu-operator \
  --repo https://helm.ngc.nvidia.com/nvidia --version v26.7.2 \
  --namespace gpu-operator --create-namespace \
  --values gpu-operator-experimental-values.yaml --set driver.enabled=false
kubectl apply -f signed-driver-probe.yaml
kubectl wait --for=condition=Ready pod/signed-driver-load --timeout=300s
tr -d '\r' < Install-SignedDriver.sh |
  kubectl exec -i signed-driver-load -- bash
```

Require `SIGNED_DRIVER_LOADED=1` and a zero pipeline status. The script verifies
the exact kernel, Secure Boot, all five module signatures/version/vermagic and
the pinned module-deb SHA-256. It extracts matching packages in the pod, copies
only versioned firmware to the host, loads crypto dependencies and NVIDIA/UVM,
then starts UVM persistence **before the first GPU query**. It requires CC ON,
PRODUCTION and repeated Ready/persistence checks before exposing the coherent
driver tree at `/run/nvidia/driver`.

No full host metapackage, DKMS, kernel replacement or signing-key enrollment is
performed. A preexisting driver, driver tree or firmware directory is a hard
stop: inspect and cleanly recycle the disposable node instead of reloading
modules on a GPU with a failed CC cleanup. Keep the probe alive during testing.

On Windows PowerShell, normalize stdin at the receiving end as well:

```powershell
Get-Content -Raw .\Install-SignedDriver.sh |
    kubectl exec -i signed-driver-load -- bash -c 'tr -d "\r" | bash'
if ($LASTEXITCODE -ne 0) { throw 'Signed-driver setup failed' }
```

Use the same pattern for the two attestation scripts below. An immutable Pod
spec cannot be updated in place; do not delete/recreate an active probe to add
mounts, since that also kills its persistence daemon.

## 4. Require a schedulable GPU and a real CUDA workload

Give the Operator toolkit and device plugin up to ten minutes to initialize:

```bash
kubectl wait --for=jsonpath='{.status.allocatable.nvidia\.com/gpu}'=1 \
  node -l agentpool=gpunp --timeout=600s
kubectl get pods -n gpu-operator -o wide
tr -d '\r' < Test-GpuAttestation.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/gpu-attestation-before.log
kubectl apply -f gpu-smoke-test.yaml
kubectl wait --for=condition=Complete job/confidential-gpu-smoke --timeout=240s
kubectl logs job/confidential-gpu-smoke | tee .local/gpu-smoke.log
grep -Fx 'Test PASSED' .local/gpu-smoke.log
```

The nonprivileged Job requests and limits **one GPU**, uses runtime class
`nvidia`, and runs NVIDIA's vectorAdd. No CPU fallback is supplied. Helm
`deployed`, node Ready, or an optional monitoring operand's state is not a
substitute for these checks.

## 5. Verify GPU and CPU/CVM attestation separately

```bash
tr -d '\r' < Test-GpuAttestation.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/gpu-attestation-after.log
tr -d '\r' < Test-CvmAttestation.sh |
  kubectl exec -i signed-driver-load -- bash | tee .local/cvm-attestation-summary.log
```

Require zero pipeline exits and `GPU_ATTESTATION_VALIDATED=1` /
`CVM_ATTESTATION_VALIDATED=1`. The GPU script uses an isolated Python 3.12 venv,
checksum-pinned V4.5.1 verifier (`2.3.0`), strict OCSP, a fresh verifier nonce,
the exact positive overall verdict, and successful verification of the expected
physical GPU UUID. There is no `--test_no_gpu` or permissive revocation fallback.
The tested flow passed both before and after the CUDA workload.
The published scripts were replayed unchanged on a second fresh worker and
passed again. Optional DCGM exporter readiness remained `0/1`; this recipe
does not claim complete monitoring health.

The CPU script separately makes a real MAA request using checksum-pinned Azure
guest CLI `v0.1.0`, and requires decoded `sevsnpvm` and
`azure-compliant-cvm` claims. It is not a second independent JWT verification
implementation. Host `/dev`, read-only `/sys/firmware`, and read-only
`/sys/kernel/security` expose the Azure vTPM evidence. Without the TPM event log,
MAA returned `TcgLogs is empty in attestation request`. Sysfs stat size can be
zero: the script checks readable bytes with `wc -c`, not `test -s`.

Full results stay inside the pod at `/tmp/signed-attestation/gpu-result.log`
and `/tmp/signed-attestation/cpu-result.log`; they may include attestation
tokens. Console summaries omit the GPU token and print only selected CPU
claims. Keep any copied full evidence gitignored and access-controlled.
The GPU verifier reports future deprecation in favour of `nvattest`; migration
to that alternative is not validated by this recipe.

## 6. Stop and verify deallocation

Capture needed evidence before cleanup. On the successful probe, remove only
its four versioned firmware files, remove the test Job and pod, then stop
promptly (deleting the pod terminates persistence):

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

Require **Stopped / Succeeded** and **both VMSS capacities zero**. If an earlier
step failed, still stop the cluster; inspect which exact probe-owned files
exist before removing them. Do not attempt live recovery by loading mismatched
modules or disabling security. Retained disks/networking may still cost money.
GPU Operator is deliberately left with `driver.enabled=false`. Restarting
compute alone does not recreate the ephemeral driver installation; repeat
clean-node checks and setup.

When inspection is finished, explicitly deleting this disposable resource
group removes the cluster and its managed resources:

```bash
az group delete --subscription "$subscription" --name "$resourceGroup" --yes
```
