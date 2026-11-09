# Hello world: Azure Functions on Azure Container Apps

[All Container Apps samples](../README.md) | [Repository overview](../../README.md)

Run a small JavaScript HTTP function in the **native Azure Functions integration
with Azure Container Apps**. `GET /api/hello` returns HTTP 200:

```json
{"message":"Hello, world!"}
```

This example follows the [Functions on Container Apps overview](https://learn.microsoft.com/azure/container-apps/functions-overview)
and [native deployment guide](https://learn.microsoft.com/azure/container-apps/functions-usage).
It uses `Microsoft.App/containerApps` with `kind: functionapp`, **not** the legacy
`Microsoft.Web/sites` hosting model.

The ARM template deploys only the function app. It requires an existing
Container Apps environment, registry, managed identity and host storage. The
instructions below use the sibling sample's UAE North **confidential DC4**
environment. `kind: functionapp` alone does not enable confidential computing:
the app must explicitly select the environment's confidential workload profile.

## Start here

This walkthrough creates a public hello-world function backed by keyless,
privately reachable host storage. It is not an App Service deployment and does
not host the App Service platform inside Container Apps.

1. [Run locally](#1-run-locally) with Node.js 24 and Azurite.
2. [Prepare Azure prerequisites](#2-prepare-azure-prerequisites): deploy the
   sibling confidential environment, create ACR/storage/identity, assign scoped
   roles, and connect private Blob storage.
3. [Build a fresh image](#3-build-a-fresh-image) remotely with ACR Tasks.
4. [Validate and deploy](#4-validate-and-deploy-the-app) the immutable image.
5. [Verify placement, HTTP and storage](#5-verify-placement-http-response-and-host-storage),
   then [open the app and Azure portal](#open-the-app-and-azure-portal).
6. [Clean up](#6-cleanup) only when you are finished; nothing automatically
   removes the resources.

Run the numbered Azure steps in order, from this folder, in the same PowerShell
session. The sample assumes the sibling environment's VNet address space and a
dedicated resource group. Review names, networking and the deployment preview
before creating resources. Use your own deployment's URLs; the validation run
below is evidence, not a supported shared public demo.

### Choose the right walkthrough

| Goal | Guide |
| --- | --- |
| Deploy an HTML quickstart page with no application build or registry | [Confidential Container Apps hello world](../container-apps-acc/README.md#start-here) |
| Deploy JavaScript Functions with managed identity and private host storage | Continue with this guide |

Both use the environment's explicit `confidential` DC4 profile in UAE North.
This guide adds resources to the existing dedicated group, not a second DC4
environment. Keep the environment if you want to run either example; deleting
the whole group removes both apps and their supporting resources.

**Validation scope (2026-11-09):** source/deployment-contract tests passed
on Node.js 24. A fresh ACR task built the official Functions image with
Node.js 24.22.2 and deployed its immutable digest as a native `functionapp`
in a UAE North confidential DC4 profile. Azure readback confirmed the explicit
profile binding and a ready, running revision with zero restarts. The cloud
endpoint returned the exact JSON above with HTTP 200 and rejected POST with
HTTP 404; host logs reported `Running`. Initial cloud verification then detected
host-storage HTTP 403 because public storage networking was disabled without
a private endpoint. After deploying the private network configuration below,
Azure confirmed an approved Blob private endpoint and linked private DNS. The
replacement host created/used `azure-webjobs-hosts`, acquired its Blob lease and
remained ready/running without storage-health errors for over one minute.
Public storage access and shared keys remained disabled. Verify the host storage
checks as well as HTTP responses in your own deployment.
The local host also passed these checks
with Azurite. These are configuration and functional checks, not cryptographic
attestation or a guarantee of availability in every subscription. Run ARM
preflight and endpoint/placement checks in your own subscription. Do not
silently substitute Consumption if the service rejects that combination.

## Runtime update policy: deploy the latest supported Node.js

- Use the **newest generally available Node.js major supported by Azure
  Functions**, currently **Node.js 24**, not an older default. Check the
  [official supported-language list](https://learn.microsoft.com/azure/azure-functions/supported-languages)
  before **every deployment**. Newer upstream Node.js releases are not
  necessarily supported by the Functions host.
- The Dockerfile uses `mcr.microsoft.com/azure-functions/node:4-node24`, which
  selects the latest published Functions image for that major. Build with
  `docker build --pull --no-cache`, or use a fresh ACR build as shown below,
  so a cached base image cannot retain an old patch.
- Rebuild for every deployment, use a unique application image tag, and deploy
  the **digest returned by that new build**. Do not redeploy an old digest and
  assume the Node.js runtime has updated. Confirm `node --version` in the built
  image before pushing it. The Dockerfile also prints `node --version` into
  the build log, including when you build remotely with ACR Tasks.
- When a newer Node.js major becomes GA in Functions, update the Dockerfile,
  `package.json` engine range and runtime test together, then rerun the tests
  and container smoke test before deployment.
- Running containers **do not update themselves**. Rebuild and redeploy regularly
  for runtime/security patches. Dependency versions remain locked for repeatable
  installs; update and test those separately rather than resolving arbitrary
  application dependencies during deployment.

## Files and architecture

| File | Purpose |
| --- | --- |
| [src/hello.js](src/hello.js) | Stateless JSON response handler |
| [src/functions/hello.js](src/functions/hello.js) | Functions v4 HTTP registration: anonymous GET |
| [host.json](host.json) | Functions host configuration, `/api` route prefix |
| [Dockerfile](Dockerfile) | Official Functions host with Node.js, listening on port 80 |
| [acr-task.yaml](acr-task.yaml) | Fresh-pull, no-cache remote build and push with a unique run-ID tag |
| [main.json](main.json) | App-only ARM deployment with explicit workload profile |
| [host-storage-network.json](host-storage-network.json) | Blob private endpoint, separate subnet, private DNS zone and VNet link |
| [test/hello.test.js](test/hello.test.js) | Response, registration, runtime and deployment-contract tests |

```text
Public HTTPS -> Container Apps ingress -> port 80 -> Functions host -> /api/hello
                    |
                    +-- existing confidential DC4 workload profile in UAE North
                    +-- user-assigned identity -> private ACR image pull
                                             -> Blob private endpoint -> host storage
                                                (VNet-linked private DNS)
```

The app requests 0.5 vCPU / 1 GiB and holds one replica. The environment's
dedicated DC4 node remains billable even while idle. Registry/build, storage,
networking and environment charges also apply.

This is a public, anonymous hello-world endpoint, not a production security
architecture. Send no sensitive data. It does not implement application
authentication, remote attestation, Secure Key Release, private ingress or
centralized telemetry. The Blob private endpoint protects the host-storage
network path; ACR uses an authenticated registry endpoint, not a private endpoint.
Azure configuration checks are not cryptographic
attestation. The local storage emulator is not confidential compute.

## 1. Run locally

Prerequisites: **Node.js 24**, npm, and PowerShell. From this folder:

```powershell
npm ci
npm run check
npm test
Copy-Item .\local.settings.example.json .\local.settings.json
npm run storage
```

Leave Azurite running, then open a second terminal in this folder:

```powershell
npm start
```

In another terminal:

```powershell
$response = Invoke-WebRequest http://localhost:7071/api/hello
if ($response.StatusCode -ne 200 -or
    ($response.Content | ConvertFrom-Json).message -cne 'Hello, world!') {
    throw 'Unexpected hello-world response.'
}
$response.Content
```

Stop the host and Azurite with Ctrl+C in their terminals. Azurite uses local
ports 10000-10002 and writes ignored files under `.azurite`. The example settings
use `UseDevelopmentStorage=true`, not Azure credentials. Local file-based host
keys are for development only; those settings are not copied into the container.
Never commit a real storage connection string or `local.settings.json`.

Core Tools and Azurite are **development-only** dependencies. Their upstream
dependency trees can have audit findings; review `npm audit` and tool updates
before installation. Do not force-downgrade to obsolete tool majors to silence
an audit. The deployed image installs only production dependencies with
`npm ci --omit=dev`; check those with `npm audit --omit=dev`.

## 2. Prepare Azure prerequisites

For the Azure steps, install current **Azure CLI** (including its `containerapp`
extension), **PowerShell 7.4+**, **Az.Accounts** and **Az.Resources**. You need
permission to create the app and support resources, attach the identity, run ACR
builds, and assign the two resource-scoped data roles below. Contributor alone
cannot create role assignments. Use approved PIM access if necessary.

First deploy the [confidential environment sample](../container-apps-acc/README.md)
in a dedicated demo group and retain its resources. That guide checks regional
DC4 availability, quota, provider registration and VNet policy. There is no shared
live demo to reuse; create your own dedicated environment.

The following commands **create billable support resources**. Run them only when
you intend to deploy. Replace the subscription ID and resource group; the group
must contain the environment you just created.
Run the commands from this sample folder.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$subscriptionId = '<your-subscription-id>'
$resourceGroup = '<your-dedicated-demo-resource-group>'
$environmentName = 'cae-acc-hello'
$appName = 'ca-functions-hello'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$registryName = "acrfn$suffix"
$storageName = "stfn$suffix"

az login
az account set --subscription $subscriptionId
Connect-AzAccount -Subscription $subscriptionId
$environmentId = az containerapp env show --name $environmentName `
    --resource-group $resourceGroup --query id --output tsv
$environment = az containerapp env show --name $environmentName `
    --resource-group $resourceGroup --output json | ConvertFrom-Json
$profile = @($environment.properties.workloadProfiles |
    Where-Object name -eq 'confidential')
if ($environment.location -notin @('uaenorth', 'UAE North') -or
    $profile.Count -ne 1 -or $profile[0].workloadProfileType -ne 'DC4') {
    throw 'Expected an existing UAE North confidential DC4 environment.'
}

$identity = az identity create --name "id-functions-$suffix" `
    --resource-group $resourceGroup --location uaenorth --output json |
    ConvertFrom-Json
$registry = az acr create --name $registryName --resource-group $resourceGroup `
    --location uaenorth --sku Basic --role-assignment-mode rbac `
    --admin-enabled false --output json | ConvertFrom-Json
az acr config authentication-as-arm update --registry $registryName --status enabled
$storage = az storage account create --name $storageName `
    --resource-group $resourceGroup --location uaenorth --sku Standard_LRS `
    --kind StorageV2 --https-only true --min-tls-version TLS1_2 `
    --allow-blob-public-access false --allow-shared-key-access false `
    --public-network-access Disabled `
    --output json | ConvertFrom-Json

az role assignment create --assignee-object-id $identity.principalId `
    --assignee-principal-type ServicePrincipal --role AcrPull --scope $registry.id
az role assignment create --assignee-object-id $identity.principalId `
    --assignee-principal-type ServicePrincipal --role 'Storage Blob Data Owner' `
    --scope $storage.id
```

Allow time for RBAC propagation before starting the app. `identity.id` and
`identity.clientId` must refer to the **same** identity. A registry using
RBAC+ABAC repository permissions needs its appropriate repository-reader role
instead of `AcrPull`; the new registry above deliberately uses RBAC mode.

For this HTTP-only app, identity-based host storage needs **Storage Blob Data
Owner**. New storage-dependent triggers, bindings or Durable Functions can
require additional roles; follow the
[host-storage identity guidance](https://learn.microsoft.com/azure/azure-functions/manage-connections?pivots=functions-auth-identity&tabs=host#define-connections).
The template uses `AzureWebJobsStorage__accountName`, `__credential=managedidentity`
and `__clientId`. It does not use storage account keys. Host keys use the default
Blob backend, not ephemeral files.

### Connect private host storage

RBAC does not bypass a storage firewall. This sample disables public storage
network access and connects Blob storage through a private endpoint. Without
this path, the HTTP function can return 200 while the host reports unhealthy
storage and fails to acquire its host lock lease with HTTP 403.

The supplied network template adds a **separate, undelegated subnet**, leaving
the environment's delegated infrastructure subnet unchanged. The default
`10.42.2.0/24` fits the sibling sample's `10.42.0.0/16` VNet and does not overlap
its `10.42.0.0/23` infrastructure subnet. Review and adjust it for a customized
VNet. Storage, VNet and these network resources must be in the same dedicated
resource group for these instructions. For an existing private DNS deployment,
integrate with your organization's zone rather than creating a duplicate.

```powershell
$infrastructureSubnetId = $environment.properties.vnetConfiguration.infrastructureSubnetId
if (-not $infrastructureSubnetId) { throw 'Expected a VNet-injected environment.' }
$vnetName = ($infrastructureSubnetId -split '/')[-3]
$networkParameters = @{
    vnetName = $vnetName
    storageAccountId = $storage.id
    subnetPrefix = '10.42.2.0/24'
}
$networkErrors = @(Test-AzResourceGroupDeployment -ResourceGroupName $resourceGroup `
    -TemplateFile .\host-storage-network.json -TemplateParameterObject $networkParameters |
    Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
if ($networkErrors.Count) { throw ($networkErrors | Out-String) }
Get-AzResourceGroupDeploymentWhatIfResult -ResourceGroupName $resourceGroup `
    -TemplateFile .\host-storage-network.json -TemplateParameterObject $networkParameters
# Review the preview before creating the billable private endpoint and DNS zone.
$networkDeployment = New-AzResourceGroupDeployment -Name functions-host-storage-network `
    -ResourceGroupName $resourceGroup -Mode Incremental `
    -TemplateFile .\host-storage-network.json -TemplateParameterObject $networkParameters
if ($networkDeployment.ProvisioningState -ne 'Succeeded') {
    throw 'Host storage private networking deployment failed.'
}
```

The zone group registers Blob's private IP in
`privatelink.blob.core.windows.net`; the VNet link enables resolution from the
app's environment. Keep the normal account hostname in Functions settings, not
the private IP. Custom DNS servers must resolve/forward this private zone.
This HTTP-only example needs Blob connectivity; additional triggers or Durable
Functions may need Queue/Table endpoints, DNS zones and roles as well.
Do not redeploy the sibling VNet template without preserving the added subnet.

## 3. Build a fresh image

Run these commands **from this folder**, not the repository root. ACR Tasks
uploads this folder's build context to your Azure registry and does not require
a local Docker daemon:

```powershell
$run = az acr run --registry $registryName --file acr-task.yaml `
    --no-wait --output json . | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $run.runId) { throw 'ACR task could not be queued.' }
az acr task logs --registry $registryName --run-id $run.runId
if ($LASTEXITCODE -ne 0) { throw 'ACR build logs could not be retrieved.' }
$runStatus = az acr task show-run --registry $registryName --run-id $run.runId `
    --query status --output tsv
if ($LASTEXITCODE -ne 0 -or $runStatus -ne 'Succeeded') {
    throw "Image build did not succeed: $runStatus"
}
$imageTag = "functions-hello:$($run.runId)"
$digest = az acr repository show --name $registryName --image $imageTag `
    --query digest --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($digest)) {
    throw 'Build did not return an image digest.'
}
$image = "$($registry.loginServer)/functions-hello@$digest"
```

The [ACR task](./acr-task.yaml) runs Docker build with `--pull --no-cache`;
`az acr build` itself does not support a `--no-cache` option. Each task run uses
its unique run ID as the image tag. Review the build logs to confirm the new
Functions base image was pulled and check the printed Node.js version.
If ACR Tasks is unavailable in your subscription, use Docker locally:

```powershell
$imageTag = "functions-hello:$([guid]::NewGuid().ToString('N'))"
docker build --pull --no-cache -t "$($registry.loginServer)/$imageTag" .
docker run --rm --entrypoint node "$($registry.loginServer)/$imageTag" --version
az acr login --name $registryName
docker push "$($registry.loginServer)/$imageTag"
```

Then retrieve the digest and set `$image` as above. Before deployment, smoke-test
the built image with reachable host storage; `localhost` inside a container is
the container itself, not the Azurite process on your computer. Reusing an old
application tag/digest will not satisfy the runtime-update policy.

## 4. Validate and deploy the app

Keep the variables from the preceding steps in the same PowerShell session.
Use Azure PowerShell for the ARM deployment:

```powershell
$parameters = @{
    appName = $appName
    environmentId = $environmentId
    workloadProfileName = 'confidential'
    image = $image
    registryServer = $registry.loginServer
    identityId = $identity.id
    identityClientId = $identity.clientId
    storageAccountName = $storageName
}
$errors = @(Test-AzResourceGroupDeployment -ResourceGroupName $resourceGroup `
    -TemplateFile .\main.json -TemplateParameterObject $parameters |
    Where-Object { $null -ne $_ -and $_ -isnot [string] -or
        ($_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_)) })
if ($errors.Count) { throw ($errors | Out-String) }
Get-AzResourceGroupDeploymentWhatIfResult -ResourceGroupName $resourceGroup `
    -TemplateFile .\main.json -TemplateParameterObject $parameters
```

Review the what-if result: expect one app Create (or Modify for your existing
sample app), no environment replacement or deletes. Then deploy:

```powershell
$deployment = New-AzResourceGroupDeployment -Name "functions-$suffix" `
    -ResourceGroupName $resourceGroup -TemplateFile .\main.json `
    -TemplateParameterObject $parameters -ErrorAction Stop
if ($deployment.ProvisioningState -ne 'Succeeded') { throw 'Deployment failed.' }
$helloUrl = $deployment.Outputs.helloUrl.Value
```

The template defaults to UAE North and the `confidential` profile. It does not
create a profile or prove its hardware type. Do not override that parameter to
an ordinary profile if you need confidential execution. Deployment success can
precede revision readiness.

## 5. Verify placement, HTTP response and host storage

After the latest revision becomes ready, read both resources back from Azure.
The shared helper from the sibling sample requires a Succeeded app/environment,
the exact environment binding, a `confidential` DC4 profile with one node,
UAE North, public HTTPS-only ingress, port 80 and a ready latest revision:

```powershell
. ..\container-apps-acc\DeploymentHelpers.ps1
$app = Get-ArmJson -Path "$($deployment.Outputs.appId.Value)?api-version=2025-07-01"
$environment = Get-ArmJson -Path "${environmentId}?api-version=2025-07-01"
if ($app.kind -ne 'functionapp') { throw 'Expected native Functions integration.' }
$baseUrl = Assert-ConfidentialContainerApp -App $app -Environment $environment
$helloUrl = "$baseUrl/api/hello"
$response = Invoke-WebRequest -Uri $helloUrl -TimeoutSec 30 -MaximumRedirection 0
if ($response.StatusCode -ne 200 -or
    ($response.Content | ConvertFrom-Json).message -cne 'Hello, world!') {
    throw 'Function did not return the expected JSON response.'
}
$helloUrl
$response.Content
```

### Show explicit confidential-compute evidence

Run the shared [read-only placement verification](../README.md#validate-confidential-compute-placement)
from the repository root with `$appName = 'ca-functions-hello'` and your actual
subscription, group and environment name. It reads the **Functions app itself**;
checking only the sibling HTML app does not establish Functions placement.

Confirm the output shows the Functions app's ID, its expected environment ID,
`AssignedProfile: confidential`, `ProfileType: DC4`, and a latest ready revision
that is active, has at least one replica, is `Running` (or `RunningAtMaxScale`)
and `Healthy`. The procedure throws on a binding/profile/state
mismatch and includes a timestamp for recording the evidence. Follow its portal
cross-check to independently inspect the same resource configuration.

Neither `kind: functionapp`, a healthy storage lease nor HTTP 200 proves
confidential placement without the app-to-DC4 binding. Conversely, successful
DC4 verification does not establish Functions host-storage health: complete the
checks below too. These steps verify Azure-reported placement, not a
cryptographically signed hardware attestation report.

Also inspect host logs and confirm that Blob host storage is actually in use:

```powershell
az containerapp logs show --name $appName --resource-group $resourceGroup `
    --container hello --type console --tail 100
if ($LASTEXITCODE -ne 0) { throw 'Could not retrieve Functions host logs.' }
$containers = Get-ArmJson -Path "$($storage.id)/blobServices/default/containers?api-version=2023-05-01"
if ('azure-webjobs-hosts' -notin $containers.value.name) {
    throw 'Functions has not created its host storage container.'
}
```

Look for `Host lock lease acquired`, a running host, and no ongoing
`AuthorizationFailure` or `Process reporting unhealthy` entries. Check at least
two health-check intervals (one minute) after startup/network changes; an HTTP
200 or a ready replica alone does **not** validate storage health. If networking
was fixed after startup, allow DNS propagation and restart the revision if it
retains cached DNS or unhealthy state, then check the new process's logs.
Do not retrieve or print host keys to perform these checks.

For startup failures, check revision state and Container Apps console/system logs.
Image-pull failures commonly indicate missing `AcrPull`, disabled ARM audience
tokens, an incorrect digest or RBAC propagation. Host storage failures commonly
indicate missing data-plane roles, a mismatched client ID or blocked networking.
If the base image is unavailable for a newly supported major, stop rather than
silently deploying an older Node.js version.

### Open the app and Azure portal

The function is an API endpoint, not a separate HTML web page. Open `$helloUrl`
in a browser to see the JSON response. A request to `/` is not the hello-world
route; use `/api/hello`.

Generate portal links from the resources in your deployment:

```powershell
$appId = $deployment.Outputs.appId.Value
$appPortalUrl = "https://portal.azure.com/#resource$appId/overview"
$groupPortalUrl = "https://portal.azure.com/#resource/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/overview"
$helloUrl
$appPortalUrl
$groupPortalUrl
```

In the app's Container Apps resource, inspect revisions/replicas and console or
system logs. In the environment, verify the `confidential` DC4 workload profile.
In the storage account, check the approved Blob private endpoint connection;
the private DNS zone must be linked to the environment's VNet.

### Troubleshooting checklist

| Symptom | Check and next action |
| --- | --- |
| Role-assignment creation is denied | Contributor is insufficient. Obtain approved Owner or role-assignment administration access at the appropriate scope, then allow RBAC propagation. |
| Image pull fails | Confirm the exact digest exists, the app uses the intended identity, `AcrPull` is assigned at the registry, and ARM audience authentication is enabled. |
| HTTP 200 but storage health is unhealthy/403 | Check the Blob private endpoint is approved, DNS resolves the account through the linked private zone, and the same identity has Storage Blob Data Owner. RBAC alone cannot bypass disabled public networking. Recheck new-process logs after any restart. |
| `/` returns 404 | Use `GET /api/hello`. POST to that route is intentionally not registered. |
| DC4 deployment or capacity check fails | Check current UAE North availability, quota, permissions and policy. Do not silently deploy to Consumption or an ordinary workload profile. |

## 6. Cleanup

No command above automatically deletes resources. Delete only the app if you
want to retain the environment and shared prerequisites:

```powershell
az containerapp delete --name $appName --resource-group $resourceGroup --yes
```

This leaves billable DC4, registry, storage, private endpoint and DNS resources
in place. If you created
the **entire dedicated demo group** for these samples, confirm its contents and
name in the portal, then explicitly delete that group when finished. Do not
delete a shared group or manually edit the service-managed infrastructure group.
Verify that Azure removes both the demo group and its managed infrastructure
group before considering full cleanup complete.
