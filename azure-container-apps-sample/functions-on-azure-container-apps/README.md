# Hello world: Azure Functions on Azure Container Apps

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

**Validation scope:** nine source/deployment-contract tests passed on Node.js 24.
The real local Functions host, backed by Azurite, reported `Running`, returned
the exact JSON above with HTTP 200, and rejected POST with HTTP 404.
The Functions app has not been deployed to Azure, and its container has not been
built in this development environment because the Docker daemon was unavailable.
Native Functions on the confidential profile therefore remains an unverified
combination here; run ARM preflight and endpoint/placement checks in your own
subscription before treating it as deployable. Do not silently substitute
Consumption if the service rejects that combination.

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
| [main.json](main.json) | App-only ARM deployment with explicit workload profile |
| [test/hello.test.js](test/hello.test.js) | Response, registration, runtime and deployment-contract tests |

```text
Public HTTPS -> Container Apps ingress -> port 80 -> Functions host -> /api/hello
                    |
                    +-- existing confidential DC4 workload profile in UAE North
                    +-- user-assigned identity -> private ACR image pull
                                             -> Azure Blob host storage
```

The app requests 0.5 vCPU / 1 GiB and holds one replica. The environment's
dedicated DC4 node remains billable even while idle. Registry/build, storage,
networking and environment charges also apply.

This is a public, anonymous hello-world endpoint, not a production security
architecture. Send no sensitive data. It does not implement application
authentication, remote attestation, Secure Key Release, private endpoints or
centralized telemetry. Azure configuration checks are not cryptographic
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
Blob backend, not ephemeral files. Storage must remain network-reachable from
the app; private storage requires separately configured networking and DNS.

## 3. Build a fresh image

Run these commands **from this folder**, not the repository root. ACR Tasks
uploads this folder's build context to your Azure registry and does not require
a local Docker daemon:

```powershell
$imageTag = "functions-hello:$([guid]::NewGuid().ToString('N'))"
az acr build --registry $registryName --image $imageTag --no-cache .
$digest = az acr repository show --name $registryName --image $imageTag `
    --query digest --output tsv
if ([string]::IsNullOrWhiteSpace($digest)) { throw 'Build did not return an image digest.' }
$image = "$($registry.loginServer)/functions-hello@$digest"
```

Review the ACR build logs to confirm the new Functions base image was pulled.
If ACR Tasks is unavailable in your subscription, use Docker locally:

```powershell
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

## 5. Verify placement and the HTTP response

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

For startup failures, check revision state and Container Apps console/system logs.
Image-pull failures commonly indicate missing `AcrPull`, disabled ARM audience
tokens, an incorrect digest or RBAC propagation. Host storage failures commonly
indicate missing data-plane roles, a mismatched client ID or blocked networking.
If the base image is unavailable for a newly supported major, stop rather than
silently deploying an older Node.js version.

## 6. Cleanup

No command above automatically deletes resources. Delete only the app if you
want to retain the environment and shared prerequisites:

```powershell
az containerapp delete --name $appName --resource-group $resourceGroup --yes
```

This leaves billable DC4, registry and storage resources in place. If you created
the **entire dedicated demo group** for these samples, confirm its contents and
name in the portal, then explicitly delete that group when finished. Do not
delete a shared group or manually edit the service-managed infrastructure group.
Verify that Azure removes both the demo group and its managed infrastructure
group before considering full cleanup complete.
