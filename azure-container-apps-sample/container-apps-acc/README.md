# Hello world on confidential Azure Container Apps

[All Container Apps samples](../README.md) | [Repository overview](../../README.md)

Deploy Microsoft's hello-world container to **Azure Container Apps** in **UAE
North**, using a dedicated **DC4 confidential workload profile**. Then verify the
app's Azure-reported placement and open its public HTTPS page.

This example follows [Confidential compute in Azure Container Apps](https://learn.microsoft.com/azure/container-apps/confidential-compute)
and uses the public image and port from the
[Container Apps quickstart](https://learn.microsoft.com/azure/container-apps/get-started).

**Tested:** 9 November 2026 in UAE North. ARM deployment succeeded, Azure-reported
DC4 binding and ready revision were verified, and the public endpoint returned
HTTP 200 with the hello-world page. Availability, quota and organizational
policies still need checking in your own subscription.

For an application-code example, continue with
[Functions on Azure Container Apps](../functions-on-azure-container-apps/README.md).
It uses the native Functions integration with Node.js 24, a fresh runtime-image
pull on each build, managed identity, and private Blob host storage; see its
runtime-update policy.
The original test deployment is not a shared live demo; this README describes how
to create your own resources, not a retained public demo.

## Start here

1. Review [resources and cost](#resources-and-cost) and [prerequisites](#prerequisites).
2. [Sign in and select the subscription](#1-sign-in-and-select-the-subscription).
3. [Validate, then deploy](#2-validate-then-deploy) into a new dedicated group.
4. [Verify again](#3-verify-again-without-deploying) without creating resources.
5. Optionally [add the Functions sample](#next-step-add-a-function), or use
   [optional cleanup](#optional-cleanup-only-when-you-choose) when finished.

This sample serves an HTML hello-world page from a public quickstart image.
The [Functions sample](../functions-on-azure-container-apps/README.md#start-here)
instead runs your JavaScript code and serves JSON at `GET /api/hello`.
Neither sample silently substitutes ordinary compute when DC4 is unavailable.

## What makes this confidential?

Confidential compute is an **environment workload-profile setting**, not an image
setting or a container flag:

1. The environment defines a profile named `confidential`, type **DC4**.
2. The app explicitly sets `properties.workloadProfileName` to `confidential`.
3. The verification script reads both resources back from Azure and requires that
   exact binding. It never falls back to Consumption or a nonconfidential profile.

The DC-series profile provides the service's confidential-computing protection
for data in use. No application SDK, custom runtime or image changes are required
for this quickstart. Configuration verification is **not independent
cryptographic hardware attestation**. This example does not implement attestation,
Secure Key Release, application authentication, or protection of external storage.

## Resources and cost

```text
New dedicated resource group (UAE North)
  Virtual network (10.42.0.0/16)
    Delegated infrastructure subnet (10.42.0.0/23), with NSG
  Container Apps environment
    confidential: DC4, minimum 1 / maximum 1 node
      hello-world app: minimum 1 / maximum 1 replica
        public HTTPS ingress -> container port 80
```

- **DC4 dedicates 4 vCPUs and 16 GiB to the profile**, even though the example
  container requests only 0.5 vCPU and 1 GiB.
- Dedicated compute and applicable environment/network charges continue while
  resources are retained, including when there is no traffic. This is not a
  free Consumption deployment. Review [Container Apps pricing](https://azure.microsoft.com/pricing/details/container-apps/)
  for current regional rates.
- There is no custom registry, database, managed identity or role assignment.
  The environment is integrated into the new subnet to support subscriptions
  requiring VNet injection. The NSG uses Azure's default rules; it is not a
  production egress firewall. There is no peering to existing networks; review
  address-space overlap before extending this example.
  Azure creates a service-managed infrastructure resource group containing
  resources such as its load balancer and public IP. Do not modify those directly.
- Log Analytics is deliberately omitted (empty ARM log destination). Centralized
  application log retention is not configured.
- **Nothing is automatically deleted**, on success or failure.
- The endpoint is publicly accessible without sign-in. Send no sensitive data.
  TLS terminates at the managed ingress; the container listens on port 80.
- The Microsoft quickstart image uses a mutable `latest` tag. For production,
  review and pin an approved image digest and add appropriate identity,
  networking, monitoring, attestation and lifecycle controls.

## Prerequisites

- An Azure public-cloud subscription authorized for confidential Container Apps.
  The linked documentation currently lists **UAE North**. Availability and capacity
  can change; this sample intentionally permits only `uaenorth`.
- Permission to create a resource group, VNet, NSG, managed environment and container app
  (for example Contributor at subscription scope). **Owner is not required**;
  this example does not activate PIM roles or create role assignments. Activate
  any required eligible role through your organization's normal process first.
- The `Microsoft.App` and `Microsoft.Network` providers must be registered. Registration requires
  subscription-level provider registration permission.
- Available regional environment quota and DC4 capacity. An advertised profile
  does not guarantee capacity. The script checks profile availability and
  environment-count quota; ARM preflight/provisioning may reveal additional
  service restrictions.
- PowerShell **7+** and the `Az.Accounts` and `Az.Resources` modules.
  Azure CLI, `Az.App`, Bicep, Node.js and Docker are not required.

If needed, install the two modules in PowerShell 7:

```powershell
Install-Module Az.Accounts, Az.Resources -Scope CurrentUser -Repository PSGallery
```

## 1. Sign in and select the subscription

From the repository root in PowerShell 7:

```powershell
Connect-AzAccount
Get-AzSubscription | Select-Object Name, Id
$subscriptionId = '<your-subscription-id>'
Set-AzContext -SubscriptionId $subscriptionId

Register-AzResourceProvider -ProviderNamespace Microsoft.App
Register-AzResourceProvider -ProviderNamespace Microsoft.Network
(Invoke-AzRestMethod -Method GET -Path "/subscriptions/$subscriptionId/providers/Microsoft.App?api-version=2021-04-01").Content |
    ConvertFrom-Json | Select-Object registrationState
```

Registration is a subscription-wide prerequisite, not a demo resource. Repeat
the status command for both providers until each reports `Registered` (replace
`Microsoft.App` with `Microsoft.Network` for the network provider); registration can take several
minutes. The script fails with an actionable error if it is not registered.

## 2. Validate, then deploy

Choose a **new, dedicated** group and keep its name for verification and optional
cleanup:

```powershell
Set-Location .\azure-container-apps-sample\container-apps-acc
$resourceGroup = "rg-container-apps-acc-$([guid]::NewGuid().ToString('N').Substring(0, 8))"

# Optional preflight: creates only the empty resource group, then validates ARM.
.\Deploy-ContainerApp.ps1 -SubscriptionId $subscriptionId `
    -ResourceGroupName $resourceGroup -ValidateOnly

# Validates again, deploys, and verifies placement plus the HTTPS response.
$result = .\Deploy-ContainerApp.ps1 -SubscriptionId $subscriptionId `
    -ResourceGroupName $resourceGroup
$result | Format-List
Start-Process $result.AppUrl
```

The script uses [main.json](main.json) with Container Apps API `2025-07-01`
and Network API `2024-05-01`. Default names are
`cae-acc-hello` and `ca-acc-hello`. Optional `-EnvironmentName` and `-AppName`
parameters customize those names; use the same names for verification.

Expect environment creation and DC4 provisioning to take several minutes.
Success produces `AppUrl` and `PortalUrl`, both fully qualified HTTPS links, plus
resource IDs and the verified profile. The page is Microsoft's Container Apps
hello-world/quickstart page.

Use `$result.PortalUrl` to open the deployed app's Azure portal resource.
Use `$result.AppUrl` for its public HTML page; use the links returned by your
own deployment rather than an earlier test deployment's address.

For safety, deployment refuses existing populated or unrelated groups. It can
reuse only an **empty** group tagged `sample=container-apps-acc`, such as the one
created by `-ValidateOnly`. After deploying, use verification rather than running
deployment again. If a failure leaves partial resources, inspect them before
choosing a new group or explicitly cleaning up; repeated new groups can multiply
charges.

## 3. Verify again without deploying

```powershell
.\Test-ContainerApp.ps1 -SubscriptionId $subscriptionId `
    -ResourceGroupName $resourceGroup | Format-List
```

Verification requires:

- Provisioning and latest-revision readiness settle within a bounded wait of
  60 checks, 10 seconds apart. A temporarily `Updating` environment after ARM
  deployment is retried; failed or unexpected states terminate immediately.
- Both resources report `Succeeded` in UAE North.
- The app references the expected environment and its `confidential` DC4 profile,
  with exactly one dedicated node.
- The latest revision is ready and ingress is public, HTTPS-only, on target port 80.
- The HTTPS endpoint returns **200** and the Microsoft quickstart page contains
  `Azure Container Apps`. Transient HTTP statuses are retried for up to 12 requests;
  redirects, incorrect content and transport errors terminate verification.

In the portal, inspect **Environment > Workload profiles** for `DC4`, then the
app's **JSON View** for `properties.workloadProfileName: confidential`. Neither
the web page alone nor a successful ARM deployment alone proves DC4 placement.
Azure may also add its default `Consumption` profile to the environment. Its
presence does not change this app's explicit binding to `confidential`; the
verification checks the app's selected profile, not merely available profiles.

### Show explicit confidential-compute evidence

Follow the [read-only placement verification](../README.md#validate-confidential-compute-placement)
from the repository root. Set `$appName = 'ca-acc-hello'` and use the subscription,
group and environment from your deployment (including any customized names).
The procedure prints the live app/environment IDs, assigned profile name,
**DC4 profile type**, latest ready revision, running/health states and timestamp.
It fails rather than reporting success for ordinary compute or an unhealthy
revision. The same section provides a portal cross-check and explains the
limits of control-plane evidence.

For this example, retain both that output and the result of
[Test-ContainerApp.ps1](Test-ContainerApp.ps1): the former makes the placement
evidence visible, while the latter additionally validates the HTML endpoint.
An HTTP 200 page by itself is not confidential-computing verification.

## Next step: add a function

Keep the environment and follow the
[Functions deployment walkthrough](../functions-on-azure-container-apps/README.md#start-here).
Use this deployment's subscription, resource group and environment name there.
The Functions app explicitly selects the same `confidential` DC4 profile and
can share its existing node with the quickstart app.

The Functions guide adds a registry, user-assigned identity, scoped role
assignments, host storage and private Blob networking. Unlike this quickstart,
it requires permission to create role assignments. Its additional subnet
defaults to `10.42.2.0/24`; preserve that subnet if you later modify the VNet.
Do not rerun this sample's deployment script against the now-populated group.
Verify both app placement and Functions host-storage health using the
respective guides; a successful hello-world response alone is insufficient.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Provider is not registered | Register the named provider in the selected subscription and wait for `Registered`. |
| Authorization/PIM error | Confirm tenant/subscription and activate an appropriate role; retry after propagation. |
| No DC4 profile, zero/exhausted quota, or insufficient capacity | Check UAE North support and request service access/quota/capacity through Azure support. Do not substitute ordinary compute. |
| ARM validation or deployment fails | Read the terminating error and the resource group's **Deployments** details. Inspect partial resources; they are retained. |
| Organizational networking policy rejects deployment | The template includes VNet injection and a subnet NSG. Review any additional private-ingress, outbound connectivity, address-space or tagging requirements with your administrator; do not bypass policy. |
| Deployment succeeded but verification failed | Inspect the revision and profile, then rerun the verification script. Do not treat this as a verified confidential deployment. |
| Need centralized logs | Add your approved logging configuration separately; this minimal example does not provision a workspace. |

## Optional cleanup (only when you choose)

**This deletes the selected group and everything inside it.** First confirm the
subscription and inventory. Do not use a shared group.
If you added the Functions sample to this group, group deletion also removes
its app, registry, identity, storage, private endpoint and DNS resources.
Deleting only an app does not stop charges for the retained DC4 environment.

```powershell
Set-AzContext -SubscriptionId $subscriptionId
Get-AzResource -ResourceGroupName $resourceGroup |
    Select-Object Name, ResourceType, ResourceId
# Run only after reviewing the inventory and deciding to remove the demo:
Remove-AzResourceGroup -Name $resourceGroup
```

Confirm completion in the portal, including any associated service-managed
infrastructure group. Provider registration is not undone.

## Offline regression tests

These use PowerShell mocks; no Pester dependency, Azure sign-in, or cloud
resources are required (the two Az modules must be installed):

```powershell
.\tests\Test-Sample.ps1
```

The tests cover the template's confidential binding/TLS/scaling, negative
placement and HTTP checks, and deployment preflight/failure behavior.
