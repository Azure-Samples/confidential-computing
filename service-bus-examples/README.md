# Confidential Azure Service Bus Premium

Creates a **new Premium namespace with confidential computing enabled**, a queue,
and passwordless send/receive role assignments. Sends three fictional JSON orders,
reads them back, compares IDs and complete payloads, and completes the messages.
This tests messaging, not hardware attestation: the management-plane check verifies
that Azure reports `platformCapabilities.confidentialCompute.mode = Enabled`.

Public documentation:
[Azure Service Bus with confidential computing - Microsoft Learn](https://learn.microsoft.com/en-us/azure/service-bus-messaging/confidential-computing?tabs=bicep).
As checked on October 29, 2026, Microsoft lists **Korea Central** and **UAE North**.
This capability requires Premium and must be enabled when creating the namespace;
it cannot be enabled on an existing namespace. The template uses the documented
`2025-05-01-preview` namespace API.

## Prerequisites

- PowerShell 7+, `Az.Accounts` and `Az.Resources` modules.
- Node.js 22+ and npm.
- An Azure public-cloud subscription with permission to create resource groups,
  Service Bus namespaces/queues, and role assignments (for example, Contributor
  plus Role Based Access Control Administrator at the relevant scope).
- If these permissions are PIM-eligible, activate them before running the script
  and allow time for propagation. Owner is not a prerequisite; the required
  permissions must cover the deployment scope and Sender/Receiver assignments.
- Sign in with `Connect-AzAccount`. The Node sample uses `AzurePowerShellCredential`
  so it authenticates through Azure PowerShell too, not the separate VS Code
  Azure extension or Azure CLI login.
- Outbound HTTPS for Azure management/authentication and AMQP/TLS on port 5671.

## Run

From the repository root, enter this directory, install dependencies, and sign in:

```powershell
Set-Location .\service-bus-examples
npm ci
Connect-AzAccount
.\Deploy-ServiceBus.ps1 -SubscriptionId '<subscription-id>'
```

By default the script creates uniquely named resources and attempts **Korea Central
(`koreacentral`), then UAE North (`uaenorth`)**. Fallback happens only for
recognized regional feature/SKU availability or capacity errors. Authentication,
policy, role-assignment, and other deployment failures stop the script.
It never falls back to Standard tier or disables confidential computing.

The script prints the selected namespace, location, resource group and queue, and
verifies Premium, confidential mode and disabled local authentication before sending.
Each location is preflighted with Azure ARM validation before namespace creation,
including the permissions required to create the role assignments. Preflight failure
can leave an empty resource group, but does not create a billable namespace.
New Azure Service Bus Data Sender and Data Receiver permissions can take several
minutes to propagate; authorization probes retry for up to five minutes.
No connection string, SAS key, or credential file is generated.

Override locations or resource names when needed:

```powershell
.\Deploy-ServiceBus.ps1 -SubscriptionId '<subscription-id>' `
    -ResourceGroupName 'rg-my-confidential-servicebus-demo' `
    -NamespacePrefix 'sbcc-my-unique-prefix' `
    -Locations koreacentral,uaenorth
```

The resource group's metadata location defaults to the first requested location;
the namespace itself is created in the successful fallback location.
Existing resource groups are not relocated. Failed attempts remain visible in
deployment history. Partial resources are not automatically deleted.

Use `-SkipMessages` to provision only. To assign roles to a signed-in automation
identity instead of the current user, pass its **object ID** with
`-PrincipalId '<object-id>' -PrincipalType ServicePrincipal`. The messaging client
must authenticate as that principal.

## Test against Azure

The deployment command above runs the live test automatically. To require Korea
Central without regional fallback:

```powershell
.\Deploy-ServiceBus.ps1 -SubscriptionId '<subscription-id>' -Locations koreacentral
```

Success requires all three checks:

1. The script prints `Verified:` with Premium and `confidentialCompute=Enabled`;
   it also checks that local authentication is disabled.
2. The client prints `Sent 3 sample messages`, followed by three
   `Received and completed` lines containing the fictional JSON orders.
3. The client prints `PASS: all 3 sample payloads read back, verified, and completed.`
   The command exits successfully and returns the namespace, queue, and location.

To run messaging again against the namespace and queue printed by the script,
use the tenant ID printed at deployment start:

```powershell
node .\send-receive.mjs '<namespace>.servicebus.windows.net' '<queue-name>' '<tenant-id>'
```

Use a **dedicated, empty queue without competing consumers**. Each run uses unique
message and correlation IDs. Unexpected or corrupt messages fail the test and are
abandoned, not silently consumed. Receive timeout is two minutes. Failed sends can
have ambiguous delivery; don't blindly rerun against a queue with leftover messages.
Successful runs remove the three sample messages by completing them.

### Manually send and verify a message in the Azure portal

Use the portal's built-in **Service Bus Explorer**, not the standalone desktop
application. See Microsoft's
[Service Bus Explorer guide](https://learn.microsoft.com/en-us/azure/service-bus-messaging/explorer).

Before starting, stop any SDK receivers and use a dedicated, empty demo queue.
Do not run the automated round-trip script while manual messages remain: it
intentionally rejects messages from a different run.

1. Sign in to the [Azure portal](https://portal.azure.com) as the identity given
   **Azure Service Bus Data Sender** and **Azure Service Bus Data Receiver** by
   the deployment. A different portal user needs equivalent data-plane permissions;
   subscription Owner alone does not grant message send/receive access. Allow
   several minutes for new role assignments to propagate.
2. Open your deployed namespace, select **Queues**, open the queue printed by the
   script, and select **Service Bus Explorer**. Use **Microsoft Entra**
   authentication if prompted to select an authentication method. Do not enable
   local/SAS authentication or use an access key.
3. Select **Send messages**, choose **Application/Json** as the content type, and
   paste this fictional payload into **Message body**:

   ```json
   {
     "orderId": "MANUAL-1001",
     "product": "Confidential widget",
     "quantity": 2
   }
   ```

4. Under **Broker properties**, set **Message ID** to `manual-order-1001` and
   **Correlation ID** to `manual-check-1001`. Leave scheduled enqueue unset and
   **Repeat send** off, then select **Send** once. Use new IDs for subsequent tests.
5. Select **Peek Mode**, select the **Queue / Subscription** subqueue (not
   **DeadLetter**), and select **Peek from start**. Open the message and verify:
   - The body has exactly the three fields and values above.
   - **Message Properties** shows Message ID `manual-order-1001`, Correlation ID
     `manual-check-1001`, and content type `application/json`.
   - Peeking again still shows the message: **peek does not consume it**.
6. Select **Receive Mode**, then **Receive messages**. Choose **PeekLock**, request
   **1** message, set a wait time such as **10 seconds**, and select **Receive**.
   Do not choose **ReceiveAndDelete**, which removes the message before you verify it.
7. Open the received message and compare its complete JSON body, Message ID,
   Correlation ID, and content type with the values you sent. If they match,
   select that message in the grid and choose **Complete**. The sample queue's lock
   lasts one minute: finish verification and completion before it expires. If the
   lock expires, receive again and recheck before completing. If the payload does
   not match, use **Abandon lock**, investigate, and do not complete it.
8. Return to **Peek Mode** and choose **Peek from start** again. The completed
   message should be absent. Refresh the queue counts; for an otherwise empty
   queue, **Active Messages** and **Dead-lettered Messages** should both be zero
   after the counts update. A further receive should return no message.

Successful verification means the matching message was sent, inspected, received,
and explicitly completed, not merely that the portal accepted a send request.
If a message is missing, check the selected namespace/queue and subqueue, whether
another receiver consumed it, and whether its TTL expired. For authorization
failures, check the portal identity and data roles; do not switch to SAS as a workaround.

## Cost, security, and cleanup

**Premium messaging units incur ongoing charges even when idle.** This sample uses
one messaging unit and one partition. Resources are intentionally left available
for inspection; no automatic deletion occurs.

After inspecting the output, delete the **dedicated demo group**:

```powershell
Remove-AzResourceGroup -Name '<resource-group-name-printed-by-the-script>'
```

Do not delete a reused resource group containing unrelated resources.

The public endpoint is enabled for this local demo, requires Entra authentication,
and enforces TLS 1.2+. Sender/receiver permissions are namespace-scoped. Production
workloads should consider queue-scoped roles, managed identity, private endpoints,
network restrictions, monitoring, and customer-managed keys. Confidential compute
is a creation-time setting, not an upgrade path for an existing namespace.

## Local checks

```powershell
npm test
.\Test-DeploymentHelpers.ps1
.\Test-Deployment.ps1
```

Tests check payload/ID integrity, missing/duplicate/unrelated messages, link cleanup,
bounded RBAC retries, conservative regional fallback classification, and mocked
end-to-end deployment/preflight flows. The PowerShell tests require the Az modules
but do not call Azure.

### Validation in this workspace (October 29, 2026)

Live deployment and messaging succeeded in **Korea Central**:

- Azure reports Premium, confidential compute Enabled, and local authentication disabled.
- Both namespace-scoped Sender and Receiver assignments were verified.
- Three sample orders were sent, read back with exact payload verification, and
  completed. The queue subsequently reported zero active and dead-letter messages.

Live testing also identified and fixed an incorrect Receiver role ID and handling
of Azure PowerShell's empty-string validation success result. Local checks pass:
10 Node tests, 10 regional error classifications, and eight mocked deployment
scenarios, including the empty-string regression and built-in role ID assertions.
These are historical validation results, not a guarantee that the demo resources
still exist. While retained, they incur Premium charges. Use the cleanup command
in the cost, security, and cleanup section with your deployment's resource group.

## References

- [Service Bus confidential computing (including ARM/Bicep examples)](https://learn.microsoft.com/en-us/azure/service-bus-messaging/confidential-computing?tabs=bicep)
- [Service Bus JavaScript SDK](https://learn.microsoft.com/javascript/api/overview/azure/service-bus-readme)
- [Azure PowerShell credential](https://learn.microsoft.com/javascript/api/@azure/identity/azurepowershellcredential)
- [Service Bus Entra authentication and built-in roles](https://learn.microsoft.com/azure/service-bus-messaging/authenticate-application)
- [Service Bus Explorer: send, peek, receive, and complete messages](https://learn.microsoft.com/en-us/azure/service-bus-messaging/explorer)
