import { AzurePowerShellCredential } from "@azure/identity";
import { ServiceBusClient } from "@azure/service-bus";
import { roundTrip } from "./round-trip.mjs";

async function main() {
  const [namespace, queueName, tenantId] = process.argv.slice(2);
  if (!namespace || !queueName || !tenantId || !/^[a-z0-9-]+\.servicebus\.windows\.net$/i.test(namespace)) {
    throw new Error("Usage: node send-receive.mjs <namespace.servicebus.windows.net> <dedicated-queue> <tenant-id>");
  }
  const credential = new AzurePowerShellCredential({ tenantId });
  const client = new ServiceBusClient(namespace, credential, {
    retryOptions: { maxRetries: 3, timeoutInMs: 30_000 },
  });
  try {
    await roundTrip(client, queueName);
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error("Service Bus demo failed:", error);
  process.exitCode = 1;
});
