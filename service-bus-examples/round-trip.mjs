import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

export async function retryAuthorization(operation, {
  timeoutMs = 300_000,
  intervalMs = 10_000,
  sleep = delay,
  now = Date.now,
} = {}) {
  const deadline = now() + timeoutMs;
  for (;;) {
    try {
      return await operation();
    } catch (error) {
      if (error.code !== "UnauthorizedAccess" || now() >= deadline) {
        throw error;
      }
      console.warn("Service Bus RBAC has not propagated yet; retrying authorization...");
      await sleep(Math.min(intervalMs, deadline - now()));
    }
  }
}

export async function roundTrip(client, queueName, {
  runId = randomUUID(),
  receiveTimeoutMs = 120_000,
  now = Date.now,
  authorize = retryAuthorization,
} = {}) {
  const samples = [
    { orderId: "DEMO-1001", product: "Confidential widget", quantity: 2 },
    { orderId: "DEMO-1002", product: "Encrypted gadget", quantity: 1 },
    { orderId: "DEMO-1003", product: "Sovereign sensor", quantity: 5 },
  ];
  const expected = new Map(samples.map((body, index) => [`${runId}-${index}`, body]));
  const pending = new Map(expected);
  const sender = client.createSender(queueName);
  try {
    // Retry an authorization probe, not the send: an ambiguous send retry can duplicate messages.
    await authorize(() => sender.createMessageBatch());
    await sender.sendMessages([...expected].map(([messageId, body]) => ({
      messageId, correlationId: runId, contentType: "application/json", body,
    })));
    console.log(`Sent ${samples.length} sample messages (run ${runId}).`);
    const receiver = client.createReceiver(queueName, { receiveMode: "peekLock" });
    try {
      await authorize(() => receiver.peekMessages(1));
      const deadline = now() + receiveTimeoutMs;
      while (pending.size > 0 && now() < deadline) {
        const messages = await receiver.receiveMessages(pending.size, {
          maxWaitTimeInMs: Math.min(10_000, Math.max(1, deadline - now())),
        });
        for (const message of messages) {
          try {
            assert.equal(message.correlationId, runId, "Use a dedicated empty queue for this demo");
            assert.ok(pending.has(message.messageId), `Unexpected or duplicate message: ${message.messageId}`);
            assert.deepEqual(message.body, pending.get(message.messageId), "Received payload differs from sent payload");
          } catch (error) {
            await receiver.abandonMessage(message);
            throw error;
          }
          await receiver.completeMessage(message);
          pending.delete(message.messageId);
          console.log(`Received and completed ${message.messageId}: ${JSON.stringify(message.body)}`);
        }
      }
      assert.equal(pending.size, 0, `Timed out waiting for ${pending.size} sample messages`);
      console.log(`PASS: all ${samples.length} sample payloads read back, verified, and completed.`);
      return samples.length;
    } finally {
      await receiver.close();
    }
  } finally {
    await sender.close();
  }
}
