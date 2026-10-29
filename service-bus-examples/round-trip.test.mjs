import assert from "node:assert/strict";
import test from "node:test";
import { retryAuthorization, roundTrip } from "./round-trip.mjs";

function fakeClient(transform = (messages) => messages) {
  const state = { sent: [], completed: [], abandoned: [], closed: [], sends: 0 };
  const receiver = {
    peekMessages: async () => [],
    receiveMessages: async () => transform(state.sent),
    completeMessage: async (message) => state.completed.push(message),
    abandonMessage: async (message) => state.abandoned.push(message),
    close: async () => state.closed.push("receiver"),
  };
  const sender = {
    createMessageBatch: async () => ({}),
    sendMessages: async (messages) => { state.sent = messages; state.sends++; },
    close: async () => state.closed.push("sender"),
  };
  return { state, createSender: () => sender, createReceiver: () => receiver };
}

test("sends and verifies three JSON messages, completing each and closing links", async () => {
  const client = fakeClient();
  assert.equal(await roundTrip(client, "test-queue"), 3);
  assert.equal(client.state.sends, 1);
  assert.equal(client.state.completed.length, 3);
  assert.equal(new Set(client.state.sent.map((message) => message.messageId)).size, 3);
  assert.deepEqual(client.state.closed, ["receiver", "sender"]);
});

for (const [name, transform] of [
  ["corrupt payload", (messages) => [{ ...messages[0], body: { corrupt: true } }]],
  ["unrelated run", (messages) => [{ ...messages[0], correlationId: "another-run" }]],
  ["unexpected ID", (messages) => [{ ...messages[0], messageId: "unexpected" }]],
  ["duplicate message", (messages) => [messages[0], messages[0]]],
]) {
  test(`rejects ${name} without completing the bad message`, async () => {
    const client = fakeClient(transform);
    await assert.rejects(roundTrip(client, "test-queue"));
    assert.equal(client.state.abandoned.length, 1);
    assert.deepEqual(client.state.closed, ["receiver", "sender"]);
  });
}

test("fails if not all messages are received before deadline", async () => {
  const client = fakeClient(() => []);
  let time = 0;
  await assert.rejects(roundTrip(client, "test-queue", {
    receiveTimeoutMs: 2, now: () => time++,
  }), /Timed out/);
  assert.equal(client.state.completed.length, 0);
  assert.deepEqual(client.state.closed, ["receiver", "sender"]);
});

test("authorization propagation retries are bounded and succeed when access appears", async () => {
  let attempts = 0;
  let time = 0;
  const result = await retryAuthorization(async () => {
    if (++attempts < 3) throw Object.assign(new Error("RBAC pending"), { code: "UnauthorizedAccess" });
    return "authorized";
  }, { now: () => time, sleep: async (ms) => { time += ms; }, intervalMs: 1, timeoutMs: 3 });
  assert.equal(result, "authorized");
  assert.equal(attempts, 3);
});

test("authorization timeout and non-authentication errors surface", async () => {
  let time = 0;
  const authError = Object.assign(new Error("denied"), { code: "UnauthorizedAccess" });
  await assert.rejects(retryAuthorization(async () => { throw authError; }, {
    now: () => time, sleep: async (ms) => { time += ms; }, intervalMs: 1, timeoutMs: 2,
  }), /denied/);
  const error = Object.assign(new Error("network failure"), { code: "ServiceCommunicationProblem" });
  await assert.rejects(retryAuthorization(async () => { throw error; }), /network failure/);
});

test("send failure is not retried and closes the sender", async () => {
  const client = fakeClient();
  const sender = client.createSender();
  sender.sendMessages = async () => {
    client.state.sends++;
    throw new Error("ambiguous send failure");
  };
  await assert.rejects(roundTrip(client, "test-queue"), /ambiguous send/);
  assert.equal(client.state.sends, 1);
  assert.deepEqual(client.state.closed, ["sender"]);
});

test("receive failure closes both links", async () => {
  const client = fakeClient();
  client.createReceiver().receiveMessages = async () => { throw new Error("receive failure"); };
  await assert.rejects(roundTrip(client, "test-queue"), /receive failure/);
  assert.deepEqual(client.state.closed, ["receiver", "sender"]);
});
