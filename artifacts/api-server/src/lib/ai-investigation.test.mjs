import assert from "node:assert/strict";
import test from "node:test";
import { runAiInvestigation } from "./ai-investigation.ts";
import {
  createNebiusClient,
  NebiusClientError,
} from "./nebius-client.ts";
import {
  applyRemediation,
  loadScenario,
  produceVerificationReport,
  recomputeReachability,
  simulateContainment,
} from "./incident-engine.ts";

function toolCall(name, args, id = `call-${name}`) {
  return {
    id,
    type: "function",
    function: { name, arguments: JSON.stringify(args) },
  };
}

function completion({ content = null, toolCalls } = {}) {
  return {
    choices: [{
      message: {
        role: "assistant",
        content,
        ...(toolCalls ? { tool_calls: toolCalls } : {}),
      },
    }],
  };
}

function mockClient(responses) {
  const requests = [];
  return {
    requests,
    client: {
      async complete(options) {
        requests.push(options);
        const response = responses.shift();
        if (response instanceof Error) throw response;
        return response;
      },
    },
  };
}

test("orchestrates allowlisted tools and keeps model findings as hypotheses", async () => {
  const originalScenario = loadScenario();
  const { client, requests } = mockClient([
    completion({ toolCalls: [
      toolCall("get_incident_timeline", { limit: 25 }),
      toolCall("enumerate_attack_paths", {}),
      toolCall("inspect_identity", { identityId: "identity-violet-chen" }),
    ] }),
    completion({ toolCalls: [
      toolCall("simulate_remediation", { actionIds: ["revoke-user-session"] }),
      toolCall("verify_containment", {
        actionIds: ["revoke-user-session", "revoke-app-consent"],
      }),
    ] }),
    completion({ content: JSON.stringify({
      explanation: "The second access route is independently controlled.",
      findings: [{
        text: "The compromised identity used a delegated app grant.",
        evidenceIds: ["evt-app-consent"],
      }],
    }) }),
  ]);

  const result = await runAiInvestigation(client);

  assert.equal(requests.length, 3);
  assert.ok(requests.every((request) => request.timeoutMs <= 20_000));
  assert.equal(result.toolExecutions.length, 5);
  assert.equal(result.simulations.length, 1);
  assert.deepEqual(result.verification, simulateContainment([
    "revoke-user-session",
    "revoke-app-consent",
  ]));
  assert.equal(result.verification.status, "verified-contained");
  assert.deepEqual(
    result.verification.verifiedClosedPaths.map((path) => path.id).sort(),
    [
      "path-app-consent-agent-release-release-vault",
      "path-session-admin-admin-vault",
    ],
  );
  assert.deepEqual(result.verification.remainingReachablePaths, []);
  assert.equal(result.findings.at(-1).kind, "model-hypothesis");
  assert.ok(result.findings.slice(0, -1).every((finding) => finding.kind === "verified-fact"));
  assert.ok(result.inspectedEvidence.some((event) => event.id === "evt-app-consent"));
  assert.deepEqual(loadScenario(), originalScenario);
});

test("rejects invalid tool arguments without applying a remediation", async () => {
  const { client } = mockClient([
    completion({ toolCalls: [toolCall("simulate_remediation", {
      actionIds: ["delete-everything"],
    })] }),
    completion({ content: JSON.stringify({ explanation: "Done", findings: [] }) }),
  ]);

  const result = await runAiInvestigation(client);

  assert.equal(result.toolExecutions[0].status, "rejected");
  assert.match(result.toolExecutions[0].summary, /invalid tool arguments/i);
  assert.equal(result.simulations.length, 0);
  assert.equal(result.verification.status, "incomplete");
});

test("valid partial remediation is incomplete with the app-consent path remaining", async () => {
  const { client } = mockClient([
    completion({ toolCalls: [toolCall("verify_containment", {
      actionIds: ["revoke-user-session"],
    })] }),
    completion({ content: JSON.stringify({
      explanation: "The app-consent route remains reachable.",
      findings: [],
    }) }),
  ]);

  const result = await runAiInvestigation(client);
  const expected = simulateContainment(["revoke-user-session"]);

  assert.deepEqual(result.verification, expected);
  assert.equal(result.verification.status, "incomplete");
  assert.deepEqual(
    result.verification.remainingReachablePaths.map((path) => path.id),
    ["path-app-consent-agent-release-release-vault"],
  );
});

test("alternate enabled access edge defeats revoking the original session", () => {
  const pristine = loadScenario();
  const pristineCopy = structuredClone(pristine);
  const scenarioWithAlternateEdge = structuredClone(pristine);
  scenarioWithAlternateEdge.edges.push({
    id: "edge-alt-session-admin",
    sourceId: "identity-violet-chen",
    targetId: "role-cloud-operator",
    relationship: "Alternate privileged session",
    enabled: true,
    eventIds: ["evt-role-assume"],
  });

  const initialPaths = recomputeReachability(scenarioWithAlternateEdge);
  const updated = applyRemediation(scenarioWithAlternateEdge, ["revoke-user-session"]);
  const report = produceVerificationReport(
    scenarioWithAlternateEdge,
    updated,
    ["revoke-user-session"],
  );

  assert.ok(initialPaths.some((path) => path.id === "path-alt-session-admin-admin-vault"));
  assert.equal(report.status, "incomplete");
  assert.deepEqual(
    report.remainingReachablePaths.map((path) => path.id),
    [
      "path-app-consent-agent-release-release-vault",
      "path-alt-session-admin-admin-vault",
    ],
  );
  assert.deepEqual(pristine, pristineCopy);
  assert.deepEqual(loadScenario(), pristineCopy);
});

test("stops after the configured model iteration limit", async () => {
  const { client, requests } = mockClient(Array.from({ length: 5 }, (_, index) =>
    completion({ toolCalls: [toolCall("enumerate_attack_paths", {}, `call-${index}`)] }),
  ));

  const result = await runAiInvestigation(client);

  assert.equal(requests.length, 4);
  assert.equal(result.toolExecutions.length, 4);
  assert.match(result.explanation, /tool-step limit/i);
});

test("reports missing credentials through the existing Nebius client error", () => {
  assert.throws(
    () => createNebiusClient({ apiKey: " " }),
    (error) => error instanceof NebiusClientError && error.code === "missing-api-key",
  );
});

test("maps a mocked Nebius rate limit to the typed client error", async () => {
  const client = createNebiusClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response("{}", { status: 429 }),
  });

  await assert.rejects(
    client.complete({ messages: [{ role: "user", content: "test" }] }),
    (error) => error instanceof NebiusClientError && error.code === "rate-limited" && error.statusCode === 429,
  );
});

test("rejects malformed or oversized mocked provider responses", async () => {
  const malformedClient = createNebiusClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response("not-json"),
  });
  const oversizedClient = createNebiusClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response("x".repeat(65 * 1024)),
  });
  const invalidToolCallClient = createNebiusClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response(JSON.stringify({
      choices: [{
        message: {
          role: "assistant",
          content: null,
          tool_calls: [{
            id: "fixture-call",
            type: "custom",
            function: { name: "enumerate_attack_paths", arguments: "{}" },
          }],
        },
      }],
    })),
  });
  const request = { messages: [{ role: "user", content: "test" }] };

  await assert.rejects(
    malformedClient.complete(request),
    (error) => error instanceof NebiusClientError && error.code === "invalid-response",
  );
  await assert.rejects(
    oversizedClient.complete(request),
    (error) => error instanceof NebiusClientError && error.code === "invalid-response",
  );
  await assert.rejects(
    invalidToolCallClient.complete(request),
    (error) => error instanceof NebiusClientError && error.code === "invalid-response",
  );
});

test("accepts the provider's null tool_calls field on a text response", async () => {
  const client = createNebiusClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response(JSON.stringify({
      id: "fixture-completion",
      choices: [{
        index: 0,
        finish_reason: "stop",
        message: {
          role: "assistant",
          content: "synthetic fixture response",
          tool_calls: null,
        },
      }],
    }), { status: 200, headers: { "content-type": "application/json" } }),
  });

  const result = await client.complete({
    messages: [{ role: "user", content: "fixture request" }],
  });

  assert.equal(result.choices[0].message.tool_calls, null);
});

test("propagates provider errors for sanitized route handling", async () => {
  const providerError = new NebiusClientError("Provider unavailable", 502, "provider-error");
  const { client } = mockClient([providerError]);

  await assert.rejects(runAiInvestigation(client), (error) => error === providerError);
});

test("normalizes provider failures without exposing upstream details or credentials", async () => {
  const credential = "fixture-api-key-not-real";
  const upstreamSecret = "fixture-upstream-detail-not-for-clients";
  const client = createNebiusClient({
    apiKey: credential,
    fetchImpl: async () => new Response(JSON.stringify({
      error: { message: upstreamSecret },
    }), { status: 500 }),
  });
  let publicError;

  await assert.rejects(
    client.complete({ messages: [{ role: "user", content: "test" }] }),
    (error) => {
      publicError = { error: error.message };
      return error instanceof NebiusClientError &&
        error.code === "provider-error" &&
        error.statusCode === 502;
    },
  );

  const serializedError = JSON.stringify(publicError);
  assert.doesNotMatch(serializedError, new RegExp(credential));
  assert.doesNotMatch(serializedError, new RegExp(upstreamSecret));
  assert.doesNotMatch(serializedError, /NebiusClientError|\bat\s+\S+\s+\(/);
});

test("normalizes an aborted provider request to a sanitized timeout", async () => {
  const client = createNebiusClient({
    apiKey: "fixture-api-key-not-real",
    fetchImpl: async () => {
      throw Object.assign(new Error("fixture-provider-secret"), { name: "AbortError" });
    },
  });

  await assert.rejects(
    client.complete({ messages: [{ role: "user", content: "test" }] }),
    (error) => error instanceof NebiusClientError &&
      error.code === "timeout" &&
      error.statusCode === 504 &&
      !error.message.includes("fixture-provider-secret"),
  );
});

test("does not execute unsupported tool names", async () => {
  const { client, requests } = mockClient([
    completion({ toolCalls: [toolCall("delete_cloud_account", {})] }),
    completion({ content: JSON.stringify({ explanation: "Finished", findings: [] }) }),
  ]);

  const result = await runAiInvestigation(client);

  assert.equal(result.toolExecutions.length, 0);
  assert.ok(requests[1].messages.some((message) =>
    message.role === "tool" && message.content.includes("Tool is not available"),
  ));
});

test("drops hypotheses that cite evidence absent from the scenario", async () => {
  const { client } = mockClient([
    completion({ content: JSON.stringify({
      explanation: "Analysis complete",
      findings: [
        { text: "Supported", evidenceIds: ["evt-role-assume"] },
        { text: "Unsupported", evidenceIds: ["invented-event"] },
      ],
    }) }),
  ]);

  const result = await runAiInvestigation(client);

  assert.deepEqual(result.findings.at(-1), {
    kind: "model-hypothesis",
    text: "Supported",
    evidenceIds: ["evt-role-assume"],
  });
});

test("model claims cannot override independently failed containment verification", async () => {
  const { client } = mockClient([
    completion({ toolCalls: [toolCall("verify_containment", {
      actionIds: ["revoke-user-session"],
    })] }),
    completion({ content: JSON.stringify({
      explanation: "Containment is verified-contained.",
      findings: [
        { text: "All attacker paths are closed.", evidenceIds: ["path-session-admin-admin-vault"] },
        { text: "Unsupported citation.", evidenceIds: ["invented-event-id"] },
      ],
    }) }),
  ]);

  const result = await runAiInvestigation(client);

  assert.equal(result.verification.status, "incomplete");
  assert.equal(result.verification.remainingReachablePaths.length, 1);
  assert.equal(result.findings.at(-1).kind, "model-hypothesis");
  assert.equal(result.findings.some((finding) => finding.text === "Unsupported citation."), false);
  assert.deepEqual(result.findings.at(-1).evidenceIds, ["path-session-admin-admin-vault"]);
});