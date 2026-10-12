import assert from "node:assert/strict";
import test from "node:test";
import {
  applyRemediation,
  getAuditEvidenceForEdge,
  loadScenario,
  produceVerificationReport,
  recomputeReachability,
  simulateContainment,
} from "./incident-engine.ts";

test("the initial scenario reconstructs both expected paths", () => {
  const scenario = loadScenario();
  const paths = recomputeReachability(scenario);

  assert.equal(paths.length, 2);
  assert.ok(paths.some((path) => path.edgeIds.includes("edge-session-admin")));
  assert.ok(paths.some((path) => path.edgeIds.includes("edge-app-consent")));
  assert.ok(paths.every((path) => path.nodeIds.includes("resource-customer-vault")));
});

test("each sensitive-resource route links to evidence from its acting role", () => {
  const scenario = loadScenario();
  const adminEdge = scenario.edges.find((edge) => edge.id === "edge-admin-vault");
  const releaseEdge = scenario.edges.find((edge) => edge.id === "edge-release-vault");

  assert.ok(adminEdge);
  assert.ok(releaseEdge);
  assert.deepEqual(
    getAuditEvidenceForEdge(adminEdge, scenario.auditEvents).map((event) => event.actorId),
    ["role-cloud-operator"],
  );
  assert.deepEqual(
    getAuditEvidenceForEdge(releaseEdge, scenario.auditEvents).map((event) => event.actorId),
    ["role-release-operator"],
  );
});

test("revoking only the user session is rejected while the app-consent route remains", () => {
  const report = simulateContainment(["revoke-user-session"]);

  assert.equal(report.status, "incomplete");
  assert.equal(report.remainingReachablePaths.length, 1);
  assert.ok(
    report.remainingReachablePaths[0].edgeIds.includes("edge-app-consent"),
  );
  assert.match(report.unresolvedFindings[0], /Reachable path remains/);
});

test("revoking the session and app consent closes the known paths", () => {
  const report = simulateContainment([
    "revoke-user-session",
    "revoke-app-consent",
  ]);

  assert.equal(report.status, "verified-contained");
  assert.equal(report.remainingReachablePaths.length, 0);
  assert.equal(report.verifiedClosedPaths.length, 2);
  assert.deepEqual(report.unresolvedFindings, []);
});

test("simulation changes a copy and does not mutate the original scenario", () => {
  const original = loadScenario();
  const originalCopy = structuredClone(original);
  const updated = applyRemediation(original, ["revoke-user-session"]);
  const report = produceVerificationReport(original, updated, [
    "revoke-user-session",
  ]);

  assert.deepEqual(original, originalCopy);
  assert.equal(recomputeReachability(original).length, 2);
  assert.equal(report.remainingReachablePaths.length, 1);
});

test("repeated runs of the same scenario produce identical reports", () => {
  const first = simulateContainment(["revoke-user-session"]);
  const second = simulateContainment(["revoke-user-session"]);

  assert.deepEqual(first, second);
});
