import type {
  AccessEdge,
  AttackPath,
  AuditEvent,
  Identity,
  Incident,
  IncidentSnapshot,
  RemediationAction,
  RemediationActionId,
  Resource,
  Role,
  VerificationReport,
} from "@workspace/api-zod";

export type ScenarioState = {
  incident: Incident;
  identities: Identity[];
  roles: Role[];
  resources: Resource[];
  edges: AccessEdge[];
  auditEvents: AuditEvent[];
  assumptions: string[];
};

const scenarioTemplate: ScenarioState = {
  incident: {
    id: "INC-2026-1042",
    title: "Unusual identity access to customer data vault",
    status: "Investigating",
    severity: "Critical",
    detectedAt: new Date("2026-10-12T10:18:00.000Z"),
    summary:
      "A compromised user identity reached a restricted customer-data resource through two independently enabled access routes.",
  },
  identities: [
    {
      id: "identity-violet-chen",
      name: "violet.chen@northstar.example",
      kind: "user",
      compromised: true,
      status: "Compromised",
      detail: "Interactive identity with an active privileged session.",
    },
    {
      id: "identity-build-agent",
      name: "svc-build-release",
      kind: "service",
      compromised: false,
      status: "Active",
      detail: "Workload identity reachable through a standing application grant.",
    },
  ],
  roles: [
    {
      id: "role-cloud-operator",
      name: "CloudOpsAdmin",
      privilege: "Privileged",
      detail: "Can administer cloud data services and read the customer vault.",
    },
    {
      id: "role-release-operator",
      name: "ReleaseOperator",
      privilege: "Elevated",
      detail: "Workload role with read access to the customer vault.",
    },
  ],
  resources: [
    {
      id: "resource-customer-vault",
      name: "Customer Data Vault",
      sensitivity: "Restricted",
      detail: "Synthetic customer records and export snapshots.",
    },
  ],
  edges: [
    {
      id: "edge-session-admin",
      sourceId: "identity-violet-chen",
      targetId: "role-cloud-operator",
      relationship: "Active session grants CloudOpsAdmin",
      enabled: true,
      eventIds: ["evt-role-assume"],
    },
    {
      id: "edge-app-consent",
      sourceId: "identity-violet-chen",
      targetId: "identity-build-agent",
      relationship: "Standing app consent can mint workload tokens",
      enabled: true,
      eventIds: ["evt-app-consent"],
    },
    {
      id: "edge-agent-release",
      sourceId: "identity-build-agent",
      targetId: "role-release-operator",
      relationship: "Workload identity assumes ReleaseOperator",
      enabled: true,
      eventIds: ["evt-workload-role"],
    },
    {
      id: "edge-admin-vault",
      sourceId: "role-cloud-operator",
      targetId: "resource-customer-vault",
      relationship: "CloudOpsAdmin can read and export data",
      enabled: true,
      eventIds: ["evt-vault-export"],
    },
    {
      id: "edge-release-vault",
      sourceId: "role-release-operator",
      targetId: "resource-customer-vault",
      relationship: "ReleaseOperator can read data",
      enabled: true,
      eventIds: ["evt-vault-read"],
    },
  ],
  auditEvents: [
    {
      id: "evt-role-assume",
      timestamp: new Date("2026-10-12T10:14:22.000Z"),
      actorId: "identity-violet-chen",
      action: "AssumeRole",
      targetId: "role-cloud-operator",
      result: "Allowed",
      sourceIp: "185.231.72.14",
      summary: "New interactive session assumed the privileged cloud role.",
    },
    {
      id: "evt-app-consent",
      timestamp: new Date("2026-10-12T10:15:08.000Z"),
      actorId: "identity-violet-chen",
      action: "UseDelegatedAppGrant",
      targetId: "identity-build-agent",
      result: "Allowed",
      sourceIp: "185.231.72.14",
      summary: "Standing application consent was used to request a workload token.",
    },
    {
      id: "evt-workload-role",
      timestamp: new Date("2026-10-12T10:15:31.000Z"),
      actorId: "identity-build-agent",
      action: "AssumeRole",
      targetId: "role-release-operator",
      result: "Allowed",
      sourceIp: "workload:build-runner-07",
      summary: "Build service identity assumed its release operator role.",
    },
    {
      id: "evt-vault-read",
      timestamp: new Date("2026-10-12T10:16:03.000Z"),
      actorId: "role-release-operator",
      action: "ReadCustomerRecords",
      targetId: "resource-customer-vault",
      result: "Allowed",
      sourceIp: "workload:build-runner-07",
      summary: "A restricted customer-data resource was read.",
    },
    {
      id: "evt-vault-export",
      timestamp: new Date("2026-10-12T10:16:17.000Z"),
      actorId: "role-cloud-operator",
      action: "ExportCustomerRecords",
      targetId: "resource-customer-vault",
      result: "Allowed",
      sourceIp: "185.231.72.14",
      summary: "The privileged user route exported records from the restricted resource.",
    },
  ],
  assumptions: [
    "All identities, relationships, audit events, and resources in this scenario are synthetic.",
    "An enabled graph edge represents a currently usable access relationship in the simulation.",
    "The graph includes only the access relationships supplied in this demonstration scenario.",
    "A verified result applies only to this copied graph; no live cloud account was queried or changed.",
  ],
};

const remediationCatalog: RemediationAction[] = [
  {
    id: "revoke-user-session",
    title: "Revoke Violet Chen's active session",
    description:
      "Remove the compromised user's current interactive session and its direct role access.",
    expectedEffect: "Closes the direct CloudOpsAdmin route.",
    category: "Identity session",
    edgeIds: ["edge-session-admin"],
  },
  {
    id: "restrict-admin-role",
    title: "Restrict the CloudOpsAdmin assignment",
    description:
      "Remove the compromised identity's direct assignment to the privileged cloud role.",
    expectedEffect: "Closes the privileged-role route, but does not remove app consent.",
    category: "Role access",
    edgeIds: ["edge-session-admin"],
  },
  {
    id: "revoke-app-consent",
    title: "Revoke the standing build-app consent",
    description:
      "Remove the compromised user's delegated grant that can mint workload identity tokens.",
    expectedEffect: "Closes the service-identity route, but leaves the direct session route.",
    category: "Application grant",
    edgeIds: ["edge-app-consent"],
  },
];

export function loadScenario(): ScenarioState {
  return structuredClone(scenarioTemplate);
}

export function generateCandidateRemediations(): RemediationAction[] {
  return structuredClone(remediationCatalog);
}

function getNodeName(
  scenario: ScenarioState,
  nodeId: string,
): string {
  return (
    scenario.identities.find((identity) => identity.id === nodeId)?.name ??
    scenario.roles.find((role) => role.id === nodeId)?.name ??
    scenario.resources.find((resource) => resource.id === nodeId)?.name ??
    nodeId
  );
}

function isSensitiveResource(scenario: ScenarioState, nodeId: string): boolean {
  const resource = scenario.resources.find((item) => item.id === nodeId);
  return resource?.sensitivity === "Restricted" || resource?.sensitivity === "High";
}

export function reconstructAttackPaths(scenario: ScenarioState): AttackPath[] {
  const paths: AttackPath[] = [];
  const starts = scenario.identities
    .filter((identity) => identity.compromised)
    .map((identity) => identity.id);
  const enabledEdges = scenario.edges.filter((edge) => edge.enabled);

  const walk = (
    currentId: string,
    nodeIds: string[],
    edgeIds: string[],
  ): void => {
    if (isSensitiveResource(scenario, currentId) && edgeIds.length > 0) {
      const names = nodeIds.map((nodeId) => getNodeName(scenario, nodeId));
      paths.push({
        id: `path-${edgeIds.map((edgeId) => edgeId.replace(/^edge-/, "")).join("-")}`,
        label: names.join(" → "),
        nodeIds: [...nodeIds],
        edgeIds: [...edgeIds],
      });
      return;
    }

    for (const edge of enabledEdges) {
      if (edge.sourceId !== currentId || nodeIds.includes(edge.targetId)) {
        continue;
      }
      walk(edge.targetId, [...nodeIds, edge.targetId], [...edgeIds, edge.id]);
    }
  };

  for (const startId of starts) {
    walk(startId, [startId], []);
  }

  return paths;
}

export function applyRemediation(
  scenario: ScenarioState,
  actionIds: RemediationActionId[],
): ScenarioState {
  const updated = structuredClone(scenario);
  const actions = generateCandidateRemediations();

  for (const actionId of actionIds) {
    const action = actions.find((candidate) => candidate.id === actionId);
    if (!action) {
      throw new Error(`Unknown remediation action: ${actionId}`);
    }

    updated.edges = updated.edges.map((edge) =>
      action.edgeIds.includes(edge.id) ? { ...edge, enabled: false } : edge,
    );
  }

  return updated;
}

export function recomputeReachability(scenario: ScenarioState): AttackPath[] {
  return reconstructAttackPaths(scenario);
}

export function produceVerificationReport(
  original: ScenarioState,
  updated: ScenarioState,
  actionIds: RemediationActionId[],
): VerificationReport {
  const initialPaths = recomputeReachability(original);
  const remainingReachablePaths = recomputeReachability(updated);
  const remainingPathIds = new Set(
    remainingReachablePaths.map((path) => path.id),
  );
  const verifiedClosedPaths = initialPaths.filter(
    (path) => !remainingPathIds.has(path.id),
  );

  return {
    status:
      remainingReachablePaths.length === 0
        ? "verified-contained"
        : "incomplete",
    appliedActions: generateCandidateRemediations().filter((action) =>
      actionIds.includes(action.id),
    ),
    verifiedClosedPaths,
    remainingReachablePaths,
    unresolvedFindings: remainingReachablePaths.map(
      (path) =>
        `Reachable path remains: ${path.label}. At least one enabled access route to a restricted resource is still present.`,
    ),
    assumptions: [...original.assumptions],
  };
}

export function getIncidentSnapshot(): IncidentSnapshot {
  const scenario = loadScenario();
  return {
    ...scenario,
    attackPaths: reconstructAttackPaths(scenario),
    remediations: generateCandidateRemediations(),
  };
}

export function simulateContainment(
  actionIds: RemediationActionId[],
): VerificationReport {
  const original = loadScenario();
  const updated = applyRemediation(original, actionIds);
  return produceVerificationReport(original, updated, actionIds);
}

export function getAuditEvidenceForEdge(
  edge: AccessEdge,
  events: AuditEvent[],
): AuditEvent[] {
  const linkedIds = new Set(edge.eventIds);
  return events.filter((event) => linkedIds.has(event.id));
}

export function getScenarioEdgeById(
  scenario: ScenarioState,
  edgeId: string,
): AccessEdge | undefined {
  return scenario.edges.find((edge) => edge.id === edgeId);
}
