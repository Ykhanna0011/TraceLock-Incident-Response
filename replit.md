# TraceLock

A defensive identity-incident simulator that reconstructs synthetic cloud access paths and verifies containment by recomputing reachability.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the shared Express API
- `pnpm --filter @workspace/tracelock run dev` — run the TraceLock web app
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm --filter @workspace/api-server run test` — run the incident-engine tests
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React, TypeScript, Vite
- API: Express 5, with Zod request/response validation
- API codegen: Orval (from OpenAPI spec)
- Tests: Node's built-in test runner

## Where things live

- `artifacts/tracelock/src/pages/investigation.tsx` — incident investigation interface
- `artifacts/tracelock/src/index.css` — visual theme and responsive layout
- `artifacts/api-server/src/lib/incident-engine.ts` — synthetic scenario and graph simulation logic
- `artifacts/api-server/src/routes/incidents.ts` — incident and simulation API
- `lib/api-spec/openapi.yaml` — API contract source of truth

## Architecture decisions

- Milestone 1 uses deterministic synthetic data and does not connect to a database or real cloud accounts.
- Each remediation is applied to a copied scenario graph. Verification independently recomputes paths from enabled edges; it is not selected-action-based.
- Audit events link to access relationships so the investigation can trace graph findings to evidence.
- This app simulates defensive response only; it never revokes real sessions, roles, or application grants.

## Product

- Use the dark operations console to investigate a compromised identity, inspect reconstructed paths and synthetic audit evidence, select containment actions, and compare verified closed paths with any remaining reachable paths.
- The demonstration includes an insufficient single action and a successful multi-action containment combination.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
