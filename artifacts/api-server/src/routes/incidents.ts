import { Router, type IRouter } from "express";
import {
  GetCurrentIncidentResponse,
  GetIncidentRemediationsResponse,
  RunAiIncidentInvestigationResponse,
  SimulateContainmentBody,
  SimulateContainmentResponse,
} from "@workspace/api-zod";
import {
  generateCandidateRemediations,
  getIncidentSnapshot,
  simulateContainment,
} from "../lib/incident-engine";
import { runAiInvestigation } from "../lib/ai-investigation";
import { createNebiusClient, NebiusClientError } from "../lib/nebius-client";

const router: IRouter = Router();

router.get("/incidents/current", (_req, res) => {
  res.json(GetCurrentIncidentResponse.parse(getIncidentSnapshot()));
});

router.get("/incidents/current/remediations", (_req, res) => {
  res.json(
    GetIncidentRemediationsResponse.parse(generateCandidateRemediations()),
  );
});

router.post("/incidents/current/simulations", (req, res) => {
  const parsed = SimulateContainmentBody.safeParse(req.body);
  if (!parsed.success) {
    req.log.warn({ errors: parsed.error.message }, "Invalid containment simulation");
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const report = simulateContainment(parsed.data.actionIds);
  res.json(SimulateContainmentResponse.parse(report));
});

router.post("/incidents/current/ai-investigations", async (req, res) => {
  try {
    const result = await runAiInvestigation(createNebiusClient());
    res.json(RunAiIncidentInvestigationResponse.parse(result));
  } catch (error) {
    if (error instanceof NebiusClientError) {
      req.log.warn({ code: error.code }, "AI investigation provider request failed");
      res.status(error.statusCode).json({ error: error.message });
      return;
    }

    req.log.error("AI investigation failed unexpectedly");
    res.status(502).json({ error: "The investigation could not be completed." });
  }
});

export default router;
