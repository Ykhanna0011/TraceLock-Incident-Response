import { Router, type IRouter } from "express";
import {
  GetCurrentIncidentResponse,
  GetIncidentRemediationsResponse,
  SimulateContainmentBody,
  SimulateContainmentResponse,
} from "@workspace/api-zod";
import {
  generateCandidateRemediations,
  getIncidentSnapshot,
  simulateContainment,
} from "../lib/incident-engine";

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

export default router;
