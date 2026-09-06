import type {
  EndpointSummary,
  EndpointUpdateInput,
  IncidentDetail,
  IncidentList,
  IncidentStatus,
  Override,
  OverrideRequest,
  ResetResult,
  SessionState,
  SimulateRun,
  Stats,
} from "@/lib/types";
import incidentList from "@/fixtures/incidents.json";
import incidentDetail from "@/fixtures/incident-detail.json";
import endpoints from "@/fixtures/endpoints.json";
import stats from "@/fixtures/stats.json";

export const usingFixtures = process.env.NEXT_PUBLIC_USE_FIXTURES === "1";
export const baseUrl = process.env.NEXT_PUBLIC_MONIKA_URL ?? "";

async function delay(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function get<T>(path: string, fixtureValue: T): Promise<T> {
  if (usingFixtures) {
    await delay(150);
    return fixtureValue;
  }
  const response = await fetch(`${baseUrl}${path}`);
  if (!response.ok) throw new Error(`Monika API request failed: ${response.status}`);
  return response.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown, fixtureValue: () => T): Promise<T> {
  if (usingFixtures) {
    await delay(150);
    return fixtureValue();
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!response.ok) {
    const detail = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(detail?.detail ?? `Monika API request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function put<T>(path: string, body: unknown, fixtureValue: () => T | null): Promise<T> {
  if (usingFixtures) {
    await delay(150);
    const value = fixtureValue();
    if (value === null) throw new Error("not found");
    return value;
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!response.ok) {
    const detail = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(detail?.detail ?? `Monika API request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

// Fixture mode has no server, so simulated scenario runs are tracked here and resolve to
// "done" after a short delay — enough to exercise the same poll loop the real endpoint uses.
const fixtureRuns = new Map<string, { scenario: string; startedAt: number }>();
const FIXTURE_RUN_MS = 900;

function fixtureStartRun(scenario: string): SimulateRun {
  const run_id = `fixture-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  fixtureRuns.set(run_id, { scenario, startedAt: Date.now() });
  return { run_id, scenario, status: "running" };
}

function fixtureRunStatus(runId: string): SimulateRun {
  const run = fixtureRuns.get(runId);
  if (!run) return { run_id: runId, scenario: "unknown", status: "failed" };
  const status = Date.now() - run.startedAt >= FIXTURE_RUN_MS ? "done" : "running";
  return { run_id: runId, scenario: run.scenario, status };
}

// Fixture mode has no server, so an override mutates this in-memory copy of the single
// incident-detail fixture (the fixture `getIncident` always returns regardless of id — see
// below) instead of a real POST, so the override buttons still work for screenshots/offline
// demoing of the flow.
let fixtureDetail: IncidentDetail = incidentDetail as unknown as IncidentDetail;

function fixtureStatusFor(action: OverrideRequest["action"]): IncidentStatus {
  if (action === "acknowledge") return "acknowledged";
  if (action === "force_block") return "open";
  return "overridden"; // unblock | false_positive
}

function applyFixtureOverride(body: OverrideRequest): IncidentDetail {
  const override: Override = {
    id: `fixture-override-${Date.now()}`,
    analyst: body.analyst,
    action: body.action,
    reason: body.reason,
    created_at: new Date().toISOString(),
  };
  fixtureDetail = {
    ...fixtureDetail,
    status: fixtureStatusFor(body.action),
    action_taken:
      body.action === "force_block"
        ? "BLOCK"
        : body.action === "unblock" || body.action === "false_positive"
          ? "NORMAL"
          : fixtureDetail.action_taken,
    overrides: [...fixtureDetail.overrides, override],
  };
  return fixtureDetail;
}

// Fixture mode has no server, so endpoint edits mutate this in-memory copy of the fixture
// list instead of a real PUT.
let fixtureEndpoints: EndpointSummary[] = endpoints as unknown as EndpointSummary[];

function applyFixtureEndpointUpdate(id: string, body: EndpointUpdateInput): EndpointSummary | null {
  const index = fixtureEndpoints.findIndex((e) => e.id === id);
  if (index === -1) return null;
  const updated: EndpointSummary = {
    ...fixtureEndpoints[index],
    owner_field: body.owner_field,
    sensitive_fields: body.sensitive_fields,
    auth_required: body.auth_required,
  };
  fixtureEndpoints = fixtureEndpoints.map((e, i) => (i === index ? updated : e));
  return updated;
}

export const api = {
  getIncidents: async () =>
    (await get<IncidentList>("/_monika/incidents", incidentList as unknown as IncidentList)).items,
  getIncident: (id: string) => get<IncidentDetail>(`/_monika/incidents/${id}`, fixtureDetail),
  getEndpoints: () => get<EndpointSummary[]>("/_monika/endpoints", fixtureEndpoints),
  getStats: () => get<Stats>("/_monika/stats", stats as unknown as Stats),

  overrideIncident: (id: string, body: OverrideRequest) =>
    post<IncidentDetail>(`/_monika/incidents/${id}/override`, body, () => applyFixtureOverride(body)),
  updateEndpoint: (id: string, body: EndpointUpdateInput) =>
    put<EndpointSummary>(`/_monika/endpoints/${id}`, body, () => applyFixtureEndpointUpdate(id, body)),
  getSession: (sessionKey: string) =>
    get<SessionState>(`/_monika/sessions/${sessionKey}`, {
      session_key: sessionKey,
      state: "NORMAL",
      score: 0,
      last_signal_at: null,
      signals_5m: 0,
    }),

  startSimulation: (scenario: string) =>
    post<SimulateRun>("/_monika/simulate", { scenario }, () => fixtureStartRun(scenario)),
  getSimulationStatus: (runId: string) =>
    get<SimulateRun>(`/_monika/simulate/${runId}`, fixtureRunStatus(runId)),

  resetDemoData: () =>
    post<ResetResult>("/_monika/reset", undefined, () => ({
      incidents_cleared: incidentList.items.length,
      signals_cleared: 0,
      preserved_incidents: 0,
    })),
};

export function endpointLabel(endpoint: Pick<EndpointSummary, "method" | "path_pattern"> | undefined): string {
  return endpoint ? `${endpoint.method} ${endpoint.path_pattern}` : "unknown endpoint";
}
