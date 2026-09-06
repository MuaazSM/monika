// Mirrors the backend Pydantic response models exactly (monika/app/*/models.py). Keep in
// sync by hand until `make types` generates lib/types.gen.ts from the OpenAPI schema and
// these become thin aliases into it.

export type ThreatType =
  | "BOLA_ENUMERATION"
  | "CREDENTIAL_STUFFING"
  | "SQL_INJECTION"
  | "DATA_EXPOSURE"
  | "FUNCTION_LEVEL_AUTH"
  | "RATE_ABUSE";

// Score bands are a dashboard-only concept (the engine returns a raw 0-100 score) — see
// lib/utils.ts::scoreToBand for the thresholds, taken from the README's documented bands.
export type RiskBand = "SAFE" | "SUSPICIOUS" | "HIGH" | "CRITICAL" | "SEVERE";

export type LadderState = "NORMAL" | "OBSERVE" | "RATE_LIMIT" | "CHALLENGE" | "BLOCK" | "REVOKE";
export type IncidentStatus = "open" | "acknowledged" | "overridden" | "closed";
export type EndpointRiskLevel = "green" | "amber" | "red";

// SignalOut (monika/app/incidents/models.py)
export interface Signal {
  id: string;
  category: "auth" | "enum" | "rate" | "payload" | "exposure";
  severity: number;
  evidence: Record<string, unknown>; // rendered verbatim (CLAUDE.md rule 5) — never reshaped
  request_id: string;
  session_key: string;
  endpoint_id: string | null;
  created_at: string;
}

// OverrideOut
export interface Override {
  id: string;
  analyst: string;
  action: "acknowledge" | "unblock" | "false_positive" | "force_block";
  reason: string;
  created_at: string;
}

// IncidentOut
export interface Incident {
  id: string;
  session_key: string;
  endpoint_id: string;
  threat_type: ThreatType;
  risk_score: number;
  confidence: number;
  action_taken: LadderState;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
}

// IncidentDetailOut
export interface IncidentDetail extends Incident {
  llm_explanation: string | null;
  llm_next_step: string | null;
  signals: Signal[];
  overrides: Override[];
}

// IncidentListOut
export interface IncidentList {
  items: Incident[];
  next_cursor: string | null;
}

// SessionStateOut
export interface SessionState {
  session_key: string;
  state: LadderState;
  score: number;
  last_signal_at: number | null;
  signals_5m: number;
}

// EndpointOut (monika/app/endpoints/models.py — the §13.1 risk map)
export interface EndpointSummary {
  id: string;
  method: string;
  path_pattern: string;
  auth_required: boolean;
  admin_only: boolean;
  sensitive_fields: string[];
  baseline_rpm_mean: number;
  baseline_rpm_std: number;
  baseline_resp_bytes: number;
  incident_count: number;
  max_risk_score: number | null;
  risk_level: EndpointRiskLevel;
}

// StatsOut
export interface Stats {
  total_requests: number;
  incidents: number;
  blocked: number;
  endpoints_configured: number;
  precision: number | null; // null (not 0) when no request reached >= RATE_LIMIT
  recall: number | null; // null (not 0) when no attack scenario ran
  benign_by_rung: Record<LadderState, number>;
  window_minutes: number;
}

// SimulateRun (monika/app/simulator/router.py)
export type SimulationStatus = "running" | "done" | "failed";

export interface SimulateRun {
  run_id: string;
  scenario: string;
  status: SimulationStatus;
}

// ResetOut (monika/app/policy/reset.py)
export interface ResetResult {
  incidents_cleared: number;
  signals_cleared: number;
  preserved_incidents: number;
}

// SSE payloads are the same JSON shapes as the matching REST GET response (CLAUDE.md §7).
export type SseEvent =
  | { type: "incident.created"; payload: Incident }
  | { type: "incident.updated"; payload: Incident }
  | { type: "incident.explained"; payload: IncidentDetail }
  | { type: "session.changed"; payload: SessionState }
  | { type: "stats.tick"; payload: Stats };
