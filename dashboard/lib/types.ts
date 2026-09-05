export type ThreatType = "BOLA" | "BOLA_ENUMERATION" | "CREDENTIAL_STUFFING" | "RATE_ABUSE" | "SQLI" | "PAYLOAD_EXPOSURE";
export type RiskBand = "SAFE" | "SUSPICIOUS" | "HIGH" | "CRITICAL" | "SEVERE";
export type LadderState = "NORMAL" | "OBSERVE" | "RATE_LIMIT" | "CHALLENGE" | "BLOCK" | "REVOKE";
export type IncidentStatus = "open" | "acknowledged" | "overridden" | "closed";

export interface Signal {
  category: "auth" | "enum" | "rate" | "payload" | "exposure";
  severity: number;
  evidence: Record<string, unknown>;
  request_id: string;
  endpoint_id: string | null;
  session_key: string;
}

export interface Override {
  action: "acknowledge" | "unblock" | "false_positive" | "force_block";
  analyst: string;
  reason: string;
  created_at: string;
}

export interface Incident {
  id: string;
  threat_type: ThreatType;
  endpoint: string;
  method: string;
  session_key: string;
  score: number;
  confidence: number;
  band: RiskBand;
  status: IncidentStatus;
  first_seen: string;
  last_seen: string;
  llm_explanation: string | null;
  signals: Signal[];
  actions: Array<{ state: LadderState; score: number; timestamp: string }>;
  overrides: Override[];
}

export interface IncidentDetail extends Incident {
  requests: Array<{ timestamp: string; method: string; path: string; status: number; action_applied: LadderState }>;
}

export interface SessionState {
  session_key: string;
  state: LadderState;
  score: number;
  last_signal_at: string;
  jti_revoked: boolean;
}

export interface EndpointSummary {
  id: string;
  method: string;
  path: string;
  auth_required: boolean;
  baseline_rpm: number;
  incidents_24h: number;
  top_threat: ThreatType | null;
  band: RiskBand;
  owner_field: string | null;
  sensitive_fields: string[];
  baseline_n: number;
}

export interface Stats {
  requests: number;
  incidents: number;
  blocked: number;
  endpoints: number;
  learning: boolean;
  activity: Array<{ minute: string; requests: number; incidents: number }>;
  precision: { precision: number; recall: number; benign_by_rung: Record<LadderState, number> };
}

export type SseEvent =
  | { type: "incident.created"; payload: Incident }
  | { type: "incident.updated"; payload: Incident }
  | { type: "incident.explained"; payload: Pick<Incident, "id" | "llm_explanation"> }
  | { type: "session.changed"; payload: SessionState }
  | { type: "stats.tick"; payload: Stats };
