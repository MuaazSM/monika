import { create } from "zustand";
import type { EndpointSummary, Incident, IncidentDetail, SessionState, SseEvent, Stats } from "@/lib/types";

export const emptyStats: Stats = {
  total_requests: 0,
  incidents: 0,
  blocked: 0,
  endpoints_configured: 0,
  precision: null,
  recall: null,
  benign_by_rung: {},
  window_minutes: 30,
  learning: true,
};

function upsertIncident(list: Incident[], incident: Incident): Incident[] {
  const index = list.findIndex((item) => item.id === incident.id);
  if (index === -1) return [incident, ...list];
  const next = [...list];
  next[index] = incident;
  return next;
}

interface IncidentStoreState {
  incidents: Incident[];
  incidentDetails: Record<string, IncidentDetail>;
  endpoints: EndpointSummary[];
  stats: Stats;
  sessions: Record<string, SessionState>;
  hydrated: boolean;
  hydrate: (data: { incidents: Incident[]; endpoints: EndpointSummary[]; stats: Stats }) => void;
  setEndpoints: (endpoints: EndpointSummary[]) => void;
  setIncidentDetail: (detail: IncidentDetail) => void;
  setSession: (session: SessionState) => void;
  applyEvent: (event: SseEvent) => void;
}

/**
 * Single shared store fed by /_monika/events (CLAUDE.md §8: "a single IncidentStore fed by
 * lib/sse.ts; pages read from it, no react-query polling"). AppShell hydrates it once from
 * the REST endpoints and keeps it live via connectToStream; pages just select from here.
 */
export const useIncidentStore = create<IncidentStoreState>((set) => ({
  incidents: [],
  incidentDetails: {},
  endpoints: [],
  stats: emptyStats,
  sessions: {},
  hydrated: false,
  hydrate: (data) =>
    set({
      incidents: data.incidents,
      endpoints: data.endpoints,
      stats: data.stats,
      // hydrate() re-syncs the store to a fresh REST snapshot (initial load, or after a
      // demo-data reset), so any per-id caches from before must be dropped too — otherwise
      // a reset would leave stale detail/session data behind for ids that no longer exist.
      incidentDetails: {},
      sessions: {},
      hydrated: true,
    }),
  setEndpoints: (endpoints) => set({ endpoints }),
  setIncidentDetail: (detail) =>
    set((state) => ({ incidentDetails: { ...state.incidentDetails, [detail.id]: detail } })),
  setSession: (session) =>
    set((state) => ({ sessions: { ...state.sessions, [session.session_key]: session } })),
  applyEvent: (event) =>
    set((state) => {
      switch (event.type) {
        case "incident.created":
        case "incident.updated":
          return { incidents: upsertIncident(state.incidents, event.payload) };
        case "incident.explained": {
          const detail = event.payload;
          const base: Incident = {
            id: detail.id,
            session_key: detail.session_key,
            endpoint_id: detail.endpoint_id,
            threat_type: detail.threat_type,
            risk_score: detail.risk_score,
            confidence: detail.confidence,
            action_taken: detail.action_taken,
            status: detail.status,
            created_at: detail.created_at,
            updated_at: detail.updated_at,
          };
          return {
            incidents: upsertIncident(state.incidents, base),
            incidentDetails: { ...state.incidentDetails, [detail.id]: detail },
          };
        }
        case "session.changed":
          return { sessions: { ...state.sessions, [event.payload.session_key]: event.payload } };
        case "stats.tick":
          return { stats: event.payload };
        default:
          return {};
      }
    }),
}));
