"use client";

import { LockKeyhole, Search, SlidersHorizontal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useIncidentStore } from "@/lib/store";
import type { EndpointSummary, Incident, ThreatType } from "@/lib/types";
import { RiskLevelBadge } from "@/components/risk/RiskLevelBadge";
import { ThreatTypeLabel } from "@/components/risk/ThreatTypeLabel";
import { Mono } from "@/components/ui/Mono";
import { EndpointSheet } from "@/components/EndpointSheet";

const riskOrder = { red: 0, amber: 1, green: 2 };
// No hardcoded risk colours outside components/risk/ — this borrows RiskLevelBadge's own
// token map instead of a second, separately-maintained one.
const riskBorder: Record<EndpointSummary["risk_level"], string> = {
  red: "border-l-red-500",
  amber: "border-l-amber-400",
  green: "border-l-zinc-700",
};

function topThreatByEndpoint(incidents: Incident[]): Map<string, ThreatType> {
  const counts = new Map<string, Map<ThreatType, number>>();
  for (const incident of incidents) {
    const perEndpoint = counts.get(incident.endpoint_id) ?? new Map<ThreatType, number>();
    perEndpoint.set(incident.threat_type, (perEndpoint.get(incident.threat_type) ?? 0) + 1);
    counts.set(incident.endpoint_id, perEndpoint);
  }
  const result = new Map<string, ThreatType>();
  for (const [endpointId, perEndpoint] of counts) {
    const [top] = [...perEndpoint.entries()].sort((a, b) => b[1] - a[1]);
    if (top) result.set(endpointId, top[0]);
  }
  return result;
}

export default function EndpointsPage() {
  const endpoints = useIncidentStore((state) => state.endpoints);
  const incidents = useIncidentStore((state) => state.incidents);
  const setEndpoints = useIncidentStore((state) => state.setEndpoints);
  const [query, setQuery] = useState("");
  const [table, setTable] = useState(false);
  const [editing, setEditing] = useState<EndpointSummary | null>(null);

  // incident_count/max_risk_score/risk_level are a live 30-min-window aggregate computed
  // server-side per request (monika/app/endpoints/service.py::list_endpoints) — there is no
  // SSE event for it, so refetch on each visit rather than relying on the app-wide hydrate.
  useEffect(() => {
    api.getEndpoints().then(setEndpoints).catch(() => undefined);
  }, [setEndpoints]);

  const topThreats = useMemo(() => topThreatByEndpoint(incidents), [incidents]);

  const visible = useMemo(
    () =>
      endpoints
        .filter((endpoint) => `${endpoint.method} ${endpoint.path_pattern}`.toLowerCase().includes(query.toLowerCase()))
        .sort((a, b) => riskOrder[a.risk_level] - riskOrder[b.risk_level] || b.incident_count - a.incident_count),
    [endpoints, query],
  );

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between gap-4">
        <div><p className="eyebrow">Surface map</p><h1 className="page-title">Endpoints <span className="ml-2 text-base font-normal text-zinc-500">{endpoints.length} protected</span></h1></div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs text-zinc-500"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter endpoints" className="w-40 bg-transparent outline-none placeholder:text-zinc-700" /></label>
          <button type="button" onClick={() => setTable(!table)} className="console-toggle"><SlidersHorizontal size={14} /> {table ? "Grid" : "Table"}</button>
        </div>
      </header>
      {table ? (
        <EndpointTable endpoints={visible} topThreats={topThreats} onEdit={setEditing} />
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {visible.map((endpoint) => (
            <EndpointTile key={endpoint.id} endpoint={endpoint} topThreat={topThreats.get(endpoint.id)} onEdit={setEditing} />
          ))}
        </div>
      )}
      {editing && <EndpointSheet endpoint={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

function EndpointTile({
  endpoint,
  topThreat,
  onEdit,
}: {
  endpoint: EndpointSummary;
  topThreat: ThreatType | undefined;
  onEdit: (endpoint: EndpointSummary) => void;
}) {
  return (
    <article
      role="button"
      tabIndex={0}
      onClick={() => onEdit(endpoint)}
      onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && onEdit(endpoint)}
      className={`console-card cursor-pointer border-l-2 p-4 transition-colors hover:bg-zinc-900/40 ${riskBorder[endpoint.risk_level]}`}
    >
      <div className="flex items-start justify-between gap-3">
        <Mono className="text-sm text-zinc-200">{endpoint.method} {endpoint.path_pattern}</Mono>
        <RiskLevelBadge level={endpoint.risk_level} />
      </div>
      <div className="mt-5 grid grid-cols-3 gap-3 text-xs">
        <div><p className="text-zinc-600">Baseline rpm</p><Mono className="text-zinc-300">{endpoint.baseline_rpm_mean.toFixed(1)}</Mono></div>
        <div><p className="text-zinc-600">Incidents (30m)</p><Mono className="text-zinc-300">{endpoint.incident_count}</Mono></div>
        <div><p className="text-zinc-600">Auth</p><LockKeyhole size={14} className={endpoint.auth_required ? "text-emerald-400" : "text-zinc-700"} /></div>
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-zinc-800 pt-3 text-xs">
        <span className="text-zinc-600">Top threat</span>
        {topThreat ? <ThreatTypeLabel threatType={topThreat} /> : <span className="text-zinc-500">None</span>}
      </div>
    </article>
  );
}

function EndpointTable({
  endpoints,
  topThreats,
  onEdit,
}: {
  endpoints: EndpointSummary[];
  topThreats: Map<string, ThreatType>;
  onEdit: (endpoint: EndpointSummary) => void;
}) {
  return (
    <div className="console-card overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="border-b border-zinc-800 text-[11px] uppercase tracking-[0.08em] text-zinc-600">
          <tr>{["Endpoint", "Risk", "Baseline rpm", "Incidents (30m)", "Auth", "Top threat"].map((heading) => <th key={heading} className="px-4 py-3 font-medium">{heading}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/70">
          {endpoints.map((endpoint) => {
            const topThreat = topThreats.get(endpoint.id);
            return (
              <tr key={endpoint.id} onClick={() => onEdit(endpoint)} className="cursor-pointer hover:bg-zinc-900">
                <td className="px-4 py-3"><Mono>{endpoint.method} {endpoint.path_pattern}</Mono></td>
                <td className="px-4 py-3"><RiskLevelBadge level={endpoint.risk_level} /></td>
                <td className="px-4 py-3"><Mono>{endpoint.baseline_rpm_mean.toFixed(1)}</Mono></td>
                <td className="px-4 py-3"><Mono>{endpoint.incident_count}</Mono></td>
                <td className="px-4 py-3">{endpoint.auth_required ? "Required" : "Public"}</td>
                <td className="px-4 py-3">{topThreat ? <ThreatTypeLabel threatType={topThreat} /> : "-"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
