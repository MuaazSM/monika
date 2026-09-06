"use client";

import { Activity, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, endpointLabel, usingFixtures } from "@/lib/api";
import type { EndpointSummary, Incident, Stats } from "@/lib/types";
import { ThreatTypeLabel } from "@/components/risk/ThreatTypeLabel";

const emptyStats: Stats = {
  total_requests: 0,
  incidents: 0,
  blocked: 0,
  endpoints_configured: 0,
  precision: null,
  recall: null,
  benign_by_rung: {},
  window_minutes: 30,
};

function topThreats(incidents: Incident[]): Array<{ name: string; count: number; width: string }> {
  const counts = new Map<string, number>();
  for (const incident of incidents) counts.set(incident.threat_type, (counts.get(incident.threat_type) ?? 0) + 1);
  const max = Math.max(1, ...counts.values());
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count, width: `${Math.round((count / max) * 100)}%` }));
}

function mostTargeted(incidents: Incident[], endpoints: EndpointSummary[]): Array<{ id: string; label: string; count: number }> {
  const byId = new Map(endpoints.map((endpoint) => [endpoint.id, endpoint]));
  const counts = new Map<string, number>();
  for (const incident of incidents) counts.set(incident.endpoint_id, (counts.get(incident.endpoint_id) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([id, count]) => ({ id, label: endpointLabel(byId.get(id)), count }));
}

export default function Home() {
  const [stats, setStats] = useState<Stats>(emptyStats);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointSummary[]>([]);

  useEffect(() => {
    api.getStats().then(setStats).catch(() => undefined);
    api.getIncidents().then(setIncidents).catch(() => undefined);
    api.getEndpoints().then(setEndpoints).catch(() => undefined);
  }, []);

  const threats = useMemo(() => topThreats(incidents), [incidents]);
  const targeted = useMemo(() => mostTargeted(incidents, endpoints), [incidents, endpoints]);
  const openIncidents = useMemo(() => incidents.filter((incident) => incident.status === "open").length, [incidents]);
  const isQuiet = incidents.length === 0;

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <p className="eyebrow">Monika / security operations</p>
          <h1 className="page-title">Overview <span className="ml-2 text-base font-normal text-zinc-500">live posture</span></h1>
        </div>
        {usingFixtures && <span className="mono text-xs text-zinc-600">FIXTURE MODE</span>}
      </header>
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Overview metrics">
        <Metric label="Requests" value={stats.total_requests.toLocaleString()} note={`last ${stats.window_minutes} min`} icon={Activity} />
        <Metric label="Incidents" value={stats.incidents.toLocaleString()} note={`${openIncidents} open`} icon={TriangleAlert} />
        <Metric label="Blocked" value={stats.blocked.toLocaleString()} note="requests" icon={ShieldCheck} />
        <Metric label="Endpoints" value={stats.endpoints_configured.toLocaleString()} note="under protection" icon={Server} />
      </section>
      {isQuiet && (
        <div className="console-card flex flex-col items-center gap-2 px-6 py-14 text-center">
          <ShieldCheck size={22} className="text-emerald-400" />
          <p className="text-sm text-zinc-400">Nothing flagged. Monika is watching {stats.endpoints_configured} endpoints.</p>
        </div>
      )}
      <section className="grid gap-3 xl:grid-cols-[1fr_1fr_1.15fr]">
        <ListPanel title="Top threats">
          {threats.length === 0 && <p className="text-xs text-zinc-600">No incidents yet.</p>}
          {threats.map((threat) => (
            <div key={threat.name} className="space-y-1.5">
              <div className="flex justify-between gap-3">
                <ThreatTypeLabel threatType={threat.name as Incident["threat_type"]} />
                <span className="mono text-xs text-zinc-400">{threat.count}</span>
              </div>
              <div className="h-1 rounded bg-zinc-800"><div className="h-1 rounded bg-indigo-400" style={{ width: threat.width }} /></div>
            </div>
          ))}
        </ListPanel>
        <ListPanel title="Most targeted endpoints">
          {targeted.length === 0 && <p className="text-xs text-zinc-600">No incidents yet.</p>}
          {targeted.map((endpoint) => (
            <div key={endpoint.id} className="flex items-center justify-between gap-3 border-b border-zinc-800/70 pb-2 last:border-0">
              <span className="mono truncate text-xs text-zinc-300">{endpoint.label}</span>
              <span className="mono text-xs text-zinc-400">{endpoint.count}</span>
            </div>
          ))}
        </ListPanel>
        <div className="console-card p-4">
          <div className="section-label">Detection quality</div>
          <div className="mt-5 grid grid-cols-2 gap-4">
            <Quality value={stats.precision === null ? "—" : `${Math.round(stats.precision * 100)}%`} label="Precision" definition="of throttled traffic, actually attack" />
            <Quality value={stats.recall === null ? "—" : `${Math.round(stats.recall * 100)}%`} label="Recall" definition="of attacks run, caught by engine" />
          </div>
          <div className="mt-5 flex h-1.5 overflow-hidden rounded bg-zinc-800">
            {Object.entries(stats.benign_by_rung).map(([rung, count]) => (
              <div key={rung} title={rung} className="bg-zinc-500 first:bg-zinc-600" style={{ width: `${Math.max(2, count / 1.56)}%` }} />
            ))}
          </div>
          <p className="mt-2 text-[11px] text-zinc-600">Benign traffic by response rung</p>
        </div>
      </section>
    </div>
  );
}

function Metric({ label, value, note, icon: Icon }: { label: string; value: string; note: string; icon: typeof Activity }) {
  return <div className="console-card p-4"><div className="flex items-start justify-between"><span className="section-label">{label}</span><Icon size={16} className="text-zinc-600" /></div><div className="mt-3 flex items-baseline gap-2"><span className="mono text-3xl font-semibold text-zinc-100">{value}</span></div><p className="mt-1 text-xs text-zinc-600">{note}</p></div>;
}

function ListPanel({ title, children }: { title: string; children: React.ReactNode }) { return <div className="console-card space-y-3 p-4"><div className="section-label">{title}</div>{children}</div>; }
function Quality({ value, label, definition }: { value: string; label: string; definition: string }) { return <div><p className="mono text-2xl font-semibold text-zinc-100">{value}</p><p className="mt-1 text-xs text-zinc-300">{label}</p><p className="mt-1 text-[11px] leading-4 text-zinc-600">{definition}</p></div>; }
