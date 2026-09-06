"use client";

import Link from "next/link";
import { Filter, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { endpointLabel, usingFixtures } from "@/lib/api";
import { useIncidentStore } from "@/lib/store";
import type { EndpointSummary, Incident, IncidentStatus, RiskBand } from "@/lib/types";
import { scoreToBand } from "@/lib/utils";
import { BandBadge } from "@/components/risk/BandBadge";
import { LadderBadge } from "@/components/risk/LadderBadge";
import { ScoreBadge } from "@/components/risk/ScoreBadge";
import { ThreatTypeLabel } from "@/components/risk/ThreatTypeLabel";
import { Mono } from "@/components/ui/Mono";

const statuses: Array<"all" | IncidentStatus> = ["all", "open", "acknowledged", "overridden", "closed"];
const bands: Array<"all" | RiskBand> = ["all", "SEVERE", "CRITICAL", "HIGH", "SUSPICIOUS", "SAFE"];

export default function IncidentsPage() {
  const incidents = useIncidentStore((state) => state.incidents);
  const endpoints = useIncidentStore((state) => state.endpoints);
  const [status, setStatus] = useState<"all" | IncidentStatus>("all");
  const [band, setBand] = useState<"all" | RiskBand>("all");
  const [query, setQuery] = useState("");

  const endpointsById = useMemo(() => new Map(endpoints.map((endpoint) => [endpoint.id, endpoint])), [endpoints]);

  const filtered = useMemo(() => incidents.filter((incident) => {
    const matchesStatus = status === "all" || incident.status === status;
    const matchesBand = band === "all" || scoreToBand(incident.risk_score) === band;
    const normalized = query.toLowerCase();
    const label = endpointLabel(endpointsById.get(incident.endpoint_id)).toLowerCase();
    return matchesStatus && matchesBand && (!normalized || label.includes(normalized) || incident.session_key.toLowerCase().includes(normalized));
  }), [band, endpointsById, incidents, query, status]);

  return <div className="space-y-6">
    <header className="flex items-end justify-between gap-4"><div><p className="eyebrow">Detection feed</p><h1 className="page-title">Incidents <span className="ml-2 text-base font-normal text-zinc-500">{filtered.length} visible</span></h1></div>{usingFixtures && <Mono className="hidden text-xs text-zinc-600 sm:block">FIXTURE MODE</Mono>}</header>
    <div className="console-card flex flex-wrap items-center gap-2 p-3"><Filter size={15} className="ml-1 text-zinc-600" /><select aria-label="Filter by status" value={status} onChange={(event) => setStatus(event.target.value as "all" | IncidentStatus)} className="console-select">{statuses.map((item) => <option key={item} value={item}>{item === "all" ? "All statuses" : item}</option>)}</select><select aria-label="Filter by risk band" value={band} onChange={(event) => setBand(event.target.value as "all" | RiskBand)} className="console-select">{bands.map((item) => <option key={item} value={item}>{item === "all" ? "All bands" : item}</option>)}</select><label className="ml-auto flex min-w-56 flex-1 items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs text-zinc-500 sm:max-w-xs"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Endpoint or session" className="w-full bg-transparent outline-none placeholder:text-zinc-700" /></label></div>
    <div className="console-card overflow-hidden"><div className="overflow-x-auto"><table className="w-full min-w-205 text-left text-sm"><thead className="border-b border-zinc-800 bg-zinc-950/50 text-[11px] uppercase tracking-[0.08em] text-zinc-600"><tr><th className="px-4 py-3 font-medium">Time</th><th className="px-4 py-3 font-medium">Threat</th><th className="px-4 py-3 font-medium">Endpoint</th><th className="px-4 py-3 font-medium">Session</th><th className="px-4 py-3 font-medium">Score</th><th className="px-4 py-3 font-medium">Ladder</th><th className="px-4 py-3 font-medium">Status</th></tr></thead><tbody className="divide-y divide-zinc-800/70">{filtered.map((incident) => <IncidentRow key={incident.id} incident={incident} endpoint={endpointsById.get(incident.endpoint_id)} />)}</tbody></table></div>{filtered.length === 0 && <div className="px-6 py-16 text-center"><p className="text-sm text-zinc-400">Nothing flagged for these filters.</p><p className="mt-1 text-xs text-zinc-600">Monika is watching {endpoints.length} endpoints.</p></div>}</div>
  </div>;
}

function IncidentRow({ incident, endpoint }: { incident: Incident; endpoint: EndpointSummary | undefined }) {
  return <tr className="group transition-colors hover:bg-zinc-900/70"><td className="whitespace-nowrap px-4 py-3"><Link href={`/incidents/${incident.id}`} className="mono text-xs text-zinc-500 group-hover:text-indigo-300">{new Date(incident.updated_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</Link></td><td className="px-4 py-3"><ThreatTypeLabel threatType={incident.threat_type} /></td><td className="px-4 py-3"><Mono className="text-xs text-zinc-400">{endpointLabel(endpoint)}</Mono></td><td className="max-w-36 truncate px-4 py-3"><Mono className="text-xs text-zinc-600">{incident.session_key}</Mono></td><td className="px-4 py-3"><ScoreBadge score={incident.risk_score} /></td><td className="px-4 py-3"><LadderBadge state={incident.action_taken} /></td><td className="px-4 py-3"><div className="flex items-center gap-2"><BandBadge band={scoreToBand(incident.risk_score)} /><span className="text-xs capitalize text-zinc-500">{incident.status}</span></div></td></tr>;
}
