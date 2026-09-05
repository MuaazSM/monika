"use client";

import { LockKeyhole, Search, SlidersHorizontal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import type { EndpointSummary } from "@/lib/types";
import { BandBadge } from "@/components/risk/BandBadge";
import { ThreatTypeLabel } from "@/components/risk/ThreatTypeLabel";
import { Mono } from "@/components/ui/Mono";

const bandOrder = { SEVERE: 0, CRITICAL: 1, HIGH: 2, SUSPICIOUS: 3, SAFE: 4 };

export default function EndpointsPage() {
	const [endpoints, setEndpoints] = useState<EndpointSummary[]>([]);
	const [query, setQuery] = useState("");
	const [table, setTable] = useState(false);
	useEffect(() => { api.getEndpoints().then(setEndpoints).catch(() => undefined); }, []);
	const visible = useMemo(() => endpoints.filter((endpoint) => `${endpoint.method} ${endpoint.path}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => bandOrder[a.band] - bandOrder[b.band] || b.incidents_24h - a.incidents_24h), [endpoints, query]);
	return <div className="space-y-6"><header className="flex items-end justify-between gap-4"><div><p className="eyebrow">Surface map</p><h1 className="page-title">Endpoints <span className="ml-2 text-base font-normal text-zinc-500">{endpoints.length} protected</span></h1></div><div className="flex items-center gap-2"><label className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs text-zinc-500"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter endpoints" className="w-40 bg-transparent outline-none placeholder:text-zinc-700" /></label><button type="button" onClick={() => setTable(!table)} className="console-toggle"><SlidersHorizontal size={14} /> {table ? "Grid" : "Table"}</button></div></header>{table ? <EndpointTable endpoints={visible} /> : <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{visible.map((endpoint) => <EndpointTile key={endpoint.id} endpoint={endpoint} />)}</div>}</div>;
}

function EndpointTile({ endpoint }: { endpoint: EndpointSummary }) { return <article className={`console-card border-l-2 p-4 ${endpoint.band === "SAFE" ? "border-l-zinc-700" : endpoint.band === "SUSPICIOUS" ? "border-l-amber-400" : "border-l-red-500"}`}><div className="flex items-start justify-between gap-3"><div><Mono className="text-sm text-zinc-200">{endpoint.method} {endpoint.path}</Mono>{endpoint.baseline_n < 30 && <span className="ml-2 rounded border border-indigo-400/30 bg-indigo-400/10 px-1.5 py-0.5 text-[10px] text-indigo-300">LEARNING</span>}</div><BandBadge band={endpoint.band} /></div><div className="mt-5 grid grid-cols-3 gap-3 text-xs"><div><p className="text-zinc-600">Baseline rpm</p><Mono className="text-zinc-300">{endpoint.baseline_rpm}</Mono></div><div><p className="text-zinc-600">Incidents 24h</p><Mono className="text-zinc-300">{endpoint.incidents_24h}</Mono></div><div><p className="text-zinc-600">Auth</p><LockKeyhole size={14} className={endpoint.auth_required ? "text-emerald-400" : "text-zinc-700"} /></div></div><div className="mt-4 flex items-center justify-between border-t border-zinc-800 pt-3 text-xs"><span className="text-zinc-600">Top threat</span>{endpoint.top_threat ? <ThreatTypeLabel threatType={endpoint.top_threat} /> : <span className="text-zinc-500">None</span>}</div></article>; }
function EndpointTable({ endpoints }: { endpoints: EndpointSummary[] }) { return <div className="console-card overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="border-b border-zinc-800 text-[11px] uppercase tracking-[0.08em] text-zinc-600"><tr>{["Endpoint", "Risk", "Baseline rpm", "Incidents", "Auth", "Top threat"].map((heading) => <th key={heading} className="px-4 py-3 font-medium">{heading}</th>)}</tr></thead><tbody className="divide-y divide-zinc-800/70">{endpoints.map((endpoint) => <tr key={endpoint.id} className="hover:bg-zinc-900"><td className="px-4 py-3"><Mono>{endpoint.method} {endpoint.path}</Mono></td><td className="px-4 py-3"><BandBadge band={endpoint.band} /></td><td className="px-4 py-3"><Mono>{endpoint.baseline_rpm}</Mono></td><td className="px-4 py-3"><Mono>{endpoint.incidents_24h}</Mono></td><td className="px-4 py-3">{endpoint.auth_required ? "Required" : "Public"}</td><td className="px-4 py-3">{endpoint.top_threat ? <ThreatTypeLabel threatType={endpoint.top_threat} /> : "-"}</td></tr>)}</tbody></table></div>; }
