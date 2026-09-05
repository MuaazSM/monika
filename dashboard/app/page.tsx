"use client";

import { Activity, Server, ShieldCheck, TriangleAlert, ShieldCheck as ProtectedIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "@/lib/api";
import type { Stats } from "@/lib/types";

const fallbackStats: Stats = { requests: 18420, incidents: 12, blocked: 39, endpoints: 9, learning: true, activity: [], precision: { precision: 0.94, recall: 0.91, benign_by_rung: { NORMAL: 120, OBSERVE: 25, RATE_LIMIT: 8, CHALLENGE: 2, BLOCK: 1, REVOKE: 0 } } };

export default function Home() {
  const [stats, setStats] = useState<Stats>(fallbackStats);
  const [activeAttack, setActiveAttack] = useState(true);
  useEffect(() => { api.getStats().then(setStats).catch(() => undefined); }, []);
  const chartData = useMemo(() => stats.activity.length ? stats.activity : Array.from({ length: 30 }, (_, index) => ({ minute: `${String(14 + Math.floor(index / 6)).padStart(2, "0")}:${String((index * 2) % 60).padStart(2, "0")}`, requests: 400 + index * 13, incidents: activeAttack && index > 21 ? index - 20 : 0 })), [activeAttack, stats.activity]);
  const threats = [{ name: "BOLA_ENUMERATION", count: 4, width: "82%" }, { name: "CREDENTIAL_STUFFING", count: 3, width: "64%" }, { name: "RATE_ABUSE", count: 2, width: "45%" }, { name: "SQLI", count: 2, width: "40%" }, { name: "PAYLOAD_EXPOSURE", count: 1, width: "22%" }];
  const targeted = [{ path: "GET /api/users/{id}", count: 8 }, { path: "POST /api/auth/login", count: 4 }, { path: "GET /api/search", count: 2 }, { path: "GET /api/products", count: 1 }];
  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <p className="eyebrow">Monika / security operations</p>
          <h1 className="page-title">Overview <span className="ml-2 text-base font-normal text-zinc-500">live posture</span></h1>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" onClick={() => setActiveAttack(true)} className={`console-toggle ${activeAttack ? "console-toggle-active" : ""}`}>Active attack</button>
          <button type="button" onClick={() => setActiveAttack(false)} className={`console-toggle ${!activeAttack ? "console-toggle-active" : ""}`}>Quiet state</button>
        </div>
      </header>
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Overview metrics">
          <Metric label="Requests" value={stats.requests.toLocaleString()} note="last 30 min" icon={Activity} trend="+4.1%" />
          <Metric label="Incidents" value={stats.incidents.toLocaleString()} note="6 open" icon={TriangleAlert} trend="+12" />
          <Metric label="Blocked" value={stats.blocked.toLocaleString()} note="2 tokens revoked" icon={ShieldCheck} trend="+9" />
          <Metric label="Endpoints" value={stats.endpoints.toLocaleString()} note="under protection" icon={Server} trend="3 learning" />
      </section>
      <section className="console-card p-4 pb-2">
        <div className="flex items-baseline justify-between gap-4"><span className="section-label">Threat activity / last 30 minutes</span><span className="mono hidden text-[11px] text-zinc-600 sm:block">requests / incidents per minute</span></div>
        <div className="mt-4 h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: -24 }}>
              <defs><linearGradient id="requestFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#52525b" stopOpacity={0.5} /><stop offset="100%" stopColor="#27272a" stopOpacity={0} /></linearGradient></defs>
              <XAxis dataKey="minute" tick={{ fill: "#52525b", fontSize: 10, fontFamily: "var(--font-mono)" }} axisLine={false} tickLine={false} minTickGap={40} />
              <YAxis hide />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: 6, fontFamily: "var(--font-mono)", fontSize: 11 }} />
              <Area type="monotone" dataKey="requests" stroke="#52525b" fill="url(#requestFill)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="incidents" stroke="#818cf8" fill="none" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>
      {!activeAttack && <div className="console-card flex flex-col items-center gap-2 px-6 py-14 text-center"><ProtectedIcon size={22} className="text-emerald-400" /><p className="text-sm text-zinc-400">Nothing flagged. Monika is watching {stats.endpoints} endpoints.</p><p className="mono text-[11px] text-zinc-600">last signal 11m ago / baseline drift 0.3%</p></div>}
      <section className="grid gap-3 xl:grid-cols-[1fr_1fr_1.15fr]">
        <ListPanel title="Top threats">{threats.map((threat) => <div key={threat.name} className="space-y-1.5"><div className="flex justify-between gap-3"><span className="mono text-xs text-zinc-200">{threat.name}</span><span className="mono text-xs text-zinc-400">{threat.count}</span></div><div className="h-1 rounded bg-zinc-800"><div className="h-1 rounded bg-indigo-400" style={{ width: threat.width }} /></div></div>)}</ListPanel>
        <ListPanel title="Most targeted endpoints">{targeted.map((endpoint) => <div key={endpoint.path} className="flex items-center justify-between gap-3 border-b border-zinc-800/70 pb-2 last:border-0"><span className="mono truncate text-xs text-zinc-300">{endpoint.path}</span><span className="mono text-xs text-zinc-400">{endpoint.count}</span></div>)}</ListPanel>
        <div className="console-card p-4"><div className="section-label">Detection quality</div><div className="mt-5 grid grid-cols-2 gap-4"><Quality value={`${Math.round(stats.precision.precision * 100)}%`} label="Precision" definition="of throttled traffic, actually attack" /><Quality value={`${Math.round(stats.precision.recall * 100)}%`} label="Recall" definition="of attacks run, caught by engine" /></div><div className="mt-5 flex h-1.5 overflow-hidden rounded bg-zinc-800">{Object.entries(stats.precision.benign_by_rung).map(([rung, count]) => <div key={rung} title={rung} className="bg-zinc-500 first:bg-zinc-600" style={{ width: `${Math.max(2, count / 1.56)}%` }} />)}</div><p className="mt-2 text-[11px] text-zinc-600">Benign traffic by response rung</p></div>
      </section>
    </div>
  );
}

function Metric({ label, value, note, trend, icon: Icon }: { label: string; value: string; note: string; trend: string; icon: typeof Activity }) {
  return <div className="console-card p-4"><div className="flex items-start justify-between"><span className="section-label">{label}</span><Icon size={16} className="text-zinc-600" /></div><div className="mt-3 flex items-baseline gap-2"><span className="mono text-3xl font-semibold text-zinc-100">{value}</span><span className="text-xs text-emerald-400">{trend}</span></div><p className="mt-1 text-xs text-zinc-600">{note}</p></div>;
}

function ListPanel({ title, children }: { title: string; children: React.ReactNode }) { return <div className="console-card space-y-3 p-4"><div className="section-label">{title}</div>{children}</div>; }
function Quality({ value, label, definition }: { value: string; label: string; definition: string }) { return <div><p className="mono text-2xl font-semibold text-zinc-100">{value}</p><p className="mt-1 text-xs text-zinc-300">{label}</p><p className="mt-1 text-[11px] leading-4 text-zinc-600">{definition}</p></div>; }
