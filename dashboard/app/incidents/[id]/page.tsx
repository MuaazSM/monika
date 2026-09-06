"use client";

import { use, useEffect } from "react";
import { Clock3, Info, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, endpointLabel } from "@/lib/api";
import { useIncidentStore } from "@/lib/store";
import type { IncidentDetail } from "@/lib/types";
import { LadderBadge } from "@/components/risk/LadderBadge";
import { ScoreBadge } from "@/components/risk/ScoreBadge";
import { Mono } from "@/components/ui/Mono";
import { OverridePanel } from "@/components/OverridePanel";
import { RequestTimeline } from "@/components/RequestTimeline";

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  // Reads from the shared store so a live incident.explained / session.changed event (the
  // explanation arriving, an analyst override elsewhere) updates this page without a refetch.
  const incident = useIncidentStore((state) => state.incidentDetails[id]);
  const endpoints = useIncidentStore((state) => state.endpoints);
  const session = useIncidentStore((state) => (incident ? state.sessions[incident.session_key] : undefined));
  const setIncidentDetail = useIncidentStore((state) => state.setIncidentDetail);
  const setSession = useIncidentStore((state) => state.setSession);

  useEffect(() => {
    api
      .getIncident(id)
      .then((detail) => {
        setIncidentDetail(detail);
        api.getSession(detail.session_key).then(setSession).catch(() => undefined);
      })
      .catch(() => undefined);
  }, [id, setIncidentDetail, setSession]);

  if (!incident) return <div className="text-sm text-zinc-500">Loading…</div>;

  const endpoint = endpoints.find((e) => e.id === incident.endpoint_id);
  const currentState = session?.state ?? incident.action_taken;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Incident detail / {id}</p>
          <h1 className="page-title">{incident.threat_type.replaceAll("_", " ")}</h1>
          <Mono className="mt-2 block text-sm text-zinc-400">{endpointLabel(endpoint)} / {incident.session_key}</Mono>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right"><p className="text-xs text-zinc-600">Confidence</p><Mono className="text-sm text-zinc-300">{incident.confidence} / engine-computed</Mono></div>
          <ScoreBadge score={incident.risk_score} />
          <LadderBadge state={currentState} />
        </div>
      </header>
      <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
        <main className="space-y-4">
          <Evidence incident={incident} />
          <section className="console-card p-5">
            <h2 className="section-label">Action taken</h2>
            <div className="mt-5 flex items-center gap-3">
              <LadderBadge state={incident.action_taken} />
              <Mono className="text-xs text-zinc-600">enforced at score {incident.risk_score}</Mono>
            </div>
          </section>
          <section className="console-card p-5">
            <h2 className="section-label">Explanation</h2>
            {incident.llm_explanation ? (
              <p className="mt-4 text-sm leading-6 text-zinc-300">{incident.llm_explanation}</p>
            ) : (
              <p className="mt-4 flex items-center gap-2 text-sm text-zinc-500"><Clock3 size={15} />Writing explanation...</p>
            )}
            <p className="mt-5 border-t border-zinc-800 pt-3 text-[11px] text-zinc-600">Written by the model after the decision was enforced. Scores and actions come from the engine.</p>
          </section>
          <RequestTimeline entries={incident.request_timeline} />
        </main>
        <aside className="space-y-4">
          <OverridePanel incident={incident} ladder={currentState} />
          {incident.overrides.length > 0 && (
            <section className="console-card p-5">
              <h2 className="section-label">Override history</h2>
              <div className="mt-4 space-y-3">
                {incident.overrides.map((override) => (
                  <div key={override.id} className="flex items-center justify-between gap-3 border-b border-zinc-800/70 pb-2 text-xs last:border-0">
                    <span className="text-zinc-300">{override.action.replaceAll("_", " ")} — {override.reason}</span>
                    <span className="mono text-zinc-600">{override.analyst} / {new Date(override.created_at).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </section>
          )}
          <section className="console-card p-5">
            <h2 className="section-label">Why was this flagged</h2>
            <div className="mt-4 space-y-3">
              {[...incident.signals].sort((a, b) => b.severity - a.severity).map((signal) => (
                <div key={signal.id} className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3">
                  <div className="flex items-center justify-between"><span className="text-xs font-medium uppercase text-zinc-300">{signal.category}</span><Mono className="text-xs text-red-400">{signal.severity}</Mono></div>
                  <div className="mt-2 h-1 rounded bg-zinc-800"><div className="h-1 rounded bg-red-500" style={{ width: `${signal.severity}%` }} /></div>
                  <dl className="mt-3 space-y-2">
                    {Object.entries(signal.evidence).map(([key, value]) => (
                      <div key={key} className="flex justify-between gap-3 text-xs">
                        <dt className="text-zinc-600">{key}</dt>
                        <dd className="mono max-w-[60%] text-right text-zinc-300">{Array.isArray(value) ? value.join(", ") : String(value)}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ))}
            </div>
          </section>
          <section className="console-card p-5">
            <h2 className="section-label">Session state</h2>
            <div className="mt-4 space-y-3 text-xs">
              <div className="flex justify-between"><span className="text-zinc-600">Current ladder</span><LadderBadge state={currentState} /></div>
              <div className="flex justify-between"><span className="text-zinc-600">Session score</span><Mono className="text-zinc-400">{session?.score ?? incident.risk_score}</Mono></div>
              {currentState === "REVOKE" && <div className="flex items-center gap-1 text-red-400"><ShieldAlert size={13} /> token revoked</div>}
              {currentState === "NORMAL" && <div className="flex items-center gap-1 text-emerald-400"><ShieldCheck size={13} /> clear</div>}
              <div className="flex justify-between"><span className="text-zinc-600">Last updated</span><Mono className="text-zinc-400">{new Date(incident.updated_at).toLocaleTimeString()}</Mono></div>
            </div>
          </section>
          <section className="console-card p-5">
            <div className="flex items-start gap-3"><Info size={16} className="mt-0.5 text-indigo-300" /><p className="text-xs leading-5 text-zinc-500">Confidence is calculated by the detection engine from category diversity, prior signals, and anomaly strength.</p></div>
          </section>
        </aside>
      </div>
    </div>
  );
}

function Evidence({ incident }: { incident: IncidentDetail }) {
  return (
    <section className="console-card p-5">
      <h2 className="section-label">Evidence summary</h2>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        {incident.signals.map((signal) => (
          <div key={signal.id} className="border-l-2 border-indigo-400/60 pl-3">
            <p className="text-xs uppercase text-zinc-500">{signal.category}</p>
            <p className="mono mt-1 text-lg text-zinc-200">{signal.severity}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
