"use client";

import { Check, Loader2, RotateCcw, ShieldCheck, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { useIncidentStore } from "@/lib/store";

type ResetState = "idle" | "running" | "done" | "failed";

const LADDER = [
  ["Observe", "score >= 30"],
  ["Rate limit", "score >= 60"],
  ["Challenge", "score >= 80"],
  ["Block", "score >= 90"],
  ["Revoke", "score = 100"],
];

export default function SettingsPage() {
  const [resetState, setResetState] = useState<ResetState>("idle");
  const [summary, setSummary] = useState("");
  const hydrate = useIncidentStore((state) => state.hydrate);
  const explainerAvailable = useIncidentStore((state) => state.stats.explainer_available);
  const runtimeStatus: Array<[string, string, boolean]> = [
    ["Detection engine", "Protected", true],
    [
      "LLM explainer",
      explainerAvailable ? "Enabled after decision" : "Unavailable — no API key configured",
      explainerAvailable,
    ],
  ];

  const handleReset = async () => {
    setResetState("running");
    setSummary("");
    try {
      const result = await api.resetDemoData();
      // reset() bulk-deletes rows without publishing an SSE event (it isn't a per-request
      // detection outcome), so the store won't otherwise learn incidents/sessions were
      // cleared — re-hydrate it here from the now-empty REST snapshot.
      const [incidents, endpoints, stats] = await Promise.all([
        api.getIncidents(),
        api.getEndpoints(),
        api.getStats(),
      ]);
      hydrate({ incidents, endpoints, stats });
      setResetState("done");
      setSummary(
        `Cleared ${result.incidents_cleared} incident(s), ${result.signals_cleared} signal(s)` +
          (result.preserved_incidents > 0 ? ` — kept ${result.preserved_incidents} with an override on record.` : "."),
      );
    } catch (err) {
      setResetState("failed");
      setSummary(err instanceof Error ? err.message : "reset failed");
    }
  };

  return (
    <div className="space-y-6">
      <header><p className="eyebrow">System configuration</p><h1 className="page-title">Settings</h1></header>
      <div className="grid gap-3 lg:grid-cols-2">
        <section className="console-card p-5">
          <h2 className="text-sm font-medium text-zinc-200">Protection policy</h2>
          <div className="mt-5 divide-y divide-zinc-800">
            {LADDER.map(([name, value]) => (
              <div key={name} className="flex items-center justify-between py-3 text-xs"><span className="text-zinc-400">{name}</span><span className="mono text-zinc-600">{value}</span></div>
            ))}
          </div>
        </section>
        <section className="console-card p-5">
          <h2 className="text-sm font-medium text-zinc-200">Runtime status</h2>
          <div className="mt-5 space-y-3">
            {runtimeStatus.map(([name, value, okay]) => (
              <div key={name} className="flex items-center justify-between rounded-md bg-zinc-950/60 px-3 py-3 text-xs">
                <span className="text-zinc-400">{name}</span>
                <span className="flex items-center gap-2 text-zinc-500">{okay ? <Check size={14} className="text-emerald-400" /> : <span className="size-1.5 rounded-full bg-amber-400" />}{value}</span>
              </div>
            ))}
          </div>
        </section>
      </div>
      <section className="console-card flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck size={18} className="text-indigo-300" />
          <div>
            <h2 className="text-sm font-medium text-zinc-200">Demo data</h2>
            <p className="mt-1 text-xs text-zinc-600">
              Clears incidents, sessions, and detector state — keeps learned baselines. Overridden incidents and their audit trail are never deleted.
              For a full re-seed (including baselines), run <code className="mono">make reset</code> from the CLI.
            </p>
            {summary && (
              <p className={`mt-2 flex items-center gap-1.5 text-xs ${resetState === "failed" ? "text-red-400" : "text-emerald-400"}`}>
                {resetState === "failed" ? <TriangleAlert size={13} /> : <Check size={13} />}
                {summary}
              </p>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={handleReset}
          disabled={resetState === "running"}
          className="flex items-center gap-2 self-start rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300 hover:bg-red-500/20 disabled:opacity-50 sm:self-auto"
        >
          {resetState === "running" ? <Loader2 size={14} className="animate-spin" /> : <RotateCcw size={14} />}
          {resetState === "running" ? "Resetting…" : resetState === "failed" ? "Retry reset" : "Reset demo data"}
        </button>
      </section>
    </div>
  );
}
