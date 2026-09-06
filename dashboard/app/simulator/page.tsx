"use client";

import { AlertTriangle, CheckCircle2, Play, Radio, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, usingFixtures } from "@/lib/api";
import type { SimulationStatus } from "@/lib/types";

const scenarios = [
  ["idor", "BOLA enumeration", "Sequential object access against another user's records.", "D1 + D2 + D3 -> BOLA_ENUMERATION >= 90"],
  ["stuffing", "Credential stuffing", "Repeated login failures across distinct usernames.", "D3 -> CREDENTIAL_STUFFING >= 75"],
  ["sqli", "SQL injection", "Tautology payloads sent to the search endpoint.", "D4 -> SQL_INJECTION >= 60"],
  ["scrape", "Sensitive scrape", "High-volume product reads expose configured fields.", "D2 + D4 -> DATA_EXPOSURE >= 70"],
  ["admin", "Function abuse", "A non-admin token probes the admin surface.", "D1 -> FUNCTION_LEVEL_AUTH >= 70"],
  ["benign", "Benign burst", "Normal traffic control with no expected incident.", "No incident expected"],
] as const;

const POLL_MS = 500;

export default function SimulatorPage() {
  const [running, setRunning] = useState<string | null>(null);
  const [status, setStatus] = useState<Record<string, SimulationStatus>>({});
  const [error, setError] = useState<Record<string, string>>({});
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => { if (pollTimer.current) clearTimeout(pollTimer.current); }, []);

  const run = useCallback(async (scenario: string) => {
    setError((prev) => ({ ...prev, [scenario]: "" }));
    setRunning(scenario);
    setStatus((prev) => ({ ...prev, [scenario]: "running" }));
    try {
      const started = await api.startSimulation(scenario);
      const poll = async () => {
        const result = await api.getSimulationStatus(started.run_id);
        if (result.status === "running") {
          pollTimer.current = setTimeout(poll, POLL_MS);
          return;
        }
        setStatus((prev) => ({ ...prev, [scenario]: result.status }));
        setRunning(null);
      };
      await poll();
    } catch (err) {
      setStatus((prev) => ({ ...prev, [scenario]: "failed" }));
      setError((prev) => ({ ...prev, [scenario]: err instanceof Error ? err.message : "failed to start" }));
      setRunning(null);
    }
  }, []);

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div><p className="eyebrow">Traffic lab</p><h1 className="page-title">Simulator</h1></div>
        <span className="mono text-xs text-zinc-600">{usingFixtures ? "FIXTURE MODE" : "LIVE — hits the real proxy"}</span>
      </header>
      <div className="console-card border-indigo-400/20 bg-indigo-400/3 p-4">
        <div className="flex items-center gap-3">
          <Radio size={17} className="text-indigo-300" />
          <div>
            <p className="text-sm text-zinc-200">Run a controlled scenario</p>
            <p className="text-xs text-zinc-500">
              {usingFixtures
                ? "Fixture mode simulates the round trip without a backend."
                : "Drives real traffic through Monika's proxy via POST /_monika/simulate — only one scenario runs at a time."}
            </p>
          </div>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {scenarios.map(([id, name, description, expected]) => {
          const state = status[id];
          const isRunning = state === "running";
          const errorMessage = error[id];
          return (
            <article key={id} className="console-card flex min-h-48 flex-col p-4">
              <div className="flex items-start justify-between gap-3">
                <h2 className="font-medium text-zinc-200">{name}</h2>
                {state === "done" && <CheckCircle2 size={16} className="text-emerald-400" />}
                {state === "failed" && <AlertTriangle size={16} className="text-red-400" />}
              </div>
              <p className="mt-2 text-xs leading-5 text-zinc-500">{description}</p>
              <p className="mono mt-4 text-[11px] leading-4 text-zinc-600">Expected: {expected}</p>
              {errorMessage && <p className="mt-2 text-[11px] text-red-400">{errorMessage}</p>}
              <button
                type="button"
                onClick={() => run(id)}
                disabled={running !== null}
                className="mt-auto flex items-center justify-center gap-2 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs text-zinc-300 hover:border-indigo-400/50 hover:text-indigo-300 disabled:opacity-50"
              >
                {isRunning ? <RotateCcw size={14} className="animate-spin" /> : <Play size={14} />}
                {isRunning ? "Running" : state === "done" ? "Run again" : state === "failed" ? "Retry" : "Run scenario"}
              </button>
            </article>
          );
        })}
      </div>
    </div>
  );
}
