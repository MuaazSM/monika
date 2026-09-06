"use client";

import { useState } from "react";
import { Check, ShieldAlert, ShieldOff, Siren } from "lucide-react";
import { api } from "@/lib/api";
import { useIncidentStore } from "@/lib/store";
import { ladderAtLeast } from "@/lib/utils";
import type { IncidentDetail, LadderState, Override } from "@/lib/types";

type Action = Override["action"];

const ACTIONS: Array<{ action: Action; label: string; icon: typeof Check; confirm: string }> = [
  {
    action: "acknowledge",
    label: "Acknowledge",
    icon: Check,
    confirm: "Marks this incident as reviewed. No change to the session's ladder state.",
  },
  {
    action: "unblock",
    label: "Unblock",
    icon: ShieldOff,
    confirm:
      "This will remove the token from the denylist and reset the session to NORMAL. The incident stays on record as overridden.",
  },
  {
    action: "false_positive",
    label: "Mark false positive",
    icon: ShieldAlert,
    confirm:
      "This will remove the token from the denylist and reset the session to NORMAL. The incident stays on record as overridden.",
  },
  {
    action: "force_block",
    label: "Force block",
    icon: Siren,
    confirm: "Forces this session straight to BLOCK, even if the engine hasn't escalated it there.",
  },
];

// Implementation-Frontend.md Phase 4: enablement by ladder state.
function isEnabled(action: Action, ladder: LadderState): boolean {
  if (action === "unblock" || action === "false_positive") return ladderAtLeast(ladder, "RATE_LIMIT");
  if (action === "force_block") return !ladderAtLeast(ladder, "BLOCK");
  return true; // acknowledge is always enabled
}

export function OverridePanel({ incident, ladder }: { incident: IncidentDetail; ladder: LadderState }) {
  const applyIncidentDetail = useIncidentStore((state) => state.applyIncidentDetail);
  const lastAnalyst = useIncidentStore((state) => state.lastAnalyst);
  const setLastAnalyst = useIncidentStore((state) => state.setLastAnalyst);
  const [open, setOpen] = useState<Action | null>(null);
  const [reason, setReason] = useState("");
  const [analyst, setAnalyst] = useState(lastAnalyst);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");

  const openDialog = (action: Action) => {
    setOpen(action);
    setReason("");
    setAnalyst(lastAnalyst);
    setError("");
  };

  const submit = async () => {
    if (!open) return;
    if (!reason.trim() || !analyst.trim()) {
      setError("Reason and analyst name are both required.");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      const detail = await api.overrideIncident(incident.id, {
        action: open,
        reason: reason.trim(),
        analyst: analyst.trim(),
      });
      applyIncidentDetail(detail);
      setLastAnalyst(analyst.trim());
      const applied = open;
      setOpen(null);
      setToast(
        applied === "unblock" || applied === "false_positive"
          ? "Session cleared. Next request will be allowed."
          : applied === "force_block"
            ? "Session forced to BLOCK."
            : "Incident acknowledged.",
      );
      setTimeout(() => setToast(""), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "override failed");
    } finally {
      setSubmitting(false);
    }
  };

  const active = ACTIONS.find((a) => a.action === open);

  return (
    <section className="console-card p-5">
      <h2 className="section-label">Analyst actions</h2>
      <div className="mt-4 grid grid-cols-2 gap-2">
        {ACTIONS.map(({ action, label, icon: Icon }) => (
          <button
            key={action}
            type="button"
            disabled={!isEnabled(action, ladder)}
            onClick={() => openDialog(action)}
            className="flex items-center justify-center gap-2 rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2 text-xs text-zinc-300 transition-colors hover:border-indigo-400/50 hover:text-indigo-300 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-zinc-800 disabled:hover:text-zinc-300"
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>
      {toast && (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400">
          <Check size={13} />
          {toast}
        </p>
      )}

      {active && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
          aria-label={active.label}
        >
          <div className="console-card w-full max-w-sm bg-zinc-900 p-5">
            <h3 className="text-sm font-medium text-zinc-100">{active.label}</h3>
            <p className="mt-2 text-xs leading-5 text-zinc-500">{active.confirm}</p>
            <label htmlFor="override-reason" className="mt-4 block text-[11px] uppercase tracking-[0.08em] text-zinc-600">
              Reason
            </label>
            <textarea
              id="override-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={2}
              className="mt-1 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-indigo-400/60"
              placeholder="One line explaining this decision"
            />
            <label htmlFor="override-analyst" className="mt-3 block text-[11px] uppercase tracking-[0.08em] text-zinc-600">
              Analyst
            </label>
            <input
              id="override-analyst"
              value={analyst}
              onChange={(event) => setAnalyst(event.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-indigo-400/60"
              placeholder="Your name"
            />
            {error && <p className="mt-2 text-[11px] text-red-400">{error}</p>}
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => setOpen(null)} className="console-toggle">
                Cancel
              </button>
              <button
                type="button"
                onClick={submit}
                disabled={submitting}
                className="rounded-md border border-indigo-400/50 bg-indigo-400/10 px-3 py-1.5 text-xs text-indigo-300 hover:bg-indigo-400/20 disabled:opacity-50"
              >
                {submitting ? "Applying…" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
