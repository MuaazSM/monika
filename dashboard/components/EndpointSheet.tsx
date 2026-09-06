"use client";

import { useState } from "react";
import { X } from "lucide-react";
import { api } from "@/lib/api";
import { useIncidentStore } from "@/lib/store";
import type { EndpointSummary } from "@/lib/types";
import { Mono } from "@/components/ui/Mono";

export function EndpointSheet({ endpoint, onClose }: { endpoint: EndpointSummary; onClose: () => void }) {
  const setEndpoint = useIncidentStore((state) => state.setEndpoint);
  const [ownerField, setOwnerField] = useState(endpoint.owner_field ?? "");
  const [sensitiveFields, setSensitiveFields] = useState(endpoint.sensitive_fields.join(", "));
  const [authRequired, setAuthRequired] = useState(endpoint.auth_required);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      const updated = await api.updateEndpoint(endpoint.id, {
        owner_field: ownerField.trim() || null,
        sensitive_fields: sensitiveFields
          .split(",")
          .map((field) => field.trim())
          .filter(Boolean),
        auth_required: authRequired,
      });
      setEndpoint(updated);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" role="dialog" aria-modal="true">
      <div className="h-full w-full max-w-sm overflow-y-auto border-l border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="eyebrow">Edit endpoint</p>
            <Mono className="mt-1 block text-sm text-zinc-200">
              {endpoint.method} {endpoint.path_pattern}
            </Mono>
          </div>
          <button type="button" onClick={onClose} className="text-zinc-500 hover:text-zinc-200" aria-label="Close">
            <X size={16} />
          </button>
        </div>

        <label htmlFor="sheet-owner-field" className="mt-6 block text-[11px] uppercase tracking-[0.08em] text-zinc-600">
          Owner field
        </label>
        <input
          id="sheet-owner-field"
          value={ownerField}
          onChange={(event) => setOwnerField(event.target.value)}
          placeholder="null (public resource)"
          className="mono mt-1 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-indigo-400/60"
        />
        <p className="mt-1 text-[11px] leading-4 text-zinc-600">
          Response JSON field that identifies the owner. Blank = public resource, D1 skips it.
        </p>

        <label htmlFor="sheet-sensitive-fields" className="mt-4 block text-[11px] uppercase tracking-[0.08em] text-zinc-600">
          Sensitive fields
        </label>
        <input
          id="sheet-sensitive-fields"
          value={sensitiveFields}
          onChange={(event) => setSensitiveFields(event.target.value)}
          placeholder="password_hash, ssn"
          className="mono mt-1 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-indigo-400/60"
        />
        <p className="mt-1 text-[11px] leading-4 text-zinc-600">
          Comma-separated keys. Any of these appearing in a 200 response body trips D4 exposure.
        </p>

        <label className="mt-4 flex items-center justify-between rounded-md bg-zinc-950/60 px-3 py-3 text-xs">
          <span className="text-zinc-400">Auth required</span>
          <input
            type="checkbox"
            checked={authRequired}
            onChange={(event) => setAuthRequired(event.target.checked)}
            className="size-4 accent-indigo-400"
          />
        </label>

        {error && <p className="mt-3 text-[11px] text-red-400">{error}</p>}

        <div className="mt-6 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="console-toggle">
            Cancel
          </button>
          <button
            type="button"
            onClick={save}
            disabled={saving}
            className="rounded-md border border-indigo-400/50 bg-indigo-400/10 px-3 py-1.5 text-xs text-indigo-300 hover:bg-indigo-400/20 disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>

        <div className="mt-8 border-t border-zinc-800 pt-4">
          <p className="section-label">Baseline</p>
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
            <div>
              <p className="text-zinc-600">rpm mean</p>
              <Mono className="text-zinc-300">{endpoint.baseline_rpm_mean.toFixed(1)}</Mono>
            </div>
            <div>
              <p className="text-zinc-600">rpm std</p>
              <Mono className="text-zinc-300">{endpoint.baseline_rpm_std.toFixed(1)}</Mono>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
