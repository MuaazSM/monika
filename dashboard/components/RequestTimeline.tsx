import type { RequestLogEntry } from "@/lib/types";
import { Mono } from "@/components/ui/Mono";

const TINTED_STATUSES = new Set([401, 403, 429]);

export function RequestTimeline({ entries }: { entries: RequestLogEntry[] }) {
  if (entries.length === 0) {
    return (
      <section className="console-card p-5">
        <h2 className="section-label">Request timeline</h2>
        <p className="mt-4 text-xs text-zinc-600">No requests recorded for this session yet.</p>
      </section>
    );
  }

  return (
    <section className="console-card p-5">
      <h2 className="section-label">
        Request timeline <span className="text-zinc-700">last {entries.length}</span>
      </h2>
      <div className="mt-4 max-h-80 overflow-y-auto overflow-x-auto">
        <table className="w-full min-w-[420px] text-left text-xs">
          <thead className="text-[10px] uppercase tracking-[0.08em] text-zinc-600">
            <tr>
              <th className="py-1.5 pr-3 font-medium">Time</th>
              <th className="py-1.5 pr-3 font-medium">Method / path</th>
              <th className="py-1.5 pr-3 font-medium">Status</th>
              <th className="py-1.5 font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {entries.map((entry) => {
              const tinted = TINTED_STATUSES.has(entry.status_code);
              return (
                <tr key={entry.request_id} className={tinted ? "bg-red-500/5" : undefined}>
                  <td className="py-1.5 pr-3">
                    <Mono className="text-zinc-500">
                      {new Date(entry.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </Mono>
                  </td>
                  <td className="py-1.5 pr-3">
                    <Mono className="text-zinc-300">
                      {entry.method} {entry.path}
                    </Mono>
                  </td>
                  <td className="py-1.5 pr-3">
                    <Mono className={tinted ? "text-red-400" : "text-zinc-400"}>{entry.status_code}</Mono>
                  </td>
                  <td className="py-1.5">
                    <span className={`risk-badge ${tinted ? "risk-critical" : "risk-safe"}`}>
                      {entry.action_applied}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
