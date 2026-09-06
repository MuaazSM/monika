import type { SseEvent } from "@/lib/types";

// Matches monika/app/incidents/sse.py::EVENT_TYPES (CLAUDE.md §7).
const EVENT_TYPES = [
  "incident.created",
  "incident.updated",
  "incident.explained",
  "session.changed",
  "stats.tick",
] as const satisfies readonly SseEvent["type"][];

/**
 * Opens /_monika/events and forwards every frame to `onEvent`. The browser's EventSource
 * reconnects on its own after a drop, so no retry loop is needed here. Returns a cleanup
 * function that closes the connection.
 */
export function connectToStream(baseUrl: string, onEvent: (event: SseEvent) => void): () => void {
  const source = new EventSource(`${baseUrl}/_monika/events`);
  const listeners = EVENT_TYPES.map((type) => {
    const listener = (message: MessageEvent<string>) => {
      try {
        onEvent({ type, payload: JSON.parse(message.data) } as SseEvent);
      } catch {
        // Malformed frame: drop it, the next event resyncs state.
      }
    };
    source.addEventListener(type, listener);
    return { type, listener };
  });

  return () => {
    for (const { type, listener } of listeners) source.removeEventListener(type, listener);
    source.close();
  };
}
