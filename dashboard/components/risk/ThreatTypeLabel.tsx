import type { ThreatType } from "@/lib/types";

export function ThreatTypeLabel({ threatType }: { threatType: ThreatType }) {
  return <span className="font-medium text-zinc-200">{threatType.replaceAll("_", " ")}</span>;
}
