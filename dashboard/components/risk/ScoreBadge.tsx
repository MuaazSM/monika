import { cn } from "@/lib/utils";
import type { RiskBand } from "@/lib/types";

const bandStyles: Record<RiskBand, string> = { SAFE: "risk-safe", SUSPICIOUS: "risk-suspicious", HIGH: "risk-high", CRITICAL: "risk-critical", SEVERE: "risk-severe" };

export function ScoreBadge({ score, band }: { score: number; band?: RiskBand }) {
  const resolvedBand = band ?? (score >= 90 ? "SEVERE" : score >= 70 ? "CRITICAL" : score >= 45 ? "HIGH" : score >= 20 ? "SUSPICIOUS" : "SAFE");
  return <span className={cn("risk-badge mono", bandStyles[resolvedBand])}>{score}<span className="ml-1 text-[10px]">{resolvedBand}</span></span>;
}
