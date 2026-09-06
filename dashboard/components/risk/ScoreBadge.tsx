import { cn, scoreToBand } from "@/lib/utils";
import type { RiskBand } from "@/lib/types";

const bandStyles: Record<RiskBand, string> = { SAFE: "risk-safe", SUSPICIOUS: "risk-suspicious", HIGH: "risk-high", CRITICAL: "risk-critical", SEVERE: "risk-severe" };

export function ScoreBadge({ score }: { score: number }) {
  const band = scoreToBand(score);
  return <span className={cn("risk-badge mono", bandStyles[band])}>{score}<span className="ml-1 text-[10px]">{band}</span></span>;
}
