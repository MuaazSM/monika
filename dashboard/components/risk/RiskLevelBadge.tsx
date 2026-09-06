import { cn } from "@/lib/utils";
import type { EndpointRiskLevel } from "@/lib/types";

// EndpointOut.risk_level (green/amber/red) is a coarser, 3-state signal than the 5-band
// incident score — kept separate rather than forced into RiskBand.
const styles: Record<EndpointRiskLevel, string> = { green: "risk-safe", amber: "risk-suspicious", red: "risk-critical" };

export function RiskLevelBadge({ level }: { level: EndpointRiskLevel }) {
  return <span className={cn("risk-badge", styles[level])}>{level}</span>;
}
