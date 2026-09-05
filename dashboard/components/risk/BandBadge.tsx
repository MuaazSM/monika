import { cn } from "@/lib/utils";
import type { RiskBand } from "@/lib/types";

const styles: Record<RiskBand, string> = { SAFE: "risk-safe", SUSPICIOUS: "risk-suspicious", HIGH: "risk-high", CRITICAL: "risk-critical", SEVERE: "risk-severe" };
export function BandBadge({ band }: { band: RiskBand }) { return <span className={cn("risk-badge", styles[band])}>{band}</span>; }
