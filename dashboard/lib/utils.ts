export { cn } from "cn";

import type { RiskBand } from "@/lib/types";

// README-documented score bands (§3): 0-29 safe, 30-59 suspicious, 60-79 high, 80-89
// critical, 90-100 severe. The engine only returns a raw score; banding is display-only.
export function scoreToBand(score: number): RiskBand {
  if (score >= 90) return "SEVERE";
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "SUSPICIOUS";
  return "SAFE";
}
