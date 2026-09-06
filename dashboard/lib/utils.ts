export { cn } from "cn";

import type { LadderState, RiskBand } from "@/lib/types";

// README-documented score bands (§3): 0-29 safe, 30-59 suspicious, 60-79 high, 80-89
// critical, 90-100 severe. The engine only returns a raw score; banding is display-only.
export function scoreToBand(score: number): RiskBand {
  if (score >= 90) return "SEVERE";
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "SUSPICIOUS";
  return "SAFE";
}

// Ladder ordinal (policy/ladder.py::LADDER_ORDER) — lets the UI compare rungs, e.g. to
// enable Unblock/Mark-false-positive only once a session is at RATE_LIMIT or worse.
const LADDER_ORDER: LadderState[] = ["NORMAL", "OBSERVE", "RATE_LIMIT", "CHALLENGE", "BLOCK", "REVOKE"];

export function ladderAtLeast(state: LadderState, floor: LadderState): boolean {
  return LADDER_ORDER.indexOf(state) >= LADDER_ORDER.indexOf(floor);
}
