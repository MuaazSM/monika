import { cn } from "@/lib/utils";
import type { LadderState } from "@/lib/types";

const styles: Record<LadderState, string> = { NORMAL: "risk-safe", OBSERVE: "risk-safe", RATE_LIMIT: "risk-suspicious", CHALLENGE: "risk-high", BLOCK: "risk-critical", REVOKE: "risk-severe" };
export function LadderBadge({ state }: { state: LadderState }) { return <span className={cn("risk-badge", styles[state])}>{state.replace("_", " ")}</span>; }
