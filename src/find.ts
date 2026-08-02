// humarch-verify/src/find.ts — the --find-artifact lexical search (D100,
// SPEC 1.4.0 §1.2.5). ADDITIVE module: the normative verification routine
// (verify.ts, D63) is untouched and never imports this file. The search is
// informative by design — it answers "which events DECLARE this hash?" and
// nothing else: no result of it may ever move the verdict, the exit code or
// the VerdictProperties (the --tsa-trust/D98 neutrality pattern).
//
// Two safety properties the CLI relies on:
//   * PURE, ITERATIVE walk — hostile payload nesting must exhaust neither
//     the stack nor the gate (same discipline as shape.ts checkFinite);
//   * NO PAYLOAD TEXT crosses this boundary — payload strings never pass
//     the anti-control-byte gate (shape.ts covers identifiers only), so the
//     match report carries exclusively fields shape.ts already checked
//     (event_id, event_type, occurred_at) plus numbers. Echoing payload
//     values or paths here would reopen the V2 terminal-injection hole.

const TARGET_RE = /^[0-9a-fA-F]{64}$/;

export interface ArtifactMatch {
  event_id: string;
  event_type: string;
  sequence_number: number;
  occurred_at: string;
  /** true iff the sequence falls inside [verified_from, verified_through] */
  within_verified_range: boolean;
}

export function isArtifactTarget(value: string): boolean {
  return TARGET_RE.test(value);
}

/** Case-insensitive equality of ANY payload string value with the target. */
function payloadDeclares(payload: unknown, targetLower: string): boolean {
  const stack: unknown[] = [payload];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === "string") {
      if (v.length === 64 && v.toLowerCase() === targetLower) return true;
    } else if (Array.isArray(v)) {
      for (const x of v) stack.push(x);
    } else if (typeof v === "object" && v !== null) {
      // Values only, never keys: identifiers are recommended as values by
      // the convention, and keys are exactly where hostile text lives.
      for (const x of Object.values(v)) stack.push(x);
    }
  }
  return false;
}

/**
 * Events of the export whose payload declares `target` (64 hex chars) as a
 * string value, in sequence order. `verifiedFrom`/`verifiedThrough` come
 * from the chain verdict: a match beyond the point of rupture of a tampered
 * export is reported, but marked outside the verified range — integrity
 * says nothing about it.
 */
export function findArtifact(
  // deno-lint-ignore no-explicit-any
  exp: any,
  target: string,
  verifiedFrom: number | null,
  verifiedThrough: number | null,
): ArtifactMatch[] {
  const targetLower = target.toLowerCase();
  const matches: ArtifactMatch[] = [];
  // deno-lint-ignore no-explicit-any
  const events = [...((exp?.events ?? []) as any[])]
    .sort((a, b) => a.sequence_number - b.sequence_number);
  for (const ev of events) {
    if (!payloadDeclares(ev?.payload, targetLower)) continue;
    matches.push({
      event_id: String(ev.event_id),
      event_type: String(ev.event_type),
      sequence_number: Number(ev.sequence_number),
      occurred_at: String(ev.occurred_at),
      within_verified_range: verifiedFrom !== null && verifiedThrough !== null &&
        Number(ev.sequence_number) >= verifiedFrom &&
        Number(ev.sequence_number) <= verifiedThrough,
    });
  }
  return matches;
}
