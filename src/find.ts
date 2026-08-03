// humarch-verify/src/find.ts — the --find-artifact lexical search (D100,
// SPEC 1.4.0 §1.2.5). ADDITIVE module: the normative verification routine
// (verify.ts, D63) is untouched and never imports this file. The search is
// informative by design — it answers "which events DECLARE this hash?" and
// nothing else: no result of it may ever move the verdict, the exit code or
// the VerdictProperties (the --tsa-trust/D98 neutrality pattern).
//
// Safety properties (external audit 2026-08-02, findings 1 and 4):
//   * The verified prefix is POSITIONAL. verifyChain walks the events sorted
//     by sequence_number and stops at the first failure, so what it verified
//     is a prefix of that list — NOT "every event whose sequence_number is
//     ≤ verified_through". With a duplicated sequence number the two are
//     different sets, and the audit's reproduction had a tampered event
//     reported as inside the verified range. This module therefore walks the
//     same sorted list and marks by POSITION, stopping the prefix at the
//     first sequence that is not strictly greater than its predecessor. The
//     invariant this rests on is that find.ts and verify.ts sort the SAME
//     array with the SAME comparator (ascending sequence_number): keep them
//     in step. shape.ts rejects duplicates outright as a second, independent
//     layer, so on the CLI path the two readings cannot even diverge.
//   * The bounds are treated as a FAIL-SAFE pair: anything that is not a
//     finite number means "nothing is known to be verified", never "all of
//     it is".
//   * The walk is PURE, ITERATIVE and BOUNDED. Accessors are never invoked
//     (only data property descriptors are read) and a reflective operation
//     that throws never escapes — but a Proxy's ownKeys/getOwnPropertyDescriptor
//     traps ARE invoked and remain arbitrary code, and a generative Proxy can
//     mint children forever: the visited set stops cycles, and a hard node
//     budget stops everything else. Call this on JSON.parse output; on any
//     other object graph the budget is the only guarantee.
//   * NO PAYLOAD TEXT crosses this boundary — payload strings never pass
//     the anti-control-character gate (shape.ts covers identifiers only),
//     so the match report carries exclusively fields shape.ts already
//     checked (event_id, event_type, occurred_at) plus numbers. Echoing
//     payload values or paths here would reopen the V2 terminal-injection
//     hole.

const TARGET_RE = /^[0-9a-fA-F]{64}$/;

export interface ArtifactMatch {
  event_id: string;
  event_type: string;
  sequence_number: number;
  occurred_at: string;
  /** true iff the event belongs to the prefix verifyChain actually verified */
  within_verified_range: boolean;
}

export function isArtifactTarget(value: string): boolean {
  return TARGET_RE.test(value);
}

/**
 * Own enumerable DATA values of a container, defensively.
 *
 * Object.values() and array indexing invoke getters and Proxy traps: on a
 * hostile object graph that is arbitrary code running inside the verifier.
 * Reading descriptors and keeping only those that carry a `value` skips
 * accessors entirely (they are reported as absent, never called), and every
 * reflective step is inside the try — a Proxy whose ownKeys trap throws
 * yields "no children", never an exception escaping to a stack trace.
 */
/**
 * Own enumerable DATA property of a container, defensively (external audit
 * 2026-08-03, F3): accessors are treated as absent — never invoked — and a
 * reflective step that throws yields `undefined`, never an escaping
 * exception. The twin of the trace.ts helper, at the shared prefix boundary.
 */
function ownDataProp(container: unknown, key: string): unknown {
  if (typeof container !== "object" || container === null) return undefined;
  try {
    const d = Object.getOwnPropertyDescriptor(container, key);
    return d !== undefined && d.enumerable === true && "value" in d ? d.value : undefined;
  } catch {
    return undefined;
  }
}

function dataValues(container: object): unknown[] {
  const out: unknown[] = [];
  try {
    for (const key of Reflect.ownKeys(container)) {
      try {
        const d = Object.getOwnPropertyDescriptor(container, key);
        if (d !== undefined && d.enumerable === true && "value" in d) out.push(d.value);
      } catch {
        // one unreadable property never invalidates the others
      }
    }
  } catch {
    return [];
  }
  return out;
}

/**
 * Hard ceiling on the nodes one payload walk may visit. A 256 KB request body
 * (the ingestion limit) cannot approach it; a hostile generative Proxy would
 * otherwise run forever. Exhausting the budget ends the walk: the search is
 * best-effort by contract, and its output already declares that "not found"
 * does not mean "not there".
 */
const MAX_NODES = 2_000_000;

/** Case-insensitive equality of ANY payload string value with the target. */
function payloadDeclares(payload: unknown, targetLower: string): boolean {
  let budget = MAX_NODES;
  const stack: unknown[] = [payload];
  // Cycles are impossible in JSON.parse output but trivial for a direct
  // caller of this exported function (audit finding 4): without this set the
  // walk never terminates.
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    if (budget-- <= 0) return false; // bounded by construction
    const v = stack.pop();
    if (typeof v === "string") {
      if (v.length === 64 && v.toLowerCase() === targetLower) return true;
      continue;
    }
    if (typeof v !== "object" || v === null) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    // Values only, never keys: the convention recommends identifiers as
    // values, and keys are exactly where hostile text lives. Arrays need no
    // special case — their indices are own enumerable data properties, and
    // `length` is not enumerable.
    for (const child of dataValues(v)) stack.push(child);
  }
  return false;
}

/**
 * The export's events sorted by sequence number, with the length of the
 * positional prefix verifyChain can have verified: the leading run of
 * strictly increasing sequence numbers, cut at verified_through. Anything at
 * or past the first repetition (or gap beyond verified_through) is outside,
 * whatever its number says.
 *
 * Fail-safe: any bound that is not a finite number means nothing is known
 * to be verified (a `null`-only guard let `undefined` or NaN credit the
 * whole export - adversarial review of this remedy, 2026-08-02).
 *
 * Exported: the --trace ancestry walk (D101) positions its nodes against the
 * SAME sorted list and the SAME prefix — one implementation of the audit-F1
 * computation, never a re-derivation (user decision 2026-08-03).
 *
 * Descriptor-only at the shared boundary (external audit 2026-08-03, F3):
 * this function is part of the walk whose contract says hostile accessors
 * are never invoked, yet it read `exp.events` and each `sequence_number` as
 * plain property accesses — a getter ran arbitrary code and its throw
 * escaped. `events` and every element's `sequence_number` are now read as
 * own DATA properties, once, before the sort; the sort comparator sees only
 * the copied numbers (an accessor or unreadable value is NaN, which the
 * comparator treats exactly as the old code treated a non-number). A
 * non-array `events` yields the fail-safe empty result instead of a throw.
 * Genuine JSON.parse output sorts and measures byte-identically.
 */
export function verifiedPositionalPrefix(
  // deno-lint-ignore no-explicit-any
  exp: any,
  verifiedFrom: number | null,
  verifiedThrough: number | null,
  // deno-lint-ignore no-explicit-any
): { events: any[]; prefixLength: number } {
  const raw = ownDataProp(exp, "events");
  if (!Array.isArray(raw)) return { events: [], prefixLength: 0 };
  const decorated = raw.map((ev) => {
    const s = ownDataProp(ev, "sequence_number");
    return { ev, seq: typeof s === "number" ? s : NaN };
  });
  decorated.sort((a, b) => a.seq - b.seq);

  let prefixLength = 0;
  if (
    typeof verifiedFrom === "number" && Number.isFinite(verifiedFrom) &&
    typeof verifiedThrough === "number" && Number.isFinite(verifiedThrough)
  ) {
    let prev: number | null = null;
    for (const { seq } of decorated) {
      if (!Number.isFinite(seq)) break;
      if (prev !== null && seq <= prev) break; // duplicate or non-monotonic
      if (seq < verifiedFrom || seq > verifiedThrough) break;
      prev = seq;
      prefixLength++;
    }
  }
  return { events: decorated.map((d) => d.ev), prefixLength };
}

/**
 * Events of the export whose payload declares `target` (64 hex chars) as a
 * string value, in sequence order.
 *
 * `verifiedFrom`/`verifiedThrough` come from the chain verdict. A match is
 * `within_verified_range` only when it belongs to the positional prefix
 * verifyChain verified: a match beyond the point of rupture of a tampered
 * export — or in an export whose sequence numbering is not strictly
 * increasing — is reported, but never credited with integrity.
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
  const { events, prefixLength } = verifiedPositionalPrefix(exp, verifiedFrom, verifiedThrough);

  events.forEach((ev, index) => {
    if (!payloadDeclares(ev?.payload, targetLower)) return;
    matches.push({
      event_id: String(ev.event_id),
      event_type: String(ev.event_type),
      sequence_number: Number(ev.sequence_number),
      occurred_at: String(ev.occurred_at),
      within_verified_range: index < prefixLength,
    });
  });
  return matches;
}
