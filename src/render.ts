// Human rendering of the verdict (B10 D65, §10.6): the same truth as the JSON
// verdict, in words a non-technical reader can act on. Wording follows the
// normative examples of B10 §10.6 as amended on 2026-07-09 (user decision):
// English is the single language of the human-readable output.
//
// D65/D82 amendment 2026-07-12 (audit F1): the verdict is a conjunction of
// THREE properties — integrity (chain + signatures), time (a confirmed,
// time-consistent Bitcoin anchor BOUND to this chain's head) and attribution
// (every event's signing key inside a trusted issuer set). `verified`
// (exit 0) now requires all three; the new `unattributed` outcome maps to
// the ADDITIVE exit code 6 — exit codes 0/2/3/4/5 keep their meaning.
import type { Verdict } from "./verify.ts";
import type { AnchorVerdict } from "./ots.ts";
import type { ChainSealVerdict } from "./tst_lite.ts";
import type { Attribution } from "./issuer.ts";
import type { ArtifactMatch } from "./find.ts";
import {
  ANCESTRY_NOTE,
  ANCESTRY_SEMANTICS,
  TRACE_DEPTH_CAP,
  TRACE_TARGET_CAP,
  type TraceEventRef,
  type TraceResult,
} from "./trace.ts";

export type OverallResult =
  | "verified"
  | "tampered"
  | "anchor_failed"
  | "malformed"
  | "partial"
  | "unattributed";

export type TimeStatus = "proven" | "unproven" | "failed";

export interface VerdictProperties {
  integrity: "ok" | "failed";
  time: TimeStatus;
  attribution: Attribution;
}

/**
 * Chain↔anchor binding (audit F1, M3.1): true iff at least one CONFIRMED,
 * Bitcoin-verified, time-consistent anchor carries — among the entries its
 * recomputed aggregate commits to — the pair (export tenant_id, event_hash
 * of the HEAD of the verified range). Without this, a genuine anchor stolen
 * from a real export "verifies" attached to any fabricated chain: every
 * anchor check would pass while proving nothing about THESE events.
 * The binding reads `anchor_entries_for_aggregate` (committed by the
 * aggregate the .ots attests), never the convenience `entry` field (not
 * committed by anything).
 *
 * W3 (audit 3, reclassified 2026-07-19): verdicts and source elements are
 * coupled BY INDEX — verifyAnchors emits exactly one verdict per element of
 * `exp.anchors`, in order (pinned by test). The previous code resolved the
 * source element with `exp.anchors.find(anchor_date === a.anchor_date)`, i.e.
 * the FIRST anchor of that date — which let an attacker plant a pending decoy
 * sharing the real anchor's date, whose entries name (this tenant, this head),
 * so a genuine STOLEN anchor that passed the preconditions borrowed the
 * decoy's entries and minted a false VERIFIED on a chain that was never
 * anchored. Reading `exp.anchors[i]` binds only the very element that passed
 * the preconditions. (shape.ts independently rejects duplicate anchor dates as
 * a form error, exit 4 — the two layers are defence in depth.)
 */
export function anchorBindsChainHead(
  // deno-lint-ignore no-explicit-any
  exp: any,
  chain: Verdict,
  anchors: AnchorVerdict[],
): boolean {
  if (chain.verified_through_sequence === null) return false;
  // The head is resolved BY SEQUENCE NUMBER — the one inference SPEC §8
  // rule 10 tells consumers not to make. It is sound only while the number
  // identifies exactly one event, so refuse to bind when it does not
  // (adversarial review 2026-08-02): shape.ts already rejects duplicate
  // sequence numbers, and a library caller that skipped it must not get a
  // time property resolved against an attacker-chosen twin.
  // deno-lint-ignore no-explicit-any
  const candidates = (exp.events ?? []).filter((e: any) =>
    e.sequence_number === chain.verified_through_sequence
  );
  if (candidates.length !== 1) return false;
  const headEvent = candidates[0];
  if (typeof headEvent?.event_hash !== "string") return false;
  const head = headEvent.event_hash.toLowerCase();
  const tenant = String(exp.tenant_id ?? "").toLowerCase();
  // deno-lint-ignore no-explicit-any
  const src = (exp.anchors ?? []) as any[];
  return anchors.some((a, i) => {
    if (
      a.ots_status !== "confirmed" || !a.aggregate_recomputed ||
      a.ots_commits_to_aggregate !== true || a.bitcoin_verified !== true ||
      a.time_consistent !== true
    ) return false;
    // The source element at THIS verdict's index — never a search by date.
    // The date-equality guard is a fail-safe assertion of the ordering
    // invariant (verifyAnchors preserves order): a mismatch means misalignment
    // and refuses to bind rather than risk binding the wrong element.
    const el = src[i];
    if (!el || el.anchor_date !== a.anchor_date) return false;
    // deno-lint-ignore no-explicit-any
    return (el.anchor_entries_for_aggregate ?? []).some((e: any) =>
      String(e?.tenant_id ?? "").toLowerCase() === tenant &&
      String(e?.last_event_hash ?? "").toLowerCase() === head
    );
  });
}

export function assess(
  // deno-lint-ignore no-explicit-any
  exp: any,
  chain: Verdict,
  anchors: AnchorVerdict[],
  attribution: Attribution,
): { result: OverallResult; exitCode: number; properties: VerdictProperties } {
  const integrityOk = chain.chain_continuous && chain.signatures_valid;
  const anchorFailed = anchors.some((a) =>
    !a.aggregate_recomputed ||
    a.ots_commits_to_aggregate === false ||
    a.bitcoin_verified === false ||
    // D64 amendment 2026-07-12 (audit F1, time leg): a real attestation
    // whose block time contradicts the declared anchor_date proves only
    // LATER existence — never the claimed day.
    a.time_consistent === false
  );
  const time: TimeStatus = anchorFailed
    ? "failed"
    : anchorBindsChainHead(exp, chain, anchors)
    ? "proven"
    : "unproven";
  const properties: VerdictProperties = {
    integrity: integrityOk ? "ok" : "failed",
    time,
    attribution,
  };

  if (!integrityOk) return { result: "tampered", exitCode: 2, properties };
  if (anchorFailed) return { result: "anchor_failed", exitCode: 3, properties };
  if (attribution !== "attributed") return { result: "unattributed", exitCode: 6, properties };
  // Declared-partial outcomes (D65 exit 5): range not anchored to genesis,
  // pending/manual anchors, or a confirmed anchor that does not cover this
  // chain's head — integrity and attribution hold, time is not (yet) proven.
  if (!chain.anchored_to_genesis || time !== "proven") {
    return { result: "partial", exitCode: 5, properties };
  }
  return { result: "verified", exitCode: 0, properties };
}

/**
 * W4 (audit 3): the Bitcoin block to show on the "[OK] Anchor" line. When the
 * explorer level has verified the attestation, its attested heights are known:
 * display the DECLARED block only if it is one of them, otherwise the minimum
 * ATTESTED height — a verifier must never present a self-declared, unverified
 * number as if the chain proved it. With no attested heights (trustless /
 * convenience / no verification) fall back to the declared value unchanged.
 */
function anchorBlockForDisplay(a: AnchorVerdict): number | null {
  const attested = a.ots_btc_blocks_attested;
  if (attested && attested.length > 0) {
    if (a.ots_btc_block !== null && attested.includes(a.ots_btc_block)) return a.ots_btc_block;
    return attested[0]; // ascending sort: the minimum attested height
  }
  return a.ots_btc_block;
}

function propertyLines(properties: VerdictProperties): string[] {
  const lines: string[] = ["Properties:"];
  lines.push(
    properties.integrity === "ok"
      ? "[OK] Integrity — hash chain continuous and signatures valid."
      : "[ERROR] Integrity — the chain or the signatures do not verify (see above).",
  );
  switch (properties.time) {
    case "proven":
      lines.push(
        "[OK] Time — a confirmed Bitcoin attestation, consistent with its declared date, covers this chain's head.",
      );
      break;
    case "unproven":
      lines.push(
        "[--] Time — not proven: no confirmed Bitcoin attestation covers this chain's head (see the anchor lines above).",
      );
      break;
    case "failed":
      lines.push("[ERROR] Time — a Bitcoin attestation fails verification (see above).");
      break;
  }
  switch (properties.attribution) {
    case "attributed":
      lines.push("[OK] Attribution — every event is signed by a key in the trusted issuer set.");
      break;
    case "not_checked":
      lines.push(
        "[--] Attribution — NOT CHECKED: no trusted issuer keys available. Pass --issuer <file|url> (or --pubkey <hex>): the keys INSIDE an export prove nothing about who wrote it.",
      );
      break;
    case "foreign_key":
      lines.push(
        "[ERROR] Attribution — at least one event is signed by a key OUTSIDE the trusted issuer set.",
      );
      break;
  }
  return lines;
}

export function renderHuman(
  tenantId: string,
  chain: Verdict,
  anchors: AnchorVerdict[],
  result: OverallResult,
  properties: VerdictProperties,
  // On-demand chain seals (D104, additive): [] ⇒ no line at all — an export
  // without the field renders byte-identically to pre-1.5.
  chainSeals: ChainSealVerdict[] = [],
): string {
  const lines: string[] = [];
  const eventCount =
    chain.verified_through_sequence !== null && chain.verified_from_sequence !== null
      ? chain.verified_through_sequence - chain.verified_from_sequence + 1
      : 0;
  lines.push("Humarch — Registry verification");
  lines.push(
    `Tenant ${terminalSafe([...String(tenantId)].slice(0, 8).join(""), 32)}…  ·  sequences ${
      chain.verified_from_sequence ?? "?"
    }–${chain.verified_through_sequence ?? "?"} (${eventCount} events)`,
  );
  lines.push("");

  if (chain.chain_continuous && chain.first_failure === null) {
    lines.push(
      chain.anchored_to_genesis
        ? "[OK] Hash chain continuous — every event is linked to the previous one, back to the genesis."
        : "[OK] Hash chain continuous within the range — the entry point is not the genesis: earlier events are not covered by this export (declared partial verification).",
    );
  } else if (chain.first_failure && !chain.signatures_valid) {
    lines.push(
      `[ERROR] Invalid signature at sequence ${chain.first_failure.sequence_number} (${chain.first_failure.kind}).`,
    );
  } else if (chain.first_failure) {
    lines.push(
      `[ERROR] Chain broken at sequence ${chain.first_failure.sequence_number} — ${chain.first_failure.detail}.`,
    );
  }

  if (chain.signatures_valid && chain.first_failure === null) {
    lines.push(
      `[OK] Digital signatures valid — ${eventCount} of ${eventCount} events correctly signed (Ed25519).`,
    );
  }

  for (const a of anchors) {
    if (a.ots_status === "pending") {
      lines.push(
        `[--] Anchor of ${a.anchor_date} — not yet stamped on Bitcoin (pending); aggregate hash ${
          a.aggregate_recomputed ? "recomputed correctly" : "NOT RECOMPUTABLE"
        }.`,
      );
    } else if (a.time_consistent === false) {
      lines.push(
        `[ERROR] Anchor of ${a.anchor_date} — the Bitcoin attestation is real but does not prove the declared day: ${
          displaySafe(a.note)
        }.`,
      );
    } else if (a.bitcoin_verified === true) {
      const block = anchorBlockForDisplay(a);
      lines.push(
        `[OK] Anchor of ${a.anchor_date} — recorded on Bitcoin${
          block !== null ? ` in block ${block}` : ""
        } (${displaySafe(a.note)}).`,
      );
    } else if (
      a.bitcoin_verified === false || !a.aggregate_recomputed ||
      a.ots_commits_to_aggregate === false
    ) {
      lines.push(
        `[ERROR] Anchor of ${a.anchor_date} — verification failed (${
          displaySafe(a.note || "invalid attestation")
        }).`,
      );
    } else {
      lines.push(`[--] Anchor of ${a.anchor_date} — ${displaySafe(a.note)}.`);
    }

    // Dual anchor (D98 (e)): one ADDITIVE line per anchor, always about the
    // day's AGGREGATE (never a single event), exit-neutral by design — an
    // invalid or untrusted token is an explicit warning, never a different
    // exit code (integrity/time/attribution stay decided above).
    const qt = a.qualified_timestamp;
    if (qt) {
      switch (qt.status) {
        case "absent":
          lines.push(`[--] Qualified timestamp of ${a.anchor_date} — absent.`);
          break;
        case "valid":
          // A late mark (re-timestamp, or a token that postdates the declared
          // day's window) stays genuine but must not read [OK] for the
          // declared day (review H1): the note carries the limitation.
          lines.push(
            `[${
              qt.gen_time_consistent === false ? "WARN" : "OK"
            }] Qualified timestamp of ${a.anchor_date} — ${displaySafe(qt.note)}.`,
          );
          break;
        case "untrusted":
          lines.push(`[WARN] Qualified timestamp of ${a.anchor_date} — ${displaySafe(qt.note)}.`);
          break;
        case "invalid":
          lines.push(
            `[WARN] Qualified timestamp of ${a.anchor_date} — invalid (${displaySafe(qt.note)}).`,
          );
          break;
      }
    }
  }

  // On-demand chain seals (D104, SPEC 1.5.0): one ADDITIVE line per seal,
  // always about the chain HEAD at its declared sequence (a chain PREFIX,
  // never a per-event mark), exit-neutral by design — an invalid or
  // untrusted token is an explicit warning, never a different exit code.
  for (const s of chainSeals) {
    const seq = typeof s.sequence_number === "number" && Number.isFinite(s.sequence_number)
      ? String(s.sequence_number)
      : "?";
    switch (s.status) {
      case "valid":
        // A seal whose genTime precedes the sealed event's reception proves
        // existence at its own genTime only — it must not read [OK].
        lines.push(
          `[${
            s.gen_time_consistent === false ? "WARN" : "OK"
          }] Chain seal at sequence ${seq} — ${displaySafe(s.note)}.`,
        );
        break;
      case "untrusted":
        lines.push(`[WARN] Chain seal at sequence ${seq} — ${displaySafe(s.note)}.`);
        break;
      case "invalid":
        lines.push(`[WARN] Chain seal at sequence ${seq} — invalid (${displaySafe(s.note)}).`);
        break;
    }
  }

  lines.push("");
  lines.push(...propertyLines(properties));

  lines.push("");
  switch (result) {
    case "verified":
      lines.push(
        "RESULT: VERIFIED. Integrity, Bitcoin time anchoring and issuer attribution all hold.",
      );
      break;
    case "partial":
      lines.push(
        "RESULT: DECLARED PARTIAL VERIFICATION. Chain and signatures valid; see the notes above for the remaining steps.",
      );
      break;
    case "tampered":
      lines.push(
        `RESULT: NOT VERIFIED. Tampering detected at sequence ${
          chain.first_failure?.sequence_number ?? "?"
        } (${chain.first_failure?.kind ?? "unknown"}).`,
      );
      break;
    case "anchor_failed":
      lines.push(
        "RESULT: ANCHOR NOT VERIFIED. Chain and signatures valid, but the Bitcoin attestation cannot be verified.",
      );
      break;
    case "unattributed":
      lines.push(
        "RESULT: NOT ATTRIBUTED. The chain is internally consistent, but nothing ties its signing keys to a trusted issuer — an internally consistent export can be fabricated by anyone with their own keys.",
      );
      break;
    case "malformed":
      lines.push("RESULT: INVALID INPUT. The file is not a readable humarch-export/v1 export.");
      break;
  }
  const confirmed = anchors.filter((a) => a.bitcoin_verified === true);
  if (confirmed.length > 0 && (result === "verified" || result === "partial")) {
    const last = confirmed[confirmed.length - 1];
    lines.push(
      `Note: the Bitcoin anchor covers events up to ${last.anchor_date}; later events are protected by the chain and the signatures.`,
    );
  }
  // D98 (g), binding semantics: the presumption claim names the AGGREGATE —
  // "every event has its own timestamp" is a FORBIDDEN formulation. Gated on
  // the overall result like the Bitcoin note above (adversarial review F1):
  // a tampered or unverified export never earns the presumption sentence.
  if (
    (result === "verified" || result === "partial") &&
    anchors.some((a) =>
      a.qualified_timestamp?.status === "valid" &&
      a.qualified_timestamp?.gen_time_consistent !== false
    )
  ) {
    lines.push(
      "Note: the qualified timestamp attaches the eIDAS art. 42 presumption to the daily aggregate; every event verifiably contained in it inherits that anteriority through deterministic, reproducible recomputation.",
    );
  }
  // D104 binding semantics, same gating discipline as the qualified note
  // (D98 (g)): the presumption claim names the chain HEAD — "every event has
  // its own timestamp" stays a FORBIDDEN formulation. A tampered or
  // unverified export never earns the sentence.
  if (
    (result === "verified" || result === "partial") &&
    chainSeals.some((s) => s.status === "valid" && s.gen_time_consistent !== false)
  ) {
    lines.push(
      "Note: the on-demand chain seal attaches the eIDAS art. 42 presumption to the chain head at sealing time; every prior event of the verified prefix inherits that anteriority through deterministic, reproducible recomputation.",
    );
  }
  return lines.join("\n");
}

/**
 * Terminal-safe rendering of an export-supplied machine value (external
 * audit 2026-08-02, finding 2).
 *
 * The shape gate refuses Cc/Cf/Zl/Zp in the fields it checks, but a public
 * renderer must not rest on a precondition its own signature does not
 * express: a direct caller can pass anything. The three fields rendered by
 * renderArtifactSearch are machine values (a UUID, an event-type token, an
 * ISO timestamp), printable ASCII by construction - everything else is
 * escaped to its code point, so a hostile export can neither drive the
 * terminal (V2) nor visually reorder the verdict with a bidi override.
 * Values are length-capped too: a megabyte-long identifier is not a
 * rendering a reader can act on.
 *
 * NOT strict enough for declared payload refs: printable ASCII composes
 * words and verdict look-alike lines (external audit 2026-08-03, F2). The
 * --trace surfaces MUST use refSafe below instead.
 */
export function terminalSafe(value: string, maxLength = 128): string {
  const clipped = value.length > maxLength ? value.slice(0, maxLength) + "..." : value;
  let out = "";
  for (const ch of clipped) {
    const cp = ch.codePointAt(0) as number;
    out += cp >= 0x20 && cp <= 0x7e
      ? ch
      : "<U+" + cp.toString(16).toUpperCase().padStart(4, "0") + ">";
  }
  return out;
}
/**
 * Ref-safe rendering of a DECLARED payload reference (external audit
 * 2026-08-03, F2 — reclassified High). terminalSafe neutralizes controls
 * and non-ASCII but passes every printable ASCII character through —
 * spaces, quotes, pipes and letters included — so a hostile ref could
 * compose words, a forbidden formulation and a verdict look-alike line
 * INSIDE the trace output: the wording discipline D101 hangs on was
 * breakable by data (seven of the nine end branches rendered it). Refs are
 * machine identifiers (Make/n8n execution ids, session ids, agent run
 * refs), so the allowed alphabet is what those actually need — letters,
 * digits and `. _ - : / + @ ~ =` — and EVERYTHING else (space, quote and
 * pipe included) escapes to `<U+XXXX>`: with the space escaped no phrase
 * can render, and with quote/pipe/newline escaped nothing breaks out of
 * its delimiter. Comparisons always happen on the raw values (D101): this
 * is display only. Idempotent by construction — an already-escaped
 * `<U+XXXX>` token passes through — so the trace layer and this renderer
 * both apply it: the second application is the direct-caller barrier.
 */
const REF_ALLOWED = /[0-9A-Za-z._\-:/+@~=]/;
const REF_ESCAPE_TOKEN = /^<U\+[0-9A-F]{4,6}>/;
export function refSafe(value: string, maxLength = 128): string {
  const clipped = value.length > maxLength ? value.slice(0, maxLength) + "..." : value;
  let out = "";
  for (let i = 0; i < clipped.length;) {
    const esc = REF_ESCAPE_TOKEN.exec(clipped.slice(i));
    if (esc) {
      out += esc[0];
      i += esc[0].length;
      continue;
    }
    const cp = clipped.codePointAt(i) as number;
    const ch = String.fromCodePoint(cp);
    out += REF_ALLOWED.test(ch) ? ch : "<U+" + cp.toString(16).toUpperCase().padStart(4, "0") + ">";
    i += ch.length;
  }
  return out;
}
/**
 * Display-safe rendering of a human-facing string that may legitimately
 * carry typography (the verifier's own middle dots and em dashes, a TSA's
 * accented name) but may also carry an export-supplied fragment.
 *
 * Escapes exactly what can drive or reorder a terminal - controls, format
 * characters (the bidi overrides and isolates among them), line and
 * paragraph separators - and caps the length. Strong-directional LETTERS
 * can still reorder a line visually; that is inherent to displaying a name
 * in a right-to-left script and cannot be neutralized without mangling
 * legitimate values, so it is accepted and bounded rather than pretended
 * away. For machine identifiers use terminalSafe instead: they are ASCII
 * by construction and deserve the stricter rule.
 */
export function displaySafe(value: string, maxLength = 200): string {
  const clipped = value.length > maxLength ? value.slice(0, maxLength) + "..." : value;
  return clipped.replace(
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
    (ch) => "<U+" + (ch.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, "0") + ">",
  );
}
/**
 * Value-preserving escaping of the characters JSON.stringify emits raw
 * (external audit 2026-08-02, finding 2). JSON.stringify escapes C0 inside
 * string literals, but leaves C1 (U+0080-U+009F), the format characters
 * (bidi overrides and isolates, zero-width joiners, the BOM) and the line
 * and paragraph separators untouched. The verdict goes to stdout, which is
 * a terminal as often as it is a pipe, so those characters must not travel
 * raw.
 *
 * Rewriting each as its uXXXX escape is value-preserving: JSON.parse of the
 * result is deep-equal to the object. The structural whitespace of a
 * pretty-printed document (LF, CR, TAB) is exempt — inside a string literal
 * stringify has already escaped those, so a raw one is always structure,
 * and escaping it would produce invalid JSON.
 */
export function jsonSafe(text: string): string {
  return text.replace(
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
    (ch) => {
      const cp = ch.codePointAt(0) as number;
      if (cp === 0x0a || cp === 0x0d || cp === 0x09) return ch; // structure
      // Supplementary code points escape as their surrogate PAIR (external
      // audit 2026-08-03, F6): `\u` + five hex digits is not a JSON escape,
      // so JSON.parse would read four digits plus a stray character and the
      // value would CHANGE — on a function whose contract is preservation.
      if (cp > 0xffff) {
        const c = cp - 0x10000;
        const hi = 0xd800 + (c >> 10);
        const lo = 0xdc00 + (c & 0x3ff);
        return "\\u" + hi.toString(16).padStart(4, "0") +
          "\\u" + lo.toString(16).padStart(4, "0");
      }
      return "\\u" + cp.toString(16).padStart(4, "0");
    },
  );
}

/**
 * Rendering of the --find-artifact search (D100, SPEC §1.2.5) — a SEPARATE
 * function on purpose: the verdict rendering above and assess() are the
 * normative surface and never learn about the search. Wording discipline:
 * "events DECLARING this hash" — a declaration is recorded evidence of the
 * declaration itself, never "verified"/"bound"/"proven". Only the
 * user-supplied hash (already validated 64-hex by the CLI) and fields the
 * shape gate checked (event_id, event_type, occurred_at) are interpolated:
 * payload text never reaches the terminal (V2).
 */
export function renderArtifactSearch(
  target: string,
  matches: ArtifactMatch[],
  verifiedFrom: number | null,
  verifiedThrough: number | null,
): string {
  const range = verifiedFrom !== null && verifiedThrough !== null
    ? `${Number(verifiedFrom)}-${Number(verifiedThrough)}`
    : "none";
  const lines: string[] = [];
  lines.push("");
  lines.push(`Artifact search — ${terminalSafe(target, 64)}`);
  lines.push(
    `[--] Found: ${matches.length} event${
      matches.length === 1 ? "" : "s"
    } declaring this hash (declared references only, SPEC 1.2.5 — nothing binds the artifact to the event).`,
  );
  for (const m of matches) {
    lines.push(
      `     sequence ${Number(m.sequence_number)} · ${terminalSafe(m.event_type, 48)} · event ${
        terminalSafe(m.event_id, 48)
      } · occurred ${terminalSafe(m.occurred_at, 32)} — ${
        m.within_verified_range
          ? `inside the verified range (${range})`
          : `OUTSIDE the verified range (${range}): integrity is not established for this event`
      }`,
    );
  }
  lines.push(
    'Note: encrypted payload.personal content is invisible to this search — "not found" does not mean "not there".',
  );
  return lines.join("\n");
}

/**
 * Rendering of the --trace declared-ancestry walk (D101) — a SEPARATE
 * function on purpose: the verdict rendering above and assess() are the
 * normative surface and never learn about the trace. Wording discipline: the
 * section opens with the pinned semantics sentence, hop granularity is
 * always named (exact event vs run-level), and the forbidden formulations
 * ("verified ancestry", causation talk) never render — pinned by test.
 *
 * Every interpolated value passes through refSafe here EVEN THOUGH trace.ts
 * already sanitizes refs: a public renderer must not rest on a precondition
 * its own signature does not express (the 2026-08-02 F2 remedy lesson, and
 * the 2026-08-03 F2 finding — terminalSafe let printable ASCII compose
 * phrases, so the ref sink needs the stricter identifier alphabet). refSafe
 * is idempotent on already-escaped values, so the double application is
 * harmless for genuine input and load-bearing for a direct caller's hostile
 * one. Event fields (event_id, event_type, received_at) go through the same
 * sink: genuine values (UUIDs, snake_case types, ISO timestamps) sit fully
 * inside the identifier alphabet and render byte-identically.
 */
export function renderAncestry(
  traces: TraceResult[],
  verifiedFrom: number | null,
  verifiedThrough: number | null,
): string {
  const range = verifiedFrom !== null && verifiedThrough !== null
    ? `${Number(verifiedFrom)}-${Number(verifiedThrough)}`
    : "none";
  const pos = (within: boolean): string =>
    within
      ? `inside the verified range (${range})`
      : `OUTSIDE the verified range (${range}): integrity is not established for this event`;
  const ref = (v: string | null): string => refSafe(v ?? "?", 72);
  const evLine = (e: TraceEventRef): string =>
    `event ${refSafe(e.event_id, 48)} · seq ${
      e.sequence_number === null ? "?" : Number(e.sequence_number)
    } · ${refSafe(e.event_type, 48)} · received ${refSafe(e.received_at, 32)} — ${
      pos(e.within_verified_range)
    }`;

  const lines: string[] = [];
  lines.push("");
  lines.push("Ancestry trace");
  lines.push(ANCESTRY_SEMANTICS);
  for (const t of traces) {
    lines.push("");
    if (t.end === "target_budget_reached") {
      // The declared-truncation discipline of the depth cap (external audit
      // 2026-08-03, F1): a surplus target is reported untraced, never
      // dropped in silence and never walked without bound.
      lines.push(
        `[--] Event ${
          refSafe(t.target, 48)
        } — not traced: the target budget of this invocation (${TRACE_TARGET_CAP} targets) was reached; trace it in a separate invocation.`,
      );
      continue;
    }
    if (!t.found_in_export) {
      lines.push(
        `[--] Event ${
          refSafe(t.target, 48)
        } — not present in this export: no ancestry can be assembled from this file (the event may lie outside the exported range).`,
      );
      continue;
    }
    const hops = Number(t.chain.length) - 1;
    lines.push(
      `[--] Event ${refSafe(t.target, 48)} — declared chain, ${hops} hop${hops === 1 ? "" : "s"}:`,
    );
    for (const node of t.chain) {
      if (node.kind === "event") {
        const head = node.hop === "start" ? "     " : "     ^ declared parent (exact event): ";
        if (node.repeated) {
          lines.push(
            `${head}event ${refSafe(node.event.event_id, 48)} — already shown above.`,
          );
          continue;
        }
        lines.push(head + evLine(node.event));
        const facts: string[] = [];
        if (node.execution_ref !== null) {
          facts.push(`declares execution run '${ref(node.execution_ref)}'`);
        }
        if (node.declared_root_ref !== null) {
          facts.push(`declared root run '${ref(node.declared_root_ref)}'`);
        }
        if (node.declared_depth !== null) {
          facts.push(`declared depth ${Number(node.declared_depth)}`);
        }
        if (facts.length > 0) lines.push(`       ${facts.join(" · ")}`);
      } else if (node.kind === "run") {
        // A membership hop is the traced event's OWN declared run; a run
        // hop is a declared PARENT run. Different words on purpose (D101):
        // the next declaration belongs to the run's events, and a run of N
        // events never pretends to be one event.
        const label = node.hop === "membership"
          ? `member of declared run '${ref(node.ref)}'`
          : `declared parent (run-level): run '${ref(node.ref)}'`;
        if (node.repeated) {
          lines.push(`     ^ ${label} — already shown above.`);
          continue;
        }
        const total = Number(node.events_total);
        lines.push(
          `     ^ ${label} — ${total} event${
            total === 1 ? "" : "s"
          } in this export declare this run (${
            Number(node.events_inside_verified_range)
          } inside the verified range (${range})):`,
        );
        for (const m of node.members.slice(0, 5)) lines.push(`         ${evLine(m)}`);
        if (total > 5) {
          lines.push(
            `         … and ${total - 5} more event${total - 5 === 1 ? "" : "s"} of this run`,
          );
        }
      } else {
        if (node.hop === "exact") {
          const alsoRun = node.declared_ref !== null
            ? ` (declared parent run '${ref(node.declared_ref)}')`
            : "";
          lines.push(
            `     ^ declared parent (exact event): event ${
              ref(node.declared_event_id)
            } — not present in this export${alsoRun}; the ancestor may lie outside the exported range — a declared reference that does not resolve is not tampering.`,
          );
        } else {
          lines.push(
            `     ^ declared parent (run-level): run '${
              ref(node.declared_ref)
            }' — no events in this export declare this run; the ancestor may lie outside the exported range — a declared reference that does not resolve is not tampering.`,
          );
        }
      }
    }
    switch (t.end) {
      case "root_of_declared_chain":
        lines.push("     end of the declared chain — no further ancestry declared.");
        break;
      case "parent_not_in_export":
        break; // the missing-link line above is the end statement
      case "cycle_declared":
        lines.push(
          "     cycle — the declarations close a loop back to a link already shown in this chain; the walk stops here.",
        );
        break;
      case "continues_above":
        lines.push("     the declared chain continues as already shown above.");
        break;
      case "depth_cap_reached":
        lines.push(
          `     depth cap (${TRACE_DEPTH_CAP} hops) reached — deeper declared ancestry is not shown.`,
        );
        break;
      case "ambiguous_parents": {
        const last = t.chain[t.chain.length - 1];
        const isRun = last !== undefined && last.kind === "run";
        const list = isRun && last.distinct_parent_refs.length > 0
          ? ` (e.g. ${last.distinct_parent_refs.map((r) => `'${ref(r)}'`).join(", ")})`
          : "";
        lines.push(
          `     the events of this run declare ${
            isRun ? Number(last.distinct_parent_count) : "several"
          } different parents${list} — the declared chain diverges here; the walk stops.`,
        );
        break;
      }
      case "malformed_declaration":
        lines.push(
          "     a delegation is declared but carries no usable parent identifier — the declared chain stops here.",
        );
        break;
      case "target_not_found":
        break; // rendered above
    }
  }
  lines.push("");
  lines.push(`Note: ${ANCESTRY_NOTE}.`);
  return lines.join("\n");
}
