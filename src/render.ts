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
import type { Attribution } from "./issuer.ts";

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
  // deno-lint-ignore no-explicit-any
  const headEvent = (exp.events ?? []).find((e: any) =>
    e.sequence_number === chain.verified_through_sequence
  );
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
): string {
  const lines: string[] = [];
  const eventCount =
    chain.verified_through_sequence !== null && chain.verified_from_sequence !== null
      ? chain.verified_through_sequence - chain.verified_from_sequence + 1
      : 0;
  lines.push("Humarch — Registry verification");
  lines.push(
    `Tenant ${tenantId.slice(0, 8)}…  ·  sequences ${chain.verified_from_sequence ?? "?"}–${
      chain.verified_through_sequence ?? "?"
    } (${eventCount} events)`,
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
        `[ERROR] Anchor of ${a.anchor_date} — the Bitcoin attestation is real but does not prove the declared day: ${a.note}.`,
      );
    } else if (a.bitcoin_verified === true) {
      const block = anchorBlockForDisplay(a);
      lines.push(
        `[OK] Anchor of ${a.anchor_date} — recorded on Bitcoin${
          block !== null ? ` in block ${block}` : ""
        } (${a.note}).`,
      );
    } else if (
      a.bitcoin_verified === false || !a.aggregate_recomputed ||
      a.ots_commits_to_aggregate === false
    ) {
      lines.push(
        `[ERROR] Anchor of ${a.anchor_date} — verification failed (${
          a.note || "invalid attestation"
        }).`,
      );
    } else {
      lines.push(`[--] Anchor of ${a.anchor_date} — ${a.note}.`);
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
          lines.push(`[OK] Qualified timestamp of ${a.anchor_date} — ${qt.note}.`);
          break;
        case "untrusted":
          lines.push(
            `[WARN] Qualified timestamp of ${a.anchor_date} — valid token, untrusted TSA, no presumption.`,
          );
          break;
        case "invalid":
          lines.push(
            `[WARN] Qualified timestamp of ${a.anchor_date} — invalid (${qt.note}).`,
          );
          break;
      }
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
  // "every event has its own timestamp" is a FORBIDDEN formulation.
  if (anchors.some((a) => a.qualified_timestamp?.status === "valid")) {
    lines.push(
      "Note: the qualified timestamp attaches the eIDAS art. 42 presumption to the daily aggregate; every event verifiably contained in it inherits that anteriority through deterministic, reproducible recomputation.",
    );
  }
  return lines.join("\n");
}
