// OpenTimestamps verification at three trust levels (B10 D64, §10.5).
// Level used is ALWAYS declared in the output; the trustless gold standard
// (official opentimestamps-client + Bitcoin Core) is delegated, never faked.
//
// Note on the reader (D87, 2026-07-19): receipts are parsed and checked by
// the first-party ots_lite.ts (parseOts → digest + attestations,
// verifyBitcoinAttestations → verified block times via public explorers) —
// the npm OpenTimestamps library is no longer imported by this repo (its
// published tarball is AGPL and cannot be bundled into the MIT binaries).
// The reader's behavior is PINNED by the phase-2 interop test
// (tests/interop_ots.test.ts) against the official client on real fixtures.
// Interop finding, still true of the CORE's stamper (which keeps the
// library server-side): it serializes calendar URIs with a trailing slash,
// so `ots upgrade` on our receipts needs explicit -l whitelist flags; this
// reader is agnostic to that, and verification of confirmed files is
// unaffected.
import {
  DEFAULT_EXPLORER_DEPS,
  type ExplorerDeps,
  type OtsBitcoinAttestation,
  type OtsReceipt,
  parseOts,
  verifyBitcoinAttestations,
} from "./ots_lite.ts";
import {
  type ChainSealVerdict,
  EMBEDDED_TSA,
  type QualifiedTimestampVerdict,
  trustedTsaFingerprints,
  type TsaRegistry,
  verifyChainSeal,
  verifyQualifiedTimestamp,
} from "./tst_lite.ts";
import { verifiedPositionalPrefix } from "./find.ts";
import { aggregateHash, eventHash, jcsHash, toHex, type Verdict } from "./verify.ts";

const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export type OtsLevel = "explorer" | "trustless" | "convenience";

// Time-consistency window (D64 amendment 2026-07-12 — audit F1, time leg).
// A Bitcoin attestation proves the aggregate existed AT the block's time:
// without comparing that time to the DECLARED anchor_date, a fabricated
// export stamped today could claim any past date. Lower bound: a block
// timestamped before the anchored day even started cannot honestly commit
// to it (Bitcoin block timestamps drift ~2h; taken at 4h). Upper bound:
// stamping lands within hours (D18) and recovery retries within days; an
// attestation beyond the ceiling only proves LATER existence — exactly the
// fabrication pattern.
export const ANCHOR_TIME_SKEW_BEFORE_S = 4 * 3600;
export const ANCHOR_TIME_MAX_AFTER_S = 14 * 24 * 3600;

/** true iff a VERIFIED Bitcoin block time (unix seconds) is consistent with
 * the declared anchor_date (UTC day). */
export function anchorTimeConsistent(anchorDate: string, blockTimeS: number): boolean {
  const dayStartS = Date.parse(anchorDate + "T00:00:00Z") / 1000;
  if (!Number.isFinite(dayStartS)) return false;
  return blockTimeS >= dayStartS - ANCHOR_TIME_SKEW_BEFORE_S &&
    blockTimeS <= dayStartS + 86_400 + ANCHOR_TIME_MAX_AFTER_S;
}

export interface AnchorVerdict {
  anchor_date: string;
  ots_btc_block: number | null; // DECLARED by the export (attacker data until attested)
  ots_status: string;
  // W4 (audit 3): the block heights the parsed receipt actually attests
  // (explorer level, once bitcoin_verified); null otherwise. The declared
  // ots_btc_block above is only trustworthy when it is one of these.
  ots_btc_blocks_attested: number[] | null;
  aggregate_recomputed: boolean; // D9 formula reproduced (vector V4)
  ots_commits_to_aggregate: boolean | null; // the .ots stamps exactly aggregate_hash
  bitcoin_verified: boolean | null; // null = level requires external steps
  ots_btc_time: number | null; // earliest VERIFIED block time (unix s; explorer level)
  time_consistent: boolean | null; // block time vs anchor_date; null = no verified time
  level: OtsLevel;
  note: string;
  // Dual anchor (D98, additive): the qualified-timestamp leg of THIS DAY'S
  // AGGREGATE — never of a single event (the art. 42 presumption attaches to
  // the aggregate; events inherit anteriority by verifiable recomputation).
  // Exit-neutral by design: integrity/time/attribution stay decided above.
  // Optional so that pre-D98 verdict literals stay valid; verifyAnchors
  // always populates it (status "absent" when the export has no mark).
  qualified_timestamp?: QualifiedTimestampVerdict;
}

export async function verifyAnchors(
  exp: { anchors?: unknown[] },
  level: OtsLevel = "explorer",
  // Injectable explorer endpoints (EmailDeps pattern): production callers pass
  // nothing; tests exercise the explorer leg — including the W4 attested-block
  // check — offline against a local server. Additive: default = real network.
  deps: ExplorerDeps = DEFAULT_EXPLORER_DEPS,
  // Dual anchor (D98): trusted TSA registry (D82 pattern). Default = the
  // embedded set (empty until go-live ⇒ every valid token reads untrusted).
  tsaRegistry: TsaRegistry = EMBEDDED_TSA,
): Promise<AnchorVerdict[]> {
  const trustedFprs = trustedTsaFingerprints(tsaRegistry);
  const out: AnchorVerdict[] = [];
  // deno-lint-ignore no-explicit-any
  for (const a of (exp.anchors ?? []) as any[]) {
    // 1) aggregate_hash (D9) from anchor_entries_for_aggregate.
    const aggExpected = await aggregateHash(a.anchor_date, a.anchor_entries_for_aggregate ?? []);
    const aggregate_recomputed = aggExpected === a.aggregate_hash;

    let ots_commits_to_aggregate: boolean | null = null;
    let bitcoin_verified: boolean | null = null;
    let ots_btc_time: number | null = null;
    let time_consistent: boolean | null = null;
    let ots_btc_blocks_attested: number[] | null = null;
    let note = "";

    // W4 (audit 3): the DECLARED block is attacker data — coerce anything but
    // a finite number to null so a hostile value is never interpolated into
    // the terminal, and so it can be compared against the attested heights.
    const declaredBlock = typeof a.ots_btc_block === "number" && Number.isFinite(a.ots_btc_block)
      ? a.ots_btc_block
      : null;

    if (a.ots_status !== "pending" && a.ots_file_base64) {
      // 2) the .ots must be a detached timestamp of exactly aggregate_hash.
      // Trust-boundary discipline (audit F5): the receipt bytes are attacker
      // data — base64 that decodes fine may still not parse as an OTS file,
      // and the reader raises a typed error on any malformation, unsupported
      // construct or exceeded cap (D87). An unreadable receipt is a FAILED
      // verification (exit 3 at the CLI), never an uncaught crash.
      let receipt: OtsReceipt | null = null;
      try {
        receipt = parseOts(b64ToBytes(a.ots_file_base64));
        ots_commits_to_aggregate = toHex(receipt.digest) === a.aggregate_hash;
      } catch {
        ots_commits_to_aggregate = false;
        note = "unreadable .ots receipt (not a valid OpenTimestamps file)";
      }
      if (receipt !== null && ots_commits_to_aggregate === false) {
        note = "the .ots receipt does not commit to this aggregate_hash";
      }

      // 3) Bitcoin attestation, per level (confirmed anchors only).
      if (a.ots_status === "confirmed" && ots_commits_to_aggregate) {
        if (level === "explorer") {
          try {
            // The verified block times (unix s): one per attested height
            // whose merkle root AT LEAST ONE explorer confirms (semantics
            // pinned by the interop test; the leg itself never throws).
            const times = await verifyBitcoinAttestations(receipt as OtsReceipt, deps);
            bitcoin_verified = times.length > 0;
            if (bitcoin_verified) {
              ots_btc_time = Math.min(...times);
              time_consistent = anchorTimeConsistent(a.anchor_date, ots_btc_time);
              // W4: the block heights the receipt actually attests, from the
              // parsed tree (D87). The renderer trusts these, not the export's
              // self-declared ots_btc_block.
              ots_btc_blocks_attested = [
                ...new Set(
                  (receipt as OtsReceipt).attestations
                    .filter((at): at is OtsBitcoinAttestation => at.kind === "bitcoin")
                    .map((at) => at.height),
                ),
              ].sort((x, y) => x - y);
            }
          } catch {
            bitcoin_verified = false;
          }
          note = time_consistent === false
            ? `attested Bitcoin block time ${
              new Date((ots_btc_time as number) * 1000).toISOString()
            } is inconsistent with the declared anchor date ${a.anchor_date}`
            : bitcoin_verified && declaredBlock !== null && ots_btc_blocks_attested !== null &&
                !ots_btc_blocks_attested.includes(declaredBlock)
            // W4: the export declares a Bitcoin block the attestation does not
            // carry — say so, and the human line shows the attested height.
            ? `block-header verification via public explorers; declared block ${declaredBlock} is not among the attested block(s) ${
              ots_btc_blocks_attested.join(", ")
            }`
            : "block-header verification via public explorers";
        } else if (level === "trustless") {
          bitcoin_verified = null;
          note = `run: ots verify anchor-${a.anchor_date}.ots (official client + Bitcoin Core)`;
        } else {
          bitcoin_verified = null;
          note = "convenience check: upload the .ots to opentimestamps.org";
        }
      } else if (a.ots_status === "submitted" && ots_commits_to_aggregate) {
        note = "OTS receipt obtained, Bitcoin confirmation still pending (hours)";
      }
    } else if (a.ots_status !== "pending") {
      // A non-pending anchor without its receipt proves nothing: the verdict
      // stays honest (bitcoin_verified null ⇒ time unproven, never verified),
      // but the note must not claim "pending".
      note = `declared "${a.ots_status}" but the export carries no .ots receipt`;
    } else {
      note = "anchor not yet stamped (pending)";
    }

    // Dual anchor (D98 (e)): the qualified-timestamp leg — additive and
    // exit-neutral; an invalid/untrusted token becomes an explicit warning
    // line, never a different exit code. Bound to the RECOMPUTED aggregate
    // (adversarial review F1): the declared aggregate_hash is attacker data.
    // Defence in depth: the leg is typed-fail-safe by construction, but a
    // throw here must degrade to a declared invalid, never break the run.
    // Unreadable tokens are already handled INSIDE the call: whatever reaches
    // this catch failed later (e.g. WebCrypto refusing a malformed key), so
    // the note must not blame the parser (external audit, 2026-07-29).
    let qualified_timestamp;
    try {
      qualified_timestamp = await verifyQualifiedTimestamp(a, trustedFprs, aggExpected);
    } catch {
      qualified_timestamp = {
        status: "invalid" as const,
        matches_aggregate: null,
        signature_valid: null,
        trusted_tsa: null,
        gen_time_consistent: null,
        tsa_name: null,
        policy_oid: null,
        gen_time: null,
        note: "token verification failed unexpectedly",
      };
    }

    out.push({
      anchor_date: a.anchor_date,
      ots_btc_block: declaredBlock,
      ots_status: a.ots_status,
      ots_btc_blocks_attested,
      aggregate_recomputed,
      ots_commits_to_aggregate,
      bitcoin_verified,
      ots_btc_time,
      time_consistent,
      level,
      note,
      qualified_timestamp,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// On-demand chain seals (D104, SPEC 1.5.0 §7.2/§8 rule 12) — additive,
// exit-neutral: the verdicts below never touch result/exitCode/properties.
//
// A seal binds to the event hash RECOMPUTED from the D11 pre-image at its
// declared sequence, WITHIN the verified positional prefix (D100 rule 10:
// positions, never an interval of declared numbers) — the element's own
// fields and the event's declared `event_hash` are attacker data. A seal
// whose sequence the export does not contain, or that sits beyond the
// verified prefix, is a DECLARED invalid row: the chain up to it is not
// proven, so "every prior event inherits the anteriority" would not hold.
// ---------------------------------------------------------------------------
export async function verifyChainSeals(
  // deno-lint-ignore no-explicit-any
  exp: any,
  chain: Verdict,
  tsaRegistry: TsaRegistry = EMBEDDED_TSA,
): Promise<ChainSealVerdict[]> {
  const seals = exp?.chain_seals;
  const invalidRow = (sequence: number | null, note: string): ChainSealVerdict => ({
    sequence_number: sequence,
    status: "invalid",
    matches_head: null,
    signature_valid: null,
    trusted_tsa: null,
    gen_time_consistent: null,
    tsa_name: null,
    policy_oid: null,
    gen_time: null,
    note,
  });
  if (seals == null || (Array.isArray(seals) && seals.length === 0)) return [];
  // Library-caller symmetry (audit F4, 2026-08-05): a `chain_seals` that is
  // PRESENT but not an array gets ONE declared invalid row, never a silent
  // []. A malformed element inside an array already yields a declared row;
  // returning nothing for the malformed container broke that contract on
  // the public surface. (The CLI is unaffected: shape.ts refuses the
  // document with exit 4 before this runs.)
  if (!Array.isArray(seals)) {
    return [invalidRow(null, "chain_seals present but not an array")];
  }
  const trustedFprs = trustedTsaFingerprints(tsaRegistry);
  // The SAME sorted list and the SAME prefix computation the artifact search
  // and the trace walk use (audit-F1 single implementation, D101 decision).
  const { events, prefixLength } = verifiedPositionalPrefix(
    exp,
    chain.verified_from_sequence,
    chain.verified_through_sequence,
  );
  const out: ChainSealVerdict[] = [];
  // deno-lint-ignore no-explicit-any
  for (const seal of seals as any[]) {
    let sequence: number | null = null;
    // D98 (f) discipline, extended to the WHOLE row (lens-2 L1): index
    // resolution reads event objects that, for a direct library caller, may
    // carry hostile accessors — a throw anywhere in this row is a DECLARED
    // invalid, never a crash of the verifier. (The CLI shape-gates first,
    // so genuine JSON input never lands here.)
    let verdict: ChainSealVerdict;
    try {
      sequence = typeof seal?.sequence_number === "number" ? seal.sequence_number : null;
      const idx = sequence === null
        ? -1
        : events.findIndex((ev) => ev?.sequence_number === sequence);
      if (idx === -1) {
        out.push(invalidRow(
          sequence,
          "declared sequence not present in this export — the seal cannot be re-verified from it",
        ));
        continue;
      }
      if (idx >= prefixLength) {
        out.push(invalidRow(
          sequence,
          "declared sequence beyond the verified prefix — the chain up to it is not proven by this export",
        ));
        continue;
      }
      const ev = events[idx];
      // Recompute the sealed hash from the event's OWN pre-image parts (D11):
      // within the verified prefix the payload/actor/subject hashes and the
      // prev link were proven, so this recomputation is the chain's value —
      // never the declared `event_hash` field.
      const recomputed = await eventHash(
        ev,
        await jcsHash(ev.actor),
        await jcsHash(ev.subject),
        await jcsHash(ev.payload),
        ev.prev_hash,
      );
      verdict = await verifyChainSeal(
        seal,
        trustedFprs,
        recomputed,
        typeof ev.received_at === "string" ? ev.received_at : null,
      );
    } catch {
      verdict = invalidRow(sequence, "token verification failed unexpectedly");
    }
    out.push(verdict);
  }
  return out;
}
