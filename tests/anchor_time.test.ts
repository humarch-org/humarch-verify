// Anchor time-consistency gate (D64 amendment 2026-07-12 — audit finding F1,
// time leg). An OTS attestation proves the aggregate existed AT the block's
// time; these tests pin the comparison against the DECLARED anchor_date that
// makes a today-stamped, backdated-claim export impossible to pass off.
// The block time itself is network-obtained (explorer level): the positive
// end-to-end case lives in the NET-gated interop tier; here everything is
// offline and deterministic. (assess calls updated 2026-07-12 with the D82
// three-property verdict: attribution + chain↔anchor binding.)
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  ANCHOR_TIME_MAX_AFTER_S,
  ANCHOR_TIME_SKEW_BEFORE_S,
  anchorTimeConsistent,
  type AnchorVerdict,
  verifyAnchors,
} from "../src/ots.ts";
import { assess, renderHuman } from "../src/render.ts";
import type { Verdict } from "../src/verify.ts";

const DAY = "2026-06-12";
const dayStartS = Date.parse(DAY + "T00:00:00Z") / 1000;

Deno.test("anchorTimeConsistent: window boundaries (skew before, ceiling after)", () => {
  // inside the anchored day
  assert(anchorTimeConsistent(DAY, dayStartS + 12 * 3600));
  // the day after (normal stamping: built at 00:05, confirmed in hours)
  assert(anchorTimeConsistent(DAY, dayStartS + 86_400 + 3 * 3600));
  // block timestamp slack before the day starts: tolerated up to the skew
  assert(anchorTimeConsistent(DAY, dayStartS - ANCHOR_TIME_SKEW_BEFORE_S));
  assert(!anchorTimeConsistent(DAY, dayStartS - ANCHOR_TIME_SKEW_BEFORE_S - 1));
  // late attestation: tolerated up to the ceiling after the day ends
  assert(anchorTimeConsistent(DAY, dayStartS + 86_400 + ANCHOR_TIME_MAX_AFTER_S));
  assert(!anchorTimeConsistent(DAY, dayStartS + 86_400 + ANCHOR_TIME_MAX_AFTER_S + 1));
  // the fabrication pattern: events claimed months ago, stamped now
  assert(!anchorTimeConsistent("2025-01-01", Date.parse("2026-07-12T00:00:00Z") / 1000));
  // garbage date never passes
  assert(!anchorTimeConsistent("not-a-date", dayStartS));
});

const TENANT = "0f4a1c2e-7b3d-4e5f-9a8b-6c5d4e3f2a1b";
const HEAD = "9ef4602bd82514c2880f221549b2ce6f71d88322c4ce15c7ed03d6e4ce230a03";

const okChain: Verdict = {
  chain_continuous: true,
  signatures_valid: true,
  anchored_to_genesis: true,
  verified_from_sequence: 1,
  verified_through_sequence: 2,
  first_failure: null,
};

// Export context bound to the anchor (D82: assess also proves the binding).
const boundExp = {
  tenant_id: TENANT,
  events: [
    { sequence_number: 1, event_hash: "aa".repeat(32) },
    { sequence_number: 2, event_hash: HEAD },
  ],
  anchors: [{
    anchor_date: DAY,
    anchor_entries_for_aggregate: [{ tenant_id: TENANT, last_event_hash: HEAD }],
  }],
};

function confirmedAnchor(over: Partial<AnchorVerdict>): AnchorVerdict {
  return {
    anchor_date: DAY,
    ots_status: "confirmed",
    ots_btc_block: 901245,
    ots_btc_blocks_attested: [901245],
    aggregate_recomputed: true,
    ots_commits_to_aggregate: true,
    bitcoin_verified: true,
    ots_btc_time: dayStartS + 86_400 + 3600,
    time_consistent: true,
    level: "explorer",
    note: "block-header verification via public explorers",
    ...over,
  };
}

Deno.test("assess: time_consistent=false degrades a real attestation to anchor_failed (exit 3)", () => {
  const good = assess(boundExp, okChain, [confirmedAnchor({})], "attributed");
  assertEquals(good.result, "verified");
  assertEquals(good.exitCode, 0);

  const stale = assess(boundExp, okChain, [
    confirmedAnchor({
      ots_btc_time: Date.parse("2026-07-12T00:00:00Z") / 1000,
      time_consistent: false,
      note:
        `attested Bitcoin block time 2026-07-12T00:00:00.000Z is inconsistent with the declared anchor date ${DAY}`,
    }),
  ], "attributed");
  assertEquals(stale.result, "anchor_failed");
  assertEquals(stale.exitCode, 3);
  assertEquals(stale.properties.time, "failed");

  // null (no verified time at this level) must NOT degrade: trustless and
  // convenience already answer partial through bitcoin_verified=null.
  const manual = assess(boundExp, okChain, [
    confirmedAnchor({
      bitcoin_verified: null,
      ots_btc_time: null,
      time_consistent: null,
      level: "trustless",
    }),
  ], "attributed");
  assertEquals(manual.result, "partial");
  assertEquals(manual.exitCode, 5);
  assertEquals(manual.properties.time, "unproven");
});

Deno.test("renderHuman: the time mismatch is named, RESULT is not VERIFIED", () => {
  const anchors = [
    confirmedAnchor({
      ots_btc_time: Date.parse("2026-07-12T00:00:00Z") / 1000,
      time_consistent: false,
      note:
        `attested Bitcoin block time 2026-07-12T00:00:00.000Z is inconsistent with the declared anchor date ${DAY}`,
    }),
  ];
  const { result, properties } = assess(boundExp, okChain, anchors, "attributed");
  const human = renderHuman(TENANT, okChain, anchors, result, properties);
  assertStringIncludes(human, "does not prove the declared day");
  assertStringIncludes(human, "inconsistent with the declared anchor date");
  assert(!human.includes("RESULT: VERIFIED."), human);
});

Deno.test("pending anchors: the time fields stay null; the verdict declares time unproven (partial)", async () => {
  const exp = JSON.parse(
    Deno.readTextFileSync(new URL("../vectors/export-v2v3.json", import.meta.url)),
  );
  const anchors = await verifyAnchors(exp);
  assertEquals(anchors[0].ots_btc_time, null);
  assertEquals(anchors[0].time_consistent, null);
  // D82 amendment 2026-07-12: a pending anchor no longer yields `verified` —
  // nothing is time-proven yet, and hiding that was exactly finding F1.
  const { result, exitCode, properties } = assess(exp, okChain, anchors, "attributed");
  assertEquals(result, "partial");
  assertEquals(exitCode, 5);
  assertEquals(properties.time, "unproven");
});

// ---------------------------------------------------------------------------
// BT-06 (2026-08-21) — `anchors` is an unsigned array the document's producer
// chooses freely. Deciding the verdict with `some()` over it handed anyone a
// denial of verification on anyone else's evidence: append one junk element
// and a genuine export answers exit 3. The mirror image of BT-01(a), where
// the same array was trusted in the other direction.
//
// The fix derives the time property from a BINDING anchor and keeps exit 3
// only where it is still the honest answer: nothing binds AND something
// failed. The test above ("time_consistent=false degrades a real attestation
// to anchor_failed") is the guard on that second half and must stay green.
// ---------------------------------------------------------------------------

const SECOND_DAY = "2026-06-13";

Deno.test("BT-06: a junk anchor appended to a genuine export cannot force exit 3", () => {
  const genuine = assess(boundExp, okChain, [confirmedAnchor({})], "attributed");
  assertEquals(genuine.result, "verified");
  assertEquals(genuine.exitCode, 0);

  // The cheapest possible edit: keep everything, append one element that
  // fails. No keys, no hashes, no understanding of the format required.
  const withDecoy = {
    ...boundExp,
    anchors: [
      ...boundExp.anchors,
      { anchor_date: SECOND_DAY, anchor_entries_for_aggregate: [] },
    ],
  };
  const attacked = assess(withDecoy, okChain, [
    confirmedAnchor({}),
    confirmedAnchor({
      anchor_date: SECOND_DAY,
      aggregate_recomputed: false,
      bitcoin_verified: false,
      time_consistent: false,
    }),
  ], "attributed");
  assertEquals(attacked.result, "verified", "the real anchor still binds this chain");
  assertEquals(attacked.exitCode, 0);
  assertEquals(attacked.properties.time, "proven");
});

Deno.test("BT-06: with nothing binding, a failing anchor still answers anchor_failed (exit 3)", () => {
  // The half that must NOT regress. Here the export carries no binding anchor
  // at all, and an element genuinely failed: exit 3 is the informative answer,
  // and letting it slide to exit 5 would hide a real evidentiary degradation
  // behind the milder "not yet proven".
  const unboundExp = {
    ...boundExp,
    anchors: [{
      anchor_date: DAY,
      anchor_entries_for_aggregate: [{
        tenant_id: TENANT,
        last_event_hash: "cc".repeat(32),
      }],
    }],
  };
  const out = assess(unboundExp, okChain, [
    confirmedAnchor({ bitcoin_verified: false, time_consistent: false }),
  ], "attributed");
  assertEquals(out.result, "anchor_failed");
  assertEquals(out.exitCode, 3);
  assertEquals(out.properties.time, "failed");
});

Deno.test("BT-06: an export with no anchors at all is still partial, never failed", () => {
  const out = assess({ ...boundExp, anchors: [] }, okChain, [], "attributed");
  assertEquals(out.result, "partial");
  assertEquals(out.exitCode, 5);
  assertEquals(out.properties.time, "unproven");
});

Deno.test("BT-07: a non-binding anchor prints no coverage note next to 'time not proven'", () => {
  // The output half of the same root. The note asserts COVERAGE — "the anchor
  // covers events up to D" — and used to be gated on bitcoin_verified alone,
  // which is a fact about the attestation, not about this chain. On a
  // fabricated chain carrying a genuine anchor the verdict printed
  // "[--] Time — not proven" AND the coverage note together, and a reader who
  // trusts prose over a property table is told the opposite of the finding.
  const liftedExp = {
    ...boundExp,
    anchors: [{
      anchor_date: DAY,
      anchor_entries_for_aggregate: [{
        tenant_id: TENANT,
        last_event_hash: "cc".repeat(32), // some other chain's head
      }],
    }],
  };
  const anchors = [confirmedAnchor({})];
  const out = assess(liftedExp, okChain, anchors, "attributed");
  assertEquals(out.properties.time, "unproven");
  assertEquals(out.result, "partial");

  const human = renderHuman(TENANT, okChain, anchors, out.result, out.properties);
  assertStringIncludes(human, "Time");
  assert(
    !human.includes("the Bitcoin anchor covers events up to"),
    "no coverage claim for an anchor that covers nothing of this export",
  );

  // ...and the note is still printed when the anchor really does bind.
  const bound = assess(boundExp, okChain, anchors, "attributed");
  const humanOk = renderHuman(TENANT, okChain, anchors, bound.result, bound.properties);
  assertStringIncludes(humanOk, "the Bitcoin anchor covers events up to");
});
