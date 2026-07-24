// Attribution + chain↔anchor binding gate (B10 D82, audit F1; M3 of the
// remediation plan, 2026-07-12). Unit level, fully offline: the subprocess
// CLI cases live in cli.test.ts, the network exit-0 end-to-end in the
// NET-gated tier of interop_ots.test.ts.
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  attributeEvents,
  EMBEDDED_ISSUER,
  type IssuerRegistry,
  issuerShapeProblems,
  trustedKeyBytes,
} from "../src/issuer.ts";
import { anchorBindsChainHead, assess, renderHuman } from "../src/render.ts";
import { type Verdict, verifyChain } from "../src/verify.ts";
import type { AnchorVerdict } from "../src/ots.ts";
import { FORGED_TENANT, forgeExport } from "./forge_helper.ts";

const RFC8032_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const goldenPath = new URL("../vectors/export-v2v3.json", import.meta.url);
const golden = () => JSON.parse(Deno.readTextFileSync(goldenPath));
const issuerVector = () =>
  JSON.parse(
    Deno.readTextFileSync(new URL("../vectors/issuer-vector.json", import.meta.url)),
  ) as IssuerRegistry;

// ---------------------------------------------------------------------------
// Registry document (humarch-keys/v1)
// ---------------------------------------------------------------------------
Deno.test("issuer registry: the vectors' trusted set is well-formed and carries the RFC 8032 key", () => {
  const reg = issuerVector();
  assertEquals(issuerShapeProblems(reg), []);
  assert(trustedKeyBytes(reg).has(RFC8032_KEY));
});

Deno.test("issuer registry: malformed documents are named, never thrown", () => {
  assert(issuerShapeProblems(null).length > 0);
  assert(issuerShapeProblems([]).length > 0);
  assert(issuerShapeProblems({ format: "something-else", keys: [] }).length > 0);
  assert(issuerShapeProblems({ format: "humarch-keys/v1", keys: "nope" }).length > 0);
  assert(
    issuerShapeProblems({ format: "humarch-keys/v1", keys: [{ public_key: "beef" }] }).length > 0,
  );
  assert(
    issuerShapeProblems({
      format: "humarch-keys/v1",
      keys: [{ public_key: RFC8032_KEY, algorithm: "rsa" }],
    }).length > 0,
  );
  assertEquals(issuerShapeProblems({ format: "humarch-keys/v1", keys: [] }), []);
});

Deno.test("trustedKeyBytes: byte identity is case-insensitive (lowercase-normalized hex)", () => {
  const set = trustedKeyBytes({
    format: "humarch-keys/v1",
    keys: [{ public_key: RFC8032_KEY.toUpperCase() }],
  });
  assert(set.has(RFC8032_KEY));
});

// ---------------------------------------------------------------------------
// M3.6 guardian: the RFC 8032 key (private seed PUBLISHED in the RFC) must
// never become a default-trusted key. Written to keep holding after go-live,
// when EMBEDDED_ISSUER is populated with the production key.
// ---------------------------------------------------------------------------
Deno.test("guardian: the RFC 8032 test key is NEVER in the embedded issuer registry", () => {
  assertEquals(issuerShapeProblems(EMBEDDED_ISSUER), []);
  assert(!trustedKeyBytes(EMBEDDED_ISSUER).has(RFC8032_KEY));
});

Deno.test("embedded issuer: still empty pre-go-live ⇒ bare invocations are not_checked", () => {
  assertEquals(attributeEvents(golden(), trustedKeyBytes(EMBEDDED_ISSUER)), "not_checked");
});

// ---------------------------------------------------------------------------
// Per-event, byte-level attribution (the F1 fix)
// ---------------------------------------------------------------------------
Deno.test("attribution: genuine export against its issuer set → attributed", () => {
  assertEquals(attributeEvents(golden(), trustedKeyBytes(issuerVector())), "attributed");
});

Deno.test("attribution: forged chain is internally consistent, only attribution rejects it", async () => {
  const forged = await forgeExport();
  const chain = await verifyChain(forged);
  assertEquals(chain.chain_continuous, true, "the forgery IS chain-valid (that is finding F1)");
  assertEquals(chain.signatures_valid, true);
  assertEquals(attributeEvents(forged, trustedKeyBytes(issuerVector())), "foreign_key");
});

Deno.test("attribution: the padding bypass — genuine key as decoy in signing_keys, events signed by the attacker → foreign_key", async () => {
  const forged = await forgeExport({ padGenuineKey: RFC8032_KEY });
  // The old membership test (keys.includes(expected)) would PASS here:
  assert(
    forged.signing_keys.some((k: { public_key: string }) => k.public_key === RFC8032_KEY),
    "the genuine key sits in the export as a decoy",
  );
  const chain = await verifyChain(forged);
  assertEquals(chain.signatures_valid, true);
  // The per-event byte check does not:
  assertEquals(attributeEvents(forged, trustedKeyBytes(issuerVector())), "foreign_key");
});

Deno.test("attribution: an event whose signing_key_id resolves to nothing is foreign, never attributed", () => {
  const exp = golden();
  exp.events[1].signing_key_id = "ed25519:0000000000000000";
  assertEquals(attributeEvents(exp, trustedKeyBytes(issuerVector())), "foreign_key");
});

// ---------------------------------------------------------------------------
// M3.1: chain↔anchor binding, and the verdict ladder around it
// ---------------------------------------------------------------------------
const TENANT = "0f4a1c2e-7b3d-4e5f-9a8b-6c5d4e3f2a1b";
const HEAD = "9ef4602bd82514c2880f221549b2ce6f71d88322c4ce15c7ed03d6e4ce230a03";
const DAY = "2026-06-12";

const okChain: Verdict = {
  chain_continuous: true,
  signatures_valid: true,
  anchored_to_genesis: true,
  verified_from_sequence: 1,
  verified_through_sequence: 2,
  first_failure: null,
};

function confirmedAnchor(over: Partial<AnchorVerdict> = {}): AnchorVerdict {
  return {
    anchor_date: DAY,
    ots_status: "confirmed",
    ots_btc_block: 901245,
    ots_btc_blocks_attested: [901245],
    aggregate_recomputed: true,
    ots_commits_to_aggregate: true,
    bitcoin_verified: true,
    ots_btc_time: Date.parse(DAY + "T00:00:00Z") / 1000 + 86_400 + 3600,
    time_consistent: true,
    level: "explorer",
    note: "block-header verification via public explorers",
    ...over,
  };
}

// Minimal export context for assess: the verified head + the entries the
// anchor's recomputed aggregate commits to.
function expWith(
  entries: { tenant_id: string; last_event_hash: string }[],
  anchorExtra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    format: "humarch-export/v1",
    tenant_id: TENANT,
    events: [
      { sequence_number: 1, event_hash: "aa".repeat(32) },
      { sequence_number: 2, event_hash: HEAD },
    ],
    anchors: [{ anchor_date: DAY, anchor_entries_for_aggregate: entries, ...anchorExtra }],
  };
}

Deno.test("binding: a confirmed, time-consistent anchor committing to (tenant, head) binds — VERIFIED (exit 0)", () => {
  const exp = expWith([
    { tenant_id: "e7a1c9d0-1234-4abc-9def-0123456789ab", last_event_hash: "bb".repeat(32) },
    { tenant_id: TENANT, last_event_hash: HEAD },
  ]);
  const anchors = [confirmedAnchor()];
  assert(anchorBindsChainHead(exp, okChain, anchors));
  const { result, exitCode, properties } = assess(exp, okChain, anchors, "attributed");
  assertEquals(result, "verified");
  assertEquals(exitCode, 0);
  assertEquals(properties, { integrity: "ok", time: "proven", attribution: "attributed" });
  const human = renderHuman(TENANT, okChain, anchors, result, properties);
  assertStringIncludes(human, "[OK] Time");
  assertStringIncludes(human, "[OK] Attribution");
  assertStringIncludes(human, "RESULT: VERIFIED");
});

Deno.test("binding (M3 case 6): a genuine anchor STOLEN from another chain does not bind → never verified", () => {
  // Real, confirmed, time-consistent anchor — but its committed entries name
  // a different chain head: every per-anchor check passes, the binding not.
  const exp = expWith([{ tenant_id: TENANT, last_event_hash: "cc".repeat(32) }]);
  const anchors = [confirmedAnchor()];
  assert(!anchorBindsChainHead(exp, okChain, anchors));
  const { result, exitCode, properties } = assess(exp, okChain, anchors, "attributed");
  assertEquals(result, "partial", "declared partial: time not proven for THESE events");
  assertEquals(exitCode, 5);
  assertEquals(properties.time, "unproven");
  const human = renderHuman(TENANT, okChain, anchors, result, properties);
  assert(!human.includes("RESULT: VERIFIED"), human);
  assertStringIncludes(human, "[--] Time — not proven");
});

Deno.test("binding: same head under another tenant does not bind", () => {
  const exp = expWith([
    { tenant_id: "e7a1c9d0-1234-4abc-9def-0123456789ab", last_event_hash: HEAD },
  ]);
  assert(!anchorBindsChainHead(exp, okChain, [confirmedAnchor()]));
});

Deno.test("binding: reads the aggregate-committed entries, never the convenience `entry` field", () => {
  // `entry` is attacker-writable without touching aggregate_recomputed:
  // claiming the binding there must not count.
  const exp = expWith(
    [{ tenant_id: TENANT, last_event_hash: "cc".repeat(32) }],
    { entry: { tenant_id: TENANT, last_event_hash: HEAD } },
  );
  assert(!anchorBindsChainHead(exp, okChain, [confirmedAnchor()]));
});

Deno.test("binding: a pending or unverified anchor never binds, whatever its entries", () => {
  const exp = expWith([{ tenant_id: TENANT, last_event_hash: HEAD }]);
  for (
    const over of [
      {
        ots_status: "pending",
        ots_commits_to_aggregate: null,
        bitcoin_verified: null,
        ots_btc_time: null,
        time_consistent: null,
      },
      {
        bitcoin_verified: null,
        ots_btc_time: null,
        time_consistent: null,
        level: "trustless" as const,
      },
      { time_consistent: false },
      { aggregate_recomputed: false },
    ]
  ) {
    assert(
      !anchorBindsChainHead(exp, okChain, [confirmedAnchor(over)]),
      JSON.stringify(over),
    );
  }
});

Deno.test("verdict ladder: unattributed (exit 6) outranks partial, integrity failures outrank everything", () => {
  const exp = expWith([{ tenant_id: TENANT, last_event_hash: HEAD }]);
  const anchors = [confirmedAnchor()];

  const notChecked = assess(exp, okChain, anchors, "not_checked");
  assertEquals(notChecked.result, "unattributed");
  assertEquals(notChecked.exitCode, 6);

  const foreign = assess(exp, okChain, anchors, "foreign_key");
  assertEquals(foreign.result, "unattributed");
  assertEquals(foreign.exitCode, 6);
  const human = renderHuman(TENANT, okChain, anchors, foreign.result, foreign.properties);
  assertStringIncludes(human, "RESULT: NOT ATTRIBUTED");
  assert(!human.includes("no alteration"), "the old blanket claim is gone");

  const tamperedChain: Verdict = {
    ...okChain,
    signatures_valid: false,
    first_failure: {
      sequence_number: 2,
      kind: "bad_signature",
      detail: "invalid Ed25519 signature (D13)",
    },
  };
  const tampered = assess(exp, tamperedChain, anchors, "not_checked");
  assertEquals(tampered.result, "tampered", "integrity first: exit 2 even when unattributed");
  assertEquals(tampered.exitCode, 2);
});

Deno.test("forged export end-to-end at unit level: no anchors, own key ⇒ exit 6, never 0", async () => {
  const forged = await forgeExport({ padGenuineKey: RFC8032_KEY });
  const chain = await verifyChain(forged);
  const attribution = attributeEvents(forged, trustedKeyBytes(issuerVector()));
  const { result, exitCode, properties } = assess(forged, chain, [], attribution);
  assertEquals(result, "unattributed");
  assertEquals(exitCode, 6);
  assertEquals(properties, { integrity: "ok", time: "unproven", attribution: "foreign_key" });
  assertEquals(FORGED_TENANT, forged.tenant_id);
});
