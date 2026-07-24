// W5 (audit 3): the local verifier runs on a file the operator chose, so the
// mission-correct answer to "huge export" is not an arbitrary cap (that would
// deny legitimate verification of large exports) but a guarantee that the cost
// stays LINEAR in the export size. These smoke tests pin that linearity
// against future regressions; they do NOT measure throughput, so the budgets
// are deliberately generous (a quadratic regression blows past them by orders
// of magnitude — the O(anchors²) find-by-date of W3 layer 1, now removed, was
// exactly such a pattern).
//
// The pure-JS hot paths (exportShapeProblems, anchorBindsChainHead) are pinned
// at 60k with a cheap synthetic export — that is where the audited changes
// live and where a quadratic would most plausibly creep in. verifyChain is
// crypto-bound and inherently single-pass; it is pinned on a real valid chain
// at a smaller size, whose full walk (chain + every Ed25519 signature) is
// exercised end to end.
import { assert } from "jsr:@std/assert@1";
import { exportShapeProblems } from "../src/shape.ts";
import { anchorBindsChainHead } from "../src/render.ts";
import type { AnchorVerdict } from "../src/ots.ts";
import {
  eventHash,
  expectedKeyId,
  fromHex,
  genesisHash,
  jcsHash,
  toHex,
  type Verdict,
  verifyChain,
} from "../src/verify.ts";

const TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const HEX64 = "a".repeat(64);
const HEX128 = "b".repeat(128);
const HEAD = "c".repeat(64);

Deno.test("W5 perf: exportShapeProblems and the chain↔anchor binding stay linear (60k events)", () => {
  const N = 60_000;
  // deno-lint-ignore no-explicit-any
  const events: any[] = [];
  for (let seq = 1; seq <= N; seq++) {
    events.push({
      event_id: `${seq.toString(16).padStart(8, "0")}-1111-4222-8333-444444444444`,
      tenant_id: TENANT,
      sequence_number: seq,
      received_at: "2025-01-01T00:00:00.000000Z",
      occurred_at: "2025-01-01T00:00:00.000000Z",
      source: "make",
      event_type: "agent_action",
      signing_key_id: "ed25519:0000000000000000",
      actor: { type: "agent", id: "a" },
      subject: { type: "none" },
      payload: { n: seq },
      payload_hash: HEX64,
      prev_hash: HEX64,
      event_hash: seq === N ? HEAD : HEX64,
      signature: HEX128,
    });
  }
  const exp = {
    format: "humarch-export/v1",
    tenant_id: TENANT,
    range: { from_sequence: 1, to_sequence: N },
    events,
    anchors: [{
      anchor_date: "2026-01-01",
      ots_status: "confirmed",
      aggregate_hash: HEX64,
      anchor_entries_for_aggregate: [{ tenant_id: TENANT, last_event_hash: HEAD }],
    }],
  };

  const t0 = performance.now();
  const problems = exportShapeProblems(exp);
  const shapeMs = performance.now() - t0;
  assert(
    problems.length === 0,
    `expected a well-formed synthetic export, got ${JSON.stringify(problems.slice(0, 3))}`,
  );

  // Binding scans events once for the head, then the single anchor's entries.
  const chain: Verdict = {
    chain_continuous: true,
    signatures_valid: true,
    anchored_to_genesis: true,
    verified_from_sequence: 1,
    verified_through_sequence: N,
    first_failure: null,
  };
  const anchors: AnchorVerdict[] = [{
    anchor_date: "2026-01-01",
    ots_btc_block: 1,
    ots_status: "confirmed",
    ots_btc_blocks_attested: [1],
    aggregate_recomputed: true,
    ots_commits_to_aggregate: true,
    bitcoin_verified: true,
    ots_btc_time: 0,
    time_consistent: true,
    level: "explorer",
    note: "",
  }];
  const t1 = performance.now();
  const binds = anchorBindsChainHead(exp, chain, anchors);
  const bindMs = performance.now() - t1;
  assert(binds, "the synthetic anchor commits to the head — it must bind");

  // 60k linear work is sub-second here; a quadratic would need minutes.
  assert(shapeMs < 15_000, `exportShapeProblems took ${shapeMs.toFixed(0)}ms for ${N} events`);
  assert(bindMs < 15_000, `anchorBindsChainHead took ${bindMs.toFixed(0)}ms for ${N} events`);
});

Deno.test("W5 perf: verifyChain walks a real valid chain in linear time (6k events)", async () => {
  const N = 6000;
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]) as CryptoKeyPair;
  const pubHex = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  const keyId = await expectedKeyId(pubHex);

  let prev = await genesisHash(TENANT);
  // deno-lint-ignore no-explicit-any
  const events: any[] = [];
  for (let seq = 1; seq <= N; seq++) {
    const ev = {
      event_id: `${seq.toString(16).padStart(8, "0")}-1111-4222-8333-444444444444`,
      tenant_id: TENANT,
      sequence_number: seq,
      received_at: "2025-01-01T00:00:00.000000Z",
      occurred_at: "2025-01-01T00:00:00.000000Z",
      source: "make",
      event_type: "agent_action",
      actor: { type: "agent", id: "a" },
      subject: { type: "none" },
      payload: { n: seq },
    };
    const ph = await jcsHash(ev.payload);
    const eh = await eventHash(ev, await jcsHash(ev.actor), await jcsHash(ev.subject), ph, prev);
    const sig = toHex(
      new Uint8Array(
        await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, fromHex(eh) as BufferSource),
      ),
    );
    events.push({
      ...ev,
      payload_hash: ph,
      prev_hash: prev,
      event_hash: eh,
      signature: sig,
      signing_key_id: keyId,
    });
    prev = eh;
  }
  const exp = {
    format: "humarch-export/v1",
    tenant_id: TENANT,
    range: { from_sequence: 1, to_sequence: N },
    signing_keys: [{
      signing_key_id: keyId,
      algorithm: "ed25519",
      public_key: pubHex,
      created_at: "2025-01-01T00:00:00.000000Z",
      retired_at: null,
    }],
    events,
    anchors: [],
  };

  const t0 = performance.now();
  const problems = exportShapeProblems(exp);
  const chain = await verifyChain(exp);
  const ms = performance.now() - t0;

  assert(problems.length === 0, JSON.stringify(problems.slice(0, 3)));
  assert(chain.chain_continuous && chain.signatures_valid, JSON.stringify(chain.first_failure));
  assert(
    chain.verified_through_sequence === N,
    `walked to ${chain.verified_through_sequence}, expected ${N}`,
  );
  // ~1.2 ms/event here ⇒ ~7s; a generous ceiling that a quadratic cannot meet.
  assert(ms < 45_000, `shape + verifyChain took ${ms.toFixed(0)}ms for ${N} events`);
});
