// Conformance gate (B2 §2.8/§2.9, B10 §10.7, B12 §12.3): vectors V0–V5 must be
// reproduced byte-for-byte, re-canonicalizing from PARSED VALUES (golden rule).
import { assertEquals } from "jsr:@std/assert@1";
import {
  aggregateHash,
  edVerify,
  eventHash,
  eventPreimage,
  expectedKeyId,
  genesisHash,
  jcs,
  jcsHash,
  verifyChain,
} from "../src/verify.ts";

const vec = (p: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../vectors/${p}`, import.meta.url)));

const v0 = vec("chain/v0.json");
const v1a = vec("canonicalization/v1a.json");
const v1b = vec("canonicalization/v1b.json");
const v1c = vec("canonicalization/v1c.json");
const v2 = vec("chain/v2.json");
const v3 = vec("chain/v3.json");
const v4 = vec("anchors/v4.json");

Deno.test("V0 — per-tenant genesis (D4)", async () => {
  assertEquals(await genesisHash(v0.tenant_id), v0.genesis);
});

Deno.test("V1a — JCS recursive key ordering", async () => {
  assertEquals(jcs(v1a.input), v1a.canonical);
  assertEquals(await jcsHash(v1a.input), v1a.sha256);
});

Deno.test("V1b — ECMAScript numbers and unicode (1e21 → 1e+21)", async () => {
  assertEquals(jcs(v1b.input), v1b.canonical);
  assertEquals(await jcsHash(v1b.input), v1b.sha256);
  // the Postgres-export spelling of the same value re-canonicalizes identically
  const pgSpelling = JSON.parse(
    '{"msg":"order already confirmed — city: Köln ❤","n":1.5,"big":1000000000000000000000,"small":0.0001}',
  );
  assertEquals(jcs(pgSpelling), v1b.canonical);
});

Deno.test("V1c / V5c — literal and \\u escape canonicalize identically (not tampering)", async () => {
  assertEquals(jcs(v1c.input_literal), v1c.canonical);
  assertEquals(jcs(JSON.parse(v1c.input_escaped_text)), v1c.canonical);
  assertEquals(await jcsHash(v1c.input_literal), v1c.sha256);
  assertEquals(await jcsHash(JSON.parse(v1c.input_escaped_text)), v1c.sha256);
});

Deno.test("V2 — component hashes, pre-image, event_hash, signature", async () => {
  const e = v2.event;
  assertEquals(await jcsHash(e.actor), v2.actor_hash);
  assertEquals(await jcsHash(e.subject), v2.subject_hash);
  assertEquals(await jcsHash(e.payload), e.payload_hash);
  assertEquals(e.prev_hash, await genesisHash(e.tenant_id));
  const pre = eventPreimage(e, v2.actor_hash, v2.subject_hash, e.payload_hash, e.prev_hash);
  assertEquals(
    pre,
    "humarch:event:v1\n7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a\n" +
      "0f4a1c2e-7b3d-4e5f-9a8b-6c5d4e3f2a1b\n1\n2026-06-12T09:15:42.123456Z\n" +
      "2026-06-12T09:15:42.123456Z\nmake\nagent_action\n" +
      "b0486a11017485e017970ece65cc6f169b1936126d17527fed3f4ffd4e48fe91\n" +
      "1d97e8b28f01dfe12529d6ff57e0caad30819d51820ef49980f88b92ad7d918a\n" +
      "c0578caa2b1a014d6089c693a0a00354290834d3068cac5a1a8ed79479e449bc\n" +
      "ce0d561658e27956a6e600098c094d320ff8b01280f466d5dac742cd34b14e3c\n",
  );
  assertEquals(
    await eventHash(e, v2.actor_hash, v2.subject_hash, e.payload_hash, e.prev_hash),
    e.event_hash,
  );
  assertEquals(await expectedKeyId(v2.signing_key.public_key), e.signing_key_id);
  assertEquals(await edVerify(v2.signing_key.public_key, e.signature, e.event_hash), true);
});

Deno.test("V3 — chained event with declared occurred_at", async () => {
  const e = v3.event;
  assertEquals(await jcsHash(e.actor), v3.actor_hash);
  assertEquals(await jcsHash(e.subject), v3.subject_hash);
  assertEquals(await jcsHash(e.payload), e.payload_hash);
  assertEquals(e.prev_hash, v2.event.event_hash);
  assertEquals(
    await eventHash(e, v3.actor_hash, v3.subject_hash, e.payload_hash, e.prev_hash),
    e.event_hash,
  );
  assertEquals(await edVerify(v2.signing_key.public_key, e.signature, e.event_hash), true);
});

Deno.test("V4 — daily anchor aggregate (formula D9)", async () => {
  assertEquals(await aggregateHash(v4.anchor_date, v4.entries), v4.aggregate_hash);
});

const exportForVerdict = () => ({
  format: "humarch-export/v1",
  tenant_id: v2.event.tenant_id,
  range: { from_sequence: 1, to_sequence: 2 },
  signing_keys: [{
    signing_key_id: v2.signing_key.signing_key_id,
    algorithm: "ed25519",
    public_key: v2.signing_key.public_key,
    created_at: "2026-06-01T00:00:00.000000Z",
    retired_at: null,
  }],
  events: [structuredClone(v2.event), structuredClone(v3.event)],
});

Deno.test("verdict on the V2/V3 export: fully verified", async () => {
  const v = await verifyChain(exportForVerdict());
  assertEquals(v.chain_continuous, true);
  assertEquals(v.signatures_valid, true);
  assertEquals(v.anchored_to_genesis, true);
  assertEquals(v.verified_from_sequence, 1);
  assertEquals(v.verified_through_sequence, 2);
  assertEquals(v.first_failure, null);
});

Deno.test("V5a — one character of the V2 payload altered → payload_hash_mismatch at seq 1", async () => {
  const exp = exportForVerdict();
  exp.events[0].payload.params.subject = "Order confirmation #4822";
  // the altered payload would hash differently, exactly as the vector states:
  assertEquals(
    await jcsHash(exp.events[0].payload),
    "c94f093d95cfede8c6ccb290cd9aab3ab3bc78d0372d4ddc634cd255db029d25",
  );
  const v = await verifyChain(exp);
  assertEquals(v.chain_continuous, false);
  assertEquals(v.first_failure?.sequence_number, 1);
  assertEquals(v.first_failure?.kind, "payload_hash_mismatch");
});

Deno.test("V5b — one bit of the V2 signature flipped → bad_signature", async () => {
  const exp = exportForVerdict();
  const sig = exp.events[0].signature;
  const firstByte = parseInt(sig.slice(0, 2), 16) ^ 0x01; // flip one bit
  exp.events[0].signature = firstByte.toString(16).padStart(2, "0") + sig.slice(2);
  const v = await verifyChain(exp);
  assertEquals(v.signatures_valid, false);
  assertEquals(v.first_failure?.sequence_number, 1);
  assertEquals(v.first_failure?.kind, "bad_signature");
});

Deno.test("fromHex guard: garbage never becomes bytes silently (external review 2026-07-16)", async () => {
  const { fromHex, toHex } = await import("../src/verify.ts");
  // round-trip on valid hex, both cases
  assertEquals(toHex(fromHex("deadBEEF")), "deadbeef");
  assertEquals(fromHex(""), new Uint8Array(0));
  for (const bad of ["abc", "zz", "0x00", "de ad"]) {
    let threw = false;
    try {
      fromHex(bad);
    } catch {
      threw = true;
    }
    assertEquals(threw, true, `fromHex(${JSON.stringify(bad)}) must throw`);
  }
});

Deno.test("tampered event_id → event_hash_mismatch (pre-image D11 covers identity fields)", async () => {
  const exp = exportForVerdict();
  exp.events[0].event_id = "00000000-0000-4000-8000-000000000000";
  const v = await verifyChain(exp);
  assertEquals(v.first_failure?.kind, "event_hash_mismatch");
});
