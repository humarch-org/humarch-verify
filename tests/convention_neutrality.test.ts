// Convention-payload neutrality regression (D91; SPEC §1.2, spec v1.2.0).
// The payload conventions `tool_call` and `delegation` are ordinary payload
// content: an export carrying them verifies through the SAME code paths and
// yields the SAME verdict shape as its twin without them, and the fields sit
// INSIDE the integrity perimeter (any tampered byte is detected). No change
// to verify.ts was needed — this test is the proof, exactly like
// shredded_export.test.ts proved it for the personal envelope.
import { assertEquals } from "jsr:@std/assert@1";
import {
  eventHash,
  expectedKeyId,
  fromHex,
  genesisHash,
  jcsHash,
  toHex,
  verifyChain,
} from "../src/verify.ts";

const TENANT = "b3d1f0aa-2c4e-4d6f-8a1b-9c7e5d3f2b0a";

// The stored/exported form of payload.personal, from the published shredded
// export vector — a realistic AES-256-GCM envelope, not a made-up object.
const personalEnvelope = () =>
  JSON.parse(
    Deno.readTextFileSync(new URL("../vectors/export-shredded.json", import.meta.url)),
  ).events[0].payload.personal;

// Internally consistent single-tenant export over the given payloads
// (forge_helper method: fresh key, genesis-anchored, densely sequenced).
// deno-lint-ignore no-explicit-any
async function buildExport(payloads: unknown[]): Promise<any> {
  const kp = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const pubHex = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  const keyId = await expectedKeyId(pubHex);

  let prev = await genesisHash(TENANT);
  // deno-lint-ignore no-explicit-any
  const events: any[] = [];
  for (let i = 0; i < payloads.length; i++) {
    const seq = i + 1;
    const ev = {
      event_id: `0000000${seq}-2222-4333-8444-555555555555`,
      tenant_id: TENANT,
      sequence_number: seq,
      received_at: `2026-07-21T10:12:0${seq}.000000Z`,
      occurred_at: `2026-07-21T10:12:0${seq}.000000Z`,
      source: "generic",
      event_type: "agent_action",
      actor: { type: "agent", id: "langgraph-orchestrator" },
      subject: {
        workflow: { ref: "pipeline-orders-v2" },
        end_client: { ref: "acme-ltd" },
        tool: { ref: "gmail" },
      },
      payload: payloads[i],
    };
    const payload_hash = await jcsHash(ev.payload);
    const eh = await eventHash(
      ev,
      await jcsHash(ev.actor),
      await jcsHash(ev.subject),
      payload_hash,
      prev,
    );
    const signature = toHex(
      new Uint8Array(
        await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, fromHex(eh) as BufferSource),
      ),
    );
    events.push({ ...ev, payload_hash, prev_hash: prev, event_hash: eh, signature, signing_key_id: keyId });
    prev = eh;
  }

  return {
    format: "humarch-export/v1",
    generated_at: "2026-07-21T12:00:00.000000Z",
    tenant_id: TENANT,
    range: { from_sequence: 1, to_sequence: payloads.length },
    genesis_note: "synthetic export for the D91 neutrality regression",
    signing_keys: [{
      signing_key_id: keyId,
      algorithm: "ed25519",
      public_key: pubHex,
      created_at: "2026-07-21T00:00:00.000000Z",
      retired_at: null,
    }],
    events,
    anchors: [],
  };
}

const conventionPayloads = () => [
  {
    action: "send_email",
    tool_call: {
      name: "send_email",
      params: { template: "order-confirmation", recipient_ref: "crm-4821" },
      result: { message_sha256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" },
      status: "ok",
    },
    personal: personalEnvelope(),
  },
  {
    action: "update_crm",
    tool_call: { name: "update_contact", params: { contact_ref: "crm-4821" }, status: "ok" },
    delegation: {
      parent: { ref: "run-9c44be00", event_id: "7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a" },
      root: { ref: "run-9c44be00" },
      depth: 1,
    },
  },
];

// The twin: same events, same identity, no convention fields.
const plainPayloads = () => [
  { action: "send_email", personal: personalEnvelope() },
  { action: "update_crm" },
];

Deno.test("convention export: fully verified, hashes recomputed on the fields as stored", async () => {
  const exp = await buildExport(conventionPayloads());
  // The component hash covers tool_call/delegation like any other content.
  assertEquals(await jcsHash(exp.events[0].payload), exp.events[0].payload_hash);
  assertEquals(await jcsHash(exp.events[1].payload), exp.events[1].payload_hash);
  const v = await verifyChain(exp);
  assertEquals(v.chain_continuous, true);
  assertEquals(v.signatures_valid, true);
  assertEquals(v.anchored_to_genesis, true);
  assertEquals(v.verified_through_sequence, 2);
  assertEquals(v.first_failure, null);
});

Deno.test("neutrality: the verdict is identical to the twin export without conventions", async () => {
  const withConv = await verifyChain(await buildExport(conventionPayloads()));
  const without = await verifyChain(await buildExport(plainPayloads()));
  assertEquals(withConv, without);
});

Deno.test("convention fields sit inside the integrity perimeter: tampering is detected", async () => {
  const exp = await buildExport(conventionPayloads());
  // Rewriting a delegation reference after the fact (the attack the
  // convention exists to make impossible) must fail at the exact sequence.
  exp.events[1].payload.delegation.parent.ref = "run-attacker";
  const v = await verifyChain(exp);
  assertEquals(v.chain_continuous, false);
  assertEquals(v.first_failure?.sequence_number, 2);
  assertEquals(v.first_failure?.kind, "payload_hash_mismatch");
});
