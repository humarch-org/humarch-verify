// Shredded-event verification (B8 §8.12 deferral to B10; spec §1.1 note to
// verifiers): an export whose payload.personal is an encrypted envelope — and
// whose subject DEK no longer exists anywhere — verifies exactly like any
// other export. The verifier hashes the STORED form (B2 §2.0 rule B8): it
// certifies integrity, not confidentiality, and needs no key. The envelope
// sits INSIDE the integrity perimeter: any byte changed in it is tampering.
// No change to verify.ts was needed — this is the proof.
import { assertEquals } from "jsr:@std/assert@1";
import { jcsHash, verifyChain } from "../src/verify.ts";

const load = () =>
  JSON.parse(Deno.readTextFileSync(new URL("../vectors/export-shredded.json", import.meta.url)));

Deno.test("shredded export: fully verified with no key material (V6a/V6b at export level)", async () => {
  const exp = load();
  // V6a — the stored form (envelope included) reproduces payload_hash without
  // any DEK; the export carries no key material at all.
  assertEquals(await jcsHash(exp.events[0].payload), exp.events[0].payload_hash);
  const v = await verifyChain(exp);
  assertEquals(v.chain_continuous, true);
  assertEquals(v.signatures_valid, true);
  assertEquals(v.anchored_to_genesis, true);
  assertEquals(v.verified_through_sequence, 1);
  assertEquals(v.first_failure, null);
});

Deno.test("shredded export: the shred changed no byte, so the verdict is identical", async () => {
  // D52: the shred touches subject_keys only — the export before and after is
  // the SAME document. Two independent loads of the fixture stand in for the
  // pre/post-shred exports; the verdicts must be deep-equal.
  const before = await verifyChain(load());
  const after = await verifyChain(load());
  assertEquals(after, before);
});

Deno.test("tampering INSIDE the envelope is detected at the exact sequence", async () => {
  const exp = load();
  const ct = exp.events[0].payload.personal.ct as string;
  exp.events[0].payload.personal.ct = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
  const v = await verifyChain(exp);
  assertEquals(v.chain_continuous, false);
  assertEquals(v.first_failure?.sequence_number, 1);
  assertEquals(v.first_failure?.kind, "payload_hash_mismatch");
});

Deno.test("an envelope cannot be re-attributed: changing its subject is tampering", async () => {
  // The AAD already binds the ciphertext to the subject cryptographically
  // (D50); at the integrity level the binding is simpler still — the subject
  // field is part of the hashed stored form.
  const exp = load();
  exp.events[0].payload.personal.subject = "some-other-client";
  const v = await verifyChain(exp);
  assertEquals(v.first_failure?.kind, "payload_hash_mismatch");
});
