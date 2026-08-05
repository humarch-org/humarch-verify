// On-demand chain-seal gate (D104, SPEC 1.5.0): the additive `chain_seals`
// leg against vendored tokens (local openssl TSA, ECDSA P-256 — one-shot
// generated, never a live CI dependency) and the invariants the decision
// pins:
//   * EXIT NEUTRALITY — a valid/invalid/untrusted/absent seal never changes
//     the result or exit code of the existing verification, and an export
//     WITHOUT the field renders byte-identically to pre-1.5;
//   * HEAD BINDING — the token binds to the event hash RECOMPUTED from the
//     D11 pre-image at the declared sequence, within the verified POSITIONAL
//     prefix (D100 rule 10), never to declared fields (dual-anchor review
//     traps 1/10/11);
//   * PREFIX SEMANTICS — the presumption speaks of the chain head and the
//     prefix inheriting anteriority; "every event has its own timestamp"
//     stays a forbidden formulation (§0.7 class);
//   * W3 REGRESSION — two anchors on one date remain a form error (exit 4),
//     chain_seals present or not.
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { trustedTsaFingerprints, verifyChainSeal } from "../src/tst_lite.ts";
import { verifyAnchors, verifyChainSeals } from "../src/ots.ts";
import { verifyChain } from "../src/verify.ts";
import { assess, renderHuman } from "../src/render.ts";
import { attributeEvents, trustedKeyBytes } from "../src/issuer.ts";
import { exportShapeProblems } from "../src/shape.ts";

const S = (name: string) => new URL(`../vectors/seal/${name}`, import.meta.url);
const readJson = (name: string) => JSON.parse(Deno.readTextFileSync(S(name)));

const trustSeal = () => readJson("tsa-trust-seal.json");
const trustFprs = () => trustedTsaFingerprints(trustSeal());

async function fullRun(name: string, trusted: boolean, attributeToFixture = false) {
  const exp = readJson(name);
  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(
    exp,
    "trustless", // no explorer network in the suite
    undefined,
    trusted ? trustSeal() : undefined,
  );
  const chainSeals = await verifyChainSeals(exp, chain, trusted ? trustSeal() : undefined);
  const trustedKeys = attributeToFixture
    ? trustedKeyBytes({
      format: "humarch-keys/v1",
      keys: exp.signing_keys.map((k: { public_key: string }) => ({ public_key: k.public_key })),
    })
    : new Set<string>();
  const attribution = attributeEvents(exp, trustedKeys);
  const v = assess(exp, chain, anchors, attribution);
  return { exp, chain, anchors, chainSeals, ...v };
}

// ---------------------------------------------------------------------------
// Verdict statuses on the vectors.
// ---------------------------------------------------------------------------
Deno.test("chain seal verdict: valid / untrusted / mismatch / malformed / oversize / unknown sequence", async () => {
  const valid = await fullRun("export-seal.json", true);
  assertEquals(valid.chainSeals.length, 1);
  const v = valid.chainSeals[0];
  assertEquals(v.status, "valid");
  assertEquals(v.sequence_number, 3);
  assertEquals(v.matches_head, true);
  assertEquals(v.signature_valid, true);
  assertEquals(v.trusted_tsa, true);
  assertEquals(v.gen_time_consistent, true, "the seal postdates the sealed event's reception");
  assertStringIncludes(v.note, "valid · Humarch Seal Test TSA");

  const untrusted = await fullRun("export-seal.json", false);
  assertEquals(untrusted.chainSeals[0].status, "untrusted");
  assertEquals(untrusted.chainSeals[0].note, "valid token, untrusted TSA, no presumption");

  const mismatch = await fullRun("export-seal-mismatch.json", true);
  assertEquals(mismatch.chainSeals[0].status, "invalid");
  assertEquals(
    mismatch.chainSeals[0].matches_head,
    false,
    "a genuine token for another hash never binds this head",
  );
  assertStringIncludes(mismatch.chainSeals[0].note, "recomputed at the declared sequence");

  const malformed = await fullRun("export-seal-malformed.json", true);
  assertEquals(malformed.chainSeals[0].status, "invalid");
  assertStringIncludes(malformed.chainSeals[0].note, "unreadable token");

  const oversize = await fullRun("export-seal-oversize.json", true);
  assertEquals(oversize.chainSeals[0].status, "invalid");
  assertStringIncludes(oversize.chainSeals[0].note, "unreadable token");

  const unknown = await fullRun("export-seal-unknown-sequence.json", true);
  assertEquals(unknown.chainSeals[0].status, "invalid");
  assertStringIncludes(unknown.chainSeals[0].note, "not present in this export");
});

Deno.test("chain seal binds the RECOMPUTED head within the verified prefix — a tampered chain never lends it", async () => {
  // The attacker rewrites the sealed event but keeps the declared
  // event_hash field and the stolen genuine token: verifyChain breaks at
  // sequence 3, the positional prefix stops at 2, and the seal is a
  // DECLARED invalid — never an [OK] line dressed by declared fields.
  const exp = readJson("export-seal.json");
  exp.events[2].payload = { forged: true };
  const chain = await verifyChain(exp);
  assertEquals(chain.verified_through_sequence, 2);
  const seals = await verifyChainSeals(exp, chain, trustSeal());
  assertEquals(seals[0].status, "invalid");
  assertStringIncludes(seals[0].note, "beyond the verified prefix");
});

Deno.test("chain seal: the recomputed head hash is REQUIRED — no fallback (trap 11 discipline)", async () => {
  const seal = readJson("export-seal.json").chain_seals[0];
  // deno-lint-ignore no-explicit-any
  const call = verifyChainSeal as any;
  for (const bad of [undefined, "", "not-hex", "abc"]) {
    const v = await call(seal, trustFprs(), bad, null);
    assertEquals(v.status, "invalid", `expected invalid for ${JSON.stringify(bad)}`);
    assertEquals(v.matches_head, null);
    assertStringIncludes(v.note, "no recomputed head hash supplied");
  }
});

Deno.test("chain seal: a genTime before the sealed event's reception is declared, never [OK]", async () => {
  const exp = readJson("export-seal.json");
  const chain = await verifyChain(exp);
  const seal = exp.chain_seals[0];
  // Direct call with a reception time AFTER the token's genTime: coherence
  // fact false, status untouched (the token stays genuine), note declared.
  const recomputed = (await verifyChainSeals(exp, chain, trustSeal()))[0];
  assertEquals(recomputed.status, "valid");
  const early = await verifyChainSeal(
    seal,
    trustFprs(),
    // the genuine head hash of the vector (the token's imprint)
    "49a29a1a4e20c5dabac05e989eae587934bcb8eafe6a697ebc5a99deff416e1f",
    "2027-01-01T00:00:00.000000Z",
  );
  assertEquals(early.status, "valid");
  assertEquals(early.gen_time_consistent, false);
  assertStringIncludes(early.note, "genTime precedes the sealed event's reception");
  // Rendering: the early-genTime seal reads [WARN] and never earns the note.
  const human = renderHuman("t", chain, [], "verified", {
    integrity: "ok",
    time: "not_proven",
    attribution: "not_checked",
    // deno-lint-ignore no-explicit-any
  } as any, [early]);
  assertStringIncludes(human, "[WARN] Chain seal at sequence 3");
  assert(!human.includes("chain head at sealing time"), "no presumption note for an early genTime");
});

// ---------------------------------------------------------------------------
// Exit neutrality (the D98 (e)/D104 invariant).
// ---------------------------------------------------------------------------
Deno.test("exit neutrality: valid, invalid, untrusted and absent seals all leave result and exit unchanged", async () => {
  // The base is the SAME export without the field (the qualified 1.3 vector
  // this one extends): result and exit must not move in any variant.
  const base = await fullRun("../qualified/export-qualified.json" as string, true);
  for (
    const name of [
      "export-seal.json",
      "export-seal-mismatch.json",
      "export-seal-malformed.json",
      "export-seal-oversize.json",
      "export-seal-unknown-sequence.json",
    ]
  ) {
    const run = await fullRun(name, true);
    assertEquals(run.result, base.result, `${name}: result must not move`);
    assertEquals(run.exitCode, base.exitCode, `${name}: exit code must not move`);
  }
  const untrusted = await fullRun("export-seal.json", false);
  assertEquals(untrusted.exitCode, base.exitCode, "untrusted TSA: exit code must not move");
});

// ---------------------------------------------------------------------------
// Rendering: prefix semantics, gating, no forbidden formulation.
// ---------------------------------------------------------------------------
Deno.test("render: one additive line per seal, head/prefix semantics, gated presumption note", async () => {
  const valid = await fullRun("export-seal.json", true, true);
  const human = renderHuman(
    valid.exp.tenant_id,
    valid.chain,
    valid.anchors,
    valid.result,
    valid.properties,
    valid.chainSeals,
  );
  assertStringIncludes(
    human,
    "[OK] Chain seal at sequence 3 — valid · Humarch Seal Test TSA (untrusted fixture) · 2026-08-05T07:28:40Z.",
  );
  assertStringIncludes(human, "attaches the eIDAS art. 42 presumption to the chain head at sealing time");
  assertStringIncludes(
    human,
    "every prior event of the verified prefix inherits that anteriority through deterministic, reproducible recomputation",
  );
  assert(!human.includes("every event has"), "forbidden formulation (§0.7 class) must never render");

  const untrusted = await fullRun("export-seal.json", false, true);
  const humanU = renderHuman(
    untrusted.exp.tenant_id,
    untrusted.chain,
    untrusted.anchors,
    untrusted.result,
    untrusted.properties,
    untrusted.chainSeals,
  );
  assertStringIncludes(
    humanU,
    "[WARN] Chain seal at sequence 3 — valid token, untrusted TSA, no presumption.",
  );
  assert(
    !humanU.includes("chain head at sealing time"),
    "no presumption note without a trusted seal",
  );

  const invalid = await fullRun("export-seal-mismatch.json", true, true);
  const humanI = renderHuman(
    invalid.exp.tenant_id,
    invalid.chain,
    invalid.anchors,
    invalid.result,
    invalid.properties,
    invalid.chainSeals,
  );
  assertStringIncludes(humanI, "[WARN] Chain seal at sequence 3 — invalid (");

  // A tampered export never earns the presumption sentence even with a
  // genuine trusted seal riding along (same gating as the Bitcoin and
  // qualified notes).
  const tampered = readJson("export-seal.json");
  tampered.events[2].payload = { forged: true };
  const chainT = await verifyChain(tampered);
  const sealsT = await verifyChainSeals(tampered, chainT, trustSeal());
  const humanT = renderHuman(
    tampered.tenant_id,
    chainT,
    [],
    "tampered",
    // deno-lint-ignore no-explicit-any
    { integrity: "failed", time: "not_proven", attribution: "not_checked" } as any,
    sealsT,
  );
  assert(!humanT.includes("chain head at sealing time"), "tampered export: no presumption note");

  // Absent field ⇒ byte-identical rendering to the pre-1.5 call (the
  // default parameter): no seal line, no seal note.
  const baseQ = await fullRun("../qualified/export-qualified.json" as string, true);
  const withDefault = renderHuman(
    baseQ.exp.tenant_id,
    baseQ.chain,
    baseQ.anchors,
    baseQ.result,
    baseQ.properties,
  );
  const withEmpty = renderHuman(
    baseQ.exp.tenant_id,
    baseQ.chain,
    baseQ.anchors,
    baseQ.result,
    baseQ.properties,
    [],
  );
  assertEquals(withEmpty, withDefault, "absent seals: rendering byte-identical to pre-1.5");
  assert(!withDefault.includes("Chain seal"), "no seal line without the field");
});

// ---------------------------------------------------------------------------
// Shape gate + the W3 regression the plan makes mandatory.
// ---------------------------------------------------------------------------
Deno.test("shape: chain_seals is optional, validated when present; duplicates and disorder are form errors", () => {
  assertEquals(exportShapeProblems(readJson("export-seal.json")), []);

  const notArray = readJson("export-seal.json");
  notArray.chain_seals = "a string";
  assert(exportShapeProblems(notArray).some((p: string) => p.includes("expected an array")));

  const badToken = readJson("export-seal.json");
  badToken.chain_seals[0].token_base64 = "not base64 !!";
  assert(exportShapeProblems(badToken).some((p: string) => p.includes("chain_seals[0].token_base64")));

  const badSeq = readJson("export-seal.json");
  badSeq.chain_seals[0].sequence_number = 0;
  assert(exportShapeProblems(badSeq).some((p: string) => p.includes("positive integer")));

  const dupe = readJson("export-seal.json");
  dupe.chain_seals.push(structuredClone(dupe.chain_seals[0]));
  assert(
    exportShapeProblems(dupe).some((p: string) => p.includes("duplicate sealed sequence")),
    "one seal per head (the W3 decoy-riding class)",
  );

  const disorder = readJson("export-seal.json");
  disorder.chain_seals = [
    { ...structuredClone(disorder.chain_seals[0]), sequence_number: 3 },
    { ...structuredClone(disorder.chain_seals[0]), sequence_number: 2 },
  ];
  assert(exportShapeProblems(disorder).some((p: string) => p.includes("ordered by sequence")));
});

Deno.test("W3 regression (mandatory, D104 §0.1): two anchors on one date stay a form error, seals present or not", () => {
  const twoAnchors = readJson("export-seal.json");
  twoAnchors.anchors.push(structuredClone(twoAnchors.anchors[0]));
  const problems = exportShapeProblems(twoAnchors);
  assert(
    problems.some((p: string) => p.includes("duplicate anchor date")),
    "the at-most-one-anchor-per-day rule is untouched by the seal leg",
  );
});
