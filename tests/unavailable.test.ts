// Declared-unavailable gate (D105, SPEC 1.6.0 §8 rule 14): the additive
// self-declaration of omitted proof artifacts, and the invariants the
// decision pins:
//
//   * EXIT NEUTRALITY, ADVERSARIALLY — a declaration is the producer's
//     statement about its own export, and the producer may be the attacker.
//     Stripping a genuine proof and adding the matching declaration MUST
//     yield EXACTLY the outcome of the plain absence: same result, same exit
//     code, same properties, and the same rendering minus the declared
//     block. An export WITHOUT the array renders byte-identically to pre-1.6.
//   * FORM, rule-8 class — a repeated coordinate, an unknown `kind`, a
//     coordinate of the wrong shape and a coordinate that does not belong to
//     its kind are malformed input (exit 4). The declared ORDERING is not,
//     and must not become, a refusal criterion.
//   * WORDING — every rendered line names who is speaking. A declaration is
//     never presented as evidence, as a proof of absence, or as anything
//     this verifier established (trap 11: no public surface may let a caller
//     mistake a declaration for a check).
//   * DEFENSIVE READS — the library entry point never throws, never invokes
//     a hostile getter, and declares its caps instead of truncating quietly.
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";
import { verifyChain } from "../src/verify.ts";
import { verifyAnchors, verifyChainSeals } from "../src/ots.ts";
import { assess, renderHuman } from "../src/render.ts";
import { attributeEvents, trustedKeyBytes } from "../src/issuer.ts";
import { exportShapeProblems } from "../src/shape.ts";
import {
  declaredUnavailableArtifacts,
  UNAVAILABLE_READ_CAP,
  UNAVAILABLE_SEMANTICS,
} from "../src/unavailable.ts";

const U = (name: string) => new URL(`../vectors/unavailable/${name}`, import.meta.url);
const readJson = (name: string) => JSON.parse(Deno.readTextFileSync(U(name)));
const S = (name: string) => new URL(`../vectors/seal/${name}`, import.meta.url);
const readSeal = (name: string) => JSON.parse(Deno.readTextFileSync(S(name)));

const DECLARING = "export-unavailable.json";
const TWIN = "export-no-declaration.json";
const MALFORMED = [
  "export-unavailable-duplicate.json",
  "export-unavailable-unknown-kind.json",
  "export-unavailable-bad-coordinate.json",
  "export-unavailable-kind-mismatch.json",
];

// deno-lint-ignore no-explicit-any
async function fullRun(exp: any, attributeToFixture = true) {
  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(exp, "trustless"); // no explorer network here
  const chainSeals = await verifyChainSeals(exp, chain, undefined);
  const trusted = attributeToFixture
    ? trustedKeyBytes({
      format: "humarch-keys/v1",
      keys: exp.signing_keys.map((k: { public_key: string }) => ({ public_key: k.public_key })),
    })
    : new Set<string>();
  const attribution = attributeEvents(exp, trusted);
  const v = assess(exp, chain, anchors, attribution);
  const unavailable = declaredUnavailableArtifacts(exp);
  const human = renderHuman(
    exp.tenant_id,
    chain,
    anchors,
    v.result,
    v.properties,
    chainSeals,
    unavailable,
  );
  return { chain, anchors, chainSeals, unavailable, human, ...v };
}

async function runCli(
  ...args: string[]
): Promise<{ code: number; stdout: string; stderr: string }> {
  const cmd = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-read",
      "--allow-net",
      fromFileUrl(new URL("../src/cli.ts", import.meta.url)),
      ...args,
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await cmd.output();
  return {
    code: out.code,
    stdout: new TextDecoder().decode(out.stdout),
    stderr: new TextDecoder().decode(out.stderr),
  };
}

// deno-lint-ignore no-explicit-any
async function withTempExport(exp: any, fn: (path: string) => Promise<void>): Promise<void> {
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, JSON.stringify(exp));
  try {
    await fn(tmp);
  } finally {
    await Deno.remove(tmp);
  }
}

/** The rendered block, isolated — everything else must match byte for byte. */
function withoutDeclaredBlock(human: string): string {
  const at = human.indexOf("Declared unavailable (SPEC §8 rule 14)");
  if (at < 0) return human;
  const end = human.indexOf("\n", human.indexOf("\nNote: these are the producer's", at) + 1);
  // Drop the block AND the blank line that introduces it.
  return human.slice(0, at - 1).replace(/\n$/, "") + human.slice(end);
}

// ---------------------------------------------------------------------------
// The claim the whole decision rests on: a declaration moves nothing.
// ---------------------------------------------------------------------------
Deno.test("exit neutrality: the declaring export and its silent twin reach the same outcome", async () => {
  const declaring = await fullRun(readJson(DECLARING));
  const twin = await fullRun(readJson(TWIN));

  assertEquals(declaring.result, twin.result);
  assertEquals(declaring.exitCode, twin.exitCode);
  assertEquals(declaring.properties, twin.properties);
  assertEquals(declaring.chain, twin.chain);
  assertEquals(declaring.anchors, twin.anchors);
  // The rendering differs by the declared block and by nothing else.
  assertEquals(withoutDeclaredBlock(declaring.human), twin.human);
  assert(declaring.human !== twin.human, "the declaration IS rendered");
});

Deno.test("exit neutrality at CLI level: identical exit codes, verdict lines and JSON verdict", async () => {
  const pub = readJson(DECLARING).signing_keys[0].public_key;
  await withTempExport(readJson(DECLARING), async (decl) => {
    await withTempExport(readJson(TWIN), async (twin) => {
      for (const flags of [[], ["--pubkey", pub]]) {
        const a = await runCli(decl, ...flags);
        const b = await runCli(twin, ...flags);
        assertEquals(a.code, b.code, "the declaration must never move the exit code");
        assertEquals(withoutDeclaredBlock(a.stdout), b.stdout);
      }
      // In JSON the verdict members are identical; only an additive key rides.
      const aj = JSON.parse((await runCli(decl, "--json", "--pubkey", pub)).stdout);
      const bj = JSON.parse((await runCli(twin, "--json", "--pubkey", pub)).stdout);
      assert("declared_unavailable" in aj, "the declaring export exposes the additive key");
      assert(!("declared_unavailable" in bj), "the silent twin exposes nothing");
      delete aj.declared_unavailable;
      assertEquals(aj, bj, "chain, anchors, properties and result are untouched");
    });
  });
});

Deno.test("adversarial lane: stripping a genuine proof and declaring it gains the attacker nothing", async () => {
  // The attack rule 14 must be immune to: take a document whose seal and
  // qualified timestamp verify, remove them, and add the matching
  // declarations so the missing proofs look accounted for. The outcome must
  // be the outcome of the plain absence — not one notch friendlier.
  const genuine = readSeal("export-seal.json");
  assert(genuine.chain_seals?.length === 1 && genuine.anchors[0].qualified_timestamp);

  const stripped = JSON.parse(JSON.stringify(genuine));
  delete stripped.chain_seals;
  delete stripped.anchors[0].qualified_timestamp;
  delete stripped.anchors[0].ots_file_base64;

  const spoofed = JSON.parse(JSON.stringify(stripped));
  spoofed.unavailable_artifacts = [
    { kind: "ots_receipt", anchor_date: stripped.anchors[0].anchor_date },
    { kind: "qualified_timestamp", anchor_date: stripped.anchors[0].anchor_date },
    { kind: "chain_seal", sequence_number: genuine.chain_seals[0].sequence_number },
  ];

  const a = await fullRun(stripped);
  const b = await fullRun(spoofed);
  assertEquals(b.result, a.result);
  assertEquals(b.exitCode, a.exitCode);
  assertEquals(b.properties, a.properties);
  assertEquals(b.chainSeals, a.chainSeals);
  assertEquals(withoutDeclaredBlock(b.human), a.human);
  // And the anchor's own honest line is unchanged: the declaration does not
  // soften "declared confirmed but the export carries no .ots receipt".
  assertStringIncludes(b.human, "carries no .ots receipt");

  // A declaration whose coordinate the document does not even contain is
  // still just a declaration: well-formed, inert, and it proves nothing.
  const dangling = JSON.parse(JSON.stringify(stripped));
  dangling.unavailable_artifacts = [{ kind: "chain_seal", sequence_number: 999 }];
  const c = await fullRun(dangling);
  assertEquals(c.exitCode, a.exitCode);
  assertEquals(exportShapeProblems(dangling), []);
});

Deno.test("self-contradiction: an artifact both carried and declared is named, and moves nothing", async () => {
  // Adversarial review 2026-08-06, finding 4. Rule 13/14 make this state
  // impossible for an honest exporter, and it is outcome-free — but rendered
  // as a plain declaration it hands a reader an excuse for a proof that is
  // PRESENT and failing ("[WARN] … invalid" re-read as "unavailable").
  const carried = readSeal("export-seal.json");
  assert(carried.chain_seals?.length === 1 && carried.anchors[0].qualified_timestamp);
  assert(typeof carried.anchors[0].ots_file_base64 === "string");

  const contradicting = JSON.parse(JSON.stringify(carried));
  contradicting.unavailable_artifacts = [
    { kind: "ots_receipt", anchor_date: carried.anchors[0].anchor_date },
    { kind: "qualified_timestamp", anchor_date: carried.anchors[0].anchor_date },
    { kind: "chain_seal", sequence_number: carried.chain_seals[0].sequence_number },
  ];
  // A well-formed array: the gate has nothing to say, and must not invent it.
  assertEquals(exportShapeProblems(contradicting), []);

  const report = declaredUnavailableArtifacts(contradicting);
  assertEquals(report?.entries.map((e) => e.contradicted), [true, true, true]);

  const plain = await fullRun(carried);
  const both = await fullRun(contradicting);
  // Outcome-free, exactly like any other declaration.
  assertEquals(both.result, plain.result);
  assertEquals(both.exitCode, plain.exitCode);
  assertEquals(both.properties, plain.properties);
  assertEquals(both.chainSeals, plain.chainSeals);
  // And the contradiction is stated, not smuggled past the reader.
  const count = (both.human.match(/self-contradictory/g) ?? []).length;
  assertEquals(count, 3, both.human);
  assertStringIncludes(both.human, "yet this document carries it");

  // A declaration for an artifact the document genuinely lacks is NOT
  // contradicted — the flag must discriminate, not decorate.
  const honest = JSON.parse(JSON.stringify(carried));
  delete honest.chain_seals;
  honest.unavailable_artifacts = [
    { kind: "chain_seal", sequence_number: carried.chain_seals[0].sequence_number },
  ];
  assertEquals(declaredUnavailableArtifacts(honest)?.entries[0].contradicted, false);
  const h = await fullRun(honest);
  assert(!h.human.includes("self-contradictory"), h.human);
});

Deno.test("byte identity: a pre-1.6 export renders exactly as before the feature existed", async () => {
  for (const name of ["export-v2v3.json", "export-shredded.json"]) {
    const exp = JSON.parse(
      Deno.readTextFileSync(new URL(`../vectors/${name}`, import.meta.url)),
    );
    const chain = await verifyChain(exp);
    const anchors = await verifyAnchors(exp, "trustless");
    const { result, properties } = assess(exp, chain, anchors, attributeEvents(exp, new Set()));
    const before = renderHuman(exp.tenant_id, chain, anchors, result, properties);
    const after = renderHuman(exp.tenant_id, chain, anchors, result, properties, [], null);
    assertEquals(after, before);
    assertEquals(declaredUnavailableArtifacts(exp), null, "no array ⇒ no report at all");
  }
  // An empty declaration is nothing to say, and says nothing.
  const exp = readJson(TWIN);
  exp.unavailable_artifacts = [];
  const empty = await fullRun(exp);
  const twin = await fullRun(readJson(TWIN));
  assertEquals(empty.human, twin.human);
});

// ---------------------------------------------------------------------------
// Form gate (rule-8 class).
// ---------------------------------------------------------------------------
Deno.test("shape gate: the four malformed vectors are refused, the valid pair is not", async () => {
  for (const name of MALFORMED) {
    const problems = exportShapeProblems(readJson(name));
    assert(problems.length > 0, `${name} must be refused by the gate`);
    await withTempExport(readJson(name), async (tmp) => {
      const r = await runCli(tmp);
      assertEquals(r.code, 4, `${name} must exit 4`);
      assertStringIncludes(r.stderr, "malformed input");
      assertStringIncludes(r.stderr, "unavailable_artifacts");
    });
  }
  assertEquals(exportShapeProblems(readJson(DECLARING)), []);
  assertEquals(exportShapeProblems(readJson(TWIN)), []);
});

Deno.test("shape gate: the closed enumeration, the coordinate pairing, and what stays allowed", () => {
  const base = readJson(TWIN);
  // deno-lint-ignore no-explicit-any
  const withArray = (arr: any) => ({ ...base, unavailable_artifacts: arr });
  const refused = (arr: unknown, hint: string) => {
    const problems = exportShapeProblems(withArray(arr));
    assert(problems.length > 0, `should be refused: ${hint}`);
    assert(
      problems.some((p) => p.startsWith("unavailable_artifacts")),
      `the problem must name the field: ${hint} (${problems.join("; ")})`,
    );
  };

  refused({}, "not an array");
  refused(["ots_receipt"], "element not an object");
  refused([{ anchor_date: "2026-07-06" }], "no kind");
  refused([{ kind: "ots", anchor_date: "2026-07-06" }], "kind outside the enumeration");
  refused([{ kind: "ots_receipt" }], "no coordinate");
  refused([{ kind: "ots_receipt", anchor_date: "2026-07-06junk" }], "lenient date (W2 class)");
  refused([{ kind: "ots_receipt", anchor_date: "2026-07-06", sequence_number: 3 }], "both");
  refused([{ kind: "chain_seal", anchor_date: "2026-07-06" }], "seal with an anchor coordinate");
  refused([{ kind: "chain_seal", sequence_number: 0 }], "sequence below 1");
  refused([{ kind: "chain_seal", sequence_number: 1.5 }], "non-integer sequence");
  refused(
    [{ kind: "chain_seal", sequence_number: Number.MAX_SAFE_INTEGER + 2 }],
    "sequence past the safe range (W9 class)",
  );
  refused(
    [{ kind: "ots_receipt", anchor_date: "2026-07-06" }, {
      kind: "ots_receipt",
      anchor_date: "2026-07-06",
    }],
    "the same artifact cannot be unavailable twice",
  );

  // Allowed: same coordinate under DIFFERENT kinds (two distinct artifacts
  // of the same anchor really can both be missing), and the same kind on
  // different coordinates.
  assertEquals(
    exportShapeProblems(withArray([
      { kind: "ots_receipt", anchor_date: "2026-07-06" },
      { kind: "qualified_timestamp", anchor_date: "2026-07-06" },
    ])),
    [],
  );
  // Allowed, deliberately: a declared ORDER that is not the exporter's.
  // Rule 14 binds exporters there, not verifiers — refusing this would be a
  // self-inflicted denial of verification over a list that proves nothing.
  assertEquals(
    exportShapeProblems(withArray([
      { kind: "chain_seal", sequence_number: 9 },
      { kind: "chain_seal", sequence_number: 2 },
      { kind: "ots_receipt", anchor_date: "2026-07-06" },
    ])),
    [],
  );
});

// ---------------------------------------------------------------------------
// Wording: who is speaking, and what is never claimed.
// ---------------------------------------------------------------------------
Deno.test("rendering: the block names the producer, marks every entry declared, and claims nothing", async () => {
  const { human } = await fullRun(readJson(DECLARING));
  assertStringIncludes(human, "Declared unavailable (SPEC §8 rule 14)");
  assertStringIncludes(human, "the producer of this document states that it could not include:");
  assertStringIncludes(human, "  [--] the OTS receipt of the 2026-07-06 anchor");
  assertStringIncludes(human, "  [--] the qualified timestamp of the 2026-07-06 anchor");
  assertStringIncludes(human, "  [--] the chain seal at sequence 3");
  assertStringIncludes(human, "not findings of this verifier");
  assertStringIncludes(human, "a declaration is not evidence that the artifact exists");
  assertStringIncludes(human, "reaches the same result and the same exit code");

  // The forbidden readings, none of which may ever render (the mandate's
  // wording constraint and the §0.7 forbidden-formulation class).
  const blockAt = human.indexOf("Declared unavailable");
  const block = human.slice(
    blockAt,
    human.indexOf("\n", human.indexOf("\nNote: these", blockAt) + 1),
  );
  for (const forbidden of ["excused", "proven missing", "proven absent", "waived", "exempt"]) {
    assert(!block.toLowerCase().includes(forbidden), `"${forbidden}" must never render`);
  }
  // And no declared line may read as a verifier finding.
  assert(!/\[OK\]/.test(block) && !/\[ERROR\]/.test(block), block);
  assert(!/declared unavailable[^\n]*(verified|proven|confirmed)/i.test(block), block);
  // The block sits BEFORE the verdict: a reader meets the caveat first.
  assert(
    human.indexOf("Declared unavailable") < human.indexOf("RESULT:"),
    "the declared block precedes the result",
  );
});

Deno.test("rendering: the display cap is declared, never a silent truncation", async () => {
  const exp = readJson(TWIN);
  exp.unavailable_artifacts = Array.from({ length: 25 }, (_, i) => ({
    kind: "chain_seal",
    sequence_number: i + 1,
  }));
  const { human } = await fullRun(exp);
  assertStringIncludes(human, "  [--] the chain seal at sequence 20");
  assert(!human.includes("the chain seal at sequence 21"), "past the display cap");
  assertStringIncludes(human, "and 5 more declared the same way (not shown)");
});

// ---------------------------------------------------------------------------
// The library entry point, called by someone who skipped the gate.
// ---------------------------------------------------------------------------
Deno.test("declaredUnavailableArtifacts: absent ⇒ null, unusable ⇒ DECLARED, never silence", () => {
  assertEquals(declaredUnavailableArtifacts({}), null);
  assertEquals(declaredUnavailableArtifacts({ unavailable_artifacts: null }), null);
  assertEquals(declaredUnavailableArtifacts(null), null);
  assertEquals(declaredUnavailableArtifacts("nope"), null);

  // F4 discipline: present but not an array is stated, not flattened to [].
  const notArray = declaredUnavailableArtifacts({ unavailable_artifacts: { kind: "chain_seal" } });
  assertEquals(notArray?.entries, []);
  assertEquals(notArray?.unreadable, 1);
  assertEquals(notArray?.semantics, UNAVAILABLE_SEMANTICS);

  // Elements that are not rule-14 entries are counted, never guessed at.
  const mixed = declaredUnavailableArtifacts({
    unavailable_artifacts: [
      { kind: "chain_seal", sequence_number: 4 },
      { kind: "nope", anchor_date: "2026-07-06" },
      { kind: "chain_seal", anchor_date: "2026-07-06" },
      { kind: "ots_receipt", anchor_date: "not-a-date" },
      "string",
      null,
    ],
  });
  assertEquals(mixed?.entries, [{
    kind: "chain_seal",
    anchor_date: null,
    sequence_number: 4,
    contradicted: false,
  }]);
  assertEquals(mixed?.unreadable, 5);
});

Deno.test("declaredUnavailableArtifacts: hostile graphs neither run code nor throw", () => {
  // Accessors are treated as absent — never invoked (the find.ts/trace.ts
  // discipline). If this regressed, `touched` would flip.
  let touched = false;
  const hostile = {
    unavailable_artifacts: [
      Object.defineProperty({ kind: "chain_seal" }, "sequence_number", {
        enumerable: true,
        get() {
          touched = true;
          return 1;
        },
      }),
    ],
  };
  const r = declaredUnavailableArtifacts(hostile);
  assertEquals(touched, false, "a getter must never be invoked");
  assertEquals(r?.entries, []);
  assertEquals(r?.unreadable, 1);

  // A Proxy whose reflective steps throw yields "not readable", not a crash.
  const trap = new Proxy([{ kind: "chain_seal", sequence_number: 1 }], {
    getOwnPropertyDescriptor() {
      throw new Error("boom");
    },
  });
  const t = declaredUnavailableArtifacts({ unavailable_artifacts: trap });
  assertEquals(t?.entries, []);
  assert((t?.unreadable ?? 0) >= 1);

  // Self-referential data is data, not a hang.
  // deno-lint-ignore no-explicit-any
  const cyclic: any = { kind: "ots_receipt", anchor_date: "2026-07-06" };
  cyclic.self = cyclic;
  const c = declaredUnavailableArtifacts({ unavailable_artifacts: [cyclic] });
  assertEquals(c?.entries.length, 1);
});

Deno.test("library callers: the gate and the reader agree, and the renderer trusts neither blindly", async () => {
  // `undefined` as a VALUE and "no such member" are the same thing to a
  // descriptor read, but not to the gate, which uses `in`. The two must
  // refuse the same document, or a value the CLI calls malformed would be
  // rendered as a fact by a library caller.
  const base = readJson(TWIN);
  for (
    const el of [
      { kind: "chain_seal", sequence_number: 3, anchor_date: undefined },
      { kind: "ots_receipt", anchor_date: "2026-07-06", sequence_number: undefined },
    ]
  ) {
    const doc = { ...base, unavailable_artifacts: [el] };
    assert(exportShapeProblems(doc).length > 0, `gate must refuse ${JSON.stringify(el)}`);
    assertEquals(
      declaredUnavailableArtifacts(doc)?.entries,
      [],
      "and the reader must refuse it too",
    );
  }

  // A hand-built report is the one way a kind outside the enumeration can
  // reach the renderer. It is counted, never described as an empty artifact.
  const { chain, anchors, result, properties } = await fullRun(readJson(TWIN));
  const human = renderHuman(readJson(TWIN).tenant_id, chain, anchors, result, properties, [], {
    semantics: UNAVAILABLE_SEMANTICS,
    entries: [{ kind: "receipt_of_nothing", anchor_date: "2026-07-06", sequence_number: null }],
    unreadable: 0,
    truncated: 0,
    note: "n/a",
    // deno-lint-ignore no-explicit-any
  } as any);
  assert(!human.includes("undefined"), human);
  assertStringIncludes(human, "1 declaration(s) in this document are not readable");
});

Deno.test("declaredUnavailableArtifacts: the read cap is declared, not silently applied", () => {
  const many = Array.from({ length: UNAVAILABLE_READ_CAP + 7 }, (_, i) => ({
    kind: "chain_seal",
    sequence_number: i + 1,
  }));
  const r = declaredUnavailableArtifacts({ unavailable_artifacts: many });
  assertEquals(r?.entries.length, UNAVAILABLE_READ_CAP);
  assertEquals(r?.truncated, 7);
  assertEquals(r?.unreadable, 0);
});
