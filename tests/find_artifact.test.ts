// --find-artifact gate (D100, SPEC 1.4.0 §1.2.5): the lexical artifact
// search is ADDITIVE and INFORMATIVE — the invariants pinned here, modeled
// on qualified.test.ts (the D98 exit-neutrality precedent):
//   * EXIT NEUTRALITY — with/without the flag, the result and exit code are
//     identical on verified-shaped AND tampered exports; zero matches change
//     nothing; a non-hex argument is a usage error (exit 4);
//   * NO PAYLOAD TEXT in the output — a hostile payload string (control
//     bytes) never reaches the terminal, even when it sits next to a match
//     (the V2 discipline: only the validated hash and shape-checked fields
//     are interpolated);
//   * RANGE HONESTY — a match beyond the point of rupture of a tampered
//     export is reported but marked OUTSIDE the verified range.
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";
import {
  eventHash,
  expectedKeyId,
  fromHex,
  genesisHash,
  jcsHash,
  toHex,
  verifyChain,
} from "../src/verify.ts";
import { findArtifact, isArtifactTarget } from "../src/find.ts";
import { displaySafe, jsonSafe, renderArtifactSearch, renderHuman } from "../src/render.ts";
import { exportShapeProblems } from "../src/shape.ts";

const TENANT = "c4e2a1bb-3d5f-4e7a-9b2c-0d8f6e4a3c1b";
const ARTIFACT = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
const MESSAGE_ID_DIGEST = "cd71135384f140d325708ac71da6a6705a603e362042abfcc956c9781a589e50";
const goldenPath = new URL("../vectors/export-v2v3.json", import.meta.url);

// Internally consistent export over the given payloads (the
// convention_neutrality.test.ts method: fresh key, genesis-anchored, densely
// sequenced). Returns the export AND the public key so a test can attribute
// it via --pubkey (legitimate for a local fixture, never a product behavior).
// deno-lint-ignore no-explicit-any
async function buildExport(payloads: unknown[]): Promise<{ exp: any; pubHex: string }> {
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
      event_id: `0000000${seq}-3333-4444-8555-666666666666`,
      tenant_id: TENANT,
      sequence_number: seq,
      received_at: `2026-08-02T09:41:0${seq}.000000Z`,
      occurred_at: `2026-08-02T09:41:0${seq}.000000Z`,
      source: "generic",
      event_type: "agent_action",
      actor: { type: "agent", id: "langgraph-orchestrator" },
      subject: {
        workflow: { ref: "pipeline-orders-v2" },
        end_client: { ref: "acme-ltd" },
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
    exp: {
      format: "humarch-export/v1",
      generated_at: "2026-08-02T12:00:00.000000Z",
      tenant_id: TENANT,
      range: { from_sequence: 1, to_sequence: payloads.length },
      genesis_note: "synthetic export for the D100 find-artifact gate",
      signing_keys: [{
        signing_key_id: keyId,
        algorithm: "ed25519",
        public_key: pubHex,
        created_at: "2026-08-02T00:00:00.000000Z",
        retired_at: null,
      }],
      events,
      anchors: [],
    },
    pubHex,
  };
}

const declaringPayloads = () => [
  { action: "start", note: "no references here" },
  {
    action: "confirm_order",
    external_refs: [
      { artifact_sha256: ARTIFACT },
      { system: "shopify", ref: "5723911058629" },
      { message_id_sha256: MESSAGE_ID_DIGEST },
    ],
    execution: { ref: "sess-9c44be02" },
  },
  {
    action: "send_email",
    tool_call: {
      name: "send_email",
      result: { message_sha256: ARTIFACT },
      status: "ok",
    },
  },
];

// ---------------------------------------------------------------------------
// Unit level: the pure search.
// ---------------------------------------------------------------------------
Deno.test("findArtifact: matches any payload string value, case-insensitive, in sequence order", async () => {
  const { exp } = await buildExport(declaringPayloads());
  const chain = await verifyChain(exp);
  assertEquals(chain.verified_through_sequence, 3);

  const matches = findArtifact(
    exp,
    ARTIFACT.toUpperCase(), // the CLI lowercases; the function tolerates either
    chain.verified_from_sequence,
    chain.verified_through_sequence,
  );
  assertEquals(matches.map((m) => m.sequence_number), [2, 3]);
  assert(matches.every((m) => m.within_verified_range));
  assertEquals(matches[0].event_type, "agent_action");

  // The message-id digest matches only event 2 — equality, not substring.
  const mid = findArtifact(exp, MESSAGE_ID_DIGEST, 1, 3);
  assertEquals(mid.map((m) => m.sequence_number), [2]);

  // Zero matches: empty, never a throw.
  assertEquals(findArtifact(exp, "0".repeat(64), 1, 3), []);
});

Deno.test("findArtifact: values only, never keys", async () => {
  // The target as a map KEY must not match (ids are recommended as values).
  const asKey = { action: "x", refs: { [ARTIFACT]: true } };
  const { exp } = await buildExport([asKey]);
  assertEquals(findArtifact(exp, ARTIFACT, 1, 1), []);
});

Deno.test("findArtifact: hostile nesting never crashes (iterative walk)", () => {
  // 100k-deep nesting: a recursive walk would blow the stack here. The
  // search runs directly on the parsed object (a hand-crafted export never
  // reaches jcsHash through this path — findArtifact is hash-agnostic).
  // deno-lint-ignore no-explicit-any
  let deep: any = { artifact_sha256: ARTIFACT };
  for (let i = 0; i < 100_000; i++) deep = { nested: [deep] };
  const exp = {
    events: [{
      event_id: "00000001-3333-4444-8555-666666666666",
      event_type: "custom",
      sequence_number: 1,
      occurred_at: "2026-08-02T09:41:01.000000Z",
      payload: deep,
    }],
  };
  const matches = findArtifact(exp, ARTIFACT, 1, 1);
  assertEquals(matches.map((m) => m.sequence_number), [1]);
  assertEquals(matches[0].within_verified_range, true);
});

Deno.test("findArtifact: a match beyond the point of rupture is OUTSIDE the verified range", async () => {
  const { exp } = await buildExport(declaringPayloads());
  // Tamper event 2 (which declares the hash): the chain breaks there.
  exp.events[1].payload.note = "tampered";
  const chain = await verifyChain(exp);
  assertEquals(chain.first_failure?.sequence_number, 2);
  assertEquals(chain.verified_through_sequence, 1);
  const matches = findArtifact(
    exp,
    ARTIFACT,
    chain.verified_from_sequence,
    chain.verified_through_sequence,
  );
  assertEquals(matches.map((m) => m.sequence_number), [2, 3]);
  assert(matches.every((m) => !m.within_verified_range));
});

Deno.test("isArtifactTarget: 64 hex only", () => {
  assert(isArtifactTarget(ARTIFACT));
  assert(isArtifactTarget(ARTIFACT.toUpperCase()));
  assert(!isArtifactTarget(ARTIFACT.slice(0, 63)));
  assert(!isArtifactTarget(ARTIFACT + "0"));
  assert(!isArtifactTarget("not-a-hash"));
  assert(!isArtifactTarget(""));
});

// ---------------------------------------------------------------------------
// CLI level: exit neutrality, rendering, injection.
// ---------------------------------------------------------------------------
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

Deno.test("cli exit neutrality: with/without --find-artifact, same exit on attributed, unattributed and tampered exports", async () => {
  const { exp, pubHex } = await buildExport(declaringPayloads());
  await withTempExport(exp, async (tmp) => {
    // Attributed (local fixture key via --pubkey): partial, exit 5.
    const base = await runCli(tmp, "--pubkey", pubHex);
    assertEquals(base.code, 5, base.stderr);
    const flagged = await runCli(tmp, "--pubkey", pubHex, "--find-artifact", ARTIFACT);
    assertEquals(flagged.code, base.code, "a match must not move the exit code");
    // No trusted set: exit 6, matches or not.
    const un = await runCli(tmp);
    const unFlagged = await runCli(tmp, "--find-artifact", ARTIFACT);
    assertEquals(un.code, 6);
    assertEquals(unFlagged.code, 6);
  });

  // Tampered: exit 2 with and without the flag, match or no match.
  const tampered = await buildExport(declaringPayloads());
  tampered.exp.events[1].payload.note = "tampered";
  await withTempExport(tampered.exp, async (tmp) => {
    const base = await runCli(tmp, "--pubkey", tampered.pubHex);
    assertEquals(base.code, 2, base.stderr);
    for (const target of [ARTIFACT, "0".repeat(64)]) {
      const flagged = await runCli(tmp, "--pubkey", tampered.pubHex, "--find-artifact", target);
      assertEquals(flagged.code, 2, `tampered exit must not move (target ${target.slice(0, 8)})`);
    }
  });

  // Zero matches on the golden export: exit unchanged (6, no issuer).
  const zero = await runCli(fromFileUrl(goldenPath), "--find-artifact", "0".repeat(64));
  assertEquals(zero.code, 6, zero.stderr);
  assertStringIncludes(zero.stdout, "[--] Found: 0 events declaring this hash");
});

Deno.test("cli: non-hex --find-artifact argument is a usage error (exit 4)", async () => {
  for (const bad of ["nope", ARTIFACT.slice(0, 63), ARTIFACT + "00", "xx".repeat(32)]) {
    const r = await runCli(fromFileUrl(goldenPath), "--find-artifact", bad);
    assertEquals(r.code, 4, `expected exit 4 for ${JSON.stringify(bad)}`);
    assertStringIncludes(r.stderr, "64 hex");
  }
  const missing = await runCli(fromFileUrl(goldenPath), "--find-artifact");
  assertEquals(missing.code, 4);
});

Deno.test("cli rendering: declared wording, range position, personal note; matches beyond rupture marked OUTSIDE", async () => {
  const { exp, pubHex } = await buildExport(declaringPayloads());
  await withTempExport(exp, async (tmp) => {
    const r = await runCli(tmp, "--pubkey", pubHex, "--find-artifact", ARTIFACT);
    assertStringIncludes(r.stdout, "[--] Found: 2 events declaring this hash");
    assertStringIncludes(r.stdout, `Artifact search — ${ARTIFACT}`);
    assertStringIncludes(r.stdout, "inside the verified range (1-3)");
    assertStringIncludes(r.stdout, 'Note: encrypted payload.personal content is invisible to this search');
    // Declared, never proven: the forbidden words never render for a match.
    assert(!r.stdout.includes("Artifact search — proven"), r.stdout);
    assert(!/declaring this hash[^\n]*(verified|proven|bound)/.test(r.stdout), r.stdout);
  });

  const tampered = await buildExport(declaringPayloads());
  tampered.exp.events[1].payload.note = "tampered";
  await withTempExport(tampered.exp, async (tmp) => {
    const r = await runCli(tmp, "--pubkey", tampered.pubHex, "--find-artifact", ARTIFACT);
    assertEquals(r.code, 2);
    assertStringIncludes(r.stdout, "OUTSIDE the verified range");
    assertStringIncludes(r.stdout, "integrity is not established");
  });
});

Deno.test("cli anti-injection: hostile payload strings never reach the terminal, even next to a match", async () => {
  // A payload value carrying terminal control bytes sits in the SAME payload
  // as the declared hash: the report must carry the match without ever
  // echoing payload text (shape.ts only gates identifiers, not payloads).
  const hostile = {
    action: "confirm_order",
    external_refs: [{ artifact_sha256: ARTIFACT }],
    innocent_looking: "evil\x1b[2J\x07payload\x1b]0;owned\x07",
  };
  const { exp, pubHex } = await buildExport([hostile]);
  await withTempExport(exp, async (tmp) => {
    for (const flags of [["--find-artifact", ARTIFACT], ["--find-artifact", ARTIFACT, "--json"]]) {
      const r = await runCli(tmp, "--pubkey", pubHex, ...flags);
      assertStringIncludes(r.stdout, ARTIFACT);
      assert(
        // deno-lint-ignore no-control-regex
        !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(r.stdout + r.stderr),
        "control bytes leaked into the CLI output",
      );
      assert(!r.stdout.includes("evil"), "payload text leaked into the CLI output");
    }
  });
});

Deno.test("cli --json: artifact_search is an additive top-level key; chain/anchors/properties/result untouched", async () => {
  const { exp, pubHex } = await buildExport(declaringPayloads());
  await withTempExport(exp, async (tmp) => {
    const without = JSON.parse((await runCli(tmp, "--pubkey", pubHex, "--json")).stdout);
    const withFlag = JSON.parse(
      (await runCli(tmp, "--pubkey", pubHex, "--json", "--find-artifact", ARTIFACT)).stdout,
    );
    assertEquals(without.artifact_search, undefined);
    assertEquals(withFlag.artifact_search.target, ARTIFACT);
    assertEquals(
      withFlag.artifact_search.matches.map((m: { sequence_number: number }) => m.sequence_number),
      [2, 3],
    );
    assert(withFlag.artifact_search.matches.every(
      (m: { within_verified_range: boolean }) => m.within_verified_range,
    ));
    // Everything else is byte-equal: remove the additive key and compare.
    delete withFlag.artifact_search;
    assertEquals(withFlag, without);
  });
});

// ---------------------------------------------------------------------------
// External audit 2026-08-02 — remedies. Findings 1, 2 and 4 each get the
// reproduction that failed before the fix, at the layer the fix lives in.
// ---------------------------------------------------------------------------

Deno.test("audit F1: a duplicated sequence number never credits an unverified event (positional prefix)", async () => {
  // The audit's reproduction: duplicate the sequence of a verified event and
  // tamper with the duplicate. verifyChain stops at the duplicate, so its
  // verified set is the POSITIONAL prefix - "sequence <= verified_through"
  // would wrongly include the tampered twin, which carries the same number.
  const { exp } = await buildExport(declaringPayloads());
  exp.events[1].sequence_number = 1;
  exp.events[1].payload.external_refs = [{ artifact_sha256: ARTIFACT }];
  const chain = await verifyChain(exp);
  assertEquals(chain.verified_through_sequence, 1, "the chain stops at the duplicate");
  const matches = findArtifact(
    exp,
    ARTIFACT,
    chain.verified_from_sequence,
    chain.verified_through_sequence,
  );
  const dup = matches.find((m) => m.sequence_number === 1);
  assert(dup !== undefined, "the duplicated event is still reported");
  assertEquals(
    dup?.within_verified_range,
    false,
    "an event past the first repetition is never inside the verified range",
  );
  assert(
    matches.every((m) => !m.within_verified_range),
    "nothing after the rupture may claim integrity",
  );
});

Deno.test("audit F1: the shape gate refuses duplicate sequence numbers and duplicate event ids (exit 4)", async () => {
  const { exp, pubHex } = await buildExport(declaringPayloads());

  const dupSeq = structuredClone(exp);
  dupSeq.events[1].sequence_number = 1;
  assert(
    exportShapeProblems(dupSeq).some((p: string) => p.includes("duplicate sequence number")),
    "duplicate sequence_number is a form error",
  );

  const dupId = structuredClone(exp);
  dupId.events[1].event_id = dupId.events[0].event_id;
  assert(
    exportShapeProblems(dupId).some((p: string) => p.includes("duplicate event_id")),
    "duplicate event_id is a form error",
  );

  // A genuine export stays well-formed (no false positive on the new rule).
  assertEquals(exportShapeProblems(exp), []);

  // End to end: the CLI stops at the boundary instead of issuing a verdict.
  await withTempExport(dupSeq, async (tmp) => {
    const r = await runCli(tmp, "--pubkey", pubHex, "--find-artifact", ARTIFACT);
    assertEquals(r.code, 4, r.stdout);
    assertStringIncludes(r.stderr, "duplicate sequence number");
    assertEquals(r.stdout, "", "no verdict, no search output on malformed input");
  });
});

Deno.test("audit F2: bidi and C1 characters are refused by the gate and escaped by the renderer", async () => {
  const BIDI_OVERRIDE = String.fromCharCode(0x202e);
  const ISOLATE = String.fromCharCode(0x2066);
  const C1 = String.fromCharCode(0x9b);

  // Layer 1 - the shape gate: machine fields carrying them are malformed.
  const { exp, pubHex } = await buildExport(declaringPayloads());
  const spoofed = structuredClone(exp);
  spoofed.events[1].event_type = "agent_action" + BIDI_OVERRIDE + "]DEIFIREV[" + ISOLATE;
  assert(
    exportShapeProblems(spoofed).some((p: string) => p.includes("events[1].event_type")),
    "a bidi override in a machine field is a form error",
  );
  await withTempExport(spoofed, async (tmp) => {
    const r = await runCli(tmp, "--pubkey", pubHex, "--find-artifact", ARTIFACT);
    assertEquals(r.code, 4, r.stdout);
    assert(!r.stdout.includes(BIDI_OVERRIDE), "no raw bidi override on stdout");
    assert(!r.stderr.includes(BIDI_OVERRIDE), "no raw bidi override on stderr");
  });

  // Layer 2 - the renderer does not rest on that precondition: called
  // directly with hostile values it escapes them to their code points.
  const rendered = renderArtifactSearch(
    ARTIFACT,
    [{
      event_id: "00000001-3333-4444-8555-666666666666" + C1,
      event_type: "agent_action" + BIDI_OVERRIDE + "]DEIFIREV[" + ISOLATE,
      sequence_number: 2,
      occurred_at: "2026-08-02T09:41:02.000000Z",
      within_verified_range: true,
    }],
    1,
    3,
  );
  for (const ch of [BIDI_OVERRIDE, ISOLATE, C1]) {
    assert(!rendered.includes(ch), "hostile character rendered raw");
  }
  assertStringIncludes(rendered, "<U+202E>");
  assertStringIncludes(rendered, "<U+2066>");
  assertStringIncludes(rendered, "<U+009B>");
  // Long values are clipped rather than flooding the reader's terminal.
  const long = renderArtifactSearch(ARTIFACT, [{
    event_id: "a".repeat(5000),
    event_type: "custom",
    sequence_number: 1,
    occurred_at: "2026-08-02T09:41:02.000000Z",
    within_verified_range: true,
  }], 1, 1);
  assert(long.length < 1000, "a hostile identifier is clipped, not printed whole");
});

Deno.test("audit F2: jsonSafe escapes what JSON.stringify leaves raw, without changing any value", () => {
  const hostile = {
    a: "bidi" + String.fromCharCode(0x202e) + "end",
    b: "c1" + String.fromCharCode(0x9b) + "end",
    c: "sep" + String.fromCharCode(0x2028) + String.fromCharCode(0x2029) + "end",
    d: "zero" + String.fromCharCode(0xfeff) + "width",
    nested: { list: ["plain", "iso" + String.fromCharCode(0x2066)] },
  };
  // BOTH shapes: compact, and the pretty-printed form the CLI actually
  // prints. The indented document carries REAL newlines as structure —
  // escaping those would produce invalid JSON, so the exemption is part of
  // the contract, not an implementation detail.
  for (const raw of [JSON.stringify(hostile), JSON.stringify(hostile, null, 2)]) {
    const safe = jsonSafe(raw);
    // Value preservation is the whole point: same object after a round trip.
    assertEquals(JSON.parse(safe), hostile);
    // And the stream carries none of those characters, bar the structure.
    const leftovers = [...safe].filter((ch) =>
      /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(ch) && !["\n", "\r", "\t"].includes(ch)
    );
    assertEquals(leftovers, [], "escaped stream is clean");
    assert(/[\p{Cf}]/u.test(raw), "the raw stringify output did carry them");
  }
});

Deno.test("audit F4: a cyclic payload terminates, and hostile accessors are never invoked", () => {
  // Cycle: impossible from JSON.parse, trivial for a direct API caller. Before
  // the fix this call never returned.
  // deno-lint-ignore no-explicit-any
  const cyclic: any = { external_refs: [{ artifact_sha256: ARTIFACT }] };
  cyclic.self = cyclic;
  cyclic.deep = { back: cyclic, list: [cyclic, { again: cyclic }] };
  const cyclicExp = {
    events: [{
      event_id: "00000001-3333-4444-8555-666666666666",
      event_type: "custom",
      sequence_number: 1,
      occurred_at: "2026-08-02T09:41:01.000000Z",
      payload: cyclic,
    }],
  };
  assertEquals(findArtifact(cyclicExp, ARTIFACT, 1, 1).length, 1);

  // Accessors: reading a getter is running someone else's code inside the
  // verifier. The walk reads data descriptors only.
  let getterCalls = 0;
  const withGetter = {};
  Object.defineProperty(withGetter, "trap", {
    enumerable: true,
    get() {
      getterCalls++;
      throw new Error("hostile getter invoked");
    },
  });
  Object.defineProperty(withGetter, "plain", {
    enumerable: true,
    value: { artifact_sha256: ARTIFACT },
  });
  const getterExp = {
    events: [{
      event_id: "00000002-3333-4444-8555-666666666666",
      event_type: "custom",
      sequence_number: 1,
      occurred_at: "2026-08-02T09:41:01.000000Z",
      payload: withGetter,
    }],
  };
  assertEquals(findArtifact(getterExp, ARTIFACT, 1, 1).length, 1, "data properties still scanned");
  assertEquals(getterCalls, 0, "the getter was never invoked");

  // A Proxy whose reflective traps throw yields "no children", never a throw.
  const hostileProxy = new Proxy({}, {
    ownKeys() {
      throw new Error("ownKeys trap");
    },
    getOwnPropertyDescriptor() {
      throw new Error("descriptor trap");
    },
  });
  const proxyExp = {
    events: [{
      event_id: "00000003-3333-4444-8555-666666666666",
      event_type: "custom",
      sequence_number: 1,
      occurred_at: "2026-08-02T09:41:01.000000Z",
      payload: { hostileProxy, ref: { artifact_sha256: ARTIFACT } },
    }],
  };
  assertEquals(findArtifact(proxyExp, ARTIFACT, 1, 1).length, 1);
});

// ---------------------------------------------------------------------------
// Adversarial review of the remedies (2026-08-02). Each of these is a hole the
// first round of fixes left open, pinned at the layer that now closes it.
// ---------------------------------------------------------------------------

Deno.test("review: stderr carries no attacker bytes on the malformed-input path (V8 quotes the file verbatim)", async () => {
  // JSON.parse's SyntaxError embeds ~20 characters of the offending input. The
  // CLI used to echo that message, so a file starting with terminal escapes
  // drove the reader's terminal BEFORE any shape gate could run - and a
  // fabricated "RESULT: VERIFIED" line could be planted in the transcript.
  const ESC = String.fromCharCode(27);
  const BEL = String.fromCharCode(7);
  const hostile = '{"format":"humarch-export/v1","events":' + ESC + "[2J" + ESC + "[H" + ESC +
    "[31mRESULT: VERIFIED" + BEL + "}";
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, hostile);
  try {
    const r = await runCli(tmp);
    assertEquals(r.code, 4);
    const printable = /^[\x20-\x7E\n]*$/;
    assert(printable.test(r.stderr), "stderr must be printable ASCII: " + JSON.stringify(r.stderr));
    assert(printable.test(r.stdout), "stdout must be printable ASCII");
    assert(!r.stderr.includes("RESULT"), "no attacker text is echoed at all");
    assertEquals(r.stderr.split("\n").filter((l) => l.length > 0).length, 1, "one line, one message");
  } finally {
    await Deno.remove(tmp);
  }
});

Deno.test("review: findArtifact bounds are fail-SAFE - undefined or NaN means nothing is verified", async () => {
  const { exp } = await buildExport(declaringPayloads());
  // deno-lint-ignore no-explicit-any
  const call = findArtifact as any;
  for (const [from, through] of [[undefined, undefined], [1, undefined], [NaN, 3], [1, NaN], ["1", "3"]]) {
    const matches = call(exp, ARTIFACT, from, through);
    assert(matches.length > 0, "the matches themselves are still reported");
    assert(
      matches.every((m: { within_verified_range: boolean }) => !m.within_verified_range),
      "a bound that is not a finite number must never credit an event: " + JSON.stringify([from, through]),
    );
  }
});

Deno.test("review: the walk is bounded - a generative Proxy cannot run forever", () => {
  // A Proxy minting fresh children on every enumeration defeats the visited
  // set (each child is a new object). Only the node budget stops it.
  const generative: ProxyHandler<object> = {
    ownKeys: () => ["a", "b"],
    getOwnPropertyDescriptor: () => ({
      enumerable: true,
      configurable: true,
      value: new Proxy({}, generative),
    }),
  };
  const exp = {
    events: [{
      event_id: "00000009-3333-4444-8555-666666666666",
      event_type: "custom",
      sequence_number: 1,
      occurred_at: "2026-08-02T09:41:01.000000Z",
      payload: new Proxy({}, generative),
    }],
  };
  const started = performance.now();
  const matches = findArtifact(exp, ARTIFACT, 1, 1);
  const elapsed = performance.now() - started;
  assertEquals(matches.length, 0, "no match, and above all: it returned");
  assert(elapsed < 60_000, "the budget bounds the walk (took " + Math.round(elapsed) + "ms)");
});

Deno.test("review: the shape gate is bounded and accessor-safe too (it runs BEFORE the search)", () => {
  // checkFinite walks actor/subject/payload at the trust boundary: a cyclic
  // graph used to hang it and Object.entries used to invoke hostile getters.
  // deno-lint-ignore no-explicit-any
  const cyclic: any = { a: 1 };
  cyclic.self = cyclic;
  let getterCalls = 0;
  const payload = { nested: cyclic };
  Object.defineProperty(payload, "trap", {
    enumerable: true,
    get() {
      getterCalls++;
      return Infinity;
    },
  });
  const exp = {
    format: "humarch-export/v1",
    tenant_id: "c4e2a1bb-3d5f-4e7a-9b2c-0d8f6e4a3c1b",
    events: [{
      event_id: "0000000a-3333-4444-8555-666666666666",
      tenant_id: "c4e2a1bb-3d5f-4e7a-9b2c-0d8f6e4a3c1b",
      sequence_number: 1,
      received_at: "2026-08-02T09:41:01.000000Z",
      occurred_at: "2026-08-02T09:41:01.000000Z",
      source: "generic",
      event_type: "custom",
      signing_key_id: "ed25519:0000000000000000",
      actor: { type: "agent", id: "x" },
      subject: { workflow: { ref: "w" } },
      payload,
      payload_hash: "0".repeat(64),
      prev_hash: "0".repeat(64),
      event_hash: "0".repeat(64),
      signature: "0".repeat(128),
    }],
    anchors: [],
  };
  const problems = exportShapeProblems(exp); // must return, not hang
  assertEquals(getterCalls, 0, "the gate never invokes a hostile getter");
  assert(Array.isArray(problems));
});

Deno.test("review: the verdict header escapes the export's tenant_id and slices it by code point", () => {
  const BIDI = String.fromCharCode(0x202e);
  const chain = {
    chain_continuous: true,
    signatures_valid: true,
    anchored_to_genesis: true,
    verified_from_sequence: 1,
    verified_through_sequence: 1,
    first_failure: null,
  };
  const human = renderHuman(
    "\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}" + BIDI + "admin",
    chain,
    [],
    "partial",
    { integrity: "ok", time: "unproven", attribution: "not_checked" },
  );
  assert(!human.includes(BIDI), "no raw bidi override in the header");
  assert(!human.includes("\uFFFD"), "no replacement character: the slice respects code points");
});

Deno.test("review: a provider-supplied TSA name keeps a format character (the gate must not make our own day unverifiable)", () => {
  // The registry stores the name read from the QTSP certificate; the reader
  // strips controls but keeps LRM/soft hyphen. If the export gate refused
  // them, one legitimate QTSP name would make an anchored day unverifiable
  // for every tenant. The gate refuses controls only; the renderer escapes.
  const LRM = String.fromCharCode(0x200e);
  const exp = JSON.parse(
    Deno.readTextFileSync(new URL("../vectors/qualified/export-qualified.json", import.meta.url)),
  );
  exp.anchors[0].qualified_timestamp.tsa_name = "InfoCert" + LRM + " Qualified TSA";
  assertEquals(
    exportShapeProblems(exp).filter((p: string) => p.includes("tsa_name")),
    [],
    "a directional mark inside a genuine name is not a form error",
  );
  // ...but a real control character still is.
  exp.anchors[0].qualified_timestamp.tsa_name = "InfoCert" + String.fromCharCode(7);
  assert(exportShapeProblems(exp).some((p: string) => p.includes("tsa_name")));
});

Deno.test("review: displaySafe keeps legitimate typography, escapes what drives a terminal", () => {
  assertEquals(displaySafe("valid · TSA — 2026-07-27"), "valid · TSA — 2026-07-27");
  assertEquals(
    displaySafe("ok" + String.fromCharCode(0x202e) + "x" + String.fromCharCode(0x9b)),
    "ok<U+202E>x<U+009B>",
  );
  assert(displaySafe("a".repeat(500)).length < 250, "notes are capped");
});

// ---------------------------------------------------------------------------
// BT-37 / BT-39 (2026-08-21) — two claims this module made that were not true
// of the code beneath them.
// ---------------------------------------------------------------------------

Deno.test("BT-37: findArtifact invokes no accessor, as its contract has always claimed", () => {
  // The module header says "Accessors are never invoked (only data property
  // descriptors are read)". `verifiedPositionalPrefix` was hardened for that
  // in the F3 remedy; these five reads in findArtifact were left as plain
  // property accesses, so on an object graph carrying getters exactly five of
  // them ran. Nothing was exploitable through the CLI, whose input is
  // JSON.parse output and carries no accessors — the DEFECT WAS THE FALSE
  // CLAIM, on an exported function a library caller may hand a live graph,
  // having been told that doing so was safe.
  let invoked = 0;
  const spy = (value: unknown) => ({
    get() {
      invoked++;
      return value;
    },
    enumerable: true,
    configurable: true,
  });
  const target = "ab".repeat(32);
  const ev = {};
  Object.defineProperties(ev, {
    sequence_number: spy(1),
    event_id: spy("e1"),
    event_type: spy("agent_action"),
    occurred_at: spy("2026-07-06T10:00:00.000000Z"),
    payload: spy({ external_refs: [{ artifact_sha256: target }] }),
  });
  const exp = { tenant_id: "t", events: [ev] };

  const matches = findArtifact(exp, target, 1, 1);
  assertEquals(invoked, 0, `${invoked} accessor(s) ran on a walk that promises none`);
  // And the walk is not merely silent: a genuine graph still produces the
  // same answer, so the hardening did not buy safety by breaking the feature.
  assertEquals(
    findArtifact(
      {
        tenant_id: "t",
        events: [{
          sequence_number: 1,
          event_id: "e1",
          event_type: "agent_action",
          occurred_at: "2026-07-06T10:00:00.000000Z",
          payload: { external_refs: [{ artifact_sha256: target }] },
        }],
      },
      target,
      1,
      1,
    ).length,
    1,
  );
  // Accessor-only members are invisible rather than trusted: fail-closed.
  assertEquals(matches.length, 0);
});

Deno.test("BT-39: --find-artifact renders refs through refSafe, like --trace", () => {
  // The F2 audit introduced refSafe because terminalSafe passes every
  // printable ASCII character — spaces, quotes and pipes included — so a
  // hostile 48-character identifier can compose words and a verdict
  // look-alike fragment. --trace was moved onto it; --find-artifact was left
  // on the looser sink. One lane hardened, its sibling not.
  const rendered = renderArtifactSearch(
    "cd".repeat(32),
    [{
      event_id: "RESULT: VERIFIED | all good",
      event_type: 'x" OK ok',
      sequence_number: 1,
      occurred_at: "2026-07-06T10:00:00.000000Z",
      within_verified_range: true,
    }],
    1,
    1,
  );
  // With the space escaped no phrase can render at all.
  assert(!rendered.includes("RESULT: VERIFIED"), rendered);
  assert(!rendered.includes("| all good"), rendered);
  assertStringIncludes(rendered, "<U+0020>", "spaces escape, so words cannot form");
  assertStringIncludes(rendered, "<U+0022>", "quotes escape, so delimiters hold");
  // The legitimate identifier characters still render as themselves: this
  // must stay readable for the honest case, which is every real case.
  assertStringIncludes(rendered, "2026-07-06T10:00:00.000000Z");
});
