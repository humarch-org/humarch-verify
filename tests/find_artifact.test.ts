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

const TENANT = "c4e2a1bb-3d5f-4e7a-9b2c-0d8f6e4a3c1b";
const ARTIFACT = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
const MESSAGE_ID_DIGEST = "b2c76efb2f60c6acd44f4437a3f2f95acb01e73bcb9d4761994c1747db66b0c8";
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
