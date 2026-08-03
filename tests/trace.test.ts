// --trace gate (D101): the declared-ancestry walk is ADDITIVE and
// INFORMATIVE — the invariants pinned here, modeled on find_artifact.test.ts
// (the D100 exit-neutrality precedent):
//   * EXIT NEUTRALITY — with/without the flag, the result and exit code are
//     identical on verified-shaped AND tampered exports; a target that is
//     not in the export changes nothing; a non-UUID argument is a usage
//     error (exit 4);
//   * SEMANTICS HEADER — the exact D101 sentence opens the rendering (human
//     and JSON), and the forbidden formulations never appear anywhere in
//     the trace output;
//   * HOP GRANULARITY — an exact hop (parent.event_id) and a run-level hop
//     (parent.ref → the SET of events declaring that execution.ref) render
//     with different words, and a membership hop (the traced event's own
//     run) with different words again;
//   * SANITIZED REFS — payload refs cross into the output only through
//     terminalSafe: control bytes and bidi never reach the terminal, long
//     refs are clipped, and no other payload text renders at all (V2);
//   * RANGE HONESTY — every node is positioned against the POSITIONAL
//     verified prefix; nodes beyond the point of rupture are marked OUTSIDE.
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
import {
  ANCESTRY_NOTE,
  ANCESTRY_SEMANTICS,
  isTraceTarget,
  TRACE_DEPTH_CAP,
  TRACE_MEMBER_CAP,
  TRACE_TARGET_CAP,
  traceAncestry,
  type TraceRunNode,
} from "../src/trace.ts";
import { jsonSafe, refSafe, renderAncestry } from "../src/render.ts";
import { verifiedPositionalPrefix } from "../src/find.ts";

const TENANT = "c4e2a1bb-3d5f-4e7a-9b2c-0d8f6e4a3c1b";
const goldenPath = new URL("../vectors/export-v2v3.json", import.meta.url);

/** Stable per-sequence event ids, valid UUIDs (the CLI validates --trace). */
const evId = (seq: number): string => `${String(seq).padStart(8, "0")}-aaaa-4bbb-8ccc-dddddddddddd`;

interface Item {
  event_type?: string;
  payload: unknown;
}

// Internally consistent export over the given payloads (the
// find_artifact.test.ts method: fresh key, genesis-anchored, densely
// sequenced). Returns the export AND the public key so a test can attribute
// it via --pubkey (legitimate for a local fixture, never a product behavior).
// deno-lint-ignore no-explicit-any
async function buildExport(items: Item[]): Promise<{ exp: any; pubHex: string }> {
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
  for (let i = 0; i < items.length; i++) {
    const seq = i + 1;
    const ev = {
      event_id: evId(seq),
      tenant_id: TENANT,
      sequence_number: seq,
      received_at: `2026-08-03T09:41:${String(seq).padStart(2, "0")}.000000Z`,
      occurred_at: `2026-08-03T09:41:${String(seq).padStart(2, "0")}.000000Z`,
      source: "n8n",
      event_type: items[i].event_type ?? "agent_action",
      actor: { type: "agent", id: "n8n-sub-worker" },
      subject: {
        workflow: { ref: "wf_311" },
        end_client: { ref: "beta-corp" },
      },
      payload: items[i].payload,
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
    events.push({
      ...ev,
      payload_hash,
      prev_hash: prev,
      event_hash: eh,
      signature,
      signing_key_id: keyId,
    });
    prev = eh;
  }

  return {
    exp: {
      format: "humarch-export/v1",
      generated_at: "2026-08-03T12:00:00.000000Z",
      tenant_id: TENANT,
      range: { from_sequence: 1, to_sequence: items.length },
      genesis_note: "synthetic export for the D101 trace gate",
      signing_keys: [{
        signing_key_id: keyId,
        algorithm: "ed25519",
        public_key: pubHex,
        created_at: "2026-08-03T00:00:00.000000Z",
        retired_at: null,
      }],
      events,
      anchors: [],
    },
    pubHex,
  };
}

/**
 * The readability case (D101): the n8n delegation-chain fixture extended
 * into a full export — real n8n execution-id forms (numeric strings), the
 * delegation declared once per run on its start event, the contested event
 * an action carrying only its own execution.ref. Chain to read: action →
 * its run (84211) → the delegating event of run 84210 (exact, from the 202
 * echo) → the root run 84203.
 */
const n8nChain = (): Item[] => [
  { event_type: "workflow_run", payload: { phase: "start", execution: { ref: "84203" } } },
  { payload: { action: "collect_leads", execution: { ref: "84203" } } },
  {
    event_type: "workflow_run",
    payload: {
      phase: "start",
      execution: { ref: "84210" },
      delegation: { parent: { ref: "84203" }, root: { ref: "84203" }, depth: 1 },
    },
  },
  {
    event_type: "workflow_run",
    payload: {
      phase: "start",
      execution: { ref: "84211" },
      delegation: {
        parent: { ref: "84210", event_id: evId(3) },
        root: { ref: "84203" },
        depth: 2,
      },
    },
  },
  {
    payload: {
      action: "enrich_contact",
      execution: { ref: "84211" },
      tool_call: { name: "enrich_contact", status: "ok" },
    },
  },
];

const FORBIDDEN =
  /verified ancestry|proven ancestry|\bcaused\b|\bcauses\b|\bcausation\b|\bproves\b|reconstructs why/i;

/**
 * The multi-word forbidden formulations — the composition refSafe must make
 * impossible (F2, external audit 2026-08-03). Output that renders HOSTILE
 * refs is held to this phrase set plus the verdict-line checks below, not to
 * the bare single words: any alphabet that admits letters admits "caused" as
 * an identifier token, and an escaped token inside a quoted ref is the
 * export's text, not the verifier speaking. What must never survive is
 * composition: phrases (the space escapes away) and verdict look-alike
 * lines (quotes, pipes and newlines escape away).
 */
const FORBIDDEN_PHRASES =
  /(verified|proven|proved)\s+ancestry|proven\s+causation|reconstructs\s+why/i;

/**
 * The banned-formulations check: strip the exact header sentence first.
 * `refsHostile` selects the phrase-level set (see FORBIDDEN_PHRASES); the
 * methodological hole F2 exposed was that this check only ever ran on output
 * generated from OUR strings — it now runs on hostile-payload output too.
 */
function assertWordingDiscipline(traceOutput: string, refsHostile = false): void {
  assertStringIncludes(traceOutput, ANCESTRY_SEMANTICS);
  const stripped = traceOutput.split(ANCESTRY_SEMANTICS).join("");
  const forbidden = refsHostile ? FORBIDDEN_PHRASES : FORBIDDEN;
  assert(
    !forbidden.test(stripped),
    "forbidden formulation in the trace output: " + JSON.stringify(stripped.match(forbidden)),
  );
  // A line that reads as a verdict is the damage before any banned word is
  // (F2): the trace section must never carry the verdict phrase, nor a line
  // that opens like the verdict line.
  assert(!stripped.includes("RESULT: VERIFIED"), "verdict phrase in the trace output");
  assert(!/^\s*RESULT:/m.test(stripped), "verdict-shaped line in the trace output");
}

// ---------------------------------------------------------------------------
// Unit level: the pure walk.
// ---------------------------------------------------------------------------

Deno.test("traceAncestry: the n8n readability chain — membership, exact and run-level hops in order", async () => {
  const { exp } = await buildExport(n8nChain());
  const chain = await verifyChain(exp);
  assertEquals(chain.verified_through_sequence, 5);

  const [t] = traceAncestry(
    exp,
    [evId(5)],
    chain.verified_from_sequence,
    chain.verified_through_sequence,
  );
  assert(t.found_in_export);
  assertEquals(t.end, "root_of_declared_chain");
  assertEquals(t.chain.map((n) => n.kind), ["event", "run", "event", "run"]);
  assertEquals(
    t.chain.map((n) => n.hop),
    ["start", "membership", "exact", "run"],
  );

  const [start, ownRun, parentEvent, rootRun] = t.chain;
  assert(start.kind === "event" && start.event.event_id === evId(5));
  assertEquals(start.kind === "event" ? start.execution_ref : null, "84211");
  assert(ownRun.kind === "run" && ownRun.ref === "84211");
  assertEquals(ownRun.kind === "run" ? ownRun.events_total : 0, 2); // e4 and e5
  assert(parentEvent.kind === "event" && parentEvent.event.event_id === evId(3));
  assert(rootRun.kind === "run" && rootRun.ref === "84203");
  assertEquals(rootRun.kind === "run" ? rootRun.events_total : 0, 2); // e1 and e2
  // Everything verified: every node inside the positional prefix.
  assert(t.chain.every((n) => n.kind !== "event" || n.event.within_verified_range));
});

Deno.test("traceAncestry: an own declaration wins — the exact hop needs no membership step", async () => {
  const { exp } = await buildExport(n8nChain());
  const [t] = traceAncestry(exp, [evId(4)], 1, 5);
  assertEquals(t.chain.map((n) => n.hop), ["start", "exact", "run"]);
  const start = t.chain[0];
  // Declared root and depth are printed facts of the start node, never
  // compared with the walk's outcome.
  assert(start.kind === "event");
  assertEquals(start.declared_root_ref, "84203");
  assertEquals(start.declared_depth, 2);
});

Deno.test("traceAncestry: a target that is not in the export is declared, never a throw", async () => {
  const { exp } = await buildExport(n8nChain());
  const [t] = traceAncestry(exp, ["ffffffff-ffff-4fff-8fff-ffffffffffff"], 1, 5);
  assertEquals(t.found_in_export, false);
  assertEquals(t.chain, []);
  assertEquals(t.end, "target_not_found");
});

Deno.test("traceAncestry: an unresolved exact parent stops the walk — no fallback to the run", async () => {
  const missingId = "eeeeeeee-1111-4222-8333-444444444444";
  const { exp } = await buildExport([
    { payload: { execution: { ref: "84210" }, note: "the declared run DOES exist here" } },
    {
      payload: {
        execution: { ref: "84211" },
        delegation: { parent: { ref: "84210", event_id: missingId } },
      },
    },
  ]);
  const [t] = traceAncestry(exp, [evId(2)], 1, 2);
  assertEquals(t.end, "parent_not_in_export");
  const last = t.chain[t.chain.length - 1];
  assert(last.kind === "missing" && last.hop === "exact");
  assertEquals(last.declared_event_id, missingId);
  // The declared run id is still shown — but the walk did NOT resolve it
  // (granularity stays what the child declared, D101).
  assertEquals(last.declared_ref, "84210");
  assertEquals(t.chain.filter((n) => n.kind === "run").length, 0);
});

Deno.test("traceAncestry: an unresolved run is declared as such", async () => {
  const { exp } = await buildExport([
    { payload: { execution: { ref: "84211" }, delegation: { parent: { ref: "99999" } } } },
  ]);
  const [t] = traceAncestry(exp, [evId(1)], 1, 1);
  assertEquals(t.end, "parent_not_in_export");
  const last = t.chain[t.chain.length - 1];
  assert(last.kind === "missing" && last.hop === "run");
  assertEquals(last.declared_ref, "99999");
});

Deno.test("traceAncestry: a declared cycle is data — reported and stopped, never a hang", async () => {
  const { exp } = await buildExport([
    { payload: { execution: { ref: "run-a" }, delegation: { parent: { ref: "run-b" } } } },
    { payload: { execution: { ref: "run-b" }, delegation: { parent: { ref: "run-a" } } } },
  ]);
  const [t] = traceAncestry(exp, [evId(1)], 1, 2);
  assertEquals(t.end, "cycle_declared");
  const last = t.chain[t.chain.length - 1];
  assert(last.kind === "run" && last.repeated, "the closing point is marked repeated");
});

Deno.test("traceAncestry: the depth cap bounds a deep declared chain and is declared", () => {
  // Pure synthetic export (the walk is hash-agnostic): 70 runs, each
  // delegating to the previous one. Null bounds → nothing is verified
  // (fail-safe), which this test also pins.
  // deno-lint-ignore no-explicit-any
  const events: any[] = [];
  for (let seq = 1; seq <= 70; seq++) {
    events.push({
      event_id: evId(seq),
      event_type: "workflow_run",
      sequence_number: seq,
      received_at: `2026-08-03T10:00:${String(seq % 60).padStart(2, "0")}.000000Z`,
      payload: {
        execution: { ref: `r${seq}` },
        ...(seq > 1 ? { delegation: { parent: { ref: `r${seq - 1}` } } } : {}),
      },
    });
  }
  const [t] = traceAncestry({ events }, [evId(70)], null, null);
  assertEquals(t.end, "depth_cap_reached");
  assertEquals(t.chain.length, TRACE_DEPTH_CAP + 1);
  // deno-lint-ignore no-explicit-any
  const everyEvent = t.chain.filter((n): n is any => n.kind === "event");
  assert(
    everyEvent.every((n) => n.event.within_verified_range === false),
    "null bounds credit nothing",
  );
});

Deno.test("traceAncestry: two contested events with shared ancestors — the second chain defers to the first (dedup)", async () => {
  const { exp } = await buildExport(n8nChain());
  const [first, second] = traceAncestry(exp, [evId(5), evId(4)], 1, 5);
  assertEquals(first.end, "root_of_declared_chain");
  assertEquals(second.end, "continues_above");
  // e4 itself was only a member LISTING of run 84211, never a walk node, so
  // its own line is fresh; its exact parent e3 was already shown.
  assertEquals(second.chain.map((n) => n.kind), ["event", "event"]);
  const deferred = second.chain[1];
  assert(deferred.kind === "event" && deferred.repeated);
  assertEquals(deferred.event.event_id, evId(3));
});

Deno.test("traceAncestry: diverging run declarations stop the walk as a declared divergence", async () => {
  const { exp } = await buildExport([
    { payload: { execution: { ref: "R" }, delegation: { parent: { ref: "P1" } } } },
    { payload: { execution: { ref: "R" }, delegation: { parent: { ref: "P2" } } } },
    { payload: { execution: { ref: "R" }, note: "the contested one declares no delegation" } },
  ]);
  const [t] = traceAncestry(exp, [evId(3)], 1, 3);
  assertEquals(t.end, "ambiguous_parents");
  const run = t.chain[t.chain.length - 1] as TraceRunNode;
  assert(run.kind === "run" && run.hop === "membership");
  assertEquals(run.distinct_parent_count, 2);
  assertEquals([...run.distinct_parent_refs].sort(), ["P1", "P2"]);
});

Deno.test("traceAncestry: completeness differences are agreement, not divergence (echo merge)", async () => {
  const idX = "eeeeeeee-1111-4222-8333-444444444444"; // not in the export
  const { exp } = await buildExport([
    { payload: { execution: { ref: "R" }, delegation: { parent: { ref: "P", event_id: idX } } } },
    { payload: { execution: { ref: "R" }, delegation: { parent: { ref: "P" } } } },
    { payload: { execution: { ref: "R" }, note: "contested" } },
  ]);
  const [t] = traceAncestry(exp, [evId(3)], 1, 3);
  // Same ref, one echo: merged into ONE parent, exact granularity (and here
  // unresolved, which ends the walk honestly).
  assertEquals(t.end, "parent_not_in_export");
  const last = t.chain[t.chain.length - 1];
  assert(last.kind === "missing" && last.hop === "exact");
  assertEquals(last.declared_event_id, idX);
  assertEquals(last.declared_ref, "P");
});

Deno.test("traceAncestry: a delegation without a usable parent identifier is declared malformed", async () => {
  const { exp } = await buildExport([
    { payload: { delegation: { parent: { note: "no ref, no event_id" } } } },
  ]);
  const [t] = traceAncestry(exp, [evId(1)], 1, 1);
  assertEquals(t.end, "malformed_declaration");
});

Deno.test("traceAncestry: refs are sanitized at the result boundary — control bytes, bidi, length", async () => {
  const hostileRef = "84\u202E10\x1b[2J";
  const longRef = "L".repeat(500);
  const { exp } = await buildExport([
    { payload: { execution: { ref: hostileRef } } },
    {
      payload: {
        execution: { ref: longRef },
        delegation: { parent: { ref: hostileRef, event_id: "not-a-uuid\x07" } },
      },
    },
  ]);
  const [t] = traceAncestry(exp, [evId(2)], 1, 2);
  const json = JSON.stringify(t);
  // deno-lint-ignore no-control-regex
  assert(!/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(json), "raw control bytes in the result");
  assert(!json.includes("\u202E"), "raw bidi override in the result");
  assertStringIncludes(json, "<U+202E>");
  assertStringIncludes(json, "<U+001B>");
  assertStringIncludes(json, "<U+0007>");
  const start = t.chain[0];
  assert(start.kind === "event" && start.execution_ref !== null);
  assert(start.execution_ref.length <= 64 + 3, "long refs are clipped in the result");
});

Deno.test("isTraceTarget: UUID only", () => {
  assert(isTraceTarget(evId(1)));
  assert(isTraceTarget("C4E2A1BB-3D5F-4E7A-9B2C-0D8F6E4A3C1B"));
  assert(!isTraceTarget("0".repeat(64)));
  assert(!isTraceTarget("c4e2a1bb-3d5f-4e7a-9b2c"));
  assert(!isTraceTarget("c4e2a1bb3d5f4e7a9b2c0d8f6e4a3c1b"));
  assert(!isTraceTarget(""));
});

// ---------------------------------------------------------------------------
// Rendering level: header, wording discipline, granularity words.
// ---------------------------------------------------------------------------

Deno.test("renderAncestry: the semantics header is pinned and the forbidden formulations never render", async () => {
  // Every wording branch: readability chain, unresolved exact, unresolved
  // run, cycle, divergence, malformed, depth cap, not-found, hostile refs.
  const outputs: string[] = [];

  const n8n = await buildExport(n8nChain());
  outputs.push(renderAncestry(traceAncestry(n8n.exp, [evId(5)], 1, 5), 1, 5));
  outputs.push(
    renderAncestry(
      traceAncestry(n8n.exp, ["ffffffff-ffff-4fff-8fff-ffffffffffff"], 1, 5),
      1,
      5,
    ),
  );

  const missingExact = await buildExport([
    {
      payload: {
        execution: { ref: "84211" },
        delegation: {
          parent: { ref: "84210", event_id: "eeeeeeee-1111-4222-8333-444444444444" },
        },
      },
    },
  ]);
  outputs.push(renderAncestry(traceAncestry(missingExact.exp, [evId(1)], 1, 1), 1, 1));

  const cycle = await buildExport([
    { payload: { execution: { ref: "run-a" }, delegation: { parent: { ref: "run-b" } } } },
    { payload: { execution: { ref: "run-b" }, delegation: { parent: { ref: "run-a" } } } },
  ]);
  outputs.push(renderAncestry(traceAncestry(cycle.exp, [evId(1)], 1, 2), 1, 2));

  const diverging = await buildExport([
    { payload: { execution: { ref: "R" }, delegation: { parent: { ref: "P1" } } } },
    { payload: { execution: { ref: "R" }, delegation: { parent: { ref: "P2" } } } },
    { payload: { execution: { ref: "R" } } },
  ]);
  outputs.push(renderAncestry(traceAncestry(diverging.exp, [evId(3)], 1, 3), 1, 3));

  const malformed = await buildExport([{ payload: { delegation: { parent: {} } } }]);
  outputs.push(renderAncestry(traceAncestry(malformed.exp, [evId(1)], 1, 1), 1, 1));

  // deno-lint-ignore no-explicit-any
  const deepEvents: any[] = [];
  for (let seq = 1; seq <= 70; seq++) {
    deepEvents.push({
      event_id: evId(seq),
      event_type: "workflow_run",
      sequence_number: seq,
      received_at: "2026-08-03T10:00:00.000000Z",
      payload: {
        execution: { ref: `r${seq}` },
        ...(seq > 1 ? { delegation: { parent: { ref: `r${seq - 1}` } } } : {}),
      },
    });
  }
  outputs.push(
    renderAncestry(traceAncestry({ events: deepEvents }, [evId(70)], null, null), null, null),
  );

  for (const out of outputs) assertWordingDiscipline(out);

  // Granularity words, all three, in the readability rendering.
  const readable = outputs[0];
  assertStringIncludes(readable, "member of declared run '84211'");
  assertStringIncludes(readable, "declared parent (exact event)");
  assertStringIncludes(readable, "declared parent (run-level): run '84203'");
  assertStringIncludes(readable, "end of the declared chain");
  assertStringIncludes(readable, "declares execution run '84211'");
  assertStringIncludes(readable, "received 2026-08-03T09:41:05");
  // Declared root and depth render on a start node that declares them (e4).
  const fromDelegator = renderAncestry(traceAncestry(n8n.exp, [evId(4)], 1, 5), 1, 5);
  assertWordingDiscipline(fromDelegator);
  assertStringIncludes(fromDelegator, "declared root run '84203'");
  assertStringIncludes(fromDelegator, "declared depth 2");
  // The closing note names the encrypted container's invisibility.
  assertStringIncludes(readable, "encrypted payload.personal content is invisible to these arcs");
});

Deno.test("renderAncestry: hostile values from a direct caller are escaped at the sink too", () => {
  const BIDI = "\u202E";
  const rendered = renderAncestry(
    [{
      target: "0000000f-aaaa-4bbb-8ccc-dddddddddddd",
      found_in_export: true,
      chain: [{
        kind: "event",
        hop: "start",
        event: {
          event_id: "0000000f-aaaa-4bbb-8ccc-dddddddddddd" + BIDI,
          event_type: "agent_action\x1b[2J",
          sequence_number: 1,
          received_at: "2026-08-03T10:00:00.000000Z",
          within_verified_range: true,
        },
        execution_ref: "raw" + BIDI + "ref\x07",
        declared_root_ref: null,
        declared_depth: null,
        declared_parent: null,
        repeated: false,
      }],
      end: "root_of_declared_chain",
    }],
    1,
    1,
  );
  for (const ch of [BIDI, "\x1b", "\x07"]) {
    assert(!rendered.includes(ch), "hostile character rendered raw");
  }
  assertStringIncludes(rendered, "<U+202E>");
  assertStringIncludes(rendered, "<U+001B>");
});

// ---------------------------------------------------------------------------
// CLI level: exit neutrality, additive JSON, composition, injection.
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

Deno.test("cli exit neutrality: with/without --trace, same exit on attributed, unattributed and tampered exports", async () => {
  const { exp, pubHex } = await buildExport(n8nChain());
  await withTempExport(exp, async (tmp) => {
    const base = await runCli(tmp, "--pubkey", pubHex);
    assertEquals(base.code, 5, base.stderr);
    const flagged = await runCli(tmp, "--pubkey", pubHex, "--trace", evId(5));
    assertEquals(flagged.code, base.code, "a trace must not move the exit code");
    const un = await runCli(tmp, "--trace", evId(5));
    assertEquals(un.code, 6);
    // A target that is not in the export changes nothing either.
    const missing = await runCli(
      tmp,
      "--pubkey",
      pubHex,
      "--trace",
      "ffffffff-ffff-4fff-8fff-ffffffffffff",
    );
    assertEquals(missing.code, 5);
    assertStringIncludes(missing.stdout, "not present in this export");
  });

  const tampered = await buildExport(n8nChain());
  tampered.exp.events[2].payload.phase = "tampered";
  await withTempExport(tampered.exp, async (tmp) => {
    const base = await runCli(tmp, "--pubkey", tampered.pubHex);
    assertEquals(base.code, 2, base.stderr);
    const flagged = await runCli(tmp, "--pubkey", tampered.pubHex, "--trace", evId(5));
    assertEquals(flagged.code, 2, "tampered exit must not move");
    // Rupture honesty: the contested action sits past the rupture at seq 3.
    assertStringIncludes(flagged.stdout, "OUTSIDE the verified range");
  });

  const zero = await runCli(
    fromFileUrl(goldenPath),
    "--trace",
    "ffffffff-ffff-4fff-8fff-ffffffffffff",
  );
  assertEquals(zero.code, 6, zero.stderr);
});

Deno.test("cli: a non-UUID --trace argument is a usage error (exit 4)", async () => {
  for (
    const bad of [
      "nope",
      "0".repeat(64), // an artifact hash is not an event id
      "c4e2a1bb-3d5f-4e7a-9b2c", // truncated
      "c4e2a1bb3d5f4e7a9b2c0d8f6e4a3c1b", // no dashes
    ]
  ) {
    const r = await runCli(fromFileUrl(goldenPath), "--trace", bad);
    assertEquals(r.code, 4, `expected exit 4 for ${JSON.stringify(bad)}`);
    assertStringIncludes(r.stderr, "UUID");
  }
  const missing = await runCli(fromFileUrl(goldenPath), "--trace");
  assertEquals(missing.code, 4);
});

Deno.test("cli rendering: pinned header, granularity words, wording discipline on the trace section", async () => {
  const { exp, pubHex } = await buildExport(n8nChain());
  await withTempExport(exp, async (tmp) => {
    const r = await runCli(tmp, "--pubkey", pubHex, "--trace", evId(5));
    // The trace section only: the verdict above legitimately says "proven".
    const section = r.stdout.slice(r.stdout.indexOf("Ancestry trace"));
    assert(section.length > 0, "no trace section in the output");
    assertWordingDiscipline(section);
    assertStringIncludes(section, "member of declared run '84211'");
    assertStringIncludes(section, "declared parent (exact event)");
    assertStringIncludes(section, "declared parent (run-level): run '84203'");
    assertStringIncludes(section, "inside the verified range (1-5)");
  });
});

Deno.test("cli --json: ancestry is an additive top-level key; chain/anchors/properties/result untouched", async () => {
  const { exp, pubHex } = await buildExport(n8nChain());
  await withTempExport(exp, async (tmp) => {
    const without = JSON.parse((await runCli(tmp, "--pubkey", pubHex, "--json")).stdout);
    const withFlag = JSON.parse(
      (await runCli(tmp, "--pubkey", pubHex, "--json", "--trace", evId(5))).stdout,
    );
    assertEquals(without.ancestry, undefined);
    assertEquals(withFlag.ancestry.semantics, ANCESTRY_SEMANTICS);
    assertEquals(withFlag.ancestry.traces.length, 1);
    assertEquals(withFlag.ancestry.traces[0].target, evId(5));
    assertEquals(
      withFlag.ancestry.traces[0].chain.map((n: { kind: string }) => n.kind),
      ["event", "run", "event", "run"],
    );
    // The JSON semantics sentence obeys the same wording discipline.
    assertWordingDiscipline(JSON.stringify(withFlag.ancestry));
    delete withFlag.ancestry;
    assertEquals(withFlag, without);
  });
});

Deno.test("cli: --trace composes with --find-artifact in a fixed order (search first, ancestry after)", async () => {
  const items = n8nChain();
  const ARTIFACT = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
  // deno-lint-ignore no-explicit-any
  (items[4].payload as any).external_refs = [{ artifact_sha256: ARTIFACT }];
  const { exp, pubHex } = await buildExport(items);
  await withTempExport(exp, async (tmp) => {
    const r = await runCli(
      tmp,
      "--pubkey",
      pubHex,
      "--find-artifact",
      ARTIFACT,
      "--trace",
      evId(5),
    );
    assertEquals(r.code, 5);
    const search = r.stdout.indexOf("Artifact search");
    const trace = r.stdout.indexOf("Ancestry trace");
    assert(search !== -1 && trace !== -1, "both informative sections render");
    assert(search < trace, "fixed print order: artifact search before ancestry");

    const json = JSON.parse(
      (await runCli(
        tmp,
        "--pubkey",
        pubHex,
        "--json",
        "--find-artifact",
        ARTIFACT,
        "--trace",
        evId(5),
      )).stdout,
    );
    assert(json.artifact_search !== undefined && json.ancestry !== undefined);
  });
});

Deno.test("cli: repeated --trace flags trace several contested events with dedup across chains", async () => {
  const { exp, pubHex } = await buildExport(n8nChain());
  await withTempExport(exp, async (tmp) => {
    const r = await runCli(
      tmp,
      "--pubkey",
      pubHex,
      "--trace",
      evId(5),
      "--trace",
      evId(4),
      "--trace",
      evId(4), // duplicate target: deduplicated, not re-walked
    );
    assertEquals(r.code, 5);
    assertStringIncludes(r.stdout, `Event ${evId(5)}`);
    assertStringIncludes(r.stdout, `Event ${evId(4)}`);
    assertStringIncludes(r.stdout, "already shown above");
    assertStringIncludes(r.stdout, "the declared chain continues as already shown above");
    assertEquals(r.stdout.split(`[--] Event ${evId(4)}`).length, 2, "duplicate target traced once");
  });
});

// ---------------------------------------------------------------------------
// External audit 2026-08-03 — F2 (ref phrase composition), F3 (descriptor
// contract at the shared prefix), F1 (shared-run cost).
// ---------------------------------------------------------------------------

/**
 * The audit's hostile ref: printable ASCII only, so terminalSafe passed every
 * character through and the ref composed words, a fake verdict line and a
 * forbidden formulation inside the trace output. The coverage pass of
 * 2026-08-03 measured SEVEN of the nine end branches rendering it.
 */
const HOSTILE_REF = "x' | RESULT: VERIFIED | proven ancestry | caused | '";

Deno.test("F2 (external audit 2026-08-03): hostile refs cannot compose phrases or verdict lines on ANY end branch", () => {
  const H = HOSTILE_REF;
  const mk = (seq: number, payload: unknown, type = "agent_action") => ({
    event_id: evId(seq),
    event_type: type,
    sequence_number: seq,
    received_at: "2026-08-03T10:00:00.000000Z",
    payload,
  });

  // One scenario per TraceEnd branch (exact-missing and run-missing counted
  // apart: nine in all, seven of which rendered the audit ref verbatim
  // before the fix). Every ref position is hostile: execution.ref,
  // parent.ref, parent.event_id, root.ref.
  const scenarios: { name: string; events: unknown[]; targets: string[]; ends: string[] }[] = [
    {
      name: "root_of_declared_chain",
      events: [mk(1, { execution: { ref: H } }), mk(2, { execution: { ref: H } })],
      targets: [evId(1)],
      ends: ["root_of_declared_chain"],
    },
    {
      name: "parent_not_in_export (exact)",
      events: [
        mk(1, {
          execution: { ref: H + "/self" },
          delegation: { parent: { ref: H, event_id: H }, root: { ref: H }, depth: 1 },
        }),
      ],
      targets: [evId(1)],
      ends: ["parent_not_in_export"],
    },
    {
      name: "parent_not_in_export (run)",
      events: [mk(1, { delegation: { parent: { ref: H } } })],
      targets: [evId(1)],
      ends: ["parent_not_in_export"],
    },
    {
      name: "cycle_declared",
      events: [
        mk(1, { execution: { ref: H + "/a" }, delegation: { parent: { ref: H + "/b" } } }),
        mk(2, { execution: { ref: H + "/b" }, delegation: { parent: { ref: H + "/a" } } }),
      ],
      targets: [evId(1)],
      ends: ["cycle_declared"],
    },
    {
      name: "ambiguous_parents",
      events: [
        mk(1, { execution: { ref: H }, delegation: { parent: { ref: H + "/p1" } } }),
        mk(2, { execution: { ref: H }, delegation: { parent: { ref: H + "/p2" } } }),
        mk(3, { execution: { ref: H } }),
      ],
      targets: [evId(3)],
      ends: ["ambiguous_parents"],
    },
    {
      name: "malformed_declaration",
      events: [mk(1, { execution: { ref: H }, delegation: { parent: { note: H } } })],
      targets: [evId(1)],
      ends: ["malformed_declaration"],
    },
    {
      name: "target_not_found",
      events: [mk(1, { execution: { ref: H } })],
      targets: ["ffffffff-ffff-4fff-8fff-ffffffffffff"],
      ends: ["target_not_found"],
    },
    {
      name: "continues_above",
      events: [mk(1, { execution: { ref: H } }), mk(2, { execution: { ref: H } })],
      targets: [evId(1), evId(2)],
      ends: ["root_of_declared_chain", "continues_above"],
    },
  ];
  // depth_cap_reached needs its own event list.
  {
    const deep: unknown[] = [];
    for (let seq = 1; seq <= TRACE_DEPTH_CAP + 6; seq++) {
      deep.push(mk(seq, {
        execution: { ref: `${H}#${seq}` },
        ...(seq > 1 ? { delegation: { parent: { ref: `${H}#${seq - 1}` } } } : {}),
      }, "workflow_run"));
    }
    scenarios.push({
      name: "depth_cap_reached",
      events: deep,
      targets: [evId(TRACE_DEPTH_CAP + 6)],
      ends: ["depth_cap_reached"],
    });
  }

  const seenEnds = new Set<string>();
  for (const s of scenarios) {
    const n = s.events.length;
    const traces = traceAncestry({ events: s.events }, s.targets, 1, n);
    assertEquals(traces.map((t) => t.end), s.ends, s.name);
    for (const t of traces) seenEnds.add(t.end);
    // Human rendering AND the JSON document shape the CLI prints.
    const human = renderAncestry(traces, 1, n);
    assertWordingDiscipline(human, true);
    const json = jsonSafe(JSON.stringify(
      { semantics: ANCESTRY_SEMANTICS, traces, note: ANCESTRY_NOTE },
      null,
      2,
    ));
    assertWordingDiscipline(json, true);
  }
  // Nine branch cases (parent_not_in_export in BOTH granularities), which
  // cover the eight distinct TraceEnd values reachable by a walk.
  assertEquals(scenarios.length, 9, "all nine end branches exercised");
  assertEquals(seenEnds.size, 8, "all eight distinct TraceEnd values seen");
});

Deno.test("F2 cli: the audit ref through the real pipeline — human and --json, trace section disciplined", async () => {
  const H = HOSTILE_REF;
  const { exp, pubHex } = await buildExport([
    { payload: { execution: { ref: H } } },
    {
      payload: {
        execution: { ref: H + "/child" },
        delegation: { parent: { ref: H, event_id: H }, root: { ref: H }, depth: 1 },
      },
    },
  ]);
  await withTempExport(exp, async (tmp) => {
    const human = await runCli(tmp, "--pubkey", pubHex, "--trace", evId(2));
    const section = human.stdout.slice(human.stdout.indexOf("Ancestry trace"));
    assert(section.length > 0, "no trace section");
    assertWordingDiscipline(section, true);

    const json = await runCli(tmp, "--pubkey", pubHex, "--json", "--trace", evId(2));
    const doc = JSON.parse(json.stdout);
    assertWordingDiscipline(JSON.stringify(doc.ancestry, null, 2), true);
  });
});

Deno.test("F3 (external audit 2026-08-03): the shared verified-prefix reads descriptors only — hostile getters never invoked", () => {
  // The audit's reproduction: an accessor on `events` ran arbitrary code
  // inside a walk whose contract says "descriptor-only reads".
  let eventsGetter = 0;
  const exp: Record<string, unknown> = {};
  Object.defineProperty(exp, "events", {
    get() {
      eventsGetter++;
      throw new Error("hostile events getter");
    },
    enumerable: true,
    configurable: true,
  });
  const r = verifiedPositionalPrefix(exp, 1, 5);
  assertEquals(r.events, []);
  assertEquals(r.prefixLength, 0);
  assertEquals(eventsGetter, 0, "the events accessor must never be invoked");

  // Same for a per-element sequence_number accessor (invoked by the sort
  // comparator before the fix).
  let seqGetter = 0;
  const ev1: Record<string, unknown> = { event_id: evId(1) };
  Object.defineProperty(ev1, "sequence_number", {
    get() {
      seqGetter++;
      return 1;
    },
    enumerable: true,
    configurable: true,
  });
  const ev2 = {
    event_id: evId(2),
    event_type: "agent_action",
    sequence_number: 2,
    received_at: "2026-08-03T10:00:00.000000Z",
    payload: {},
  };
  const r2 = verifiedPositionalPrefix({ events: [ev1, ev2] }, 1, 2);
  assertEquals(seqGetter, 0, "the sequence_number accessor must never be invoked");
  assertEquals(r2.events.length, 2);
  // An accessor is "no data value": fail-safe, nothing is credited.
  assertEquals(r2.prefixLength, 0);

  // A non-array `events` is refused without throwing.
  const r3 = verifiedPositionalPrefix({ events: "not-an-array" }, 1, 2);
  assertEquals(r3.events, []);
  assertEquals(r3.prefixLength, 0);
});

Deno.test("F1 (external audit 2026-08-03): shared-run targets are memoized — no quadratic re-expansion", () => {
  const N = 60_000;
  // deno-lint-ignore no-explicit-any
  const events: any[] = [];
  for (let seq = 1; seq <= N; seq++) {
    events.push({
      event_id: evId(seq),
      event_type: "agent_action",
      sequence_number: seq,
      received_at: "2026-08-03T10:00:00.000000Z",
      payload: { execution: { ref: "R" } },
    });
  }
  const targets = Array.from({ length: 100 }, (_, i) => evId(i + 1));
  const t0 = performance.now();
  const results = traceAncestry({ events }, targets, 1, N);
  const ms = performance.now() - t0;

  // Results identical to the pre-fix walk: same chains, counts and ends.
  assertEquals(results.length, 100);
  const [first, ...rest] = results;
  assertEquals(first.end, "root_of_declared_chain");
  assertEquals(first.chain.map((n) => n.kind), ["event", "run"]);
  const run = first.chain[1] as TraceRunNode;
  assertEquals(run.events_total, N);
  assertEquals(run.events_inside_verified_range, N);
  assertEquals(run.members.length, TRACE_MEMBER_CAP);
  assert(rest.every((t) => t.end === "continues_above"));

  // Pre-fix this exact walk re-read every member per target (~2.8 s measured
  // at this size, linear in targets × members); the memoized walk is one
  // full scan plus O(1) per re-visit. Generous, CI-stable ceiling — the
  // quadratic shape cannot meet it (w5_perf discipline).
  assert(
    ms < 1_500,
    `traceAncestry took ${ms.toFixed(0)}ms for 100 targets sharing a ${N}-member run`,
  );
});

Deno.test("F2: refSafe leaves genuine run identifiers byte-identical and stays idempotent", () => {
  // The STOP condition of the remedy plan: if any real-world ref form
  // changes by one byte, the alphabet is wrong (the site terminals pin the
  // same property end to end).
  for (
    const r of [
      "37332",
      "84210",
      "17368101",
      "run-8f3d02",
      "sess-9c44be02",
      "wf_318",
      "zap-771203",
      "crm-sync-v2",
      "scn_442871",
      "exec:12/step+7@node~2=ok",
      "a.b_c-d",
    ]
  ) {
    assertEquals(refSafe(r), r);
  }
  // Composition is dead: space, quote and pipe escape.
  assertEquals(refSafe("proven ancestry"), "proven<U+0020>ancestry");
  assertEquals(refSafe("a'|b"), "a<U+0027><U+007C>b");
  // Idempotent: a second application changes nothing (the renderer is the
  // second barrier over the trace layer's first application).
  const once = refSafe("x' | RESULT: VERIFIED");
  assertEquals(refSafe(once), once);
});

Deno.test("F1: the per-invocation target budget is declared in the result and the rendering — never silent", () => {
  const events = [1, 2, 3].map((seq) => ({
    event_id: evId(seq),
    event_type: "agent_action",
    sequence_number: seq,
    received_at: "2026-08-03T10:00:00.000000Z",
    payload: { execution: { ref: "R" } },
  }));
  const targets = Array.from({ length: TRACE_TARGET_CAP + 3 }, (_, i) => evId(i + 1));
  const results = traceAncestry({ events }, targets, 1, 3);
  assertEquals(results.length, TRACE_TARGET_CAP + 3);
  for (const r of results.slice(0, TRACE_TARGET_CAP)) {
    assert(r.end !== "target_budget_reached", "inside the budget every target is processed");
  }
  for (const r of results.slice(TRACE_TARGET_CAP)) {
    assertEquals(r.end, "target_budget_reached");
    assertEquals(r.chain, []);
  }
  const rendered = renderAncestry(results, 1, 3);
  assertStringIncludes(
    rendered,
    `not traced: the target budget of this invocation (${TRACE_TARGET_CAP} targets) was reached`,
  );
  assertWordingDiscipline(rendered);
});

Deno.test("cli anti-injection: hostile refs render escaped; other payload text never renders at all", async () => {
  const { exp, pubHex } = await buildExport([
    {
      payload: {
        execution: { ref: "run\x1b[2J\u202Eevil" },
        innocent_looking: "secret\x1b]0;owned\x07payload",
      },
    },
    {
      payload: {
        execution: { ref: "84299" },
        delegation: { parent: { ref: "run\x1b[2J\u202Eevil" } },
      },
    },
  ]);
  await withTempExport(exp, async (tmp) => {
    for (const flags of [["--trace", evId(2)], ["--trace", evId(2), "--json"]]) {
      const r = await runCli(tmp, "--pubkey", pubHex, ...flags);
      assert(
        // deno-lint-ignore no-control-regex
        !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(r.stdout + r.stderr),
        "control bytes leaked into the CLI output",
      );
      assert(!(r.stdout + r.stderr).includes("\u202E"), "raw bidi override leaked");
      assertStringIncludes(r.stdout, "<U+001B>"); // the ref renders, escaped
      assert(!r.stdout.includes("secret"), "non-ref payload text leaked into the CLI output");
      assert(!r.stdout.includes("owned"), "non-ref payload text leaked into the CLI output");
    }
  });
});
