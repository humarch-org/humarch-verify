// Trust-boundary shape gate (audit F5, 2026-07-12): a malformed export —
// hex fields of the wrong length, missing members, non-array collections —
// must yield a clean `malformed` (exit 4), never a thrown error inside the
// verifier. And the gate must stay PERMEABLE to well-formed-but-tampered
// exports: those belong to the verifier (exit 2/3), or the fix would change
// semantics the vectors pin down.
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";
import { exportShapeProblems } from "../src/shape.ts";

const load = (name: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../vectors/${name}`, import.meta.url)));

Deno.test("shape: every shipped vector export is well-formed", () => {
  for (const name of ["export-v2v3.json", "export-real-anchor.json", "export-shredded.json"]) {
    assertEquals(exportShapeProblems(load(name)), [], name);
  }
});

Deno.test("shape: tampered-but-well-formed exports PASS (verdicts stay with the verifier)", () => {
  const exp = load("export-v2v3.json");
  exp.events[1].payload.note = "tampered"; // exit-2 material, not exit-4
  assertEquals(exportShapeProblems(exp), []);
  const sig = load("export-v2v3.json");
  sig.events[0].signature = "0".repeat(128); // wrong but well-shaped signature
  assertEquals(exportShapeProblems(sig), []);
});

Deno.test("shape: the F5 crash shapes are all reported", () => {
  const cases: [string, (exp: ReturnType<typeof load>) => void, string][] = [
    ["truncated public key", (e) => e.signing_keys[0].public_key = "d75a9801", "public_key"],
    [
      "odd-length signature",
      (e) => e.events[0].signature = e.events[0].signature.slice(0, 127),
      "signature",
    ],
    ["non-hex signature", (e) => e.events[0].signature = "z".repeat(128), "signature"],
    ["missing payload member", (e) => delete e.events[0].payload, "payload: missing"],
    ["missing actor member", (e) => delete e.events[0].actor, "actor: missing"],
    ["events not an array", (e) => e.events = 42, "events: expected an array"],
    ["null event element", (e) => e.events[0] = null, "events[0]: expected an object"],
    ["signing_keys not an array", (e) => e.signing_keys = {}, "signing_keys: expected an array"],
    ["missing tenant_id", (e) => delete e.tenant_id, "tenant_id"],
    ["non-hex event_hash", (e) => e.events[0].event_hash = "nope", "event_hash"],
    ["fractional sequence_number", (e) => e.events[0].sequence_number = 1.5, "positive integer"],
    ["zero sequence_number", (e) => e.events[0].sequence_number = 0, "positive integer"],
    ["string sequence_number", (e) => e.events[0].sequence_number = "1", "positive integer"],
    [
      "undecodable ots_file_base64",
      (e) => e.anchors[0].ots_file_base64 = "!!not-base64!!",
      "ots_file_base64",
    ],
    [
      "anchor entries not an array",
      (e) => e.anchors[0].anchor_entries_for_aggregate = "x",
      "anchor_entries_for_aggregate",
    ],
  ];
  for (const [label, mutate, needle] of cases) {
    const exp = load("export-v2v3.json");
    mutate(exp);
    const problems = exportShapeProblems(exp);
    assert(problems.length > 0, `${label}: expected problems`);
    assert(
      problems.some((p) => p.includes(needle)),
      `${label}: expected a problem mentioning "${needle}", got ${JSON.stringify(problems)}`,
    );
  }
  assertEquals(exportShapeProblems(null), ["export: not a JSON object"]);
  assertEquals(exportShapeProblems([]), ["export: not a JSON object"]);
});

Deno.test("shape (audit 3): hostile-content shapes are all reported", () => {
  const ESC = String.fromCharCode(0x1b);
  const cases: [string, (exp: ReturnType<typeof load>) => void, string][] = [
    // V1 — JSON.parse turns 1e999 into Infinity; canonicalize would throw.
    [
      "non-finite payload number",
      (e) => e.events[0].payload.amount = Infinity,
      "non-finite number",
    ],
    [
      "non-finite nested deep in actor",
      (e) => e.events[0].actor.meta = { a: [{ x: -Infinity }] },
      "non-finite number",
    ],
    [
      "NaN in subject (unreachable from JSON.parse, gate still closes)",
      (e) => e.events[0].subject.score = NaN,
      "non-finite number",
    ],
    // V2 — control bytes in checked fields (interpolated into the terminal).
    ["ANSI escape in tenant_id", (e) => e.tenant_id = `${ESC}[2J${e.tenant_id}`, "control bytes"],
    [
      "ANSI escape in ots_status",
      (e) => e.anchors[0].ots_status = `pending${ESC}[8m`,
      "control bytes",
    ],
    ["NUL in source", (e) => e.events[0].source = "make\u0000", "control bytes"],
    // W2 — the time-consistency window must see the declared date as written.
    [
      "anchor_date with trailing junk",
      (e) => e.anchors[0].anchor_date = "2026-06-12junk",
      "YYYY-MM-DD",
    ],
    [
      "anchor_date as full timestamp",
      (e) => e.anchors[0].anchor_date = "2026-06-12T00:00:00Z",
      "YYYY-MM-DD",
    ],
    // W1 — the event list must belong to the tenant the export declares.
    [
      "foreign-tenant event",
      (e) => e.events[1].tenant_id = "11111111-2222-4333-8444-555555555555",
      "does not match the export tenant_id",
    ],
    [
      "export relabeled to another tenant",
      (e) => e.tenant_id = "11111111-2222-4333-8444-555555555555",
      "does not match the export tenant_id",
    ],
  ];
  for (const [label, mutate, needle] of cases) {
    const exp = load("export-v2v3.json");
    mutate(exp);
    const problems = exportShapeProblems(exp);
    assert(problems.length > 0, `${label}: expected problems`);
    assert(
      problems.some((p) => p.includes(needle)),
      `${label}: expected a problem mentioning "${needle}", got ${JSON.stringify(problems)}`,
    );
  }
});

Deno.test("shape (audit 3, W3 layer 2): duplicate anchor dates are a form error", () => {
  // An export has at most one anchor per UTC day (one daily aggregate, D9);
  // two anchors sharing a date exist only in a hand-built file — the shape
  // of the chain↔anchor binding bypass (a decoy riding in on the real
  // anchor's date). The export-real-anchor fixture carries exactly one anchor.
  const exp = load("export-real-anchor.json");
  assertEquals(exportShapeProblems(exp), []);
  exp.anchors = [exp.anchors[0], structuredClone(exp.anchors[0])]; // same date twice
  const problems = exportShapeProblems(exp);
  assert(
    problems.some((p) => p.includes("duplicate anchor date")),
    JSON.stringify(problems),
  );
  // Two DIFFERENT dates stay well-formed.
  const ok = load("export-real-anchor.json");
  const second = structuredClone(ok.anchors[0]);
  second.anchor_date = "2026-07-07";
  ok.anchors = [ok.anchors[0], second];
  assertEquals(exportShapeProblems(ok), []);
});

Deno.test("shape (audit 3, W9): sequence_number beyond MAX_SAFE_INTEGER is a form error", () => {
  for (const bad of [1e21, 2 ** 53, Number.MAX_SAFE_INTEGER + 2]) {
    const exp = load("export-v2v3.json");
    exp.events[0].sequence_number = bad;
    const problems = exportShapeProblems(exp);
    assert(
      problems.some((p) => p.includes("positive integer")),
      `sequence_number ${bad}: expected a positive-integer problem, got ${
        JSON.stringify(problems)
      }`,
    );
  }
  // The largest safe integer stays ACCEPTED by the shape gate (permeability:
  // it fails later in the verifier for the hash, not here for the form).
  const exp = load("export-v2v3.json");
  exp.events[0].sequence_number = Number.MAX_SAFE_INTEGER; // 2^53 − 1
  assert(
    !exportShapeProblems(exp).some((p) => p.includes("sequence_number")),
    "2^53−1 must not be rejected by the shape gate",
  );
});

// ---------------------------------------------------------------------------
// The real CLI on the inputs that used to throw: exit 4, no stack trace.
// ---------------------------------------------------------------------------
async function runCli(...args: string[]): Promise<{ code: number; stderr: string }> {
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
  return { code: out.code, stderr: new TextDecoder().decode(out.stderr) };
}

Deno.test("cli: malformed hex (truncated public key) → exit 4, never a stack trace", async () => {
  const exp = load("export-v2v3.json");
  exp.signing_keys[0].public_key = exp.signing_keys[0].public_key.slice(0, 62);
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, JSON.stringify(exp));
  const r = await runCli(tmp);
  assertEquals(r.code, 4, r.stderr);
  assertStringIncludes(r.stderr, "malformed input");
  assert(!r.stderr.includes("Uncaught"), `stack trace leaked:\n${r.stderr}`);
  await Deno.remove(tmp);
});

Deno.test("cli: signature of the wrong length → exit 4, never a stack trace", async () => {
  const exp = load("export-v2v3.json");
  exp.events[0].signature = exp.events[0].signature.slice(0, 64);
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, JSON.stringify(exp));
  const r = await runCli(tmp);
  assertEquals(r.code, 4, r.stderr);
  assertStringIncludes(r.stderr, "malformed input");
  assert(!r.stderr.includes("Uncaught"), `stack trace leaked:\n${r.stderr}`);
  await Deno.remove(tmp);
});

Deno.test("cli (audit 3, V1): crafted 1e999 in the payload → exit 4, never a stack trace", async () => {
  // JSON.stringify can never emit 1e999 — plant a sentinel and rewrite the
  // TEXT, exactly like the hand-crafted hostile file of the finding.
  const exp = load("export-v2v3.json");
  exp.events[0].payload.evil = 12345;
  const text = JSON.stringify(exp).replace('"evil":12345', '"evil":1e999');
  assertStringIncludes(text, "1e999"); // the rewrite really happened
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, text);
  const r = await runCli(tmp);
  assertEquals(r.code, 4, r.stderr);
  assertStringIncludes(r.stderr, "malformed input");
  assertStringIncludes(r.stderr, "non-finite");
  assert(!r.stderr.includes("Uncaught"), `stack trace leaked:\n${r.stderr}`);
  await Deno.remove(tmp);
});

Deno.test("cli (audit 3, V2): control byte in a rendered field → exit 4, hostile bytes never echoed", async () => {
  const exp = load("export-v2v3.json");
  exp.anchors[0].anchor_date = "2026-06-12"; // keep W2-valid: isolate the V2 path
  exp.events[0].event_type = "agent_action\u001b[31m";
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, JSON.stringify(exp));
  const r = await runCli(tmp);
  assertEquals(r.code, 4, r.stderr);
  assertStringIncludes(r.stderr, "control bytes are not allowed");
  assert(!r.stderr.includes("\u001b"), "the hostile escape byte leaked into the error output");
  assert(!r.stderr.includes("Uncaught"), `stack trace leaked:\n${r.stderr}`);
  await Deno.remove(tmp);
});

Deno.test("F5 (external audit 2026-08-03): non-finite diagnostics never echo payload key names", () => {
  // checkFinite built its diagnostic path from the payload's own keys, so a
  // hostile key travelled into the `malformed input` message — the one sink
  // of payload text the D101 release had left open. The path must stop at
  // the documented container and continue with opaque, indexed markers.
  const exp = load("export-v2v3.json");
  exp.events[0].payload = {
    ["proven ancestry \u202E hostile"]: [{ "RESULT: VERIFIED": Infinity }],
  };
  const problems = exportShapeProblems(exp);
  const finite = problems.filter((p) => p.includes("non-finite"));
  assertEquals(finite.length, 1, JSON.stringify(problems));
  assertStringIncludes(finite[0], "events[0].payload");
  assert(!finite[0].includes("proven"), `payload key leaked: ${finite[0]}`);
  assert(!finite[0].includes("RESULT"), `payload key leaked: ${finite[0]}`);
  assert(!finite[0].includes("\u202E"), `payload key leaked: ${finite[0]}`);
  // Same rule for the other canonicalized containers (actor/subject).
  const exp2 = load("export-v2v3.json");
  exp2.events[0].actor = { type: "agent", id: "a", "hostile actor key": Infinity };
  const finite2 = exportShapeProblems(exp2).filter((p) => p.includes("non-finite"));
  assertEquals(finite2.length, 1);
  assertStringIncludes(finite2[0], "events[0].actor");
  assert(!finite2[0].includes("hostile"), `actor key leaked: ${finite2[0]}`);
});
