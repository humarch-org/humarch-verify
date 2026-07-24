// CLI-level gate (B10 §10.7, B12 §12.3): the golden export verifies; one
// altered byte → "tampered" with the exact sequence; exit codes are stable
// (D65 + additive exit 6, D82 amendment 2026-07-12). The subprocess tests
// exercise the real cli.ts entrypoint, forged exports included (audit F1).
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";
import { verifyChain } from "../src/verify.ts";
import { verifyAnchors } from "../src/ots.ts";
import { assess, renderHuman } from "../src/render.ts";
import { attributeEvents, trustedKeyBytes } from "../src/issuer.ts";
import { forgeExport } from "./forge_helper.ts";

const RFC8032_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const goldenPath = new URL("../vectors/export-v2v3.json", import.meta.url);
const issuerPath = new URL("../vectors/issuer-vector.json", import.meta.url);
const golden = () => JSON.parse(Deno.readTextFileSync(goldenPath));
const vectorTrust = () => trustedKeyBytes(JSON.parse(Deno.readTextFileSync(issuerPath)));

Deno.test("golden export + vectors issuer: chain and attribution hold, pending anchor ⇒ declared partial", async () => {
  const exp = golden();
  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(exp);
  assertEquals(chain.chain_continuous, true);
  assertEquals(chain.signatures_valid, true);
  assertEquals(chain.anchored_to_genesis, true);
  assertEquals(anchors.length, 1);
  assertEquals(anchors[0].aggregate_recomputed, true, "V4 aggregate reproduced");
  assertEquals(anchors[0].bitcoin_verified, null, "pending: nothing to verify on Bitcoin yet");
  const attribution = attributeEvents(exp, vectorTrust());
  assertEquals(attribution, "attributed");
  // D82 amendment 2026-07-12: `verified` needs the time property too — a
  // pending anchor proves nothing yet, so the honest outcome is partial.
  const { result, exitCode, properties } = assess(exp, chain, anchors, attribution);
  assertEquals(result, "partial");
  assertEquals(exitCode, 5);
  assertEquals(properties, { integrity: "ok", time: "unproven", attribution: "attributed" });
  const human = renderHuman(exp.tenant_id, chain, anchors, result, properties);
  assertStringIncludes(human, "RESULT: DECLARED PARTIAL VERIFICATION");
  assertStringIncludes(human, "[OK] Attribution");
  assertStringIncludes(human, "pending");
});

Deno.test("one altered byte → tampered with the exact sequence (exit 2)", async () => {
  const exp = golden();
  exp.events[1].payload.note = "Amount above threshold, verified manuallY"; // one byte
  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(exp);
  const { result, exitCode, properties } = assess(
    exp,
    chain,
    anchors,
    attributeEvents(exp, vectorTrust()),
  );
  assertEquals(result, "tampered");
  assertEquals(exitCode, 2);
  assertEquals(properties.integrity, "failed");
  assertEquals(chain.first_failure?.sequence_number, 2);
  assertEquals(chain.first_failure?.kind, "payload_hash_mismatch");
  const human = renderHuman(exp.tenant_id, chain, anchors, result, properties);
  assertStringIncludes(human, "sequence 2");
  assertStringIncludes(human, "NOT VERIFIED");
});

Deno.test("tampered anchor aggregate → anchor_failed (exit 3)", async () => {
  const exp = golden();
  exp.anchors[0].anchor_entries_for_aggregate[1].last_event_hash = "beef" + "0".repeat(60);
  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(exp);
  assertEquals(anchors[0].aggregate_recomputed, false);
  const { result, exitCode, properties } = assess(
    exp,
    chain,
    anchors,
    attributeEvents(exp, vectorTrust()),
  );
  assertEquals(result, "anchor_failed");
  assertEquals(exitCode, 3);
  assertEquals(properties.time, "failed");
});

Deno.test("mid-chain range: declared partial (exit 5), never silently ok", async () => {
  const exp = golden();
  exp.events = [exp.events[1]]; // range starts at sequence 2
  exp.range = { from_sequence: 2, to_sequence: 2 };
  const chain = await verifyChain(exp);
  assertEquals(chain.anchored_to_genesis, false);
  assertEquals(chain.chain_continuous, true);
  const { result, exitCode } = assess(
    exp,
    chain,
    await verifyAnchors(exp),
    attributeEvents(exp, vectorTrust()),
  );
  assertEquals(result, "partial");
  assertEquals(exitCode, 5);
});

Deno.test("unreadable .ots receipt (valid base64, not an OTS file) → anchor_failed, never a throw", async () => {
  const exp = golden();
  exp.anchors[0].ots_status = "confirmed";
  exp.anchors[0].ots_file_base64 = btoa("hello world"); // decodes fine, parses as nothing
  const anchors = await verifyAnchors(exp);
  assertEquals(anchors[0].ots_commits_to_aggregate, false);
  assertStringIncludes(anchors[0].note, "unreadable .ots receipt");
  const { result, exitCode } = assess(
    exp,
    await verifyChain(exp),
    anchors,
    attributeEvents(exp, vectorTrust()),
  );
  assertEquals(result, "anchor_failed");
  assertEquals(exitCode, 3);
});

Deno.test("non-pending anchor without a receipt: honest note, verdict stays declared-partial", async () => {
  const exp = golden();
  exp.anchors[0].ots_status = "confirmed"; // but no ots_file_base64
  const anchors = await verifyAnchors(exp);
  assertEquals(anchors[0].ots_commits_to_aggregate, null);
  assertEquals(anchors[0].bitcoin_verified, null);
  assertStringIncludes(anchors[0].note, "no .ots receipt");
  assert(!anchors[0].note.includes("pending"), anchors[0].note);
  const { result, exitCode } = assess(
    exp,
    await verifyChain(exp),
    anchors,
    attributeEvents(exp, vectorTrust()),
  );
  assertEquals(result, "partial");
  assertEquals(exitCode, 5);
});

// --------------------------------------------------------------------------
// Subprocess tests: the real CLI, exit codes included.
// --------------------------------------------------------------------------
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

Deno.test("cli (M3 case 2): genuine export WITHOUT --issuer → exit 6, NOT ATTRIBUTED", async () => {
  const r = await runCli(fromFileUrl(goldenPath));
  assertEquals(r.code, 6, r.stderr);
  assertStringIncludes(r.stdout, "RESULT: NOT ATTRIBUTED");
  assertStringIncludes(r.stdout, "[--] Attribution — NOT CHECKED");
});

Deno.test("cli: golden export + --issuer → attribution OK; pending anchor keeps it declared-partial (exit 5)", async () => {
  const r = await runCli(fromFileUrl(goldenPath), "--issuer", fromFileUrl(issuerPath));
  assertEquals(r.code, 5, r.stderr);
  assertStringIncludes(r.stdout, "[OK] Attribution");
  assertStringIncludes(r.stdout, "RESULT: DECLARED PARTIAL VERIFICATION");
});

Deno.test("cli --json: structured verdict carries the three properties", async () => {
  const r = await runCli(fromFileUrl(goldenPath), "--issuer", fromFileUrl(issuerPath), "--json");
  assertEquals(r.code, 5, r.stderr);
  const verdict = JSON.parse(r.stdout);
  assertEquals(verdict.format, "humarch-verify/v1");
  assertEquals(verdict.result, "partial");
  assertEquals(verdict.properties, {
    integrity: "ok",
    time: "unproven",
    attribution: "attributed",
  });
  assertEquals(verdict.chain.verified_through_sequence, 2);
});

Deno.test("cli: tampered file → exit 2 naming the sequence (integrity outranks attribution)", async () => {
  const tampered = golden();
  tampered.events[0].payload.params.subject = "Order confirmation #4822";
  await withTempExport(tampered, async (tmp) => {
    const r = await runCli(tmp); // no issuer on purpose: exit 2 still wins
    assertEquals(r.code, 2);
    assertStringIncludes(r.stdout, "sequence 1");
  });
});

Deno.test("cli: malformed input → exit 4", async () => {
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, "{not json");
  const r1 = await runCli(tmp);
  assertEquals(r1.code, 4);
  await Deno.writeTextFile(tmp, JSON.stringify({ format: "something-else" }));
  const r2 = await runCli(tmp);
  assertEquals(r2.code, 4);
  await Deno.remove(tmp);
});

Deno.test("cli: malformed or unreadable --issuer document → exit 4; --issuer + --pubkey → exit 4", async () => {
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, JSON.stringify({ format: "not-a-registry", keys: [] }));
  const bad = await runCli(fromFileUrl(goldenPath), "--issuer", tmp);
  assertEquals(bad.code, 4);
  assertStringIncludes(bad.stderr, "malformed issuer document");
  await Deno.remove(tmp);

  const missing = await runCli(fromFileUrl(goldenPath), "--issuer", tmp);
  assertEquals(missing.code, 4);

  const both = await runCli(
    fromFileUrl(goldenPath),
    "--issuer",
    fromFileUrl(issuerPath),
    "--pubkey",
    RFC8032_KEY,
  );
  assertEquals(both.code, 4);
  assertStringIncludes(both.stderr, "mutually exclusive");
});

Deno.test("cli --pubkey: single-key trusted set with per-event semantics", async () => {
  // The expected key really signs every event → attributed (partial: pending anchor).
  const ok = await runCli(fromFileUrl(goldenPath), "--pubkey", RFC8032_KEY);
  assertEquals(ok.code, 5, ok.stderr);
  assertStringIncludes(ok.stdout, "[OK] Attribution");
  // A different expected key → the export's events resolve OUTSIDE the set.
  const wrong = await runCli(fromFileUrl(goldenPath), "--pubkey", "ab".repeat(32), "--json");
  assertEquals(wrong.code, 6);
  assertEquals(JSON.parse(wrong.stdout).properties.attribution, "foreign_key");
});

Deno.test("cli: unreadable .ots receipt → exit 3, never a stack trace", async () => {
  const exp = golden();
  exp.anchors[0].ots_status = "confirmed";
  exp.anchors[0].ots_file_base64 = btoa("hello world");
  await withTempExport(exp, async (tmp) => {
    const r = await runCli(tmp);
    assertEquals(r.code, 3, r.stderr);
    assert(!r.stderr.includes("Uncaught"), `stack trace leaked:\n${r.stderr}`);
    assertStringIncludes(r.stdout, "unreadable .ots receipt");
  });
});

Deno.test("cli --pubkey: uppercase hex is accepted (byte identity is case-insensitive)", async () => {
  const r = await runCli(fromFileUrl(goldenPath), "--pubkey", RFC8032_KEY.toUpperCase());
  assertEquals(r.code, 5, r.stderr);
  assertStringIncludes(r.stdout, "[OK] Attribution");
});

Deno.test("cli --issuer: a plain-http URL is refused (the trusted set travels over TLS) → exit 4", async () => {
  const r = await runCli(
    fromFileUrl(goldenPath),
    "--issuer",
    "http://keys.example.com/humarch-keys.json",
  );
  assertEquals(r.code, 4);
  assertStringIncludes(r.stderr, "https");
});

Deno.test("cli --issuer (audit 3, W6): a redirecting URL is refused — no https→http downgrade → exit 4", async () => {
  // The old check validated the INITIAL URL only: a server-side 3xx could
  // re-route the trusted-set fetch to plain http after the scheme gate.
  // Loopback is exempt from the https rule, so the local server exercises
  // exactly the redirect leg.
  const srv = Deno.serve({ port: 0, onListen: () => {} }, () =>
    new Response(null, {
      status: 301,
      headers: { location: "http://insecure.example/humarch-keys.json" },
    }));
  const port = (srv.addr as Deno.NetAddr).port;
  try {
    const r = await runCli(
      fromFileUrl(goldenPath),
      "--issuer",
      `http://127.0.0.1:${port}/humarch-keys.json`,
    );
    assertEquals(r.code, 4, r.stderr);
    assertStringIncludes(r.stderr, "redirect");
  } finally {
    await srv.shutdown();
  }
});

Deno.test("cli (M3 case 3): forged export, own key, no anchors, no issuer → exit 6", async () => {
  const forged = await forgeExport();
  await withTempExport(forged, async (tmp) => {
    const r = await runCli(tmp);
    assertEquals(r.code, 6, `a fabricated export must never verify: ${r.stdout}`);
    assertStringIncludes(r.stdout, "RESULT: NOT ATTRIBUTED");
  });
});

Deno.test("cli (M3 case 4): forged export + GENUINE issuer → exit 6 (foreign_key)", async () => {
  const forged = await forgeExport();
  await withTempExport(forged, async (tmp) => {
    const r = await runCli(tmp, "--issuer", fromFileUrl(issuerPath), "--json");
    assertEquals(r.code, 6, r.stderr);
    const verdict = JSON.parse(r.stdout);
    assertEquals(verdict.result, "unattributed");
    assertEquals(verdict.properties.attribution, "foreign_key");
  });
});

Deno.test("cli (M3 case 5): the padding bypass — genuine key as decoy, events signed by the attacker → exit 6", async () => {
  // Regression for the bug the audit missed: --pubkey/--issuer used to be a
  // membership test on the export's OWN signing_keys. If this ever exits 0,
  // the attribution check is not per-event.
  const forged = await forgeExport({ padGenuineKey: RFC8032_KEY });
  await withTempExport(forged, async (tmp) => {
    const viaIssuer = await runCli(tmp, "--issuer", fromFileUrl(issuerPath), "--json");
    assertEquals(viaIssuer.code, 6, `decoy padding must not attribute: ${viaIssuer.stdout}`);
    assertEquals(JSON.parse(viaIssuer.stdout).properties.attribution, "foreign_key");
    const viaPubkey = await runCli(tmp, "--pubkey", RFC8032_KEY);
    assertEquals(viaPubkey.code, 6, `--pubkey must not be a membership test: ${viaPubkey.stdout}`);
    assert(!viaPubkey.stdout.includes("RESULT: VERIFIED"), viaPubkey.stdout);
  });
});
