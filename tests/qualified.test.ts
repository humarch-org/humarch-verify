// Dual-anchor gate (D98, SPEC 1.3.0): the first-party RFC 3161 reader
// (tst_lite) against vendored tokens from TWO independent implementations
// (local openssl TSA, ECDSA P-256 · freetsa.org, RSA-4096 — one-shot
// generated, never a live CI dependency), the additive qualified-timestamp
// vectors, and the two invariants the decision pins:
//   * EXIT NEUTRALITY — an invalid/untrusted/absent mark never changes the
//     result or exit code of the existing verification;
//   * AGGREGATE SEMANTICS — the output line and the presumption note speak
//     of the day's aggregate, never "per event" (forbidden formulation, §0.7).
import { assert, assertEquals, assertStringIncludes, assertThrows } from "jsr:@std/assert@1";
import {
  MAX_TST_BYTES,
  parseTst,
  tsaShapeProblems,
  TstParseError,
  trustedTsaFingerprints,
  verifyQualifiedTimestamp,
  verifyTstSignature,
} from "../src/tst_lite.ts";
import { verifyAnchors } from "../src/ots.ts";
import { verifyChain } from "../src/verify.ts";
import { assess, renderHuman } from "../src/render.ts";
import { attributeEvents } from "../src/issuer.ts";
import { exportShapeProblems } from "../src/shape.ts";

const Q = (name: string) => new URL(`../vectors/qualified/${name}`, import.meta.url);
const readJson = (name: string) => JSON.parse(Deno.readTextFileSync(Q(name)));
const readBytes = (name: string) => Deno.readFileSync(Q(name));
const AGG = "ee78becb1ac2a1d07aea0b1e32a326d6df410f52adc77d760893541991409290";

const trustLocal = () => trustedTsaFingerprints(readJson("tsa-trust-local.json"));
const trustNone = () => new Set<string>();

// ---------------------------------------------------------------------------
// Reader + CMS signature, both implementations.
// ---------------------------------------------------------------------------
Deno.test("tst_lite: the local ECDSA token parses and its CMS signature verifies", async () => {
  const p = parseTst(readBytes("real-local.tst"));
  assertEquals(p.messageImprintHex, AGG);
  assertEquals(p.hashAlgorithmOid, "2.16.840.1.101.3.4.2.1");
  assertEquals(p.tsaName, "Humarch Test TSA (untrusted fixture)");
  assertEquals(p.policyOid, "1.3.6.1.4.1.99999.1.1");
  assert(p.signerCertDer !== null);
  assertEquals(await verifyTstSignature(p), true);
});

Deno.test("tst_lite: the freetsa.org RSA token parses and its CMS signature verifies", async () => {
  const p = parseTst(readBytes("real-freetsa.tst"));
  assertEquals(p.messageImprintHex, AGG);
  assertEquals(p.tsaName, "www.freetsa.org");
  assertEquals(await verifyTstSignature(p), true);
});

Deno.test("tst_lite: one flipped TSTInfo byte breaks the signature, typed errors on hostile bytes", async () => {
  const raw = readBytes("real-local.tst");
  // Flip one byte of the imprint digest INSIDE the TSTInfo: pure content, so
  // the token still parses — but the message-digest attribute no longer
  // matches the TSTInfo bytes and the CMS signature check must fail.
  const hex = Array.from(raw, (b: number) => b.toString(16).padStart(2, "0")).join("");
  const at = hex.indexOf(AGG);
  assert(at >= 0 && at % 2 === 0, "the imprint digest rides inside the token");
  const flipped = new Uint8Array(raw);
  flipped[at / 2] ^= 0x01;
  const p = parseTst(flipped);
  assert(p.messageImprintHex !== AGG, "the flip landed on the imprint digest");
  assertEquals(await verifyTstSignature(p), false, "message-digest attribute must not match");
  // Hostile input: typed failure, never a crash (D87 discipline).
  assertThrows(() => parseTst(raw.slice(0, 33)), TstParseError);
  assertThrows(() => parseTst(new Uint8Array([0xde, 0xad, 0xbe, 0xef])), TstParseError);
  assertThrows(() => parseTst(new Uint8Array(MAX_TST_BYTES + 1)), TstParseError);
});

Deno.test("tst_lite: tsa-trust registry shape gate", () => {
  assertEquals(tsaShapeProblems(readJson("tsa-trust-local.json")), []);
  assert(tsaShapeProblems({ format: "nope", tsas: [] }).length > 0);
  assert(tsaShapeProblems({ format: "humarch-tsa/v1", tsas: [{}] }).length > 0);
  assert(
    tsaShapeProblems({
      format: "humarch-tsa/v1",
      tsas: [{ sha256_cert_fingerprints: ["ZZ"] }],
    }).length > 0,
  );
});

// ---------------------------------------------------------------------------
// Per-anchor verdict statuses (D98 (e)).
// ---------------------------------------------------------------------------
Deno.test("qualified verdict: absent / valid / untrusted / invalid, on the aggregate", async () => {
  const anchor = readJson("export-qualified.json").anchors[0];
  const bare = { ...anchor };
  delete bare.qualified_timestamp;

  assertEquals((await verifyQualifiedTimestamp(bare, trustLocal())).status, "absent");

  const valid = await verifyQualifiedTimestamp(anchor, trustLocal());
  assertEquals(valid.status, "valid");
  assertEquals(valid.matches_aggregate, true);
  assertEquals(valid.signature_valid, true);
  assertEquals(valid.trusted_tsa, true);
  assertStringIncludes(valid.note, "valid · Humarch Test TSA");

  const untrusted = await verifyQualifiedTimestamp(anchor, trustNone());
  assertEquals(untrusted.status, "untrusted");
  assertEquals(untrusted.note, "valid token, untrusted TSA, no presumption");

  const mismatch = readJson("export-qualified-mismatch.json").anchors[0];
  const inv = await verifyQualifiedTimestamp(mismatch, trustLocal());
  assertEquals(inv.status, "invalid");
  assertEquals(inv.matches_aggregate, false, "a token for another digest never binds this day");

  const malformed = readJson("export-qualified-malformed.json").anchors[0];
  const bad = await verifyQualifiedTimestamp(malformed, trustLocal());
  assertEquals(bad.status, "invalid");
  assertStringIncludes(bad.note, "unreadable token");

  // Oversize base64: declared invalid, never buffered or crashed.
  const huge = { ...anchor, qualified_timestamp: { token_base64: "A".repeat(90_000) } };
  assertEquals((await verifyQualifiedTimestamp(huge, trustLocal())).status, "invalid");
});

// ---------------------------------------------------------------------------
// Exit neutrality + rendering (the two D98 invariants).
// ---------------------------------------------------------------------------
async function fullRun(name: string, trusted: boolean) {
  const exp = readJson(name);
  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(
    exp,
    "trustless", // no explorer network in the suite
    undefined,
    trusted ? readJson("tsa-trust-local.json") : undefined,
  );
  const attribution = attributeEvents(exp, new Set<string>());
  const v = assess(exp, chain, anchors, attribution);
  return { exp, chain, anchors, ...v };
}

Deno.test("exit neutrality: valid, invalid and absent marks all leave result and exit unchanged", async () => {
  const base = await fullRun("../export-real-anchor.json" as string, false);
  for (const name of ["export-qualified.json", "export-qualified-mismatch.json", "export-qualified-malformed.json"]) {
    const run = await fullRun(name, true);
    assertEquals(run.result, base.result, `${name}: result must not move`);
    assertEquals(run.exitCode, base.exitCode, `${name}: exit code must not move`);
  }
});

Deno.test("render: one additive line per anchor, aggregate semantics, no forbidden formulation", async () => {
  const valid = await fullRun("export-qualified.json", true);
  const human = renderHuman(
    valid.exp.tenant_id,
    valid.chain,
    valid.anchors,
    valid.result,
    valid.properties,
  );
  assertStringIncludes(human, "[OK] Qualified timestamp of 2026-07-06 — valid · Humarch Test TSA");
  assertStringIncludes(
    human,
    "attaches the eIDAS art. 42 presumption to the daily aggregate",
  );
  assertStringIncludes(human, "inherits that anteriority through deterministic, reproducible recomputation");
  assert(!human.includes("every event has"), "forbidden formulation (§0.7) must never render");

  const untrusted = await fullRun("export-qualified.json", false);
  const humanU = renderHuman(
    untrusted.exp.tenant_id,
    untrusted.chain,
    untrusted.anchors,
    untrusted.result,
    untrusted.properties,
  );
  assertStringIncludes(
    humanU,
    "[WARN] Qualified timestamp of 2026-07-06 — valid token, untrusted TSA, no presumption.",
  );
  assert(!humanU.includes("art. 42 presumption"), "no presumption note without a trusted mark");

  const invalid = await fullRun("export-qualified-malformed.json", true);
  const humanI = renderHuman(
    invalid.exp.tenant_id,
    invalid.chain,
    invalid.anchors,
    invalid.result,
    invalid.properties,
  );
  assertStringIncludes(humanI, "[WARN] Qualified timestamp of 2026-07-06 — invalid (unreadable token");

  const absent = await fullRun("../export-real-anchor.json" as string, false);
  const humanA = renderHuman(
    absent.exp.tenant_id,
    absent.chain,
    absent.anchors,
    absent.result,
    absent.properties,
  );
  assertStringIncludes(humanA, "[--] Qualified timestamp of 2026-07-06 — absent.");
});

// ---------------------------------------------------------------------------
// Shape gate: the new field is optional and validated when present.
// ---------------------------------------------------------------------------
Deno.test("shape: qualified_timestamp is optional, validated when present", () => {
  assertEquals(exportShapeProblems(readJson("export-qualified.json")), []);
  const exp = readJson("export-qualified.json");
  exp.anchors[0].qualified_timestamp.token_base64 = "not base64 !!";
  assert(
    exportShapeProblems(exp).some((p: string) => p.includes("qualified_timestamp.token_base64")),
  );
  const exp2 = readJson("export-qualified.json");
  exp2.anchors[0].qualified_timestamp = "a string";
  assert(exportShapeProblems(exp2).some((p: string) => p.includes("expected an object")));
});
