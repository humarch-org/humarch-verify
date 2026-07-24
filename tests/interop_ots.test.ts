// Phase-2 interop gate (D20, B12 §12.3/§12.7): every .ots our stamper produces
// must be read/updated/verified both by the official Python client (`ots`,
// the expert's tool) and by our reader. Since D87 (2026-07-19) the reader is
// the first-party src/ots_lite.ts (parseOts/evaluateOps/
// verifyBitcoinAttestations) — the npm library is no longer imported by this
// repo; tier 1 pins the reader's contract on the SAME fixtures with the SAME
// expected values, and tiers 2-3 keep the official client as the cross-check
// that validates it.
//
// Fixtures (real, committed):
// - vectors/anchors/anchor-2026-07-06.ots — receipt produced by OUR anchor-stamp
//   against the four public calendars (first manual run, 2026-07-06), then
//   CONFIRMED by anchor-upgrade the same day: Bitcoin blocks 956916/956921
//   (two calendars answered; the other two promises legitimately remain
//   pending in the receipt — a timestamp is complete with one attestation).
// - vectors/anchors/hello-world.txt(.ots) — the OpenTimestamps project's
//   classic CONFIRMED attestation (Bitcoin block 358391), produced by the
//   official tooling: covers the confirmed path deterministically.
// - vectors/export-real-anchor.json — humarch-export/v1 of the local dev
//   tenant carrying the real receipt as ots_file_base64 (§4.8 rule 3).
//
// INTEROP FINDING (declared, 2026-07-06): the TS library serializes calendar
// URIs with a trailing slash (URL.toString()); the official client's default
// whitelist globs don't match them, so `ots upgrade` on OUR receipts needs
// explicit `-l <url-with-slash>` flags. Verification of CONFIRMED files is
// unaffected (the whitelist only gates calendar queries). Documented in the
// runbook; the network-gated step below exercises exactly that flow.
//
// Tiers: offline checks always run; `ots` checks run when the binary is
// available (HUMARCH_REQUIRE_OTS=1 turns absence into a failure — set in CI);
// HUMARCH_INTEROP_NET=1 adds the real network steps (explorers + calendars).
import { assert, assertEquals } from "jsr:@std/assert@1";
import { evaluateOps, parseOts, verifyBitcoinAttestations } from "../src/ots_lite.ts";
import { verifyChain } from "../src/verify.ts";
import { verifyAnchors } from "../src/ots.ts";

const OUR_RECEIPT = "vectors/anchors/anchor-2026-07-06.ots";
const OUR_DIGEST = "ee78becb1ac2a1d07aea0b1e32a326d6df410f52adc77d760893541991409290";
const OUR_BLOCKS = [956916, 956921]; // daily_anchors records the min (B3 §3.5.3)
const HELLO_OTS = "vectors/anchors/hello-world.txt.ots";
const HELLO_TXT = "vectors/anchors/hello-world.txt";
const HELLO_DIGEST = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340";
const HELLO_BLOCK = 358391;
const HELLO_MERKLEROOT = "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00";

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// ---------------------------------------------------------------------------
// Tier 1 — first-party reader (D87), offline, always. Same fixtures, same
// expected values as when the npm library was the reader.
// ---------------------------------------------------------------------------
Deno.test("reader parses our stamper's receipt: digest IS the aggregate hash", async () => {
  const receipt = parseOts(await Deno.readFile(OUR_RECEIPT));
  assertEquals(toHex(receipt.digest), OUR_DIGEST);
  // Confirmed receipt: two Bitcoin attestations landed, two calendar
  // promises legitimately remain (upgradable, not required for verification).
  const heights = receipt.attestations.filter((a) => a.kind === "bitcoin")
    .map((a) => a.height).sort((a, b) => a - b);
  assertEquals(heights, OUR_BLOCKS);
  assertEquals(
    receipt.attestations.filter((a) => a.kind === "pending").length,
    2,
    "two calendars still pending",
  );
  // canVerify/canUpgrade equivalents: a Bitcoin attestation is verifiable,
  // a pending promise is upgradable.
  assertEquals(receipt.attestations.some((a) => a.kind === "bitcoin"), true);
  assertEquals(receipt.attestations.some((a) => a.kind === "pending"), true);
});

Deno.test("reader parses the official confirmed fixture: block height and merkle root extractable", async () => {
  const receipt = parseOts(await Deno.readFile(HELLO_OTS));
  assertEquals(toHex(receipt.digest), HELLO_DIGEST);
  // The .ots is a detached timestamp of the companion file's sha256.
  const txt = await Deno.readFile(HELLO_TXT);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", txt as BufferSource));
  assertEquals(toHex(digest), HELLO_DIGEST);
  const bitcoin = receipt.attestations.filter((a) => a.kind === "bitcoin");
  assertEquals(bitcoin.map((a) => a.height), [HELLO_BLOCK]);
  // Deterministic offline check of the whole commitment evaluation (the
  // path includes ripemd160): the evaluated root, reversed to display
  // order, IS the merkle root the official client prints for block 358391.
  const root = await evaluateOps(receipt.digest, bitcoin[0].ops);
  assertEquals(toHex(root.slice().reverse()), HELLO_MERKLEROOT);
});

Deno.test("golden export with the real CONFIRMED receipt: chain green, anchor verdict declared (B10 §10.5)", async () => {
  const exp = JSON.parse(await Deno.readTextFile("vectors/export-real-anchor.json"));
  const chain = await verifyChain(exp);
  assertEquals(chain.chain_continuous, true, JSON.stringify(chain.first_failure));
  assertEquals(chain.signatures_valid, true);
  assertEquals(chain.anchored_to_genesis, true);

  // Offline tier: the trustless level never touches the network — it
  // delegates the Bitcoin check to the official client and DECLARES it
  // (D64); the explorer level is exercised in the network tier below.
  const anchors = await verifyAnchors(exp, "trustless");
  assertEquals(anchors.length, 1);
  const a = anchors[0];
  assertEquals(a.anchor_date, "2026-07-06");
  assertEquals(a.ots_status, "confirmed");
  assertEquals(a.ots_btc_block, OUR_BLOCKS[0]);
  assertEquals(a.aggregate_recomputed, true, "D9 formula reproduces aggregate_hash (V4)");
  assertEquals(a.ots_commits_to_aggregate, true, "the .ots stamps exactly the aggregate");
  assertEquals(a.bitcoin_verified, null, "trustless level delegates to the official client (D64)");
  assert(a.note.includes("ots verify"), "the verdict names the official-client step");
});

// ---------------------------------------------------------------------------
// Tier 2 — official client (`ots`), local: skip when absent; CI sets
// HUMARCH_REQUIRE_OTS=1 so absence fails the gate there (B12 §12.7).
// ---------------------------------------------------------------------------
async function runOts(args: string[]): Promise<{ code: number; out: string } | null> {
  const bin = Deno.env.get("HUMARCH_OTS_BIN") ?? "ots";
  try {
    const { code, stdout, stderr } = await new Deno.Command(bin, {
      args,
      stdout: "piped",
      stderr: "piped",
    }).output();
    return {
      code,
      out: new TextDecoder().decode(stdout) + new TextDecoder().decode(stderr),
    };
  } catch {
    if (Deno.env.get("HUMARCH_REQUIRE_OTS")) {
      throw new Error(
        "official opentimestamps-client not available but HUMARCH_REQUIRE_OTS is set",
      );
    }
    console.log("SKIP: official `ots` client not on PATH (set HUMARCH_OTS_BIN or install it)");
    return null;
  }
}

Deno.test("official client reads our stamper's receipt (ots info)", async () => {
  const res = await runOts(["info", OUR_RECEIPT]);
  if (!res) return;
  assert(res.out.includes(`File sha256 hash: ${OUR_DIGEST}`), res.out);
  for (const block of OUR_BLOCKS) {
    assert(
      res.out.includes(`BitcoinBlockHeaderAttestation(${block})`),
      `Bitcoin attestation ${block} visible to the official client`,
    );
  }
  assert(res.out.includes("PendingAttestation"), "the residual calendar promises are visible");
});

Deno.test("official client validates the confirmed fixture's commitment path (ots --no-bitcoin verify)", async () => {
  const res = await runOts(["--no-bitcoin", "verify", HELLO_OTS]);
  if (!res) return;
  // Without a Bitcoin Core node the client validates the ops chain and emits
  // the manual claim — the full trustless check is D64 level (a), the
  // expert's gold standard, out of scope for this environment by design.
  assert(res.out.includes(`block ${HELLO_BLOCK}`), res.out);
  assert(res.out.includes(HELLO_MERKLEROOT), res.out);
});

// ---------------------------------------------------------------------------
// Tier 3 — real network (explorers + public calendars), opt-in.
// ---------------------------------------------------------------------------
const NET = Deno.env.get("HUMARCH_INTEROP_NET") === "1";

Deno.test(
  { name: "explorer verification of the confirmed fixtures (D64 level b)", ignore: !NET },
  async () => {
    // Both the official project's fixture and OUR confirmed receipt.
    for (const file of [HELLO_OTS, OUR_RECEIPT]) {
      const receipt = parseOts(await Deno.readFile(file));
      const times = await verifyBitcoinAttestations(receipt);
      assert(times.length > 0, `no explorer confirmed ${file}`);
    }
  },
);

Deno.test({
  name: "golden export at explorer level: bitcoin_verified = true (D64 level b)",
  ignore: !NET,
}, async () => {
  const exp = JSON.parse(await Deno.readTextFile("vectors/export-real-anchor.json"));
  const anchors = await verifyAnchors(exp); // default level: explorer
  assertEquals(anchors[0].ots_status, "confirmed");
  assertEquals(anchors[0].bitcoin_verified, true, anchors[0].note);
  // D64 amendment 2026-07-12 (audit F1, time leg): the genuine anchor's
  // attested block time sits inside the declared-day window.
  assert(anchors[0].ots_btc_time !== null, "explorer level exposes the attested block time");
  assertEquals(anchors[0].time_consistent, true, anchors[0].note);
});

Deno.test({
  name: "end-to-end exit 0 (D82, M3 case 1): real anchored export + --issuer → VERIFIED",
  ignore: !NET,
}, async () => {
  // The three-property verdict at full strength needs the network (explorer
  // attestation of the real anchor); the trusted set is written here OUT OF
  // BAND — the dev environment key that signed the fixture, pinned as a
  // literal, never read from the export.
  const DEV_KEY = "efddcd5a449c0efbc6dcef4c9e951129fc70bad24cf9515b700ce70cd70f677f";
  const issuerTmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(
    issuerTmp,
    JSON.stringify({ format: "humarch-keys/v1", keys: [{ public_key: DEV_KEY }] }),
  );
  try {
    const cmd = new Deno.Command(Deno.execPath(), {
      args: [
        "run",
        "--allow-read",
        "--allow-net",
        "src/cli.ts",
        "vectors/export-real-anchor.json",
        "--issuer",
        issuerTmp,
        "--json",
      ],
      stdout: "piped",
      stderr: "piped",
    });
    const out = await cmd.output();
    const stdout = new TextDecoder().decode(out.stdout);
    assertEquals(out.code, 0, new TextDecoder().decode(out.stderr) + stdout);
    const verdict = JSON.parse(stdout);
    assertEquals(verdict.result, "verified");
    assertEquals(verdict.properties, {
      integrity: "ok",
      time: "proven",
      attribution: "attributed",
    });
  } finally {
    await Deno.remove(issuerTmp);
  }
});

Deno.test({
  name: "official client upgrades our receipt (whitelist wrinkle documented)",
  ignore: !NET,
}, async () => {
  // Work on a copy: a successful upgrade rewrites the file (+ .bak).
  const tmp = await Deno.makeTempDir();
  const copy = `${tmp}/anchor-2026-07-06.ots`;
  await Deno.writeFile(copy, await Deno.readFile(OUR_RECEIPT));
  const res = await runOts([
    "-l",
    "https://alice.btc.calendar.opentimestamps.org/",
    "-l",
    "https://bob.btc.calendar.opentimestamps.org/",
    "-l",
    "https://finney.calendar.eternitywall.com/",
    "-l",
    "https://btc.calendar.catallaxy.com/",
    "upgrade",
    copy,
  ]);
  if (!res) return;
  // Fresh receipt: calendars answer "Pending confirmation" (exit 1) until the
  // Bitcoin block lands (hours); afterwards the same command completes the
  // proof (exit 0). Both are correct interop outcomes — never a whitelist
  // rejection, never a parse failure.
  assert(!res.out.includes("not in whitelist"), res.out);
  assert(
    res.out.includes("Pending confirmation") || res.code === 0,
    `unexpected upgrade outcome: ${res.out}`,
  );
});
