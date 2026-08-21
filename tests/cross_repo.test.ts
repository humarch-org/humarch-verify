// Cross-repository drift gates (BT-47 and GO-LIVE B.9, 2026-08-21).
//
// These are the checks whose ABSENCE was the finding. Two facts of this
// project are deliberately published in more than one place, and in both cases
// the redundancy is the defence — which holds only while the copies agree, and
// nothing was measuring that.
//
// Both gates need the sibling `humarch-spec` checkout. A test that quietly
// skips when it cannot find one is worse than no test, because it reports
// green while checking nothing; so the absence of the sibling FAILS unless it
// is explicitly waived, and CI checks the sibling out.

import { assert, assertEquals } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";
import {
  compareTrees,
  embeddedKeysFromSource,
  keySetFingerprint,
  productionKeysFromMarkdown,
} from "../src/registries.ts";

const here = fromFileUrl(new URL("..", import.meta.url));
const specDir = Deno.env.get("HUMARCH_SPEC_DIR") ?? `${here}/../humarch-spec`;

function specAvailable(): boolean {
  try {
    return Deno.statSync(`${specDir}/SPEC.md`).isFile;
  } catch {
    return false;
  }
}

/**
 * Fail loudly rather than skip. The one waiver is an explicit environment
 * variable, so a green run that checked nothing has to be somebody's decision,
 * recorded in the command line, instead of an accident of the checkout layout.
 */
function requireSpec(): boolean {
  if (specAvailable()) return true;
  if (Deno.env.get("HUMARCH_ALLOW_NO_SIBLING") === "1") {
    console.log(
      "  cross-repo: humarch-spec not present and the waiver is set — NOT CHECKED",
    );
    return false;
  }
  throw new Error(
    `the sibling humarch-spec checkout was not found at ${specDir}. These ` +
      `gates compare this repository against it; set HUMARCH_SPEC_DIR, or ` +
      `HUMARCH_ALLOW_NO_SIBLING=1 to waive them deliberately.`,
  );
}

/** Every file under `dir`, keyed by its path relative to `dir`. */
function readTree(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (sub: string) => {
    for (const entry of Deno.readDirSync(`${dir}/${sub}`)) {
      const rel = sub === "" ? entry.name : `${sub}/${entry.name}`;
      if (entry.isDirectory) walk(rel);
      else if (entry.isFile) {
        // Bytes, not text: these are conformance vectors, and a comparison
        // that normalized line endings would call two different contracts
        // equal.
        out.set(
          rel,
          Array.from(Deno.readFileSync(`${dir}/${rel}`))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
        );
      }
    }
  };
  walk("");
  return out;
}

Deno.test("BT-47: the shared vectors of humarch-spec and humarch-verify are byte-identical", () => {
  if (!requireSpec()) return;
  const cmp = compareTrees(
    readTree(`${specDir}/vectors`),
    readTree(`${here}/vectors`),
  );

  console.log(
    `  cross-repo vectors: ${cmp.identical.length} shared and identical, ` +
      `${cmp.onlyInFirst.length} spec-only, ${cmp.onlyInSecond.length} verify-only`,
  );

  assertEquals(
    cmp.differing,
    [],
    `${cmp.differing.length} vector(s) exist in BOTH repositories with ` +
      `different bytes. A conformance vector is the contract itself ` +
      `(non-negotiable 5): two repositories publishing two versions of the ` +
      `same contract is the drift this gate exists to catch.\n` +
      cmp.differing.map((p) => `  - ${p}`).join("\n"),
  );

  // The intersection must be non-trivial, or this gate could pass by
  // comparing nothing — a renamed directory would empty it silently.
  assert(
    cmp.identical.length >= 20,
    `only ${cmp.identical.length} shared vector(s) found: the trees have ` +
      `probably been reorganized and this gate is no longer looking at them`,
  );

  // The asymmetry is reported, not failed: the trees overlap by design and do
  // not mirror. `schema/`, `shredding/`, `wrapping/`, `message-id/`,
  // `negative/` and `replay/` belong to the spec alone — a verifier
  // implements no part of ingestion — while the raw `.ots` receipts and the
  // FreeTSA fixture belong to the verifier alone. Failing on asymmetry would
  // demand a mirror nobody wants; the point is that what IS shared agrees.
  if (cmp.onlyInFirst.length > 0 || cmp.onlyInSecond.length > 0) {
    console.log(
      `    spec-only:   ${cmp.onlyInFirst.join(", ") || "(none)"}\n` +
        `    verify-only: ${cmp.onlyInSecond.join(", ") || "(none)"}`,
    );
  }
});

Deno.test("GO-LIVE B.9: the public key registries declare the same production keys", () => {
  // B.9 publishes the production signing key in five independent places, and
  // states the redundancy as the defence: "a cross-check unmasks tampering
  // with the site alone". That property holds only while the five agree, and
  // nothing verified it — the same structure as BT-91 and BT-100, both closed.
  //
  // Three of the five live in the public repositories and can be compared
  // here. The other two — the served `/.well-known/humarch-keys.json` and the
  // `signing_key_created` event on the registry itself — are runtime
  // artifacts, checked by the site's own gate and by the service-ops trail.
  const embedded = embeddedKeysFromSource(
    Deno.readTextFileSync(`${here}/src/issuer.ts`),
  );
  const verifyKeys = productionKeysFromMarkdown(
    Deno.readTextFileSync(`${here}/KEYS.md`),
  );

  assertEquals(
    keySetFingerprint(embedded),
    keySetFingerprint(verifyKeys),
    "EMBEDDED_ISSUER (what ships in the binaries) and humarch-verify/KEYS.md " +
      "(what a reader cross-checks against) declare different production keys",
  );

  if (!requireSpec()) return;
  const specKeys = productionKeysFromMarkdown(
    Deno.readTextFileSync(`${specDir}/KEYS.md`),
  );
  assertEquals(
    keySetFingerprint(specKeys),
    keySetFingerprint(embedded),
    "humarch-spec/KEYS.md and EMBEDDED_ISSUER declare different production keys",
  );

  console.log(
    `  key registries: 3 sources agree on ${embedded.length} production key(s)` +
      (embedded.length === 0 ? " (none yet — the first is generated at go-live)" : ""),
  );
});

Deno.test("GO-LIVE B.9: the RFC 8032 test key is in no production registry", () => {
  // The twin of the CI guard on issuer.ts, extended to both KEYS.md files and
  // expressed against the PARSED production section rather than against the
  // whole file — which is the distinction that matters, since both files
  // document the test key on purpose, in a section that exists to say it must
  // never be trusted.
  const RFC8032 =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const sources: [string, string][] = [
    ["humarch-verify/src/issuer.ts", `${here}/src/issuer.ts`],
    ["humarch-verify/KEYS.md", `${here}/KEYS.md`],
  ];
  if (specAvailable()) sources.push(["humarch-spec/KEYS.md", `${specDir}/KEYS.md`]);

  for (const [label, path] of sources) {
    const text = Deno.readTextFileSync(path);
    const keys = label.endsWith(".ts")
      ? embeddedKeysFromSource(text)
      : productionKeysFromMarkdown(text);
    assert(
      !keys.some((k) => k.publicKey === RFC8032),
      `${label} lists the RFC 8032 test key as a PRODUCTION key. Its private ` +
        `seed is published in the RFC: anyone could then fabricate an export ` +
        `this verifier calls VERIFIED.`,
    );
  }
});

// ---------------------------------------------------------------------------
// The gates above compare real files, and today those files agree — so on
// their own they cannot show that they would NOTICE a disagreement. These
// exercise the mechanism against constructed drift, which is the difference
// between a gate and a decoration.
// ---------------------------------------------------------------------------

Deno.test("drift detection: a changed shared vector is reported, asymmetry is not", () => {
  const spec = new Map([
    ["chain/v2.json", "aabb"],
    ["schema/i01.json", "1122"], // spec-only by design
  ]);
  const verify = new Map([
    ["chain/v2.json", "aabb"],
    ["anchors/x.ots", "3344"], // verify-only by design
  ]);
  const same = compareTrees(spec, verify);
  assertEquals(same.differing, []);
  assertEquals(same.identical, ["chain/v2.json"]);
  assertEquals(same.onlyInFirst, ["schema/i01.json"]);
  assertEquals(same.onlyInSecond, ["anchors/x.ots"]);

  const drifted = compareTrees(spec, new Map([...verify, ["chain/v2.json", "aabc"]]));
  assertEquals(drifted.differing, ["chain/v2.json"], "one byte must be enough");
});

Deno.test("drift detection: the production section is parsed, the test-key section is not", () => {
  const md = [
    "# Keys",
    "",
    "## Production keys",
    "",
    "| signing_key_id | public_key (hex) | created_at | retired_at |",
    "|---|---|---|---|",
    `| \`ed25519:1234567890abcdef\` | \`${"a".repeat(64)}\` | 2026-09-01 | |`,
    "",
    "## Test key (conformance vectors only — NEVER valid in production)",
    "",
    `| \`ed25519:21fe31dfa154a261\` | \`${"d".repeat(64)}\` |`,
    "",
  ].join("\n");
  const keys = productionKeysFromMarkdown(md);
  assertEquals(keys.length, 1, "the test-key section must stay out of the set");
  assertEquals(keys[0].signingKeyId, "ed25519:1234567890abcdef");
  assertEquals(keys[0].publicKey, "a".repeat(64));

  // The placeholder row of today's files declares nothing.
  const empty = productionKeysFromMarkdown(
    "## Production keys\n\n| signing_key_id |\n|---|\n| *(none yet)* |\n",
  );
  assertEquals(empty, []);
});

Deno.test("drift detection: a key added to one registry and not the other is caught", () => {
  const populated = `## Production keys
| id | key |
|---|---|
| \`ed25519:1234567890abcdef\` | \`${"a".repeat(64)}\` |
`;
  const embeddedEmpty = `export const EMBEDDED_ISSUER: IssuerRegistry = {
  format: "humarch-keys/v1",
  keys: [],
};`;
  const embeddedSame = `export const EMBEDDED_ISSUER: IssuerRegistry = {
  format: "humarch-keys/v1",
  keys: [
    { signing_key_id: "ed25519:1234567890abcdef", public_key: "${"a".repeat(64)}" },
  ],
};`;
  // This is the go-live failure mode B.9 leaves open: the key is published in
  // one place and the binaries still ship the empty set.
  assert(
    keySetFingerprint(productionKeysFromMarkdown(populated)) !==
      keySetFingerprint(embeddedKeysFromSource(embeddedEmpty)),
    "a key in KEYS.md but not in EMBEDDED_ISSUER must not compare equal",
  );
  assertEquals(
    keySetFingerprint(productionKeysFromMarkdown(populated)),
    keySetFingerprint(embeddedKeysFromSource(embeddedSame)),
    "and the aligned case must compare equal, or the gate is unusable",
  );

  // A wrong BYTE in the same key id is the subtle case: the id is a 64-bit
  // handle (D16), so two registries agreeing on it while disagreeing on the
  // key bytes is exactly the substitution a cross-check exists to catch.
  const swapped = populated.replace("a".repeat(64), "b".repeat(64));
  assert(
    keySetFingerprint(productionKeysFromMarkdown(swapped)) !==
      keySetFingerprint(embeddedKeysFromSource(embeddedSame)),
    "same key id, different key bytes must not compare equal",
  );
});
