// Cross-repository drift detection for the public tree (BT-47 and GO-LIVE
// B.9, 2026-08-21).
//
// Two facts of this project are published in more than one place on purpose,
// and in both cases the redundancy IS the defence:
//
//   * the conformance vectors live in `humarch-spec/vectors` and in
//     `humarch-verify/vectors`, so a verifier can be built and tested from
//     either repository alone;
//   * the issuer's production signing keys are published in five independent
//     places (see KEYS.md), so that forging the trusted set requires forging
//     all of them rather than one website.
//
// Redundancy only defends anything while the copies AGREE, and until now
// nothing checked that they did. That is the whole finding: not a divergence
// that had already happened, but a guarantee nobody was measuring. The same
// shape as BT-91 and BT-100 before it — a claim whose truth depended on
// somebody remembering.
//
// The functions here are pure and take the file contents; the wiring lives in
// tests/cross_repo.test.ts.

// ---------------------------------------------------------------------------
// The vector trees
// ---------------------------------------------------------------------------

export interface TreeComparison {
  /** Paths present in both trees whose bytes differ. The hard failure. */
  differing: string[];
  /** Paths present in both trees, byte-identical. */
  identical: string[];
  /** Present only in the first tree. Legitimate; reported, not failed. */
  onlyInFirst: string[];
  /** Present only in the second tree. Legitimate; reported, not failed. */
  onlyInSecond: string[];
}

/**
 * Compare two file maps (relative path -> bytes as a hex digest or raw text).
 *
 * Deliberately NOT an equality check on the trees. They overlap, they do not
 * mirror: 59 files in spec, 37 in verify, 14 paths in exactly one of them, all
 * of it intentional — `schema/`, `shredding/`, `wrapping/`, `message-id/`,
 * `negative/` and `replay/` are the spec's alone (a verifier implements none
 * of ingestion), while the raw `.ots` receipts and the FreeTSA fixture are the
 * verifier's alone (the spec pins formats, not network artifacts).
 *
 * So `diff -rq` on these trees prints no "Files ... differ" and fourteen
 * "Only in ..." lines, and anyone running it expecting silence concludes
 * something is broken. What must hold is that the INTERSECTION is byte-
 * identical, and that is what this returns as a failure.
 */
export function compareTrees(
  first: Map<string, string>,
  second: Map<string, string>,
): TreeComparison {
  const differing: string[] = [];
  const identical: string[] = [];
  const onlyInFirst: string[] = [];
  const onlyInSecond: string[] = [];
  for (const [path, content] of first) {
    if (!second.has(path)) {
      onlyInFirst.push(path);
    } else if (second.get(path) === content) {
      identical.push(path);
    } else {
      differing.push(path);
    }
  }
  for (const path of second.keys()) {
    if (!first.has(path)) onlyInSecond.push(path);
  }
  return {
    differing: differing.sort(),
    identical: identical.sort(),
    onlyInFirst: onlyInFirst.sort(),
    onlyInSecond: onlyInSecond.sort(),
  };
}

// ---------------------------------------------------------------------------
// The key registries
// ---------------------------------------------------------------------------

export interface DeclaredKey {
  signingKeyId: string;
  publicKey: string;
}

const KEY_ID = /ed25519:[0-9a-f]{16}/;
const PUBLIC_KEY = /\b[0-9a-f]{64}\b/;

/**
 * The PRODUCTION keys declared by a `KEYS.md`: the rows of the table under the
 * "## Production keys" heading, up to the next heading.
 *
 * Scoped to that section on purpose. Both KEYS.md files also document the
 * RFC 8032 test key, in a section whose entire point is that the key must
 * NEVER be trusted in production — reading the whole file would pull that key
 * into the comparison and, worse, would make the two registries "agree" about
 * a key that must not be in either.
 */
export function productionKeysFromMarkdown(text: string): DeclaredKey[] {
  const body = text.replace(/\r\n/g, "\n");
  const start = body.indexOf("## Production keys");
  if (start < 0) {
    throw new Error("KEYS.md carries no '## Production keys' section");
  }
  const nextHeading = body.indexOf("\n## ", start + 1);
  const section = body.slice(start, nextHeading < 0 ? body.length : nextHeading);

  const keys: DeclaredKey[] = [];
  for (const line of section.split("\n")) {
    if (!line.trimStart().startsWith("|")) continue;
    const cells = line.split("|").map((c) => c.trim());
    const id = cells.find((c) => KEY_ID.test(c));
    const pk = cells.find((c) => PUBLIC_KEY.test(c) && !KEY_ID.test(c));
    // The placeholder row ("none yet — ...") carries neither, and separator
    // rows ("|---|---|") carry neither: both are simply not keys.
    if (id === undefined || pk === undefined) continue;
    keys.push({
      signingKeyId: KEY_ID.exec(id)![0],
      publicKey: PUBLIC_KEY.exec(pk)![0],
    });
  }
  return keys;
}

/**
 * The keys compiled into the released binaries, read from the SOURCE of
 * `issuer.ts` rather than by importing it.
 *
 * Reading the source is the point: what ships in a binary is what the file
 * says, and a check that imported the module would agree with itself about a
 * value it had just evaluated. This reads the same bytes a reviewer would.
 */
export function embeddedKeysFromSource(text: string): DeclaredKey[] {
  const body = text.replace(/\r\n/g, "\n");
  const at = body.indexOf("export const EMBEDDED_ISSUER");
  if (at < 0) throw new Error("issuer.ts carries no EMBEDDED_ISSUER");
  const open = body.indexOf("keys: [", at);
  if (open < 0) throw new Error("EMBEDDED_ISSUER carries no keys array");
  const close = body.indexOf("]", open);
  const block = body.slice(open, close);

  const keys: DeclaredKey[] = [];
  // Objects are matched one at a time so a malformed entry cannot be silently
  // read as "no keys", which would make an empty comparison pass.
  for (const entry of block.matchAll(/\{[^{}]*\}/g)) {
    const id = KEY_ID.exec(entry[0]);
    const pk = PUBLIC_KEY.exec(entry[0].replace(KEY_ID, ""));
    if (id === null || pk === null) {
      throw new Error(
        `EMBEDDED_ISSUER entry is not a readable key: ${entry[0].slice(0, 80)}`,
      );
    }
    keys.push({ signingKeyId: id[0], publicKey: pk[0] });
  }
  return keys;
}

/** A stable, order-insensitive fingerprint of a declared key set. */
export function keySetFingerprint(keys: DeclaredKey[]): string {
  return keys
    .map((k) => `${k.signingKeyId}=${k.publicKey}`)
    .sort()
    .join(",");
}
