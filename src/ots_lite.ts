// First-party minimal OpenTimestamps reader/verifier (D87, 2026-07-19).
//
// Replaces npm:@lacrypta/typescript-opentimestamps in this repo: the tarball
// published on npm is AGPL-3.0, which cannot be bundled into the MIT-licensed
// release binaries (audit 3, phase 0). This module implements only what the
// verifier needs — parse a detached .ots receipt, evaluate the commitment
// operations, and check Bitcoin attestations against public block explorers —
// and nothing the stamper needs (the core keeps the library server-side).
//
// The authoritative source for the binary format is the official client
// (python-opentimestamps: op.py, timestamp.py, notary.py, serialize.py,
// detached.py); every tag below was copied from it in session (2026-07-19)
// and the CI interop gate against the official `ots` client (D20) remains
// the cross-check that keeps this reader honest.
//
// Trust-boundary discipline (audit F5): receipt bytes are attacker data.
// Every size, count and value decided by the input has an explicit cap, and
// exceeding any cap raises the SAME typed error as a malformed receipt —
// callers map it to the existing fail-safe path (unreadable receipt, exit 3),
// never to a new outcome. The tree walk is iterative (explicit stack): a
// hostile receipt cannot blow the call stack.

import { ripemd160 } from "npm:@noble/hashes@1.8.0/legacy";

// --- caps (each one is exercised by tests/ots_lite.test.ts) ----------------
export const MAX_RECEIPT_BYTES = 1 << 20; // decoded receipt, bounds all else
export const MAX_VARINT_BYTES = 9; // and value <= Number.MAX_SAFE_INTEGER
export const MAX_EVAL_BYTES = 4 << 20; // accumulated buffer in evaluateOps
export const MAX_OPS_PER_PATH = 4096; // real receipts use ~50
export const MAX_TREE_NODES = 65536; // hostile fork fan-out
export const MAX_ATTESTATIONS = 64; // real receipts carry 1-4
export const MAX_BITCOIN_HEIGHTS = 16; // distinct heights (explorer fetches)
export const MIN_BLOCK_HEIGHT = 1;
export const MAX_BLOCK_HEIGHT = 10_000_000; // never build URLs beyond this
export const MAX_URI_BYTES = 4096; // pending URI, bounded though never fetched
export const MAX_ATTESTATION_PAYLOAD = 8192; // python MAX_PAYLOAD_SIZE

// Header magic of a detached timestamp file (detached.py HEADER_MAGIC).
// Built from hex codes only — never literal control characters in source.
const HEADER_MAGIC = new Uint8Array([
  0x00,
  ...[..."OpenTimestamps"].map((c) => c.charCodeAt(0)),
  0x00,
  0x00,
  ...[..."Proof"].map((c) => c.charCodeAt(0)),
  0x00,
  0xbf,
  0x89,
  0xe2,
  0xe8,
  0x84,
  0xe8,
  0x92,
  0x94,
]);
const MAJOR_VERSION = 1;

// Op tags (op.py). The file-hash op must be sha256: Humarch aggregates are
// always sha256 (D9), and so are both committed fixtures — fail closed.
const TAG_SHA1 = 0x02;
const TAG_RIPEMD160 = 0x03;
const TAG_SHA256 = 0x08;
const TAG_APPEND = 0xf0;
const TAG_PREPEND = 0xf1;

// Timestamp-tree markers (timestamp.py).
const TAG_ATTESTATION = 0x00;
const TAG_FORK = 0xff;

// Attestation type tags, 8 bytes (notary.py), compared as hex.
const BITCOIN_ATT_TAG = "0588960d73d71901";
const PENDING_ATT_TAG = "83dfe30d2ef90c8e";

/** Typed reader error: malformed receipt, unsupported op, or any cap
 * exceeded. Callers treat every instance as "unreadable receipt". */
export class OtsParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OtsParseError";
  }
}

export type OtsOp =
  | { readonly op: "append" | "prepend"; readonly operand: Uint8Array }
  | { readonly op: "sha256" | "sha1" | "ripemd160" };

export interface OtsBitcoinAttestation {
  readonly kind: "bitcoin";
  readonly height: number;
  /** commitment path: applying these ops to the digest yields the block's
   * merkle root in INTERNAL byte order. */
  readonly ops: readonly OtsOp[];
}

export interface OtsPendingAttestation {
  readonly kind: "pending";
  readonly uri: string;
}

export type OtsAttestation = OtsBitcoinAttestation | OtsPendingAttestation;

export interface OtsReceipt {
  /** the stamped file hash (sha256, 32 bytes) */
  readonly digest: Uint8Array;
  readonly attestations: readonly OtsAttestation[];
}

const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

class ByteReader {
  pos = 0;
  constructor(readonly bytes: Uint8Array) {}

  readByte(): number {
    if (this.pos >= this.bytes.length) throw new OtsParseError("unexpected end of receipt");
    return this.bytes[this.pos++];
  }

  readBytes(n: number): Uint8Array {
    if (this.pos + n > this.bytes.length) throw new OtsParseError("unexpected end of receipt");
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** unsigned little-endian base-128 varint (serialize.py read_varuint),
   * capped at MAX_VARINT_BYTES bytes and Number.MAX_SAFE_INTEGER. */
  readVaruint(): number {
    let value = 0;
    let factor = 1;
    for (let i = 0; i < MAX_VARINT_BYTES; i++) {
      const b = this.readByte();
      value += (b & 0x7f) * factor;
      if (value > Number.MAX_SAFE_INTEGER) throw new OtsParseError("varint value too large");
      if ((b & 0x80) === 0) return value;
      factor *= 128;
    }
    throw new OtsParseError("varint too long");
  }

  /** varint length prefix + payload (serialize.py read_varbytes). */
  readVarbytes(maxLen: number, minLen = 0): Uint8Array {
    const len = this.readVaruint();
    if (len > maxLen) throw new OtsParseError(`varbytes length ${len} exceeds cap ${maxLen}`);
    if (len < minLen) throw new OtsParseError("varbytes shorter than minimum");
    return this.readBytes(len);
  }

  atEnd(): boolean {
    return this.pos === this.bytes.length;
  }
}

function parseAttestation(r: ByteReader): OtsAttestation {
  const tag = bytesToHex(r.readBytes(8));
  const payload = new ByteReader(r.readVarbytes(MAX_ATTESTATION_PAYLOAD));
  if (tag === BITCOIN_ATT_TAG) {
    const height = payload.readVaruint();
    if (!Number.isInteger(height) || height < MIN_BLOCK_HEIGHT || height > MAX_BLOCK_HEIGHT) {
      throw new OtsParseError(`bitcoin attestation height ${height} out of range`);
    }
    if (!payload.atEnd()) throw new OtsParseError("trailing bytes in bitcoin attestation payload");
    return { kind: "bitcoin", height, ops: [] };
  }
  if (tag === PENDING_ATT_TAG) {
    const uriBytes = payload.readVarbytes(MAX_URI_BYTES);
    for (const b of uriBytes) {
      // printable ASCII only; the URI is bounded and never fetched by us.
      if (b < 0x20 || b > 0x7e) throw new OtsParseError("pending attestation URI not printable");
    }
    if (!payload.atEnd()) throw new OtsParseError("trailing bytes in pending attestation payload");
    return { kind: "pending", uri: String.fromCharCode(...uriBytes) };
  }
  throw new OtsParseError(`unknown attestation type tag ${tag}`);
}

function parseOp(tag: number, r: ByteReader): OtsOp {
  switch (tag) {
    case TAG_SHA256:
      return { op: "sha256" };
    case TAG_SHA1:
      return { op: "sha1" };
    case TAG_RIPEMD160:
      return { op: "ripemd160" };
    case TAG_APPEND:
      // An operand cannot "invent" bytes beyond the receipt itself, and the
      // official client refuses empty operands (op.py min_len=1).
      return { op: "append", operand: r.readVarbytes(r.bytes.length, 1) };
    case TAG_PREPEND:
      return { op: "prepend", operand: r.readVarbytes(r.bytes.length, 1) };
    default:
      // reverse/hexlify/keccak and anything future: unsupported, fail safe.
      throw new OtsParseError(`unsupported op tag 0x${tag.toString(16).padStart(2, "0")}`);
  }
}

/** Parse a detached .ots receipt. Throws OtsParseError on any malformation,
 * unsupported construct, or exceeded cap — never anything else. */
export function parseOts(bytes: Uint8Array): OtsReceipt {
  if (bytes.length > MAX_RECEIPT_BYTES) throw new OtsParseError("receipt exceeds size cap");
  const r = new ByteReader(bytes);

  const magic = r.readBytes(HEADER_MAGIC.length);
  for (let i = 0; i < HEADER_MAGIC.length; i++) {
    if (magic[i] !== HEADER_MAGIC[i]) throw new OtsParseError("bad header magic");
  }
  const version = r.readVaruint();
  if (version !== MAJOR_VERSION) throw new OtsParseError(`unsupported version ${version}`);

  const fileHashTag = r.readByte();
  if (fileHashTag !== TAG_SHA256) {
    throw new OtsParseError("file hash op is not sha256 (Humarch aggregates are always sha256)");
  }
  const digest = r.readBytes(32);

  // Timestamp tree (timestamp.py deserialize), iterative with an explicit
  // stack of op paths: 0xff forks a branch on a COPY of the current path;
  // the first non-0xff byte starts the frame's final branch.
  const attestations: OtsAttestation[] = [];
  const bitcoinHeights = new Set<number>();
  let nodes = 0;

  const handleTagOrAttestation = (tag: number, path: OtsOp[]): OtsOp[] | null => {
    if (++nodes > MAX_TREE_NODES) throw new OtsParseError("tree node cap exceeded");
    if (tag === TAG_ATTESTATION) {
      const att = parseAttestation(r);
      if (attestations.length >= MAX_ATTESTATIONS) {
        throw new OtsParseError("attestation cap exceeded");
      }
      if (att.kind === "bitcoin") {
        bitcoinHeights.add(att.height);
        if (bitcoinHeights.size > MAX_BITCOIN_HEIGHTS) {
          throw new OtsParseError("distinct bitcoin height cap exceeded");
        }
        attestations.push({ ...att, ops: path.slice() });
      } else {
        attestations.push(att);
      }
      return null;
    }
    const op = parseOp(tag, r);
    path.push(op);
    if (path.length > MAX_OPS_PER_PATH) throw new OtsParseError("ops-per-path cap exceeded");
    return path;
  };

  const stack: OtsOp[][] = [[]];
  while (stack.length > 0) {
    const path = stack[stack.length - 1];
    const tag = r.readByte();
    if (tag === TAG_FORK) {
      const sub = handleTagOrAttestation(r.readByte(), path.slice());
      if (sub !== null) stack.push(sub);
    } else {
      stack.pop();
      const sub = handleTagOrAttestation(tag, path);
      if (sub !== null) stack.push(sub);
    }
  }

  // The tree must consume the buffer exactly (serialize.py assert_eof).
  if (!r.atEnd()) throw new OtsParseError("trailing bytes after timestamp tree");

  return { digest, attestations };
}

/** Apply a commitment path to the digest; returns the accumulated 20/32-byte
 * result (for a Bitcoin attestation: the merkle root, internal byte order).
 * Throws OtsParseError if the accumulated buffer exceeds MAX_EVAL_BYTES. */
export async function evaluateOps(
  digest: Uint8Array,
  ops: readonly OtsOp[],
): Promise<Uint8Array> {
  let cur = digest;
  for (const o of ops) {
    switch (o.op) {
      case "append":
      case "prepend": {
        if (cur.length + o.operand.length > MAX_EVAL_BYTES) {
          throw new OtsParseError("evaluation buffer cap exceeded");
        }
        const out = new Uint8Array(cur.length + o.operand.length);
        if (o.op === "append") {
          out.set(cur);
          out.set(o.operand, cur.length);
        } else {
          out.set(o.operand);
          out.set(cur, o.operand.length);
        }
        cur = out;
        break;
      }
      case "sha256":
        cur = new Uint8Array(await crypto.subtle.digest("SHA-256", cur as BufferSource));
        break;
      case "sha1":
        cur = new Uint8Array(await crypto.subtle.digest("SHA-1", cur as BufferSource));
        break;
      case "ripemd160":
        cur = ripemd160(cur);
        break;
    }
  }
  return cur;
}

// --- explorer leg (D64 level "explorer") -----------------------------------
//
// Injectable endpoints (EmailDeps pattern): production callers pass nothing;
// tests point both bases at a local server and exercise every failure mode
// of the network leg offline. Success semantics are the historical ones:
// an attestation is verified when AT LEAST ONE explorer confirms its merkle
// root at the attested height — never "both agree" (that would change
// verdicts; the contract is frozen).

export interface ExplorerDeps {
  readonly blockstreamBase: string;
  readonly blockchainInfoBase: string;
  readonly timeoutMs: number;
}

export const DEFAULT_EXPLORER_DEPS: ExplorerDeps = {
  blockstreamBase: "https://blockstream.info/api",
  blockchainInfoBase: "https://blockchain.info",
  timeoutMs: 15_000,
};

const MAX_EXPLORER_RESPONSE = 1 << 20;
const HEX64 = /^[0-9a-f]{64}$/;
// Sane unix block time: after the genesis block, before year 2100.
const timeSane = (t: unknown): t is number =>
  typeof t === "number" && Number.isInteger(t) && t >= 1_231_006_505 && t <= 4_102_444_800;

/** Explorer responses are untrusted input like everything else: the body
 * read is capped, redirects are refused (endpoints are pinned — a redirect
 * is an anomaly), and any HTTP/parse/shape violation throws (the caller
 * turns it into a "false" contribution for that explorer). */
async function fetchText(url: string, timeoutMs: number): Promise<string> {
  const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    await res.body?.cancel();
    throw new Error(`HTTP ${res.status}`);
  }
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_EXPLORER_RESPONSE) {
      await reader.cancel();
      throw new Error("explorer response exceeds read cap");
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  return new TextDecoder().decode(all);
}

/** blockstream.info: /block-height/{h} → block hash; /block/{hash} →
 * { merkle_root, timestamp }. Returns the block time iff the merkle root
 * matches expectedRootHex (display order). */
async function viaBlockstream(
  height: number,
  expectedRootHex: string,
  deps: ExplorerDeps,
): Promise<number | null> {
  const hash = (await fetchText(`${deps.blockstreamBase}/block-height/${height}`, deps.timeoutMs))
    .trim().toLowerCase();
  if (!HEX64.test(hash)) throw new Error("block hash is not 64 hex chars");
  const block = JSON.parse(
    await fetchText(`${deps.blockstreamBase}/block/${hash}`, deps.timeoutMs),
  );
  const root = block?.merkle_root;
  if (typeof root !== "string" || !HEX64.test(root.toLowerCase())) {
    throw new Error("merkle_root is not 64 hex chars");
  }
  if (!timeSane(block?.timestamp)) throw new Error("block timestamp not a sane unix time");
  return root.toLowerCase() === expectedRootHex ? block.timestamp : null;
}

/** blockchain.info: /block-height/{h}?format=json → { blocks: [...] } with
 * mrkl_root/time per block (the array may include stale forks). */
async function viaBlockchainInfo(
  height: number,
  expectedRootHex: string,
  deps: ExplorerDeps,
): Promise<number | null> {
  const body = JSON.parse(
    await fetchText(
      `${deps.blockchainInfoBase}/block-height/${height}?format=json`,
      deps.timeoutMs,
    ),
  );
  const blocks = body?.blocks;
  if (!Array.isArray(blocks)) throw new Error("blocks is not an array");
  for (const b of blocks.slice(0, 16)) {
    const root = b?.mrkl_root;
    if (typeof root !== "string" || !HEX64.test(root.toLowerCase())) continue;
    if (root.toLowerCase() === expectedRootHex && timeSane(b?.time)) return b.time;
  }
  return null;
}

/** Verify the receipt's Bitcoin attestations against the public explorers.
 * Returns the VERIFIED block times (unix s), one per confirmed height.
 * Never throws: any network/parse/shape/evaluation failure contributes
 * "unverified" for that leg. Anti-amplification: fetches are a function of
 * the caps, never of the input — one height is queried once per explorer at
 * most (duplicate heights deduplicated, distinct heights already capped at
 * MAX_BITCOIN_HEIGHTS by the parser), sequentially. */
export async function verifyBitcoinAttestations(
  receipt: OtsReceipt,
  deps: ExplorerDeps = DEFAULT_EXPLORER_DEPS,
): Promise<number[]> {
  const byHeight = new Map<number, OtsBitcoinAttestation>();
  for (const a of receipt.attestations) {
    if (a.kind === "bitcoin" && !byHeight.has(a.height)) byHeight.set(a.height, a);
  }
  const times: number[] = [];
  for (const att of byHeight.values()) {
    // Belt and braces: the parser already enforces the height range.
    if (att.height < MIN_BLOCK_HEIGHT || att.height > MAX_BLOCK_HEIGHT) continue;
    let expectedRootHex: string;
    try {
      // Explorers return the merkle root in DISPLAY order (reversed bytes).
      expectedRootHex = bytesToHex(
        (await evaluateOps(receipt.digest, att.ops)).slice().reverse(),
      );
    } catch {
      continue; // evaluation cap exceeded: this attestation stays unverified
    }
    let time: number | null = null;
    try {
      time = await viaBlockstream(att.height, expectedRootHex, deps);
    } catch {
      // this explorer contributes false; the other may still confirm
    }
    if (time === null) {
      try {
        time = await viaBlockchainInfo(att.height, expectedRootHex, deps);
      } catch {
        // both failed: the attestation stays unverified
      }
    }
    if (time !== null) times.push(time);
  }
  return times;
}
