// humarch-verify/src/verify.ts — reference implementation of the Humarch
// verification routine (B10 §10.4, D63). It applies ONLY the approved specs:
// JCS canonicalization (D12, RFC 8785), event_hash pre-image (D11),
// Ed25519 over the 32 raw bytes of the digest (D13), per-tenant genesis (D4),
// self-certifying signing_key_id (D16), anchor aggregate formula (D9).
//
// Golden rule (B2 §2.2.2): always re-canonicalize from the PARSED VALUES of
// the export, never from its serialized text.
//
// This module is imported by the humarch-core writer and report functions
// (single hashing/canonicalization implementation, brief §1.6, D63): any
// change here is a spec-level change and must reproduce vectors V0–V5.
import canonicalizeImport from "npm:canonicalize@2.0.0";

// canonicalize is a CommonJS module; Deno's type-checker sees the namespace
// instead of the callable default export. Runtime behavior is unaffected.
const canonicalize = canonicalizeImport as unknown as (input: unknown) => string | undefined;

const enc = new TextEncoder();

export const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// Defense-in-depth (external review 2026-07-16): callers inside this repo
// only reach fromHex through the shape gate, but the module is public — an
// importer without that gate must get a loud error, never bytes silently
// decoded from garbage (same fail-loud philosophy as jcs on undefined).
export const fromHex = (s: string): Uint8Array => {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error("fromHex: expected an even-length hex string");
  }
  return Uint8Array.from(s.match(/.{2}/g) ?? [], (h) => parseInt(h, 16));
};

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));
}

/** JCS (RFC 8785) canonical serialization of a parsed JSON value (D12). */
export function jcs(obj: unknown): string {
  const out = canonicalize(obj);
  if (typeof out !== "string") {
    throw new Error("jcs: value is not canonicalizable (undefined input?)");
  }
  return out;
}

/** hex(SHA-256(JCS(obj))) — component hashes of §2.3 (D8). */
export async function jcsHash(obj: unknown): Promise<string> {
  return sha256Hex(enc.encode(jcs(obj)));
}

/** Per-tenant genesis hash (D4): hex(SHA-256("humarch:genesis:" + tenant_id)). */
export async function genesisHash(tenantId: string): Promise<string> {
  return sha256Hex(enc.encode("humarch:genesis:" + tenantId));
}

/** Event fields that enter the D11 pre-image (timestamps in §2.2.3 format). */
export interface EventHashParts {
  event_id: string;
  tenant_id: string;
  sequence_number: number | bigint;
  received_at: string;
  occurred_at: string;
  source: string;
  event_type: string;
}

/** D11 pre-image: 12 lines, every line \n-terminated (the last one included). */
export function eventPreimage(
  ev: EventHashParts,
  actorHash: string,
  subjectHash: string,
  payloadHash: string,
  prevHash: string,
): string {
  return "humarch:event:v1\n" + ev.event_id + "\n" + ev.tenant_id + "\n" +
    String(ev.sequence_number) + "\n" + ev.received_at + "\n" + ev.occurred_at + "\n" +
    ev.source + "\n" + ev.event_type + "\n" +
    actorHash + "\n" + subjectHash + "\n" + payloadHash + "\n" + prevHash + "\n";
}

export async function eventHash(
  ev: EventHashParts,
  actorHash: string,
  subjectHash: string,
  payloadHash: string,
  prevHash: string,
): Promise<string> {
  return sha256Hex(enc.encode(eventPreimage(ev, actorHash, subjectHash, payloadHash, prevHash)));
}

/** Self-certifying key id (D16): "ed25519:" + first 16 hex of SHA-256(raw public key). */
export async function expectedKeyId(publicKeyHex: string): Promise<string> {
  return "ed25519:" + (await sha256Hex(fromHex(publicKeyHex))).slice(0, 16);
}

/** Ed25519 verification over the 32 raw bytes of event_hash (D13). */
export async function edVerify(
  publicKeyHex: string,
  signatureHex: string,
  eventHashHex: string,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    fromHex(publicKeyHex) as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return await crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    fromHex(signatureHex) as BufferSource,
    fromHex(eventHashHex) as BufferSource,
  );
}

/** Anchor entry pair for the D9 aggregate formula. */
export interface AnchorEntry {
  tenant_id: string;
  last_event_hash: string;
}

/**
 * Daily-anchor aggregate hash (D9): entries sorted by tenant_id as lowercase
 * UUID string, pre-image "humarch:anchor:" + date + "\n" + Σ(tenant:hash\n).
 * Single implementation: ots.ts and the tests import this one (vector V4).
 */
export async function aggregateHash(
  anchorDate: string,
  entries: AnchorEntry[],
): Promise<string> {
  const lines = [...entries]
    .sort((x, y) => (x.tenant_id < y.tenant_id ? -1 : x.tenant_id > y.tenant_id ? 1 : 0))
    .map((e) => `${e.tenant_id}:${e.last_event_hash}\n`).join("");
  return sha256Hex(enc.encode(`humarch:anchor:${anchorDate}\n` + lines));
}

export type FailureKind =
  | "payload_hash_mismatch"
  | "event_hash_mismatch"
  | "chain_mismatch"
  | "sequence_gap"
  | "unknown_key"
  | "bad_key_id"
  | "bad_signature";

export interface Verdict {
  chain_continuous: boolean;
  signatures_valid: boolean;
  anchored_to_genesis: boolean; // true when the range starts at sequence 1
  verified_from_sequence: number | null;
  verified_through_sequence: number | null;
  first_failure: { sequence_number: number; kind: FailureKind; detail: string } | null;
}

/** Chain + signature verification over a humarch-export/v1 object (B10 §10.4). */
export async function verifyChain(exp: any): Promise<Verdict> {
  const keys = new Map<string, string>();
  for (const k of exp.signing_keys ?? []) keys.set(k.signing_key_id, k.public_key);
  const events = [...(exp.events ?? [])].sort((a, b) => a.sequence_number - b.sequence_number);
  const v: Verdict = {
    chain_continuous: true,
    signatures_valid: true,
    anchored_to_genesis: false,
    verified_from_sequence: events.length ? events[0].sequence_number : null,
    verified_through_sequence: null,
    first_failure: null,
  };
  if (!events.length) return v;
  v.anchored_to_genesis = events[0].sequence_number === 1;

  let prev: string | null = null;
  let prevSeq: number | null = null;
  for (const ev of events) {
    const fail = (kind: FailureKind, detail: string) => {
      if (kind === "bad_signature" || kind === "unknown_key" || kind === "bad_key_id") {
        v.signatures_valid = false;
      } else v.chain_continuous = false;
      v.first_failure = { sequence_number: ev.sequence_number, kind, detail };
    };
    if (await jcsHash(ev.payload) !== ev.payload_hash) {
      fail("payload_hash_mismatch", "payload_hash != SHA-256(JCS(payload))");
      break;
    }
    const ah = await jcsHash(ev.actor), sh = await jcsHash(ev.subject);
    const eh = await eventHash(ev, ah, sh, ev.payload_hash, ev.prev_hash);
    if (eh !== ev.event_hash) {
      fail("event_hash_mismatch", "event_hash != recomputed pre-image (D11)");
      break;
    }

    if (prev === null) { // first event of the range
      if (ev.sequence_number === 1) {
        const g = await genesisHash(ev.tenant_id);
        if (ev.prev_hash !== g) {
          fail("chain_mismatch", "prev_hash of sequence 1 != genesis hash (D4)");
          break;
        }
      }
      // when the range starts mid-chain, prev_hash is the declared entry
      // point: not verifiable further back (B10, V5 resolution).
    } else {
      if (ev.prev_hash !== prev) {
        fail("chain_mismatch", "prev_hash != previous event_hash");
        break;
      }
      if (ev.sequence_number !== (prevSeq as number) + 1) {
        fail("sequence_gap", "sequence gap inside the range");
        break;
      }
    }

    const pub = keys.get(ev.signing_key_id);
    if (!pub) {
      fail("unknown_key", "signing_key_id missing from signing_keys");
      break;
    }
    if (ev.signing_key_id !== await expectedKeyId(pub)) {
      fail("bad_key_id", "signing_key_id does not match SHA-256(public_key) (D16)");
      break;
    }
    if (!(await edVerify(pub, ev.signature, eh))) {
      fail("bad_signature", "invalid Ed25519 signature (D13)");
      break;
    }

    v.verified_through_sequence = ev.sequence_number;
    prev = eh;
    prevSeq = ev.sequence_number;
  }
  return v;
}
