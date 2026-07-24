// humarch-verify/src/issuer.ts — trusted-issuer key attribution (B10 D82,
// audit finding F1, attribution leg; amendment 2026-07-12). ADDITIVE module:
// the normative verification routine (verify.ts, D63) and its Verdict are
// untouched.
//
// Why this exists: an export's `signing_keys` array is ATTACKER-CONTROLLED
// data. verifyChain proves the chain is internally consistent and that every
// signing_key_id is self-certifying (D16) — it cannot prove the keys belong
// to the issuer the reader trusts. D16's key id is a 64-bit LOOKUP HANDLE,
// never a trust anchor (a collision costs ~2^32 work), and a membership test
// on the export's own key list is bypassable by padding the genuine key in as
// a decoy while signing every event with another. Attribution therefore
// compares, for EVERY event of the export, the raw public-key BYTES the event
// resolves to against a trusted set obtained OUT OF BAND (a humarch-keys/v1
// document: the --issuer flag, the embedded registry, or — in the panel —
// the signing_keys table itself).

/** One key of a humarch-keys/v1 registry — same shape as a signing_keys row
 * (mig 008); only public_key is load-bearing for attribution. */
export interface IssuerKey {
  signing_key_id?: string;
  algorithm?: string;
  public_key: string;
  created_at?: string;
  retired_at?: string | null;
}

export interface IssuerRegistry {
  format: "humarch-keys/v1";
  keys: IssuerKey[];
  notice?: string;
}

/** Embedded trusted registry: PREDISPOSED BUT EMPTY until go-live (D82).
 * Empty set ⇒ attribution is `not_checked` (exit 6) unless --issuer/--pubkey
 * is given. SECURITY INVARIANT (test- and CI-guarded): the RFC 8032 test key
 * (d75a9801…511a), whose private seed is published in an RFC, must NEVER
 * appear here — anyone could then fabricate a VERIFIED export. */
export const EMBEDDED_ISSUER: IssuerRegistry = {
  format: "humarch-keys/v1",
  keys: [],
};

const HEX_64 = /^[0-9a-fA-F]{64}$/;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Structural problems of a parsed humarch-keys/v1 value; empty array means
 * the document is a well-formed registry. Same trust-boundary discipline as
 * shape.ts (audit F5): a malformed registry is `malformed` input (exit 4 at
 * the CLI), never a throw inside the verifier.
 */
export function issuerShapeProblems(value: unknown): string[] {
  const problems: string[] = [];
  if (!isObject(value)) return ["issuer: not a JSON object"];
  if (value.format !== "humarch-keys/v1") {
    problems.push('issuer.format: not "humarch-keys/v1"');
  }
  if (!Array.isArray(value.keys)) {
    problems.push("issuer.keys: expected an array");
    return problems;
  }
  value.keys.forEach((k, i) => {
    if (!isObject(k)) {
      problems.push(`issuer.keys[${i}]: expected an object`);
      return;
    }
    if (typeof k.public_key !== "string" || !HEX_64.test(k.public_key)) {
      problems.push(`issuer.keys[${i}].public_key: expected 64 hex chars (raw Ed25519 public key)`);
    }
    if (k.algorithm !== undefined && k.algorithm !== "ed25519") {
      problems.push(`issuer.keys[${i}].algorithm: only "ed25519" is supported`);
    }
  });
  return problems;
}

/** The trusted PUBLIC-KEY BYTES of a registry, as lowercase hex. Retired
 * keys stay trusted: key rotation is additive — a retired key keeps
 * attesting the history it signed. */
export function trustedKeyBytes(registry: IssuerRegistry): Set<string> {
  return new Set(registry.keys.map((k) => k.public_key.toLowerCase()));
}

export type Attribution = "attributed" | "not_checked" | "foreign_key";

/**
 * Per-event, byte-level attribution (the F1 fix): for EVERY event of the
 * export, the public key its signing_key_id resolves to (in the export's own
 * signing_keys list — the same resolution verifyChain uses) must have its
 * raw bytes inside the trusted set. Never compares signing_key_id values.
 *
 * - empty trusted set ⇒ `not_checked` (nobody vouches for any key);
 * - any event resolving to a key outside the set (or to no key at all) ⇒
 *   `foreign_key` — the decoy/padding bypass lands here by construction;
 * - otherwise `attributed`.
 */
export function attributeEvents(
  exp: {
    signing_keys?: { signing_key_id: string; public_key: string }[];
    events?: { signing_key_id: string }[];
  },
  trusted: Set<string>,
): Attribution {
  if (trusted.size === 0) return "not_checked";
  const byId = new Map<string, string>();
  for (const k of exp.signing_keys ?? []) {
    byId.set(k.signing_key_id, k.public_key.toLowerCase());
  }
  for (const ev of exp.events ?? []) {
    const pub = byId.get(ev.signing_key_id);
    if (pub === undefined || !trusted.has(pub)) return "foreign_key";
  }
  return "attributed";
}
