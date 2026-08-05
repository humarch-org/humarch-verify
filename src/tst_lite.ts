// First-party RFC 3161 TimeStampToken reader/verifier (D98, B3 §3.10 /
// B10 §10.2 — dual anchor). Bounded like ots_lite (D87): explicit caps,
// typed error, fail-safe — an unreadable token is a DECLARED `invalid`,
// never a crash, and the exit codes of the verifier are UNCHANGED (the
// qualified timestamp is additive: integrity/time/attribution stay decided
// by the chain, the signatures and the OTS anchor).
//
// What this verifies, on the day's aggregate (never on a single event —
// the art. 42 presumption attaches to the daily aggregate; each event
// verifiably contained in it inherits that anteriority through
// deterministic, reproducible recomputation):
//   1. the token parses as CMS SignedData carrying a TSTInfo;
//   2. TSTInfo.messageImprint is exactly the anchor's aggregate_hash;
//   3. the TSA's CMS signature over the signed attributes verifies
//      (WebCrypto: RSASSA-PKCS1-v1_5 or ECDSA, SHA-256/384/512), including
//      the message-digest attribute against the TSTInfo bytes;
//   4. the signer certificate is pinned in a trusted TSA registry
//      (`humarch-tsa/v1`, D82 pattern — embedded set + --tsa-trust override).
// Full eIDAS chain validation against the EU Trusted List is DECLARED out of
// scope: it belongs to standard third-party tooling (`openssl ts`, EU TL) —
// this verifier checks and reports, it is never the only one able to.

export class TstParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TstParseError";
  }
}

// Caps (D87 discipline; the archival cap of the core is the same 64 KiB).
export const MAX_TST_BYTES = 64 * 1024;
const MAX_DER_DEPTH = 32;
const MAX_DER_NODES = 8192;

// --- OIDs -------------------------------------------------------------------
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_CN = "2.5.4.3";
const OID_RSA = "1.2.840.113549.1.1.1";
const OID_SHA256_RSA = "1.2.840.113549.1.1.11";
const OID_SHA384_RSA = "1.2.840.113549.1.1.12";
const OID_SHA512_RSA = "1.2.840.113549.1.1.13";
const OID_EC_KEY = "1.2.840.10045.2.1";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4";
const OID_P256 = "1.2.840.10045.3.1.7";
const OID_P384 = "1.3.132.0.34";
const OID_P521 = "1.3.132.0.35";
const HASH_OIDS: Record<string, string> = {
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};
export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

// ---------------------------------------------------------------------------
// Bounded DER reader.
// ---------------------------------------------------------------------------
interface Tlv {
  id: number;
  constructed: boolean;
  start: number;
  end: number;
  hdr: number;
}

class DerReader {
  private nodes = 0;
  constructor(private readonly buf: Uint8Array) {}

  readTlv(offset: number, limit: number): Tlv {
    if (++this.nodes > MAX_DER_NODES) throw new TstParseError("DER node cap exceeded");
    if (offset + 2 > limit) throw new TstParseError("truncated DER header");
    const id = this.buf[offset];
    if ((id & 0x1f) === 0x1f) throw new TstParseError("multi-byte DER tags unsupported");
    let p = offset + 1;
    let len = this.buf[p++];
    if (len === 0x80) throw new TstParseError("indefinite length is not DER");
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new TstParseError("unsupported DER length-of-length");
      if (p + n > limit) throw new TstParseError("truncated DER length");
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + this.buf[p++];
    }
    const start = p;
    const end = start + len;
    if (end > limit) throw new TstParseError("DER content overruns its container");
    return { id, constructed: (id & 0x20) !== 0, start, end, hdr: offset };
  }

  children(tlv: Tlv, depth: number): Tlv[] {
    if (depth > MAX_DER_DEPTH) throw new TstParseError("DER depth cap exceeded");
    if (!tlv.constructed) throw new TstParseError("primitive TLV has no children");
    const out: Tlv[] = [];
    let p = tlv.start;
    while (p < tlv.end) {
      const child = this.readTlv(p, tlv.end);
      out.push(child);
      p = child.end;
    }
    return out;
  }

  slice(tlv: Tlv): Uint8Array {
    return this.buf.slice(tlv.hdr, tlv.end);
  }
  content(tlv: Tlv): Uint8Array {
    return this.buf.slice(tlv.start, tlv.end);
  }
}

function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) throw new TstParseError("empty OID");
  const parts: number[] = [];
  let value = 0;
  let firstDone = false;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    value = value * 128 + (b & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER / 256) throw new TstParseError("OID arc overflow");
    if ((b & 0x80) === 0) {
      if (!firstDone) {
        const head = Math.min(2, Math.floor(value / 40));
        parts.push(head, value - head * 40);
        firstDone = true;
      } else {
        parts.push(value);
      }
      value = 0;
    }
  }
  if (value !== 0) throw new TstParseError("truncated OID arc");
  return parts.join(".");
}

function toHexLocal(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function decodeGeneralizedTime(bytes: Uint8Array): string {
  const s = new TextDecoder().decode(bytes);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d{1,6})?Z$/.exec(s);
  if (!m) throw new TstParseError("genTime is not DER GeneralizedTime (Zulu)");
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`;
  // Plausibility (review L5): "2026-99-99T99:99:99Z" matches the shape but is
  // no date — refuse it here so no impossible date is ever rendered or stored.
  if (!Number.isFinite(Date.parse(iso))) {
    throw new TstParseError("genTime is not a real date");
  }
  return iso;
}

// Terminal-injection guard (adversarial review L1, same discipline as the W4
// coercion of ots_btc_block): names extracted from token bytes are rendered —
// strip C0/DEL controls and the Unicode bidi/linebreak controls that survive
// BMPString/UTF8String decoding.
// deno-lint-ignore no-control-regex
const NAME_CONTROLS = /[\u0000-\u001f\u007f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

function decodeDirectoryString(tlv: Tlv, content: Uint8Array): string | null {
  const tag = tlv.id & 0x1f;
  let out: string | null = null;
  if (tag === 0x1e) {
    out = "";
    for (let i = 0; i + 1 < content.length; i += 2) {
      out += String.fromCharCode(content[i] * 256 + content[i + 1]);
    }
  } else if (tag === 0x0c || tag === 0x13 || tag === 0x16 || tag === 0x14) {
    out = new TextDecoder().decode(content);
  }
  if (out === null) return null;
  const clean = out.replace(NAME_CONTROLS, "").trim();
  return clean === "" ? null : clean;
}

function nameCn(r: DerReader, name: Tlv, depth: number): string | null {
  for (const rdn of r.children(name, depth)) {
    if (rdn.id !== 0x31) continue;
    for (const atv of r.children(rdn, depth + 1)) {
      if (atv.id !== 0x30) continue;
      const pair = r.children(atv, depth + 2);
      if (pair.length !== 2 || pair[0].id !== 0x06) continue;
      if (decodeOid(r.content(pair[0])) !== OID_CN) continue;
      return decodeDirectoryString(pair[1], r.content(pair[1]));
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Parsed token.
// ---------------------------------------------------------------------------
export interface ParsedTst {
  policyOid: string;
  hashAlgorithmOid: string;
  messageImprintHex: string;
  genTime: string;
  /** Lowercase hex of the TSTInfo nonce, when present (the CORE's echo check
   * needs it — this module is vendored there, single implementation). */
  nonceHex: string | null;
  tsaName: string | null;
  /** DER of the TSTInfo (the digest target of the message-digest attribute). */
  tstInfoDer: Uint8Array;
  /** DER of the PREFERRED signer certificate (sid-matched, else first);
   * parse-time convenience only — trust decisions use the certificate
   * verifyTstSignature actually verified with (review M2). */
  signerCertDer: Uint8Array | null;
  /** SubjectPublicKeyInfo DER of the preferred signer certificate. */
  signerSpkiDer: Uint8Array | null;
  /** Every parseable embedded certificate, sid-matches first — the signature
   * check tries them in order (the set is not signature-covered). */
  certCandidates: TstCertCandidate[];
  /** Signed attributes with the tag rewritten to SET OF (the CMS signature
   * input); null when the token carries none (refused later — RFC 3161
   * requires them). */
  signedAttrsDer: Uint8Array | null;
  /** Value of the message-digest signed attribute. */
  messageDigestAttr: Uint8Array | null;
  /** Content-type signed attribute names id-ct-TSTInfo. */
  contentTypeOk: boolean;
  signatureAlgorithmOid: string;
  digestAlgorithmOid: string;
  signature: Uint8Array;
  /** SPKI algorithm: rsa | ec curve OID. */
  keyAlgorithmOid: string | null;
  keyCurveOid: string | null;
}

export interface TstCertCandidate {
  certDer: Uint8Array;
  spkiDer: Uint8Array;
  keyAlgorithmOid: string;
  keyCurveOid: string | null;
  subjectCn: string | null;
  sidMatch: boolean;
}

interface CertFields {
  serial: Uint8Array;
  subjectCn: string | null;
  spkiDer: Uint8Array;
  keyAlgorithmOid: string;
  keyCurveOid: string | null;
}

function parseCert(r: DerReader, cert: Tlv): CertFields | null {
  const tbs = r.children(cert, 4)[0];
  if (!tbs || tbs.id !== 0x30) return null;
  const fields = r.children(tbs, 5);
  let i = 0;
  if (fields[i] && fields[i].id === 0xa0) i++;
  // serial, sigAlg, issuer, validity, subject, spki
  const serialTlv = fields[i];
  const subject = fields[i + 4];
  const spki = fields[i + 5];
  if (!serialTlv || serialTlv.id !== 0x02 || !spki || spki.id !== 0x30) return null;
  let keyAlgorithmOid = "";
  let keyCurveOid: string | null = null;
  const spkiKids = r.children(spki, 6);
  if (spkiKids.length >= 1 && spkiKids[0].id === 0x30) {
    const alg = r.children(spkiKids[0], 7);
    if (alg.length >= 1 && alg[0].id === 0x06) keyAlgorithmOid = decodeOid(r.content(alg[0]));
    if (alg.length >= 2 && alg[1].id === 0x06) keyCurveOid = decodeOid(r.content(alg[1]));
  }
  return {
    serial: r.content(serialTlv),
    subjectCn: subject && subject.id === 0x30 ? nameCn(r, subject, 6) : null,
    spkiDer: r.slice(spki),
    keyAlgorithmOid,
    keyCurveOid,
  };
}

export function parseTst(token: Uint8Array): ParsedTst {
  if (token.byteLength > MAX_TST_BYTES) {
    throw new TstParseError(`token over the ${MAX_TST_BYTES}-byte cap`);
  }
  const r = new DerReader(token);
  const root = r.readTlv(0, token.byteLength);
  if (root.id !== 0x30) throw new TstParseError("TimeStampToken is not a SEQUENCE");
  const ci = r.children(root, 1);
  if (ci.length < 2 || ci[0].id !== 0x06 || decodeOid(r.content(ci[0])) !== OID_SIGNED_DATA) {
    throw new TstParseError("TimeStampToken is not CMS SignedData");
  }
  if (ci[1].id !== 0xa0) throw new TstParseError("missing SignedData wrapper");
  const signedData = r.children(ci[1], 2)[0];
  if (!signedData || signedData.id !== 0x30) throw new TstParseError("malformed SignedData");
  const sd = r.children(signedData, 3);
  if (sd.length < 4) throw new TstParseError("SignedData too short");
  const encap = sd[2];
  if (encap.id !== 0x30) throw new TstParseError("malformed encapContentInfo");
  const ec = r.children(encap, 4);
  if (ec.length < 2 || ec[0].id !== 0x06 || decodeOid(r.content(ec[0])) !== OID_TST_INFO) {
    throw new TstParseError("eContent is not a TSTInfo");
  }
  if (ec[1].id !== 0xa0) throw new TstParseError("missing eContent wrapper");
  const eOctets = r.children(ec[1], 5)[0];
  if (!eOctets || eOctets.id !== 0x04) throw new TstParseError("eContent is not an OCTET STRING");
  const tstInfoDer = r.content(eOctets);

  // --- TSTInfo -------------------------------------------------------------
  const tr = new DerReader(tstInfoDer);
  const tstRoot = tr.readTlv(0, tstInfoDer.byteLength);
  if (tstRoot.id !== 0x30) throw new TstParseError("TSTInfo is not a SEQUENCE");
  const tst = tr.children(tstRoot, 1);
  if (tst.length < 5) throw new TstParseError("TSTInfo too short");
  if (tst[1].id !== 0x06) throw new TstParseError("TSTInfo.policy missing");
  const policyOid = decodeOid(tr.content(tst[1]));
  if (tst[2].id !== 0x30) throw new TstParseError("TSTInfo.messageImprint missing");
  const imprint = tr.children(tst[2], 2);
  if (imprint.length !== 2 || imprint[0].id !== 0x30 || imprint[1].id !== 0x04) {
    throw new TstParseError("malformed messageImprint");
  }
  const algParts = tr.children(imprint[0], 3);
  if (algParts.length < 1 || algParts[0].id !== 0x06) {
    throw new TstParseError("malformed messageImprint algorithm");
  }
  const hashAlgorithmOid = decodeOid(tr.content(algParts[0]));
  const messageImprintHex = toHexLocal(tr.content(imprint[1]));
  if (tst[4].id !== 0x18) throw new TstParseError("TSTInfo.genTime missing");
  const genTime = decodeGeneralizedTime(tr.content(tst[4]));
  let nonceHex: string | null = null;
  let tsaName: string | null = null;
  for (let i = 5; i < tst.length; i++) {
    if (tst[i].id === 0x02) nonceHex = toHexLocal(tr.content(tst[i]));
    if (tst[i].id === 0xa0) {
      const gn = tr.children(tst[i], 2)[0];
      if (gn && gn.id === 0xa4) {
        const name = tr.children(gn, 3)[0];
        if (name && name.id === 0x30) tsaName = nameCn(tr, name, 4);
      }
    }
  }

  // --- SignerInfo ----------------------------------------------------------
  const signerSet = sd[sd.length - 1];
  if (signerSet.id !== 0x31) throw new TstParseError("missing signerInfos");
  const si = r.children(signerSet, 4)[0];
  if (!si || si.id !== 0x30) throw new TstParseError("malformed SignerInfo");
  const siKids = r.children(si, 5);
  if (siKids.length < 5) throw new TstParseError("SignerInfo too short");
  // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature
  let idx = 2;
  if (siKids[idx].id !== 0x30) throw new TstParseError("SignerInfo.digestAlgorithm missing");
  const dAlg = r.children(siKids[idx], 6);
  if (dAlg.length < 1 || dAlg[0].id !== 0x06) throw new TstParseError("malformed digestAlgorithm");
  const digestAlgorithmOid = decodeOid(r.content(dAlg[0]));
  idx++;
  let signedAttrsDer: Uint8Array | null = null;
  let messageDigestAttr: Uint8Array | null = null;
  let contentTypeOk = false;
  if (siKids[idx] && siKids[idx].id === 0xa0) {
    const attrsTlv = siKids[idx];
    // CMS: the signature is computed over the SET OF re-encoding of the
    // IMPLICIT [0] signedAttrs — same bytes, first identifier octet 0x31.
    signedAttrsDer = r.slice(attrsTlv);
    signedAttrsDer[0] = 0x31;
    for (const attr of r.children(attrsTlv, 6)) {
      if (attr.id !== 0x30) continue;
      const kv = r.children(attr, 7);
      if (kv.length !== 2 || kv[0].id !== 0x06 || kv[1].id !== 0x31) continue;
      const oid = decodeOid(r.content(kv[0]));
      const val = r.children(kv[1], 8)[0];
      if (!val) continue;
      if (oid === OID_MESSAGE_DIGEST && val.id === 0x04) messageDigestAttr = r.content(val);
      if (oid === OID_CONTENT_TYPE && val.id === 0x06) {
        contentTypeOk = decodeOid(r.content(val)) === OID_TST_INFO;
      }
    }
    idx++;
  }
  if (!siKids[idx] || siKids[idx].id !== 0x30) {
    throw new TstParseError("SignerInfo.signatureAlgorithm missing");
  }
  const sAlg = r.children(siKids[idx], 6);
  if (sAlg.length < 1 || sAlg[0].id !== 0x06) {
    throw new TstParseError("malformed signatureAlgorithm");
  }
  const signatureAlgorithmOid = decodeOid(r.content(sAlg[0]));
  idx++;
  if (!siKids[idx] || siKids[idx].id !== 0x04) throw new TstParseError("SignerInfo.signature missing");
  const signature = r.content(siKids[idx]);

  // --- signer certificate candidates ---------------------------------------
  // The certificates SET and the SignerInfo.sid are NOT covered by the CMS
  // signature (adversarial review M2): an attacker reordering the set or
  // flipping a sid bit must not be able to downgrade a genuine mark to
  // "signature does not verify". Every parseable certificate is a candidate
  // (sid serial match first as a preference); the verification step accepts
  // the first candidate whose OWN key verifies the signature — fingerprint
  // and display name then come from that same certificate, so the pinning
  // invariant (fpr ⇔ verifying key) is preserved by construction.
  const candidates: TstCertCandidate[] = [];
  const certsTlv = sd.find((t) => t.id === 0xa0);
  if (certsTlv) {
    let wantedSerial: Uint8Array | null = null;
    if (siKids[1] && siKids[1].id === 0x30) {
      const ias = r.children(siKids[1], 6);
      const serial = ias.find((k) => k.id === 0x02);
      if (serial) wantedSerial = r.content(serial);
    }
    const certs = r.children(certsTlv, 4).filter((c) => c.id === 0x30);
    for (const c of certs) {
      const f = parseCert(r, c);
      if (!f) continue;
      candidates.push({
        certDer: r.slice(c),
        spkiDer: f.spkiDer,
        keyAlgorithmOid: f.keyAlgorithmOid,
        keyCurveOid: f.keyCurveOid,
        subjectCn: f.subjectCn,
        sidMatch: wantedSerial !== null && toHexLocal(f.serial) === toHexLocal(wantedSerial),
      });
    }
    candidates.sort((a, b) => Number(b.sidMatch) - Number(a.sidMatch));
  }
  const preferred = candidates[0] ?? null;

  return {
    policyOid,
    hashAlgorithmOid,
    messageImprintHex,
    genTime,
    nonceHex,
    tsaName: tsaName ?? preferred?.subjectCn ?? null,
    tstInfoDer,
    signerCertDer: preferred?.certDer ?? null,
    signerSpkiDer: preferred?.spkiDer ?? null,
    certCandidates: candidates,
    signedAttrsDer,
    messageDigestAttr,
    contentTypeOk,
    signatureAlgorithmOid,
    digestAlgorithmOid,
    signature,
    keyAlgorithmOid: preferred?.keyAlgorithmOid ?? null,
    keyCurveOid: preferred?.keyCurveOid ?? null,
  };
}

// ---------------------------------------------------------------------------
// CMS signature verification (WebCrypto only — no new dependencies).
// ---------------------------------------------------------------------------
function hashForSignature(p: ParsedTst): string | null {
  switch (p.signatureAlgorithmOid) {
    case OID_SHA256_RSA:
    case OID_ECDSA_SHA256:
      return "SHA-256";
    case OID_SHA384_RSA:
    case OID_ECDSA_SHA384:
      return "SHA-384";
    case OID_SHA512_RSA:
    case OID_ECDSA_SHA512:
      return "SHA-512";
    case OID_RSA:
      // Bare rsaEncryption: the digest algorithm of the SignerInfo governs.
      return HASH_OIDS[p.digestAlgorithmOid] ?? null;
    default:
      return null;
  }
}

/** DER ECDSA-Sig-Value {r, s} → raw r||s of the curve's field size. */
function ecdsaDerToRaw(sig: Uint8Array, size: number): Uint8Array | null {
  try {
    const r = new DerReader(sig);
    const root = r.readTlv(0, sig.byteLength);
    if (root.id !== 0x30) return null;
    const parts = r.children(root, 1);
    if (parts.length !== 2 || parts[0].id !== 0x02 || parts[1].id !== 0x02) return null;
    const strip = (b: Uint8Array) => {
      let i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      return b.slice(i);
    };
    const rb = strip(r.content(parts[0]));
    const sb = strip(r.content(parts[1]));
    if (rb.length > size || sb.length > size) return null;
    const out = new Uint8Array(size * 2);
    out.set(rb, size - rb.length);
    out.set(sb, size * 2 - sb.length);
    return out;
  } catch {
    return null;
  }
}

async function digest(alg: string, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(alg, data as BufferSource));
}

export interface TstSignatureResult {
  valid: boolean;
  /** The certificate whose key ACTUALLY verified the signature — the only
   * legitimate fingerprint/pinning target (review M2: the certificates SET
   * and the sid are not signature-covered, so the verifying key decides). */
  signerCertDer: Uint8Array | null;
  signerCn: string | null;
  /** True when nothing verified because no candidate uses a supported
   * algorithm (review M3): reported as its own reason, never conflated with
   * a cryptographic failure. */
  unsupportedAlgorithm: boolean;
}

const NO_SIGNER: TstSignatureResult = {
  valid: false,
  signerCertDer: null,
  signerCn: null,
  unsupportedAlgorithm: false,
};

async function verifyWithCandidate(
  p: ParsedTst,
  c: TstCertCandidate,
  sigHash: string,
): Promise<boolean | "unsupported"> {
  try {
    if (c.keyAlgorithmOid === OID_RSA) {
      const key = await crypto.subtle.importKey(
        "spki",
        c.spkiDer as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash: sigHash },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        key,
        p.signature as BufferSource,
        p.signedAttrsDer as BufferSource,
      );
    }
    if (c.keyAlgorithmOid === OID_EC_KEY) {
      const curve = c.keyCurveOid === OID_P256
        ? { name: "P-256", size: 32 }
        : c.keyCurveOid === OID_P384
        ? { name: "P-384", size: 48 }
        : c.keyCurveOid === OID_P521
        ? { name: "P-521", size: 66 }
        : null;
      if (curve === null) return "unsupported";
      const raw = ecdsaDerToRaw(p.signature, curve.size);
      if (raw === null) return false;
      const key = await crypto.subtle.importKey(
        "spki",
        c.spkiDer as BufferSource,
        { name: "ECDSA", namedCurve: curve.name },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        { name: "ECDSA", hash: sigHash },
        key,
        raw as BufferSource,
        p.signedAttrsDer as BufferSource,
      );
    }
    return "unsupported";
  } catch {
    return false;
  }
}

/** CMS signature verification: the message-digest attribute must match the
 * TSTInfo bytes, and the signature over the signed attributes must verify
 * against the key of SOME embedded certificate — candidates are tried in
 * order (sid match first) because the certificates SET is not covered by the
 * signature (review M2): a reordered set or a flipped sid bit must never
 * downgrade a genuine mark. The returned certificate is the one that
 * verified — fingerprint and display name are taken from it and only it. */
export async function verifyTstSignature(p: ParsedTst): Promise<TstSignatureResult> {
  if (
    p.signedAttrsDer === null || p.messageDigestAttr === null || !p.contentTypeOk ||
    p.certCandidates.length === 0
  ) return NO_SIGNER;
  const attrHash = HASH_OIDS[p.digestAlgorithmOid];
  if (!attrHash) return { ...NO_SIGNER, unsupportedAlgorithm: true };
  const tstDigest = await digest(attrHash, p.tstInfoDer);
  if (toHexLocal(tstDigest) !== toHexLocal(p.messageDigestAttr)) return NO_SIGNER;

  const sigHash = hashForSignature(p);
  if (sigHash === null) return { ...NO_SIGNER, unsupportedAlgorithm: true };
  let sawSupported = false;
  for (const c of p.certCandidates) {
    const outcome = await verifyWithCandidate(p, c, sigHash);
    if (outcome === "unsupported") continue;
    sawSupported = true;
    if (outcome) {
      return {
        valid: true,
        signerCertDer: c.certDer,
        signerCn: c.subjectCn,
        unsupportedAlgorithm: false,
      };
    }
  }
  return { ...NO_SIGNER, unsupportedAlgorithm: !sawSupported };
}

// ---------------------------------------------------------------------------
// Trusted TSA registry (`humarch-tsa/v1`, D82 pattern): SHA-256 fingerprints
// of the QTSP signer certificate(s), embedded default + --tsa-trust override.
// Empty until go-live (the production QTSP is purchased then): every valid
// token then reads "valid token, untrusted TSA, no presumption" — honest by
// default, exactly like the empty EMBEDDED_ISSUER of D82.
// ---------------------------------------------------------------------------
export interface TsaRegistry {
  format: "humarch-tsa/v1";
  tsas: { name?: string; sha256_cert_fingerprints: string[] }[];
}

export const EMBEDDED_TSA: TsaRegistry = { format: "humarch-tsa/v1", tsas: [] };

export function tsaShapeProblems(doc: unknown): string[] {
  const problems: string[] = [];
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    return ["expected an object"];
  }
  // deno-lint-ignore no-explicit-any
  const d = doc as any;
  if (d.format !== "humarch-tsa/v1") problems.push("format is not humarch-tsa/v1");
  if (!Array.isArray(d.tsas)) {
    problems.push("tsas: expected an array");
    return problems;
  }
  d.tsas.forEach((t: unknown, i: number) => {
    if (typeof t !== "object" || t === null) {
      problems.push(`tsas[${i}]: expected an object`);
      return;
    }
    // deno-lint-ignore no-explicit-any
    const fprs = (t as any).sha256_cert_fingerprints;
    if (!Array.isArray(fprs) || fprs.length === 0) {
      problems.push(`tsas[${i}].sha256_cert_fingerprints: expected a non-empty array`);
      return;
    }
    fprs.forEach((f: unknown, j: number) => {
      if (typeof f !== "string" || !/^[0-9a-f]{64}$/.test(f)) {
        problems.push(`tsas[${i}].sha256_cert_fingerprints[${j}]: expected 64 lowercase hex chars`);
      }
    });
  });
  return problems;
}

export function trustedTsaFingerprints(reg: TsaRegistry): Set<string> {
  const out = new Set<string>();
  for (const t of reg.tsas) for (const f of t.sha256_cert_fingerprints) out.add(f.toLowerCase());
  return out;
}

// ---------------------------------------------------------------------------
// Per-anchor qualified-timestamp verdict (D98 (e)) — additive, exit-neutral.
// ---------------------------------------------------------------------------
export type QtStatus = "valid" | "absent" | "invalid" | "untrusted";

export interface QualifiedTimestampVerdict {
  status: QtStatus;
  /** The token commits to exactly the day's aggregate — the RECOMPUTED D9
   * value when the caller supplies it (adversarial review F1: the declared
   * aggregate_hash is attacker data; the presumption claim must bind to the
   * aggregate the entries actually derive). */
  matches_aggregate: boolean | null;
  signature_valid: boolean | null;
  trusted_tsa: boolean | null;
  /** genTime vs the declared anchor day (D64-style window). false never
   * degrades the status — the token's own time is self-describing — but the
   * note says it out loud (adversarial review F4). */
  gen_time_consistent: boolean | null;
  tsa_name: string | null;
  policy_oid: string | null;
  gen_time: string | null;
  note: string;
}

const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// Same window as the OTS time-consistency leg (D64 amendment, see ots.ts —
// values duplicated here to keep the module dependency-free for vendoring;
// the qualified mark lands within hours normally, retries within days).
const QT_TIME_SKEW_BEFORE_S = 4 * 3600;
const QT_TIME_MAX_AFTER_S = 14 * 24 * 3600;

function genTimeConsistent(anchorDate: unknown, genTimeIso: string): boolean | null {
  if (typeof anchorDate !== "string") return null;
  const dayStartS = Date.parse(anchorDate + "T00:00:00Z") / 1000;
  const genS = Date.parse(genTimeIso) / 1000;
  if (!Number.isFinite(dayStartS) || !Number.isFinite(genS)) return null;
  return genS >= dayStartS - QT_TIME_SKEW_BEFORE_S &&
    genS <= dayStartS + 86_400 + QT_TIME_MAX_AFTER_S;
}

export async function verifyQualifiedTimestamp(
  // deno-lint-ignore no-explicit-any
  anchor: any,
  trustedFprs: Set<string>,
  /** The aggregate hash RECOMPUTED per §7 from `anchor_entries_for_aggregate`
   * (lowercase hex, 64 chars) — REQUIRED. It is deliberately not optional and
   * has no fallback to `anchor.aggregate_hash`: that field is supplied by
   * whoever produced the export, so binding to it would let a genuine
   * (hash, token) pair lifted from a published export vouch for a fabricated
   * entry set. A signature that permits the unsafe call is a defect of the
   * signature (external audit, 2026-07-29). */
  expectedAggregateHex: string,
): Promise<QualifiedTimestampVerdict> {
  // A caller that cannot supply a well-formed recomputed aggregate gets a
  // declared `invalid` naming the real cause — never a silent never-match
  // that reads like a bad token.
  if (!/^[0-9a-f]{64}$/i.test(String(expectedAggregateHex ?? ""))) {
    return {
      status: "invalid",
      matches_aggregate: null,
      signature_valid: null,
      trusted_tsa: null,
      gen_time_consistent: null,
      tsa_name: null,
      policy_oid: null,
      gen_time: null,
      note: "no recomputed aggregate supplied to bind the token to (§7.1 step 2)",
    };
  }
  const qt = anchor?.qualified_timestamp;
  if (qt == null) {
    return {
      status: "absent",
      matches_aggregate: null,
      signature_valid: null,
      trusted_tsa: null,
      gen_time_consistent: null,
      tsa_name: null,
      policy_oid: null,
      gen_time: null,
      note: "absent",
    };
  }
  // The token bytes are attacker data (they ride in the export): bounded
  // parse, typed failure ⇒ a DECLARED invalid, never a crash (D87/D98).
  let parsed: ParsedTst;
  try {
    const raw = typeof qt.token_base64 === "string" ? qt.token_base64 : "";
    if (raw.length > Math.ceil(MAX_TST_BYTES / 3) * 4 + 4) {
      throw new TstParseError(`token over the ${MAX_TST_BYTES}-byte cap`);
    }
    parsed = parseTst(b64ToBytes(raw));
  } catch {
    return {
      status: "invalid",
      matches_aggregate: null,
      signature_valid: null,
      trusted_tsa: null,
      gen_time_consistent: null,
      tsa_name: null,
      policy_oid: null,
      gen_time: null,
      note: "unreadable token (not a valid RFC 3161 TimeStampToken)",
    };
  }
  // Bind to the RECOMPUTED aggregate (review F1 + external audit): a genuine
  // (hash, token) pair stolen from a published export must never dress a
  // fabricated entry set with an [OK] qualified-timestamp line.
  const expected = expectedAggregateHex.toLowerCase();
  const matches = parsed.hashAlgorithmOid === OID_SHA256 &&
    parsed.messageImprintHex === expected;
  if (!matches) {
    return {
      status: "invalid",
      matches_aggregate: false,
      signature_valid: null,
      trusted_tsa: null,
      gen_time_consistent: null,
      tsa_name: parsed.tsaName,
      policy_oid: parsed.policyOid,
      gen_time: parsed.genTime,
      note: "the token does not commit to this day's aggregate hash (recomputed per D9)",
    };
  }
  const sig = await verifyTstSignature(parsed);
  if (!sig.valid) {
    return {
      status: "invalid",
      matches_aggregate: true,
      signature_valid: false,
      trusted_tsa: null,
      gen_time_consistent: null,
      tsa_name: parsed.tsaName,
      policy_oid: parsed.policyOid,
      gen_time: parsed.genTime,
      // Review M3: an algorithm this verifier does not implement is its own
      // declared reason — never conflated with a cryptographic failure.
      note: sig.unsupportedAlgorithm
        ? "unsupported signature algorithm for this verifier — check the token with standard RFC 3161 tooling (e.g. openssl ts)"
        : "the TSA signature over the token does not verify",
    };
  }
  // Display name: the TSTInfo tsa field (signature-covered) wins; else the
  // CN of the certificate that actually verified the signature.
  const tsaName = parsed.tsaName ?? sig.signerCn;
  // Review H1/F4: a genuine token whose genTime sits outside the declared
  // day's window (D64-style bounds) proves existence at ITS OWN genTime,
  // never the declared day — the human line must not read [OK] and the
  // limitation is said in the note. The STATUS is unchanged: a later
  // re-timestamp on the same aggregate is the DECLARED lifecycle strategy
  // (SPEC §7.1) and remains a genuine, trusted mark.
  const gen_time_consistent = genTimeConsistent(anchor?.anchor_date, parsed.genTime);
  const lateSuffix = gen_time_consistent === false
    ? ` — issued outside the declared day's window: it proves existence at its own genTime, not the declared day`
    : "";
  const fpr = sig.signerCertDer === null
    ? null
    : toHexLocal(await digest("SHA-256", sig.signerCertDer));
  const trusted = fpr !== null && trustedFprs.has(fpr);
  return {
    status: trusted ? "valid" : "untrusted",
    matches_aggregate: true,
    signature_valid: true,
    trusted_tsa: trusted,
    gen_time_consistent,
    tsa_name: tsaName,
    policy_oid: parsed.policyOid,
    gen_time: parsed.genTime,
    note: (trusted
      ? `valid · ${tsaName ?? "(unnamed TSA)"} · ${parsed.genTime}`
      : "valid token, untrusted TSA, no presumption") + lateSuffix,
  };
}

// ---------------------------------------------------------------------------
// Per-seal verdict (D104, SPEC 1.5.0 §7.2) — additive, exit-neutral. The
// on-demand chain seal is an RFC 3161 token over the 32 bytes of ONE event
// hash: the chain head at sealing time. It attaches the presumption to that
// head; every event of the verified prefix before it inherits the
// anteriority through recomputation — never a per-event mark.
// ---------------------------------------------------------------------------
export type ChainSealStatus = "valid" | "invalid" | "untrusted";

export interface ChainSealVerdict {
  /** The declared sealed sequence (echo of the element, for rendering). */
  sequence_number: number | null;
  status: ChainSealStatus;
  /** The token commits to exactly the event hash RECOMPUTED from the D11
   * pre-image at the declared sequence, within the verified prefix — the
   * declared `event_hash`/element fields are attacker data (same discipline
   * as `matches_aggregate` above, review F1 + external audit trap 11). */
  matches_head: boolean | null;
  signature_valid: boolean | null;
  trusted_tsa: boolean | null;
  /** genTime not earlier than the sealed event's reception (4h skew): a seal
   * "issued" before the event it seals existed is incoherent. false never
   * degrades the status — the limitation is declared in the note. */
  gen_time_consistent: boolean | null;
  tsa_name: string | null;
  policy_oid: string | null;
  gen_time: string | null;
  note: string;
}

function sealGenTimeConsistent(receivedAtIso: unknown, genTimeIso: string): boolean | null {
  if (typeof receivedAtIso !== "string") return null;
  const receivedS = Date.parse(receivedAtIso) / 1000;
  const genS = Date.parse(genTimeIso) / 1000;
  if (!Number.isFinite(receivedS) || !Number.isFinite(genS)) return null;
  return genS >= receivedS - QT_TIME_SKEW_BEFORE_S;
}

function sealInvalid(
  sequence: number | null,
  note: string,
  extra: Partial<ChainSealVerdict> = {},
): ChainSealVerdict {
  return {
    sequence_number: sequence,
    status: "invalid",
    matches_head: null,
    signature_valid: null,
    trusted_tsa: null,
    gen_time_consistent: null,
    tsa_name: null,
    policy_oid: null,
    gen_time: null,
    note,
    ...extra,
  };
}

export async function verifyChainSeal(
  // deno-lint-ignore no-explicit-any
  seal: any,
  trustedFprs: Set<string>,
  /** The event hash RECOMPUTED from the D11 pre-image at the declared
   * sequence (lowercase hex, 64 chars) — REQUIRED, no fallback to the
   * element's fields or the event's declared `event_hash`: a signature that
   * permits the unsafe call is a defect of the signature (external audit
   * 2026-07-29, §7.1 precedent). */
  expectedHeadHex: string,
  /** `received_at` of the sealed event (from the verified prefix), for the
   * genTime coherence fact; null when unavailable. */
  sealedReceivedAtIso: string | null,
): Promise<ChainSealVerdict> {
  const sequence = typeof seal?.sequence_number === "number" ? seal.sequence_number : null;
  if (!/^[0-9a-f]{64}$/i.test(String(expectedHeadHex ?? ""))) {
    return sealInvalid(
      sequence,
      "no recomputed head hash supplied to bind the token to (§7.2)",
    );
  }
  let parsed: ParsedTst;
  try {
    const raw = typeof seal?.token_base64 === "string" ? seal.token_base64 : "";
    if (raw.length > Math.ceil(MAX_TST_BYTES / 3) * 4 + 4) {
      throw new TstParseError(`token over the ${MAX_TST_BYTES}-byte cap`);
    }
    parsed = parseTst(b64ToBytes(raw));
  } catch {
    return sealInvalid(sequence, "unreadable token (not a valid RFC 3161 TimeStampToken)");
  }
  const expected = expectedHeadHex.toLowerCase();
  const matches = parsed.hashAlgorithmOid === OID_SHA256 &&
    parsed.messageImprintHex === expected;
  if (!matches) {
    return sealInvalid(
      sequence,
      "the token does not commit to the chain head recomputed at the declared sequence (D11)",
      {
        matches_head: false,
        tsa_name: parsed.tsaName,
        policy_oid: parsed.policyOid,
        gen_time: parsed.genTime,
      },
    );
  }
  const sig = await verifyTstSignature(parsed);
  if (!sig.valid) {
    return sealInvalid(
      sequence,
      sig.unsupportedAlgorithm
        ? "unsupported signature algorithm for this verifier — check the token with standard RFC 3161 tooling (e.g. openssl ts)"
        : "the TSA signature over the token does not verify",
      {
        matches_head: true,
        signature_valid: false,
        tsa_name: parsed.tsaName,
        policy_oid: parsed.policyOid,
        gen_time: parsed.genTime,
      },
    );
  }
  const tsaName = parsed.tsaName ?? sig.signerCn;
  const gen_time_consistent = sealGenTimeConsistent(sealedReceivedAtIso, parsed.genTime);
  const earlySuffix = gen_time_consistent === false
    ? " — genTime precedes the sealed event's reception: it proves existence at its own genTime"
    : "";
  const fpr = sig.signerCertDer === null
    ? null
    : toHexLocal(await digest("SHA-256", sig.signerCertDer));
  const trusted = fpr !== null && trustedFprs.has(fpr);
  return {
    sequence_number: sequence,
    status: trusted ? "valid" : "untrusted",
    matches_head: true,
    signature_valid: true,
    trusted_tsa: trusted,
    gen_time_consistent,
    tsa_name: tsaName,
    policy_oid: parsed.policyOid,
    gen_time: parsed.genTime,
    note: (trusted
      ? `valid · ${tsaName ?? "(unnamed TSA)"} · ${parsed.genTime}`
      : "valid token, untrusted TSA, no presumption") + earlySuffix,
  };
}
