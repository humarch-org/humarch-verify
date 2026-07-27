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
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`;
}

function decodeDirectoryString(tlv: Tlv, content: Uint8Array): string | null {
  const tag = tlv.id & 0x1f;
  if (tag === 0x1e) {
    let out = "";
    for (let i = 0; i + 1 < content.length; i += 2) {
      out += String.fromCharCode(content[i] * 256 + content[i + 1]);
    }
    return out;
  }
  if (tag === 0x0c || tag === 0x13 || tag === 0x16 || tag === 0x14) {
    return new TextDecoder().decode(content);
  }
  return null;
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
  tsaName: string | null;
  /** DER of the TSTInfo (the digest target of the message-digest attribute). */
  tstInfoDer: Uint8Array;
  /** DER of the signer certificate (registry fingerprint target); null when
   * the token embeds no certificates. */
  signerCertDer: Uint8Array | null;
  /** SubjectPublicKeyInfo DER of the signer certificate. */
  signerSpkiDer: Uint8Array | null;
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
  let tsaName: string | null = null;
  for (let i = 5; i < tst.length; i++) {
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

  // --- signer certificate --------------------------------------------------
  let signerCertDer: Uint8Array | null = null;
  let signerSpkiDer: Uint8Array | null = null;
  let keyAlgorithmOid: string | null = null;
  let keyCurveOid: string | null = null;
  const certsTlv = sd.find((t) => t.id === 0xa0);
  if (certsTlv) {
    let wantedSerial: Uint8Array | null = null;
    if (siKids[1] && siKids[1].id === 0x30) {
      const ias = r.children(siKids[1], 6);
      const serial = ias.find((k) => k.id === 0x02);
      if (serial) wantedSerial = r.content(serial);
    }
    const certs = r.children(certsTlv, 4).filter((c) => c.id === 0x30);
    let matched: { tlv: Tlv; fields: CertFields } | null = null;
    for (const c of certs) {
      const f = parseCert(r, c);
      if (!f) continue;
      if (matched === null) matched = { tlv: c, fields: f };
      if (wantedSerial && toHexLocal(f.serial) === toHexLocal(wantedSerial)) {
        matched = { tlv: c, fields: f };
        break;
      }
    }
    if (matched) {
      signerCertDer = r.slice(matched.tlv);
      signerSpkiDer = matched.fields.spkiDer;
      keyAlgorithmOid = matched.fields.keyAlgorithmOid;
      keyCurveOid = matched.fields.keyCurveOid;
      if (tsaName === null) tsaName = matched.fields.subjectCn;
    }
  }

  return {
    policyOid,
    hashAlgorithmOid,
    messageImprintHex,
    genTime,
    tsaName,
    tstInfoDer,
    signerCertDer,
    signerSpkiDer,
    signedAttrsDer,
    messageDigestAttr,
    contentTypeOk,
    signatureAlgorithmOid,
    digestAlgorithmOid,
    signature,
    keyAlgorithmOid,
    keyCurveOid,
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

/** True iff the CMS signature of the token verifies: message-digest attribute
 * matches the TSTInfo bytes AND the signer's signature over the signed
 * attributes verifies against the embedded signer certificate's public key. */
export async function verifyTstSignature(p: ParsedTst): Promise<boolean> {
  if (
    p.signedAttrsDer === null || p.messageDigestAttr === null || !p.contentTypeOk ||
    p.signerSpkiDer === null
  ) return false;
  const attrHash = HASH_OIDS[p.digestAlgorithmOid];
  if (!attrHash) return false;
  const tstDigest = await digest(attrHash, p.tstInfoDer);
  if (toHexLocal(tstDigest) !== toHexLocal(p.messageDigestAttr)) return false;

  const sigHash = hashForSignature(p);
  if (sigHash === null) return false;
  try {
    if (p.keyAlgorithmOid === OID_RSA) {
      const key = await crypto.subtle.importKey(
        "spki",
        p.signerSpkiDer as BufferSource,
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
    if (p.keyAlgorithmOid === OID_EC_KEY) {
      const curve = p.keyCurveOid === OID_P256
        ? { name: "P-256", size: 32 }
        : p.keyCurveOid === OID_P384
        ? { name: "P-384", size: 48 }
        : p.keyCurveOid === OID_P521
        ? { name: "P-521", size: 66 }
        : null;
      if (curve === null) return false;
      const raw = ecdsaDerToRaw(p.signature, curve.size);
      if (raw === null) return false;
      const key = await crypto.subtle.importKey(
        "spki",
        p.signerSpkiDer as BufferSource,
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
  } catch {
    return false;
  }
  return false;
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
  /** The token commits to exactly the anchor's aggregate_hash. */
  matches_aggregate: boolean | null;
  signature_valid: boolean | null;
  trusted_tsa: boolean | null;
  tsa_name: string | null;
  policy_oid: string | null;
  gen_time: string | null;
  note: string;
}

const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function verifyQualifiedTimestamp(
  // deno-lint-ignore no-explicit-any
  anchor: any,
  trustedFprs: Set<string>,
): Promise<QualifiedTimestampVerdict> {
  const qt = anchor?.qualified_timestamp;
  if (qt == null) {
    return {
      status: "absent",
      matches_aggregate: null,
      signature_valid: null,
      trusted_tsa: null,
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
      tsa_name: null,
      policy_oid: null,
      gen_time: null,
      note: "unreadable token (not a valid RFC 3161 TimeStampToken)",
    };
  }
  const matches = parsed.hashAlgorithmOid === OID_SHA256 &&
    parsed.messageImprintHex === String(anchor.aggregate_hash ?? "").toLowerCase();
  if (!matches) {
    return {
      status: "invalid",
      matches_aggregate: false,
      signature_valid: null,
      trusted_tsa: null,
      tsa_name: parsed.tsaName,
      policy_oid: parsed.policyOid,
      gen_time: parsed.genTime,
      note: "the token does not commit to this aggregate_hash",
    };
  }
  const signature_valid = await verifyTstSignature(parsed);
  if (!signature_valid) {
    return {
      status: "invalid",
      matches_aggregate: true,
      signature_valid: false,
      trusted_tsa: null,
      tsa_name: parsed.tsaName,
      policy_oid: parsed.policyOid,
      gen_time: parsed.genTime,
      note: "the TSA signature over the token does not verify",
    };
  }
  const fpr = parsed.signerCertDer === null
    ? null
    : toHexLocal(await digest("SHA-256", parsed.signerCertDer));
  const trusted = fpr !== null && trustedFprs.has(fpr);
  return {
    status: trusted ? "valid" : "untrusted",
    matches_aggregate: true,
    signature_valid: true,
    trusted_tsa: trusted,
    tsa_name: parsed.tsaName,
    policy_oid: parsed.policyOid,
    gen_time: parsed.genTime,
    note: trusted
      ? `valid · ${parsed.tsaName ?? "(unnamed TSA)"} · ${parsed.genTime}`
      : "valid token, untrusted TSA, no presumption",
  };
}
