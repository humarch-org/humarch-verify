// humarch-verify CLI (B10 D62/D65, D82, D98, D100).
//
//   humarch-verify <export.json> [--issuer <file|url>] [--pubkey <hex|file>]
//                  [--tsa-trust <file>] [--find-artifact <sha256-hex>]
//                  [--ots-level explorer|trustless|convenience] [--json]
//
// Exit codes (D65 + 2026-07-12 amendment): 0 verified · 2 chain/signatures
// invalid · 3 anchor/OTS not verified · 4 malformed input · 5 declared
// partial verification · 6 keys not attributed to a trusted issuer.
// The qualified-timestamp check (D98) and the --find-artifact search (D100)
// are ADDITIVE: they never change these.
import { verifyChain } from "./verify.ts";
import { type OtsLevel, verifyAnchors } from "./ots.ts";
import { assess, renderArtifactSearch, renderHuman } from "./render.ts";
import { findArtifact, isArtifactTarget } from "./find.ts";
import { exportShapeProblems } from "./shape.ts";
import {
  attributeEvents,
  EMBEDDED_ISSUER,
  type IssuerRegistry,
  issuerShapeProblems,
  trustedKeyBytes,
} from "./issuer.ts";
import { EMBEDDED_TSA, tsaShapeProblems, type TsaRegistry } from "./tst_lite.ts";

function usage(): never {
  console.error(
    "usage: humarch-verify <export.json> [--issuer <file|url>] [--pubkey <hex|file>] [--tsa-trust <file>] [--find-artifact <sha256-hex>] [--ots-level explorer|trustless|convenience] [--json]",
  );
  Deno.exit(4);
}

async function main(): Promise<void> {
  const args = [...Deno.args];
  let file: string | null = null;
  let pubkey: string | null = null;
  let issuerSource: string | null = null;
  let tsaTrustSource: string | null = null;
  let findTarget: string | null = null;
  let otsLevel: OtsLevel = "explorer";
  let json = false;

  while (args.length) {
    const a = args.shift() as string;
    if (a === "--json") json = true;
    else if (a === "--pubkey") pubkey = args.shift() ?? usage();
    else if (a === "--issuer") issuerSource = args.shift() ?? usage();
    else if (a === "--tsa-trust") tsaTrustSource = args.shift() ?? usage();
    else if (a === "--find-artifact") findTarget = args.shift() ?? usage();
    else if (a === "--ots-level") {
      const v = args.shift() ?? usage();
      if (v !== "explorer" && v !== "trustless" && v !== "convenience") usage();
      otsLevel = v;
    } else if (a.startsWith("--")) usage();
    else if (file === null) file = a;
    else usage();
  }
  if (file === null) usage();
  if (pubkey !== null && issuerSource !== null) {
    console.error("--pubkey and --issuer are mutually exclusive (one trusted set at a time)");
    Deno.exit(4);
  }

  // --find-artifact takes a SHA-256 as 64 hex chars (validated here, like
  // --pubkey: the CLI only ever prints this validated string, never payload
  // text). The search itself runs AFTER assess and never moves the verdict.
  if (findTarget !== null) {
    if (!isArtifactTarget(findTarget)) {
      console.error("--find-artifact must be 64 hex chars (a SHA-256 digest)");
      Deno.exit(4);
    }
    findTarget = findTarget.toLowerCase();
  }

  // --pubkey accepts raw hex (either case) or a path to a file containing it.
  if (pubkey !== null) {
    if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) {
      try {
        pubkey = Deno.readTextFileSync(pubkey).trim();
      } catch {
        console.error("cannot read --pubkey file");
        Deno.exit(4);
      }
      if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) {
        console.error("--pubkey must be 64 hex chars (raw Ed25519 public key)");
        Deno.exit(4);
      }
    }
    pubkey = pubkey.toLowerCase();
  }

  // Trusted issuer set (D82): --issuer document, --pubkey single-key
  // shortcut, or the embedded registry (empty until go-live ⇒ not_checked).
  let issuer: IssuerRegistry = EMBEDDED_ISSUER;
  if (issuerSource !== null) {
    let text: string;
    try {
      if (/^https?:\/\//.test(issuerSource)) {
        // The issuer document IS the trust anchor of the attribution check:
        // fetching it over plain http would hand it to any on-path attacker.
        // TLS only (loopback exempted for local testing).
        const url = new URL(issuerSource);
        const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
        if (url.protocol !== "https:" && !loopback) {
          console.error(
            "--issuer over plain http is refused: the trusted key set must be fetched over TLS (use https://)",
          );
          Deno.exit(4);
        }
        // W6 (audit 3): the https-only rule must survive redirects — with
        // the default follow behavior a server-side 3xx re-routes the fetch
        // AFTER the scheme check, so an https URL could silently hand the
        // trusted set to plain http. Redirects are refused outright: the key
        // set lives at a stable well-known URL; if it moved, pass the final
        // https:// URL directly.
        const res = await fetch(issuerSource, {
          signal: AbortSignal.timeout(30_000),
          redirect: "manual",
        });
        if (res.status >= 300 && res.status < 400) {
          console.error(
            `--issuer ${issuerSource} redirects (HTTP ${res.status}): refused — a redirect can downgrade the TLS channel; pass the final https:// URL`,
          );
          Deno.exit(4);
        }
        if (!res.ok) {
          console.error(`cannot read --issuer ${issuerSource}: HTTP ${res.status}`);
          Deno.exit(4);
        }
        text = await res.text();
      } else {
        text = Deno.readTextFileSync(issuerSource);
      }
    } catch (err) {
      console.error(`cannot read --issuer ${issuerSource}: ${(err as Error).message}`);
      Deno.exit(4);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      console.error(`malformed issuer document: ${(err as Error).message}`);
      Deno.exit(4);
    }
    const problems = issuerShapeProblems(parsed);
    if (problems.length > 0) {
      console.error(`malformed issuer document: ${problems[0]}`);
      Deno.exit(4);
    }
    issuer = parsed as IssuerRegistry;
  } else if (pubkey !== null) {
    issuer = { format: "humarch-keys/v1", keys: [{ public_key: pubkey }] };
  }
  const trusted = trustedKeyBytes(issuer);

  // Trusted TSA registry (D98, D82 pattern): --tsa-trust document or the
  // embedded set (empty until go-live ⇒ every valid token reads "untrusted
  // TSA, no presumption" — the honest default). File only: the QTSP pin is a
  // local trust decision, not something to fetch at verification time.
  let tsaRegistry: TsaRegistry = EMBEDDED_TSA;
  if (tsaTrustSource !== null) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(Deno.readTextFileSync(tsaTrustSource));
    } catch (err) {
      console.error(`cannot read --tsa-trust ${tsaTrustSource}: ${(err as Error).message}`);
      Deno.exit(4);
    }
    const problems = tsaShapeProblems(parsed);
    if (problems.length > 0) {
      console.error(`malformed tsa-trust document: ${problems[0]}`);
      Deno.exit(4);
    }
    tsaRegistry = parsed as TsaRegistry;
  }

  // deno-lint-ignore no-explicit-any
  let exp: any;
  try {
    exp = JSON.parse(Deno.readTextFileSync(file));
  } catch (err) {
    console.error(`malformed input: ${(err as Error).message}`);
    Deno.exit(4);
  }
  if (exp?.format !== "humarch-export/v1") {
    console.error(`malformed input: format is not humarch-export/v1`);
    Deno.exit(4);
  }
  // Trust-boundary shape gate (audit F5): a malformed export must exit 4
  // here, never throw inside the verifier.
  const shapeProblems = exportShapeProblems(exp);
  if (shapeProblems.length > 0) {
    const more = shapeProblems.length > 1 ? ` (+${shapeProblems.length - 1} more)` : "";
    console.error(`malformed input: ${shapeProblems[0]}${more}`);
    Deno.exit(4);
  }

  // Attribution (D82, audit F1): per-event and on the PUBLIC-KEY BYTES —
  // never a membership test of the expected key in the export's own
  // signing_keys (attacker data: the genuine key can be padded in as a
  // decoy), never a signing_key_id comparison (64-bit handle, D16).
  const attribution = attributeEvents(exp, trusted);

  const chain = await verifyChain(exp);
  const anchors = await verifyAnchors(exp, otsLevel, undefined, tsaRegistry);
  const { result, exitCode, properties } = assess(exp, chain, anchors, attribution);

  // Informative search (D100), AFTER assess and with no hand on exitCode:
  // exit neutrality is the invariant that keeps "one verification routine".
  const artifactSearch = findTarget !== null
    ? {
      target: findTarget,
      matches: findArtifact(
        exp,
        findTarget,
        chain.verified_from_sequence,
        chain.verified_through_sequence,
      ),
      note:
        'declared references only; encrypted payload.personal content is invisible to this search — "not found" does not mean "not there"',
    }
    : null;

  if (json) {
    console.log(JSON.stringify(
      {
        format: "humarch-verify/v1",
        tenant_id: exp.tenant_id,
        range: {
          from_sequence: exp.range?.from_sequence ?? null,
          to_sequence: exp.range?.to_sequence ?? null,
          event_count: (exp.events ?? []).length,
        },
        chain,
        anchors,
        properties,
        result,
        ots_level: otsLevel,
        // Additive top-level key: chain/anchors/properties/result untouched.
        ...(artifactSearch !== null ? { artifact_search: artifactSearch } : {}),
      },
      null,
      2,
    ));
  } else {
    console.log(renderHuman(exp.tenant_id, chain, anchors, result, properties));
    if (artifactSearch !== null) {
      console.log(renderArtifactSearch(
        artifactSearch.target,
        artifactSearch.matches,
        chain.verified_from_sequence,
        chain.verified_through_sequence,
      ));
    }
  }
  Deno.exit(exitCode);
}

if (import.meta.main) await main();
