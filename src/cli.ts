// humarch-verify CLI (B10 D62/D65, D82, D98, D100, D101).
//
//   humarch-verify <export.json> [--issuer <file|url>] [--pubkey <hex|file>]
//                  [--tsa-trust <file>] [--find-artifact <sha256-hex>]
//                  [--trace <event-uuid>]...
//                  [--ots-level explorer|trustless|convenience] [--json]
//
// Exit codes (D65 + 2026-07-12 amendment): 0 verified · 2 chain/signatures
// invalid · 3 anchor/OTS not verified · 4 malformed input · 5 declared
// partial verification · 6 keys not attributed to a trusted issuer.
// The qualified-timestamp check (D98), the --find-artifact search (D100),
// the --trace ancestry walk (D101) and the declared-unavailable block (D105)
// are ADDITIVE: they never change these.
import { verifyChain } from "./verify.ts";
import { type OtsLevel, verifyAnchors, verifyChainSeals } from "./ots.ts";
import {
  assess,
  jsonSafe,
  renderAncestry,
  renderArtifactSearch,
  qualifiedMarkBindsChainHead,
  renderHuman,
  terminalSafe,
} from "./render.ts";
import { findArtifact, isArtifactTarget } from "./find.ts";
import { ANCESTRY_NOTE, ANCESTRY_SEMANTICS, isTraceTarget, traceAncestry } from "./trace.ts";
import { exportShapeProblems } from "./shape.ts";
import { declaredUnavailableArtifacts } from "./unavailable.ts";
import {
  attributeEvents,
  EMBEDDED_ISSUER,
  type IssuerRegistry,
  issuerShapeProblems,
  trustedKeyBytes,
} from "./issuer.ts";
import { EMBEDDED_TSA, type TsaRegistry, tsaShapeProblems } from "./tst_lite.ts";

/**
 * Read cap for the issuer registry, on both legs (BT-35, 2026-08-21). A key
 * registry is a handful of hex strings; a megabyte is already three orders of
 * magnitude of headroom. Deliberately the same value as the explorer cap of
 * `ots_lite.ts` — one number for "the most a remote party may hand this CLI".
 */
const MAX_ISSUER_RESPONSE = 1 << 20;

/**
 * Read a response body with a hard byte ceiling, cancelling the stream the
 * moment it is crossed. `res.text()` cannot do this: it buffers to completion,
 * so a slow, steady sender stays inside any timeout while handing over as much
 * as it likes. A timeout bounds duration; only this bounds memory.
 */
async function readCapped(
  res: Response,
  cap: number,
  what: string,
): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > cap) {
      await reader.cancel();
      throw new Error(`${what} exceeds the ${cap}-byte read cap`);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder().decode(all);
}

function usage(): never {
  console.error(
    "usage: humarch-verify <export.json> [--issuer <file|url>] [--pubkey <hex|file>] [--tsa-trust <file>] [--find-artifact <sha256-hex>] [--trace <event-uuid>]... [--ots-level explorer|trustless|convenience] [--json]",
  );
  Deno.exit(4);
}

/**
 * The only part of a JSON parse error we are willing to show: V8 embeds a
 * verbatim excerpt of the offending bytes in `message`, so echoing it hands
 * a hostile file direct control of the reader's terminal (adversarial review
 * of the F2 remedy, 2026-08-02). The position is a number and is useful; the
 * excerpt is attacker text and is not.
 */
function parsePosition(err: unknown): string {
  const m = /position (\d+)/.exec(String((err as Error)?.message ?? ""));
  return m ? `(at byte ${m[1]})` : "";
}
async function main(): Promise<void> {
  const args = [...Deno.args];
  let file: string | null = null;
  let pubkey: string | null = null;
  let issuerSource: string | null = null;
  let tsaTrustSource: string | null = null;
  let findTarget: string | null = null;
  let traceTargets: string[] = [];
  let otsLevel: OtsLevel = "explorer";
  let json = false;

  while (args.length) {
    const a = args.shift() as string;
    if (a === "--json") json = true;
    else if (a === "--pubkey") pubkey = args.shift() ?? usage();
    else if (a === "--issuer") issuerSource = args.shift() ?? usage();
    else if (a === "--tsa-trust") tsaTrustSource = args.shift() ?? usage();
    else if (a === "--find-artifact") findTarget = args.shift() ?? usage();
    else if (a === "--trace") traceTargets.push(args.shift() ?? usage());
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

  // --trace takes the event_id of a contested event, validated as a UUID
  // here (like --pubkey: the CLI only ever prints validated or sanitized
  // strings). Repeatable — several contested events share one walk with
  // dedup across their chains. The walk itself runs AFTER assess and never
  // moves the verdict (D101).
  for (const t of traceTargets) {
    if (!isTraceTarget(t)) {
      console.error("--trace must be a UUID (the event_id of the contested event)");
      Deno.exit(4);
    }
  }
  traceTargets = [...new Set(traceTargets.map((t) => t.toLowerCase()))];

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
            `--issuer ${
              terminalSafe(issuerSource, 200)
            } redirects (HTTP ${res.status}): refused — a redirect can downgrade the TLS channel; pass the final https:// URL`,
          );
          Deno.exit(4);
        }
        if (!res.ok) {
          console.error(
            `cannot read --issuer ${terminalSafe(issuerSource, 200)}: HTTP ${res.status}`,
          );
          Deno.exit(4);
        }
        // BT-35 (2026-08-21): `await res.text()` read the body whole, with no
        // bound. The 30-second timeout bounds the DURATION of the fetch, not
        // the BYTES it yields: a loopback server streaming steadily inside the
        // window handed the CLI 150 MiB, all of it buffered, before JSON.parse
        // failed on it. The explorer leg has had a read cap since D87
        // (MAX_EXPLORER_RESPONSE); this is the same defence on the other
        // network leg, which had simply been missed.
        text = await readCapped(res, MAX_ISSUER_RESPONSE, "--issuer response");
      } else {
        // The local leg is bounded too: a file is as capable of being large as
        // a socket is, and a verifier that dies of an oversized key registry
        // has still failed to verify (SPEC §8.1 class 6 — declared, never
        // silent).
        const info = Deno.statSync(issuerSource);
        if (info.size > MAX_ISSUER_RESPONSE) {
          throw new Error(
            `issuer registry exceeds ${MAX_ISSUER_RESPONSE} bytes`,
          );
        }
        text = Deno.readTextFileSync(issuerSource);
      }
    } catch (err) {
      console.error(
        `cannot read --issuer ${terminalSafe(issuerSource, 200)}: ${
          terminalSafe((err as Error).message, 200)
        }`,
      );
      Deno.exit(4);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      console.error(
        `malformed issuer document: not valid JSON ${terminalSafe(parsePosition(err), 32)}`,
      );
      Deno.exit(4);
    }
    const problems = issuerShapeProblems(parsed);
    if (problems.length > 0) {
      console.error(`malformed issuer document: ${terminalSafe(problems[0], 200)}`);
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
      console.error(
        `cannot read --tsa-trust ${terminalSafe(tsaTrustSource, 200)}: ${
          terminalSafe((err as Error).message, 200)
        }`,
      );
      Deno.exit(4);
    }
    const problems = tsaShapeProblems(parsed);
    if (problems.length > 0) {
      console.error(`malformed tsa-trust document: ${terminalSafe(problems[0], 200)}`);
      Deno.exit(4);
    }
    tsaRegistry = parsed as TsaRegistry;
  }

  // deno-lint-ignore no-explicit-any
  let exp: any;
  try {
    exp = JSON.parse(Deno.readTextFileSync(file));
  } catch (err) {
    // V8 quotes a verbatim excerpt of the offending bytes in this message.
    console.error(`malformed input: not valid JSON ${terminalSafe(parsePosition(err), 32)}`);
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
    console.error(`malformed input: ${terminalSafe(shapeProblems[0], 200)}${more}`);
    Deno.exit(4);
  }

  // Attribution (D82, audit F1): per-event and on the PUBLIC-KEY BYTES —
  // never a membership test of the expected key in the export's own
  // signing_keys (attacker data: the genuine key can be padded in as a
  // decoy), never a signing_key_id comparison (64-bit handle, D16).
  const attribution = attributeEvents(exp, trusted);

  // BT-36 (2026-08-21), second half. The shape gate is defence in depth, not a
  // proof: it can only report the shapes it knows to look for, and anything it
  // misses reaches code that may throw — canonicalize() on a value RFC 8785
  // cannot represent, a reader on bytes it cannot parse. Unguarded, such a
  // throw left the CLI at exit 1 with a stack trace, which is neither of this
  // tool's documented answers and is distinguishable, from the outside, from
  // the exit 4 an automation maps to "reject".
  //
  // Everything from here to the verdict is therefore inside one boundary that
  // maps an unexpected throw to the malformed-input outcome. It is the honest
  // reading: if the verifier cannot process the document, it has not verified
  // it, and it must say so in the vocabulary it promised (D65).
  let chain, anchors, verdict;
  try {
    chain = await verifyChain(exp);
    anchors = await verifyAnchors(exp, otsLevel, undefined, tsaRegistry);
    verdict = assess(exp, chain, anchors, attribution);
  } catch (err) {
    // The message is derived from hostile bytes, so it goes through the same
    // neutralizer as every other export-supplied string (SPEC §8 rule 9: a
    // parser typically quotes the offending bytes verbatim, and echoing its
    // message re-opens the hole this verifier just closed).
    console.error(
      `malformed input: ${terminalSafe(String((err as Error)?.message ?? err), 200)}`,
    );
    Deno.exit(4);
  }
  const { result, exitCode, properties } = verdict;

  // On-demand chain seals (D104, SPEC 1.5.0), AFTER assess and with no hand
  // on exitCode: the seal check is ADDITIVE — an export without the field
  // verifies byte-identically, an invalid/untrusted seal is a declared line,
  // never a different exit. Binding is to the head hash RECOMPUTED within
  // the verified positional prefix (verifyChainSeals), never to declared
  // fields.
  const chainSeals = await verifyChainSeals(exp, chain, tsaRegistry);

  // Declared unavailable artifacts (D105, SPEC 1.6.0 §8 rule 14), AFTER
  // assess and with no hand on exitCode: a declaration is the producer's
  // statement about its own export, never evidence and never an exemption —
  // this document and the same document with the array removed MUST reach
  // the same result and the same exit code. Nothing is verified here.
  const unavailable = declaredUnavailableArtifacts(exp);

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

  // Informative ancestry walk (D101), AFTER assess and with no hand on
  // exitCode — same neutrality contract as the artifact search above. Print
  // order is fixed: verdict, artifact search, ancestry.
  const ancestry = traceTargets.length > 0
    ? {
      semantics: ANCESTRY_SEMANTICS,
      traces: traceAncestry(
        exp,
        traceTargets,
        chain.verified_from_sequence,
        chain.verified_through_sequence,
      ),
      note: ANCESTRY_NOTE,
    }
    : null;

  if (json) {
    console.log(jsonSafe(JSON.stringify(
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
        // Additive top-level keys: chain/anchors/properties/result untouched.
        ...(chainSeals.length ? { chain_seals: chainSeals } : {}),
        ...(unavailable !== null &&
            (unavailable.entries.length || unavailable.unreadable || unavailable.truncated)
          ? { declared_unavailable: unavailable }
          : {}),
        ...(artifactSearch !== null ? { artifact_search: artifactSearch } : {}),
        ...(ancestry !== null ? { ancestry } : {}),
      },
      null,
      2,
    )));
  } else {
    console.log(
      renderHuman(
        exp.tenant_id,
        chain,
        anchors,
        result,
        properties,
        chainSeals,
        unavailable,
        qualifiedMarkBindsChainHead(exp, chain, anchors),
      ),
    );
    if (artifactSearch !== null) {
      console.log(renderArtifactSearch(
        artifactSearch.target,
        artifactSearch.matches,
        chain.verified_from_sequence,
        chain.verified_through_sequence,
      ));
    }
    if (ancestry !== null) {
      console.log(renderAncestry(
        ancestry.traces,
        chain.verified_from_sequence,
        chain.verified_through_sequence,
      ));
    }
  }
  Deno.exit(exitCode);
}

if (import.meta.main) await main();
