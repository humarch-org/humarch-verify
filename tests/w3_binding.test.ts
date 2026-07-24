// W3 (audit 3, RECLASSIFIED 2026-07-19): the chain↔anchor binding used to
// resolve the source anchor by DATE (`exp.anchors.find(anchor_date === …)`),
// not by element. That was not merely fail-safe as the audit assumed — it was
// a false-VERIFIED bypass (non-negotiable 5), reproduced empirically at exit 0
// before the fix. This is the committed reconstruction of the attack, plus the
// two INDEPENDENT layers that close it:
//   • layer 2 (shape.ts): two anchors sharing a date is a form error (exit 4);
//   • layer 1 (render.ts): each verdict binds to the source element at its own
//     index, so a decoy sharing the real anchor's date can never lend its
//     entries to a different anchor's verdict.
// The attack (empirically exit 0 pre-fix): a malicious tenant forges an
// internally-consistent chain (head H, tenant T) signed with its OWN key
// (attribution D82 does not stop it — it is signing with its own issuer), then
// attaches [0] a PENDING decoy dated D whose committed entries name (T, H),
// and [1] a GENUINE anchor of the same date D stolen verbatim from any shared
// export (the site's public demo suffices) — real entries, real .ots, real
// Bitcoin attestation, but committing to ANOTHER chain. The stolen anchor
// passes every per-anchor precondition; find-by-date then handed it the
// decoy's (T, H) entries, "proving" time on a chain that was never anchored.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";
import { aggregateHash, verifyChain } from "../src/verify.ts";
import { type AnchorVerdict, verifyAnchors } from "../src/ots.ts";
import { anchorBindsChainHead, assess } from "../src/render.ts";
import { exportShapeProblems } from "../src/shape.ts";
import { FORGED_TENANT, forgeExport } from "./forge_helper.ts";

const REAL_ANCHOR_DATE = "2026-07-06";
const realExport = () =>
  JSON.parse(
    Deno.readTextFileSync(new URL("../vectors/export-real-anchor.json", import.meta.url)),
  );

/** The attack export + its forged head. NN5: the real anchor is READ verbatim
 * from the fixture (its material is what an attacker would steal), never
 * modified. */
async function buildAttack(): Promise<{ attack: Record<string, unknown>; head: string }> {
  const forged = await forgeExport(); // FORGED_TENANT, two chained events, own key
  const head = forged.events[forged.events.length - 1].event_hash as string;
  const decoyEntries = [{ tenant_id: FORGED_TENANT, last_event_hash: head }];
  const decoy = {
    anchor_date: REAL_ANCHOR_DATE,
    ots_status: "pending",
    aggregate_hash: await aggregateHash(REAL_ANCHOR_DATE, decoyEntries),
    anchor_entries_for_aggregate: decoyEntries,
  };
  const stolen = realExport().anchors[0]; // confirmed, real .ots, entries name the REAL tenant
  assertEquals(stolen.anchor_date, REAL_ANCHOR_DATE, "fixture drift: stolen anchor date changed");
  return { attack: { ...forged, anchors: [decoy, stolen] }, head };
}

// --- Layer 2: the shape gate refuses the file outright ----------------------
Deno.test("W3 layer 2: the full attack export is rejected in shape — duplicate anchor date", async () => {
  const { attack } = await buildAttack();
  const problems = exportShapeProblems(attack);
  assert(
    problems.some((p) => p.includes("duplicate anchor date")),
    `expected a duplicate-date problem, got ${JSON.stringify(problems)}`,
  );
});

async function runCli(...args: string[]): Promise<{ code: number; stderr: string }> {
  const cmd = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-read",
      "--allow-net",
      fromFileUrl(new URL("../src/cli.ts", import.meta.url)),
      ...args,
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await cmd.output();
  return { code: out.code, stderr: new TextDecoder().decode(out.stderr) };
}

Deno.test("W3 layer 2: the attack export exits 4 at the CLI, before any anchor verification", async () => {
  const { attack } = await buildAttack();
  const tmp = await Deno.makeTempFile({ suffix: ".json" });
  await Deno.writeTextFile(tmp, JSON.stringify(attack));
  try {
    const r = await runCli(tmp);
    assertEquals(r.code, 4, r.stderr);
    assert(r.stderr.includes("duplicate anchor date"), r.stderr);
  } finally {
    await Deno.remove(tmp);
  }
});

// --- Layer 1: even bypassing the gate, assess never binds the wrong element -
Deno.test("W3 layer 1: bypassing shape, assess binds per index — the stolen anchor never mints VERIFIED", async () => {
  const { attack, head } = await buildAttack();
  const chain = await verifyChain(attack);
  assertEquals(chain.chain_continuous, true, "the forgery is chain-valid (that is the premise)");
  assertEquals(chain.signatures_valid, true);

  // The post-verification verdicts, in exp.anchors order: [0] the pending
  // decoy (fails every anchor precondition — pending), [1] the genuine stolen
  // anchor, confirmed and time-consistent, whose committed entries name a
  // DIFFERENT chain. This is the attacker's best case, handed to assess raw.
  const dayNoonS = Date.parse(REAL_ANCHOR_DATE + "T12:00:00Z") / 1000;
  const anchors: AnchorVerdict[] = [
    {
      anchor_date: REAL_ANCHOR_DATE,
      ots_btc_block: null,
      ots_status: "pending",
      ots_btc_blocks_attested: null,
      aggregate_recomputed: true,
      ots_commits_to_aggregate: null,
      bitcoin_verified: null,
      ots_btc_time: null,
      time_consistent: null,
      level: "explorer",
      note: "anchor not yet stamped (pending)",
    },
    {
      anchor_date: REAL_ANCHOR_DATE,
      ots_btc_block: 956916,
      ots_status: "confirmed",
      ots_btc_blocks_attested: [956916, 956921],
      aggregate_recomputed: true,
      ots_commits_to_aggregate: true,
      bitcoin_verified: true,
      ots_btc_time: dayNoonS,
      time_consistent: true,
      level: "explorer",
      note: "block-header verification via public explorers",
    },
  ];

  assert(
    !anchorBindsChainHead(attack, chain, anchors),
    "the genuine anchor of a DIFFERENT chain must not bind to the forged head",
  );

  // Even with attribution generously granted, time stays unproven ⇒ partial.
  const generous = assess(attack, chain, anchors, "attributed");
  assertEquals(generous.result, "partial");
  assertEquals(generous.exitCode, 5);
  assertEquals(generous.properties.time, "unproven");
  assert(generous.exitCode !== 0, "a chain that was never anchored must never exit 0");

  // Honest attribution (attacker's own key, no trusted set) ⇒ unattributed.
  assertEquals(assess(attack, chain, anchors, "not_checked").exitCode, 6);

  // Positive control: make the index-1 SOURCE element itself commit to (T, H)
  // and the SAME verdict binds — proving it is the per-index entries, not an
  // incidental precondition, that rejects the attack (and that the decoy's
  // entries are no longer consulted for anchor [1]).
  const boundSource = structuredClone(attack) as {
    anchors: { anchor_entries_for_aggregate: unknown }[];
  };
  boundSource.anchors[1].anchor_entries_for_aggregate = [{
    tenant_id: FORGED_TENANT,
    last_event_hash: head,
  }];
  assert(
    anchorBindsChainHead(boundSource, chain, anchors),
    "with the source element itself committing to (T, H), the binding holds",
  );
});

// --- The invariant layer 1 relies on ----------------------------------------
Deno.test("W3: verifyAnchors emits one verdict per exp.anchors element, in order", async () => {
  const exp = {
    anchors: [
      {
        anchor_date: "2026-01-01",
        ots_status: "pending",
        anchor_entries_for_aggregate: [],
        aggregate_hash: "00".repeat(32),
      },
      {
        anchor_date: "2026-01-02",
        ots_status: "pending",
        anchor_entries_for_aggregate: [],
        aggregate_hash: "00".repeat(32),
      },
      {
        anchor_date: "2026-01-03",
        ots_status: "pending",
        anchor_entries_for_aggregate: [],
        aggregate_hash: "00".repeat(32),
      },
    ],
  };
  const verdicts = await verifyAnchors(exp);
  assertEquals(verdicts.length, exp.anchors.length);
  verdicts.forEach((v, i) =>
    assertEquals(v.anchor_date, exp.anchors[i].anchor_date, `verdict ${i} out of order`)
  );
});
