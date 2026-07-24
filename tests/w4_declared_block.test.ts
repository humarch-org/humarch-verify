// W4 (audit 3): the export's self-declared `ots_btc_block` was shown to the
// reader ("recorded on Bitcoin in block N") even when the explorer level had
// just verified DIFFERENT attested heights. Display only, no verdict — but a
// verifier must never present an unverified number as if the chain proved it.
// The fix compares the declared block against the heights the parsed receipt
// actually attests; on a mismatch the human line shows the ATTESTED height and
// the note says so, while the verdict itself is unchanged.
//
// Exercised OFFLINE through the explorer seam (verifyAnchors' injectable deps):
// a local server impersonates the explorers and confirms the REAL receipt's
// attestations by serving the merkle roots computed from the receipt itself.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { evaluateOps, type ExplorerDeps, parseOts } from "../src/ots_lite.ts";
import { verifyAnchors } from "../src/ots.ts";
import { assess, renderHuman } from "../src/render.ts";
import { toHex, verifyChain } from "../src/verify.ts";

const REAL_ANCHOR_DATE = "2026-07-06";
const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const realExport = () =>
  JSON.parse(
    Deno.readTextFileSync(new URL("../vectors/export-real-anchor.json", import.meta.url)),
  );

// A mock server confirming exactly the receipt's attested heights, at a block
// time inside the declared-day window (so time_consistent stays true).
async function withConfirmingExplorers(
  otsFileBase64: string,
  fn: (deps: ExplorerDeps) => Promise<void>,
): Promise<void> {
  const receipt = parseOts(b64ToBytes(otsFileBase64));
  const dayStart = Date.parse(REAL_ANCHOR_DATE + "T00:00:00Z") / 1000;
  const rootByHeight = new Map<number, string>();
  const heightByHash = new Map<string, number>();
  for (const att of receipt.attestations) {
    if (att.kind === "bitcoin") {
      // explorers return the merkle root in DISPLAY order (reversed bytes)
      const root = toHex((await evaluateOps(receipt.digest, att.ops)).slice().reverse());
      rootByHeight.set(att.height, root);
      heightByHash.set(att.height.toString(16).padStart(64, "0"), att.height);
    }
  }
  const blockTime = dayStart + 12 * 3600;
  const handler = (req: Request): Response => {
    const path = new URL(req.url).pathname;
    let m = path.match(/^\/bs\/block-height\/(\d+)$/);
    if (m) {
      const h = Number(m[1]);
      return rootByHeight.has(h)
        ? new Response(h.toString(16).padStart(64, "0"))
        : new Response("not found", { status: 404 });
    }
    m = path.match(/^\/bs\/block\/([0-9a-f]{64})$/);
    if (m) {
      const h = heightByHash.get(m[1]);
      const root = h !== undefined ? rootByHeight.get(h) : undefined;
      return root
        ? new Response(JSON.stringify({ merkle_root: root, timestamp: blockTime }))
        : new Response("not found", { status: 404 });
    }
    m = path.match(/^\/bci\/block-height\/(\d+)$/);
    if (m) {
      const root = rootByHeight.get(Number(m[1]));
      return new Response(
        JSON.stringify({ blocks: root ? [{ mrkl_root: root, time: blockTime }] : [] }),
      );
    }
    return new Response("not found", { status: 404 });
  };
  const srv = Deno.serve({ port: 0, onListen: () => {} }, handler);
  const port = (srv.addr as Deno.NetAddr).port;
  try {
    await fn({
      blockstreamBase: `http://127.0.0.1:${port}/bs`,
      blockchainInfoBase: `http://127.0.0.1:${port}/bci`,
      timeoutMs: 5000,
    });
  } finally {
    await srv.shutdown();
  }
}

Deno.test("W4: a genuine declared block matches the attested heights → plain note, no mismatch", async () => {
  const exp = realExport();
  await withConfirmingExplorers(exp.anchors[0].ots_file_base64, async (deps) => {
    const a = (await verifyAnchors(exp, "explorer", deps))[0];
    assertEquals(a.bitcoin_verified, true);
    assertEquals(a.time_consistent, true);
    assertEquals(a.ots_btc_block, 956916);
    assertEquals(a.ots_btc_blocks_attested, [956916, 956921]);
    assert(!a.note.includes("not among"), a.note);
  });
});

Deno.test("W4: a declared block absent from the attested heights → honest note, attested display, verdict unchanged", async () => {
  const exp = realExport();
  await withConfirmingExplorers(exp.anchors[0].ots_file_base64, async (deps) => {
    // The genuine outcome (for the invariance comparison).
    const genuine = (await verifyAnchors(exp, "explorer", deps))[0];

    // In-memory only (NN5: the fixture file is untouched): declare a block the
    // attestation does not carry.
    exp.anchors[0].ots_btc_block = 111111;
    const altered = (await verifyAnchors(exp, "explorer", deps))[0];

    assert(
      altered.note.includes(
        "declared block 111111 is not among the attested block(s) 956916, 956921",
      ),
      altered.note,
    );
    assertEquals(altered.ots_btc_block, 111111, "the JSON keeps the DECLARED value");
    assertEquals(altered.ots_btc_blocks_attested, [956916, 956921]);
    // The verdict itself is unchanged: time is proved by the attestation, not
    // by the declared number.
    assertEquals(altered.bitcoin_verified, genuine.bitcoin_verified);
    assertEquals(altered.time_consistent, genuine.time_consistent);
    assertEquals(altered.aggregate_recomputed, genuine.aggregate_recomputed);
    assertEquals(altered.ots_commits_to_aggregate, genuine.ots_commits_to_aggregate);

    // The human line shows the ATTESTED height, never the declared one.
    const chain = await verifyChain(exp);
    const { result, properties } = assess(exp, chain, [altered], "attributed");
    const human = renderHuman(exp.tenant_id, chain, [altered], result, properties);
    assert(human.includes("in block 956916"), human);
    assert(!human.includes("in block 111111"), human);
  });
});

// Pure render-level guard (offline, no server): the display helper never shows
// a declared block that is not among the attested heights.
Deno.test("W4 render: a hand-built verdict shows the attested minimum, not the declared block", () => {
  const chain = {
    chain_continuous: true,
    signatures_valid: true,
    anchored_to_genesis: true,
    verified_from_sequence: 1,
    verified_through_sequence: 1,
    first_failure: null,
  };
  const anchor = {
    anchor_date: REAL_ANCHOR_DATE,
    ots_btc_block: 111111,
    ots_status: "confirmed",
    ots_btc_blocks_attested: [956916, 956921],
    aggregate_recomputed: true,
    ots_commits_to_aggregate: true,
    bitcoin_verified: true,
    ots_btc_time: Date.parse(REAL_ANCHOR_DATE + "T12:00:00Z") / 1000,
    time_consistent: true,
    level: "explorer" as const,
    note:
      "block-header verification via public explorers; declared block 111111 is not among the attested block(s) 956916, 956921",
  };
  const human = renderHuman(
    "0f4a1c2e-7b3d-4e5f-9a8b-6c5d4e3f2a1b",
    chain,
    [anchor],
    "partial",
    { integrity: "ok", time: "proven", attribution: "attributed" },
  );
  assert(human.includes("in block 956916"), human);
  assert(!human.includes("in block 111111"), human);
});
