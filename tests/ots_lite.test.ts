// Unit gate for the first-party OTS reader (D87): one failing case for EVERY
// cap in the parser's defense table, all malformation classes, a truncation
// sweep over every prefix of both real fixtures, a seeded deterministic fuzz
// pass, and the explorer network leg exercised OFFLINE through the injectable
// endpoint seam. A hand-written binary parser defends itself with limits, not
// optimism — and exceeding a limit is ALWAYS the existing fail-safe path
// (typed OtsParseError → unreadable receipt → exit 3), never a new outcome.
//
// Byte values appear ONLY as hex notation or runtime construction — never as
// literal control characters (see humarch-lezioni-ambiente).
import { assert, assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1";
import {
  evaluateOps,
  type ExplorerDeps,
  MAX_RECEIPT_BYTES,
  OtsParseError,
  parseOts,
  verifyBitcoinAttestations,
} from "../src/ots_lite.ts";

const OUR_RECEIPT = "vectors/anchors/anchor-2026-07-06.ots";
const HELLO_OTS = "vectors/anchors/hello-world.txt.ots";
const HELLO_MERKLEROOT = "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00";

// --- receipt builders (bytes constructed at runtime) -----------------------
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0));
const hexB = (h: string): number[] => h.match(/../g)!.map((x) => parseInt(x, 16));

const MAGIC = [
  0x00,
  ...ascii("OpenTimestamps"),
  0x00,
  0x00,
  ...ascii("Proof"),
  0x00,
  ...hexB("bf89e2e884e89294"),
];
const BITCOIN_TAG = hexB("0588960d73d71901");
const PENDING_TAG = hexB("83dfe30d2ef90c8e");
const ZERO32 = new Array(32).fill(0);

function varint(n: number): number[] {
  const out: number[] = [];
  let v = n;
  for (;;) {
    const b = v % 128;
    v = Math.floor(v / 128);
    if (v === 0) return [...out, b];
    out.push(b | 0x80);
  }
}

const attestation = (tag: number[], payload: number[]): number[] => [
  0x00,
  ...tag,
  ...varint(payload.length),
  ...payload,
];
const btcAtt = (height: number): number[] => attestation(BITCOIN_TAG, varint(height));
const pendingAtt = (uri: string): number[] =>
  attestation(PENDING_TAG, [...varint(uri.length), ...ascii(uri)]);

/** magic + version 1 + sha256 file-hash op + 32-byte digest + tree bytes */
const receipt = (tree: number[]): Uint8Array =>
  Uint8Array.from([...MAGIC, 0x01, 0x08, ...ZERO32, ...tree]);

const throws = (bytes: Uint8Array, msgIncludes: string, note?: string) =>
  assertThrows(() => parseOts(bytes), OtsParseError, msgIncludes, note);

// --- positive control: the builders produce parseable receipts -------------
Deno.test("builder control: minimal receipt with one bitcoin + one pending attestation parses", () => {
  const r = parseOts(receipt([0xff, ...pendingAtt("https://example.org/x"), ...btcAtt(358391)]));
  assertEquals(r.digest.length, 32);
  assertEquals(r.attestations.length, 2);
  assertEquals(r.attestations.filter((a) => a.kind === "bitcoin").map((a) => a.height), [358391]);
});

// --- cap table, one failing case per cap -----------------------------------
Deno.test("cap: receipt over 1 MiB is refused before any parsing", () => {
  throws(new Uint8Array(MAX_RECEIPT_BYTES + 1), "size cap");
});

Deno.test("cap: varint longer than 9 bytes", () => {
  throws(
    Uint8Array.from([...MAGIC, ...new Array(9).fill(0x80), 0x01]),
    "varint too long",
  );
});

Deno.test("cap: varint value beyond Number.MAX_SAFE_INTEGER", () => {
  // 0x7f * 128^8 needs only 9 bytes but exceeds 2^53-1.
  throws(
    Uint8Array.from([...MAGIC, ...new Array(8).fill(0x80), 0x7f]),
    "varint value too large",
  );
});

Deno.test("cap: append operand longer than the receipt itself", () => {
  throws(receipt([0xf0, ...varint(100_000)]), "exceeds cap");
});

Deno.test("cap: empty append operand (official client refuses them too)", () => {
  throws(receipt([0xf0, ...varint(0)]), "shorter than minimum");
});

Deno.test("cap: more than 4096 ops on a single path", () => {
  throws(
    receipt([...new Array(4097).fill(0x08), ...btcAtt(5)]),
    "ops-per-path cap",
  );
});

Deno.test("cap: more than 65536 tree nodes (hostile forks)", () => {
  // 17 branches of 4000 sha256 ops each: paths and attestation counts stay
  // legal, the total node count does not.
  const branch = [...new Array(4000).fill(0x08), ...btcAtt(5)];
  const tree: number[] = [];
  for (let i = 0; i < 16; i++) tree.push(0xff, ...branch);
  tree.push(...branch);
  throws(receipt(tree), "node cap");
});

Deno.test("cap: more than 64 attestations", () => {
  const tree: number[] = [];
  for (let i = 0; i < 64; i++) tree.push(0xff, ...btcAtt(5));
  tree.push(...btcAtt(5));
  throws(receipt(tree), "attestation cap");
});

Deno.test("cap: more than 16 distinct bitcoin heights", () => {
  const tree: number[] = [];
  for (let i = 1; i <= 16; i++) tree.push(0xff, ...btcAtt(i));
  tree.push(...btcAtt(17));
  throws(receipt(tree), "height cap");
});

Deno.test("cap: block height out of range (0 and above 10,000,000)", () => {
  throws(receipt(btcAtt(0)), "out of range");
  throws(receipt(btcAtt(10_000_001)), "out of range");
});

Deno.test("cap: pending URI longer than 4 KiB", () => {
  throws(receipt(pendingAtt("a".repeat(5000))), "exceeds cap");
});

Deno.test("cap: attestation payload longer than 8192 bytes", () => {
  throws(receipt(attestation(BITCOIN_TAG, new Array(9000).fill(0))), "exceeds cap");
});

Deno.test("cap (evaluateOps): accumulated buffer beyond 4 MiB", async () => {
  const big = new Uint8Array(1 << 20);
  big.fill(1);
  const ops = new Array(4).fill({ op: "append", operand: big });
  await assertRejects(
    () => evaluateOps(new Uint8Array(32), ops),
    OtsParseError,
    "buffer cap",
  );
});

// --- malformation classes ---------------------------------------------------
Deno.test("malformed: truncated magic", () => {
  throws(Deno.readFileSync(HELLO_OTS).subarray(0, 10), "end of receipt");
});

Deno.test("malformed: corrupted magic byte", () => {
  const b = Uint8Array.from(Deno.readFileSync(HELLO_OTS));
  b[3] ^= 0xff;
  throws(b, "bad header magic");
});

Deno.test("malformed: unsupported major version", () => {
  throws(
    Uint8Array.from([...MAGIC, 0x02, 0x08, ...ZERO32, ...btcAtt(5)]),
    "unsupported version",
  );
});

Deno.test("malformed: file hash op is not sha256 (fail closed)", () => {
  throws(
    Uint8Array.from([...MAGIC, 0x01, 0x02, ...ZERO32, ...btcAtt(5)]),
    "not sha256",
  );
});

Deno.test("malformed: unknown op tag (keccak/reverse/future)", () => {
  throws(receipt([0x67, ...btcAtt(5)]), "unsupported op tag");
  throws(receipt([0xf2, ...btcAtt(5)]), "unsupported op tag");
});

Deno.test("malformed: unknown 8-byte attestation type tag", () => {
  throws(receipt(attestation(new Array(8).fill(0), [0x01])), "unknown attestation type tag");
});

Deno.test("malformed: trailing bytes inside a bitcoin attestation payload", () => {
  throws(receipt(attestation(BITCOIN_TAG, [...varint(5), 0x01])), "trailing bytes in bitcoin");
});

Deno.test("malformed: non-printable byte in a pending URI", () => {
  throws(
    receipt(attestation(PENDING_TAG, [...varint(3), 0x61, 0x07, 0x62])),
    "not printable",
  );
});

Deno.test("malformed: trailing bytes after the timestamp tree", () => {
  throws(Uint8Array.from([...receipt(btcAtt(5)), 0x00]), "trailing bytes after");
  const real = Uint8Array.from([...Deno.readFileSync(HELLO_OTS), 0x41]);
  throws(real, "trailing bytes after");
});

// --- evaluateOps semantics --------------------------------------------------
Deno.test("evaluateOps: append/prepend byte order and digest lengths", async () => {
  const seed = Uint8Array.from([1, 2]);
  const app = await evaluateOps(seed, [{ op: "append", operand: Uint8Array.from([9]) }]);
  assertEquals([...app], [1, 2, 9]);
  const pre = await evaluateOps(seed, [{ op: "prepend", operand: Uint8Array.from([9]) }]);
  assertEquals([...pre], [9, 1, 2]);
  assertEquals((await evaluateOps(seed, [{ op: "sha256" }])).length, 32);
  assertEquals((await evaluateOps(seed, [{ op: "sha1" }])).length, 20);
  assertEquals((await evaluateOps(seed, [{ op: "ripemd160" }])).length, 20);
  const viaOps = await evaluateOps(seed, [
    { op: "append", operand: Uint8Array.from([9]) },
    { op: "sha256" },
  ]);
  const direct = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from([1, 2, 9]) as BufferSource),
  );
  assertEquals([...viaOps], [...direct]);
});

// --- truncation sweep + seeded fuzz (the strongest cheap defense) ----------
Deno.test("truncation sweep: every strict prefix of both fixtures raises the typed error", () => {
  for (const file of [OUR_RECEIPT, HELLO_OTS]) {
    const bytes = Deno.readFileSync(file);
    for (let len = 0; len < bytes.length; len++) {
      assertThrows(
        () => parseOts(bytes.subarray(0, len)),
        OtsParseError,
        undefined,
        `${file} prefix of length ${len}`,
      );
    }
  }
});

// Deterministic PRNG: the seed keeps CI reproducible; a failing case is
// reproducible from its index.
function mulberry32(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

Deno.test("seeded fuzz (N=2000): mutated receipts parse or raise the typed error, never crash", async () => {
  const fixtures = [Deno.readFileSync(OUR_RECEIPT), Deno.readFileSync(HELLO_OTS)];
  const rnd = mulberry32(20260719);
  const int = (n: number) => Math.floor(rnd() * n);
  for (let i = 0; i < 2000; i++) {
    const base = fixtures[i % 2];
    let m = Uint8Array.from(base);
    const kind = i % 3;
    if (kind === 0) {
      m[int(m.length)] ^= 1 << int(8); // bit flip
    } else if (kind === 1) {
      const start = int(m.length);
      const len = 1 + int(64);
      if (rnd() < 0.5) {
        m = Uint8Array.from([...m.subarray(0, start), ...m.subarray(start + len)]); // cut
      } else {
        const ins = Array.from({ length: len }, () => int(256));
        m = Uint8Array.from([...m.subarray(0, start), ...ins, ...m.subarray(start)]); // splice in
      }
    } else {
      const start = int(m.length);
      const len = 1 + int(128);
      const win = m.subarray(start, start + len);
      m = Uint8Array.from([...m.subarray(0, start + len), ...win, ...m.subarray(start + len)]); // duplicate window
    }
    try {
      const rec = parseOts(m);
      for (const a of rec.attestations) {
        if (a.kind === "bitcoin") {
          await evaluateOps(rec.digest, a.ops).catch((e) => {
            if (!(e instanceof OtsParseError)) throw e;
          });
        }
      }
    } catch (e) {
      if (!(e instanceof OtsParseError)) {
        throw new Error(`fuzz case ${i}: unexpected ${(e as Error).constructor.name}: ${e}`);
      }
    }
  }
});

// --- explorer leg, OFFLINE through the endpoint seam ------------------------
// A local server impersonates both explorers; every failure mode of the
// network leg contributes "false" (never a throw), and ONE healthy explorer
// out of two is enough (frozen >=1 semantics).
const HELLO_TIME = 1432825200; // sane mock block time (unix s)
const BLOCK_HASH = "ab".repeat(32);
const helloReceipt = () => parseOts(Deno.readFileSync(HELLO_OTS));

async function withMock(
  handler: (req: Request) => Response | Promise<Response>,
  fn: (deps: ExplorerDeps) => Promise<void>,
  timeoutMs = 5000,
): Promise<void> {
  const srv = Deno.serve({ port: 0, onListen: () => {} }, handler);
  const port = (srv.addr as Deno.NetAddr).port;
  try {
    await fn({
      blockstreamBase: `http://127.0.0.1:${port}/bs`,
      blockchainInfoBase: `http://127.0.0.1:${port}/bci`,
      timeoutMs,
    });
  } finally {
    await srv.shutdown();
  }
}

const greenHandler = (merkleRoot: string) => (req: Request): Response => {
  const path = new URL(req.url).pathname;
  if (path === "/bs/block-height/358391") return new Response(BLOCK_HASH);
  if (path === `/bs/block/${BLOCK_HASH}`) {
    return new Response(JSON.stringify({ merkle_root: merkleRoot, timestamp: HELLO_TIME }));
  }
  if (path === "/bci/block-height/358391") {
    return new Response(JSON.stringify({ blocks: [{ mrkl_root: merkleRoot, time: HELLO_TIME }] }));
  }
  return new Response("not found", { status: 404 });
};

Deno.test("explorer seam: correct merkle root at the attested height verifies (block time returned)", async () => {
  await withMock(greenHandler(HELLO_MERKLEROOT), async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), [HELLO_TIME]);
  });
});

Deno.test("explorer seam: wrong merkle root on both explorers does NOT verify", async () => {
  const wrong = HELLO_MERKLEROOT.slice(0, 63) + "1";
  await withMock(greenHandler(wrong), async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
  });
});

Deno.test("explorer seam: one healthy explorer out of two is enough (frozen >=1 semantics)", async () => {
  const green = greenHandler(HELLO_MERKLEROOT);
  await withMock((req) => {
    const path = new URL(req.url).pathname;
    if (path.startsWith("/bs/")) return new Response("boom", { status: 500 });
    return green(req);
  }, async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), [HELLO_TIME]);
  });
});

Deno.test("explorer seam: malformed JSON from both explorers contributes false, never a throw", async () => {
  await withMock(() => new Response("{not json"), async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
  });
});

Deno.test("explorer seam: non-hex block hash / bad shapes contribute false", async () => {
  await withMock((req) => {
    const path = new URL(req.url).pathname;
    if (path === "/bs/block-height/358391") return new Response("zz".repeat(32));
    if (path === "/bci/block-height/358391") {
      // blocks present but mrkl_root not hex and time absurd: shape-checked out
      return new Response(
        JSON.stringify({ blocks: [{ mrkl_root: "nope", time: 1 }] }),
      );
    }
    return new Response("not found", { status: 404 });
  }, async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
  });
});

Deno.test("explorer seam: response over the read cap contributes false", async () => {
  const huge = "a".repeat((1 << 20) + 1024);
  await withMock(() => new Response(huge), async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
  });
});

Deno.test("explorer seam: a redirecting explorer is refused (endpoints are pinned)", async () => {
  await withMock(
    () =>
      new Response(null, {
        status: 301,
        headers: { location: "http://insecure.example/api" },
      }),
    async (deps) => {
      assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
    },
  );
});

Deno.test("explorer seam: HTTP 500 from both explorers contributes false", async () => {
  await withMock(() => new Response("down", { status: 500 }), async (deps) => {
    assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
  });
});

Deno.test("explorer seam: a hanging explorer times out and contributes false", async () => {
  await withMock(
    async () => {
      await new Promise((r) => setTimeout(r, 1500));
      return new Response("late");
    },
    async (deps) => {
      assertEquals(await verifyBitcoinAttestations(helloReceipt(), deps), []);
    },
    200, // injected timeout well below the handler's delay
  );
});

// The pending-attestation URI is bounded but NEVER fetched: a receipt with
// only pending attestations must produce zero network activity.
Deno.test("explorer seam: pending attestations cause no fetch at all", async () => {
  let hits = 0;
  await withMock(() => {
    hits++;
    return new Response("never", { status: 500 });
  }, async (deps) => {
    const rec = parseOts(receipt(pendingAtt("https://alice.btc.calendar.opentimestamps.org")));
    assertEquals(await verifyBitcoinAttestations(rec, deps), []);
    assertEquals(hits, 0, "a pending-only receipt must not touch the network");
  });
});

// Anti-amplification: duplicate heights are deduplicated — the fetch count
// is a function of the caps, never of the input.
Deno.test("explorer seam: duplicate bitcoin heights are fetched once per explorer at most", async () => {
  const heightHits: string[] = [];
  const green = greenHandler(HELLO_MERKLEROOT);
  await withMock((req) => {
    const path = new URL(req.url).pathname;
    if (path.includes("block-height")) heightHits.push(path);
    return green(req);
  }, async (deps) => {
    // hello's single (height 358391) attestation duplicated 3 times.
    const hello = helloReceipt();
    const dup = {
      digest: hello.digest,
      attestations: [
        ...hello.attestations,
        ...hello.attestations,
        ...hello.attestations,
      ],
    };
    assertEquals(await verifyBitcoinAttestations(dup, deps), [HELLO_TIME]);
    assert(heightHits.length <= 2, `expected at most 2 height lookups, saw ${heightHits.length}`);
  });
});
