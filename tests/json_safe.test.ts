// F6 (external audit 2026-08-03): jsonSafe rewrote code points above U+FFFF
// as `\u` + FIVE hex digits — not a JSON escape, so JSON.parse read four
// digits and a stray character: the value CHANGED, on a function whose whole
// contract is "value-preserving". Supplementary code points must round-trip
// as their surrogate pair.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { jsonSafe } from "../src/render.ts";

Deno.test("F6: jsonSafe is value-preserving across BMP, supplementary and unpaired-surrogate content", () => {
  const samples = [
    "bmp\u202Eend", // bidi override, BMP Cf
    "astral-cf\u{1D173}end", // MUSICAL SYMBOL BEGIN BEAM, supplementary Cf
    "tag\u{E0041}end", // TAG LATIN CAPITAL LETTER A, supplementary Cf
    "emoji\u{1F600}end", // supplementary but not Cc/Cf/Zl/Zp: untouched
    "lone\uD800end", // unpaired surrogate: stringify already escapes it
    "mix\u{E0041}\u202E\u{1D173} end",
  ];
  for (const s of samples) {
    for (const raw of [JSON.stringify({ v: s }), JSON.stringify({ v: s }, null, 2)]) {
      // The property the contract states: parse of the escaped stream is
      // deep-equal to the original value.
      assertEquals(JSON.parse(jsonSafe(raw)), { v: s });
    }
  }
  // And the stream is actually clean of the raw characters, escaped as the
  // surrogate pair JSON defines for supplementary code points.
  const safe = jsonSafe(JSON.stringify({ v: "x\u{1D173}y" }));
  assert(!safe.includes("\u{1D173}"), "raw supplementary Cf left in the stream");
  assert(safe.includes("\\ud834\\udd73"), `expected a surrogate-pair escape, got: ${safe}`);
});
