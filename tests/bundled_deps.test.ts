// Bundled-dependency allowlist guardian (D87, 2026-07-19). The npm packages
// in cli.ts's module graph are exactly what `deno compile` bundles into the
// MIT-licensed release binaries: every entry must be a conscious, license-
// vetted choice (THIRD_PARTY_NOTICES.md). This gate exists because an AGPL
// package (the npm OpenTimestamps library) once sat in that graph unnoticed —
// a future dependency enters only by updating BOTH this allowlist and the
// notices file, deliberately.
import { assert } from "jsr:@std/assert@1";
import { fromFileUrl } from "jsr:@std/path@1";

const ALLOWED = new Set([
  "canonicalize@2.0.0", // Apache-2.0 (JCS, RFC 8785)
  "@noble/hashes@1.8.0", // MIT (ripemd160 for OTS commitment paths)
]);

Deno.test("npm packages in the cli.ts graph are a subset of the explicit allowlist", async () => {
  const cli = fromFileUrl(new URL("../src/cli.ts", import.meta.url));
  const out = await new Deno.Command(Deno.execPath(), {
    args: ["info", "--json", cli],
    stdout: "piped",
    stderr: "piped",
  }).output();
  assert(out.code === 0, new TextDecoder().decode(out.stderr));
  const info = JSON.parse(new TextDecoder().decode(out.stdout));
  const pkgs = Object.values(info.npmPackages ?? {}) as { name: string; version: string }[];
  assert(pkgs.length > 0, "expected npm packages in the graph (canonicalize at least)");
  for (const p of pkgs) {
    const id = `${p.name}@${p.version}`;
    assert(
      ALLOWED.has(id),
      `npm package ${id} is not in the bundled-dependency allowlist: adding a ` +
        `dependency to the released binaries is a deliberate act — vet its license, ` +
        `add it to THIRD_PARTY_NOTICES.md, then extend the allowlist here`,
    );
    assert(
      p.name !== "@lacrypta/typescript-opentimestamps",
      "the AGPL-published OTS library must never re-enter the binary trust path (D87)",
    );
  }
});
