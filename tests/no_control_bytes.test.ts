// Guard against the "binary source file" trap.
//
// A single raw C0 control byte (e.g. U+0000, NUL) in a text file makes
// grep/ripgrep AND git classify the file as *binary*: they then apply
// binary-specific handling — `git diff` shows "Binary files differ" instead
// of the change, listing modes skip the content — so code review and every
// grep-based gate can go blind on that file. This happened once in a
// private Humarch source (2026-07-09); the guard keeps it out of this
// published tree.
//
// The whole repo tree is walked from the root, skipping only
// dependency/build/tool output. A backslash-u-0000 escape written out as
// ASCII text is fine — only a raw control byte in the file is the hazard.
import { assertEquals } from "jsr:@std/assert@1";

// Text sources that tooling greps/diffs. Known-binary extensions
// (.pdf, .wasm, .png, .ots, font files) are deliberately absent.
const TEXT_EXT = new Set([
  ".ts", ".tsx", ".astro", ".mjs", ".js", ".sql", ".json", ".css", ".md",
  ".toml", ".http", ".typ", ".html", ".yml", ".yaml", ".txt",
  ".sh", ".py", ".env", ".lock", ".svg",
  ".gitignore", ".gitattributes", ".editorconfig",
]);
// Dependency/build/tool output: generated, never reviewed or grep-gated.
const SKIP_DIR = new Set(["node_modules", "dist", ".git", ".astro", ".netlify", ".temp"]);

// `import.meta.url` keeps the root correct regardless of where the repo is
// checked out (CI included).
const REPO_ROOT = new URL("../", import.meta.url);

/** .env and .env.* carry no extension in the usual sense but are text. */
function isTextName(name: string): boolean {
  if (name.startsWith(".env")) return true;
  const dot = name.lastIndexOf(".");
  return dot >= 0 && TEXT_EXT.has(name.slice(dot).toLowerCase());
}

/** C0 control byte that is NOT tab (0x09), LF (0x0A) or CR (0x0D). */
function isForbidden(b: number): boolean {
  return b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d;
}

function* walk(dir: URL): Generator<URL> {
  for (const entry of Deno.readDirSync(dir)) {
    if (entry.isDirectory) {
      if (SKIP_DIR.has(entry.name)) continue;
      yield* walk(new URL(entry.name + "/", dir));
    } else if (entry.isFile && isTextName(entry.name)) {
      yield new URL(entry.name, dir);
    }
  }
}

Deno.test("no raw control byte in the repo tree (grep/git binary trap)", () => {
  const offenders: string[] = [];
  let scanned = 0;
  for (const file of walk(REPO_ROOT)) {
    scanned++;
    const bytes = Deno.readFileSync(file);
    for (let i = 0; i < bytes.length; i++) {
      if (isForbidden(bytes[i])) {
        const rel = file.href.slice(REPO_ROOT.href.length);
        offenders.push(
          `${rel} @${i}: byte 0x${bytes[i].toString(16).padStart(2, "0")} ` +
            `(a raw NUL/control byte makes grep and git treat the file as binary)`,
        );
        break; // one report per file is enough
      }
    }
  }
  assertEquals(
    scanned > 0,
    true,
    "the guard scanned no files — the root resolved to nothing (path/setup bug)",
  );
  assertEquals(offenders, [], `raw control bytes found:\n${offenders.join("\n")}`);
});
