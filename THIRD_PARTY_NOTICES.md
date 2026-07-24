# Third-party notices

The released `humarch-verify` binaries (built with `deno compile`) bundle the
following npm packages. Their licenses were verified in the published
packages themselves (D87, 2026-07-19); the allowlist test
`tests/bundled_deps.test.ts` fails CI if the bundled set ever drifts from
this file.

| Package | Version | License | Use |
|---|---|---|---|
| [canonicalize](https://www.npmjs.com/package/canonicalize) | 2.0.0 | Apache-2.0 | JSON Canonicalization Scheme (RFC 8785) |
| [@noble/hashes](https://www.npmjs.com/package/@noble/hashes) | 1.8.0 | MIT | RIPEMD-160 for OpenTimestamps commitment paths |

- canonicalize — Copyright Erdtman & contributors, licensed under the
  Apache License, Version 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>).
- @noble/hashes — Copyright (c) 2022 Paul Miller (<https://paulmillr.com>),
  licensed under the MIT License.

The OpenTimestamps receipt reader itself (`src/ots_lite.ts`) is first-party
code, MIT like the rest of this repository. The `.ots` format is an open
binary protocol; the authoritative implementation is the official
[opentimestamps-client](https://github.com/opentimestamps/python-opentimestamps)
(used as an external CLI in the CI interop gate, never bundled).

Test-only dependencies (`jsr:@std/assert`, `jsr:@std/path`) are not part of
the released binaries.
