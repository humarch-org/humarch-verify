# humarch-verify

Open-source verifier for Humarch registry exports (`humarch-export/v1`).

> *Official distribution channel: **github.com/humarch-org** (source and the
> signed release binaries produced by `deno compile`, shipped with
> `SHA256SUMS` and Sigstore build provenance — see below). Humarch is **not**
> published on npm or PyPI — any package with this name on a registry is not
> ours.*

`src/verify.ts` is the **public reference implementation** of the Humarch
verification routine (D63): it recomputes every hash from the parsed values of
the export (JCS / RFC 8785), checks the per-tenant hash chain down to the
genesis hash, and verifies the Ed25519 signatures against the self-certifying
`signing_key_id`. The Humarch core imports this very module — the CLI and the
reports can never diverge.

The full specification (canonicalization, pre-image, signature, anchors) lives
in the [`humarch-spec`](https://github.com/humarch-org/humarch-spec)
repository, with test vectors V0–V5: any independent
implementation that reproduces those vectors is conformant.

## Usage

```
humarch-verify <export.json> [--issuer <file|url>] [--pubkey <hex|file>] [--ots-level explorer|trustless|convenience] [--json]
```

Exit codes: `0` verified · `2` chain/signatures invalid · `3` anchor/OTS not
verified · `4` malformed input · `5` declared partial verification · `6` keys
not attributed to a trusted issuer.

**VERIFIED (exit 0) is the conjunction of three properties**, each declared
on its own line of the output:

- **integrity** — hash chain continuous, every Ed25519 signature valid;
- **time** — a confirmed Bitcoin attestation, consistent with its declared
  date, covers this chain's head (the anchor's aggregate commits to the
  export's tenant and head hash — a genuine anchor stolen from another
  export does not bind);
- **attribution** — every event is signed by a key in a **trusted issuer
  set** obtained out of band: `--issuer <file|url>` (a `humarch-keys/v1`
  document, e.g. the issuer's `/.well-known/humarch-keys.json`; URLs must be
  `https://` — the trusted set is the trust anchor and never travels in
  clear), `--pubkey`
  (single-key shortcut), or the registry embedded in the released binary.
  The check is per event and on the public-key bytes: the `signing_keys`
  listed INSIDE an export prove nothing about who wrote it, and the
  self-certifying `signing_key_id` is a 64-bit lookup handle, not a trust
  anchor.

Anything less degrades honestly: `partial` (exit 5) when the anchor is
pending, not yet bound to the head, or the range does not start at the
genesis; `unattributed` (exit 6) when no trusted set is available or an
event resolves outside it.

**What VERIFIED does — and does not — prove.** A verified export proves that
these events were recorded by the holder of the trusted keys, unaltered and in
this order, and that the chain existed at the anchor's Bitcoin block time. It
proves the events **as received — not as true**: whether what a payload
asserts actually happened (amounts, decisions, outcomes) is the submitter's
responsibility and stays outside any cryptographic proof. Attribution proves
the key, not the truth.

Anchor verification levels (always declared in the output):

1. **trustless** — official `opentimestamps-client` + Bitcoin Core (the gold
   standard citable in court; the CLI prints the exact command);
2. **explorer** (default) — block-header check via public explorers;
3. **convenience** — opentimestamps.org drag & drop (quick check, not proof).

**Qualified timestamp (dual anchor, spec 1.3.0).** An export may additionally
carry, per anchor, an RFC 3161 timestamp token issued by an eIDAS qualified
trust service provider on the **same daily aggregate hash** the Bitcoin
anchor commits to. The check is **additive and exit-neutral**: the verifier
parses the token (bounded, fail-safe), checks that it commits to exactly the
anchor's `aggregate_hash`, verifies the TSA's CMS signature, and matches the
signer certificate against a trusted TSA registry (`humarch-tsa/v1` —
embedded set, or `--tsa-trust <file>`); the outcome is one extra line per
anchor (`valid · <TSA> · <genTime>` / `absent` / `invalid` /
`valid token, untrusted TSA, no presumption`) and never changes the exit
code. Semantics, pinned by the spec: the qualified timestamp attaches the
art. 42 presumption **to the daily aggregate**; every event verifiably
contained in it inherits that anteriority through deterministic,
reproducible recomputation. Full eIDAS chain validation against the EU
Trusted List belongs to standard tooling — the token is a plain
TimeStampToken, e.g.:

```sh
# extract token_base64 to token.tst, then:
openssl ts -verify -digest <aggregate_hash> -token_in -in token.tst \
  -CAfile <QTSP CA chain>
```

## Trust the binary before you trust the verdict

The verifier binary is the first link of the trust chain: a tampered download
could accept fabricated exports. Every release therefore ships with two
independent proofs — check at least one **before running the binary**:

1. **Checksum.** `SHA256SUMS` is published next to the binaries:

   ```sh
   sha256sum --check --ignore-missing SHA256SUMS
   ```

2. **Build provenance (SLSA, keyless).** Each binary carries a Sigstore
   attestation proving it was built by this repository's CI from a specific
   commit — no downloaded website in the loop:

   ```sh
   gh attestation verify humarch-verify-linux-x64 --repo humarch-org/humarch-verify
   ```

The same caution applies to the **trusted key set** itself: the issuer's
public keys are published in several independent places (this repo's
`KEYS.md`,
[`humarch-spec/KEYS.md`](https://github.com/humarch-org/humarch-spec/blob/main/KEYS.md),
the issuer's
`/.well-known/humarch-keys.json`, the service-ops evidence trail, and the
`EMBEDDED_ISSUER` registry inside the released binaries) — cross-check them;
a mismatch anywhere is a red flag. See [`KEYS.md`](KEYS.md).

## Limits

The verifier imposes **no artificial cap** on export size: it runs locally, on
a file you chose, and a fixed limit would only deny legitimate verification of
large exports. Time and memory are **proportional to the export** (linear in
the number of events and anchors) — a smoke test pins that linearity against
regressions. A very large export simply takes proportionally longer; nothing
is refused for being big. (Individual OpenTimestamps receipts are still bounded
against malformed input — an attacker cannot make one small receipt cost
unbounded work — see `THIRD_PARTY_NOTICES.md` and the reader's caps.)

## Run from source / build binaries

```sh
deno task test      # conformance vectors V0-V5 + CLI gate
deno task verify -- export.json
deno task compile   # standalone binary via deno compile (no Deno needed to run it)
```

Bitcoin anchor interop against the official client is exercised from phase 2
of the build onward (the local registry starts anchoring then).

Licenses of the third-party packages bundled in the release binaries are
listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
