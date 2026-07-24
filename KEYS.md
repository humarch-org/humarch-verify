# Trusted issuer keys — cross-check registry

This file is one of the **independent places** where the Humarch issuer's
public signing keys are published (residual-risk mandate R4, bootstrap of
trust). The attribution check (D82) is only as strong as your confidence that
the trusted set itself is genuine: a single compromised website could serve a
fake `/.well-known/humarch-keys.json` — a fake that also has to appear in this
repository's history, in `humarch-spec/KEYS.md`, in the service-ops event
history, **and** in the signed release binaries is a different attack
entirely.

Before trusting a set of keys, cross-check that the **same public key bytes**
appear in all of:

1. the issuer's `/.well-known/humarch-keys.json` (served over TLS);
2. this file (`humarch-verify/KEYS.md`) and its git history;
3. `humarch-spec/KEYS.md` (the spec repository's key registry);
4. the `EMBEDDED_ISSUER` registry compiled into the released binaries
   (`src/issuer.ts`) — releases ship with `SHA256SUMS` and keyless SLSA
   provenance (see README, "Trust the binary before you trust the verdict");
5. the issuer's `service-ops` evidence trail: every key lifecycle event
   (`signing_key_created`, rotation, retirement) is recorded in the same
   append-only, anchored registry the keys sign.

A mismatch anywhere is a red flag: stop and ask the issuer out of band.

## Production keys

| signing_key_id | public_key (hex) | created_at | retired_at |
|---|---|---|---|
| *(none yet — the first production key is generated at go-live; its row lands here in the same change that populates the well-known document and `EMBEDDED_ISSUER`)* | | | |

## Test key (conformance vectors only — NEVER valid in production)

The conformance vectors use the **RFC 8032 (TEST 1)** key, publicly known by
construction (`ed25519:21fe31dfa154a261`,
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`). It may
appear only in test and vector files, passed explicitly via `--issuer`/
`--pubkey`; CI fails the build if it ever enters `EMBEDDED_ISSUER`.
