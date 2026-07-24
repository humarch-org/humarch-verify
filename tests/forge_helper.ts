// Test-only forgery builder (audit F1; M3 cases 3–5): an INTERNALLY
// CONSISTENT humarch-export/v1 signed by a freshly generated attacker key.
// verifyChain accepts it by construction — hashes, chain, genesis, D16 key id
// and Ed25519 signatures all check out. That is exactly finding F1: only
// attribution against an OUT-OF-BAND trusted set can reject it.
import { eventHash, expectedKeyId, fromHex, genesisHash, jcsHash, toHex } from "../src/verify.ts";

export const FORGED_TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

export interface ForgeOptions {
  /** Pad this GENUINE public key (hex) into signing_keys as a decoy while
   * every event stays signed by the attacker key (the --pubkey membership
   * bypass, M3 case 5). */
  padGenuineKey?: string;
}

// deno-lint-ignore no-explicit-any
export async function forgeExport(opts: ForgeOptions = {}): Promise<any> {
  const kp = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const pubHex = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  const keyId = await expectedKeyId(pubHex);

  let prev = await genesisHash(FORGED_TENANT);
  // deno-lint-ignore no-explicit-any
  const events: any[] = [];
  for (let seq = 1; seq <= 2; seq++) {
    const ev = {
      event_id: `0000000${seq}-1111-4222-8333-444444444444`,
      tenant_id: FORGED_TENANT,
      sequence_number: seq,
      received_at: `2025-01-0${seq}T00:00:00.000000Z`,
      occurred_at: `2025-01-0${seq}T00:00:00.000000Z`,
      source: "make",
      event_type: "agent_action",
      actor: { type: "agent", id: "forged-agent" },
      subject: { type: "none" },
      payload: { note: `forged event ${seq}` },
    };
    const payload_hash = await jcsHash(ev.payload);
    const eh = await eventHash(
      ev,
      await jcsHash(ev.actor),
      await jcsHash(ev.subject),
      payload_hash,
      prev,
    );
    const signature = toHex(
      new Uint8Array(
        await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, fromHex(eh) as BufferSource),
      ),
    );
    events.push({
      ...ev,
      payload_hash,
      prev_hash: prev,
      event_hash: eh,
      signature,
      signing_key_id: keyId,
    });
    prev = eh;
  }

  const signing_keys = [{
    signing_key_id: keyId,
    algorithm: "ed25519",
    public_key: pubHex,
    created_at: "2025-01-01T00:00:00.000000Z",
    retired_at: null,
  }];
  if (opts.padGenuineKey) {
    signing_keys.unshift({
      signing_key_id: await expectedKeyId(opts.padGenuineKey),
      algorithm: "ed25519",
      public_key: opts.padGenuineKey,
      created_at: "2025-01-01T00:00:00.000000Z",
      retired_at: null,
    });
  }

  return {
    format: "humarch-export/v1",
    generated_at: "2025-01-02T00:00:00.000000Z",
    tenant_id: FORGED_TENANT,
    range: { from_sequence: 1, to_sequence: 2 },
    genesis_note: "forged for tests (audit F1)",
    signing_keys,
    events,
    anchors: [],
  };
}
