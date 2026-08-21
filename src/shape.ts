// humarch-verify/src/shape.ts — validation of the FORM of a humarch-export/v1
// value at the trust boundary (audit F5, 2026-07-12). ADDITIVE module: the
// normative verification routine (verify.ts, D63) and its Verdict are
// untouched — this file answers one question only: "can verifyChain and
// verifyAnchors consume this parsed value without throwing, and can the CLI
// interpolate the checked fields into a terminal without side effects?"
// (the second half added by audit 3, 2026-07-18: V1 non-finite numbers,
// V2 control bytes, W1 tenant coherence, W2 strict anchor_date).
//
// It never judges integrity. A well-formed-but-tampered export MUST pass this
// check and flow to the verifier for its own verdict (tampered/anchor_failed):
// only values whose SHAPE is wrong — hex fields of the wrong length or
// alphabet, missing required members, non-array collections, undecodable
// base64 — are reported. Both untrusted boundaries call it: the CLI maps a
// non-empty result to `malformed` (exit 4, D65) and the panel verifyExport
// action to its existing `rp_verify_failed` error. No new semantics.

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const HEX_128 = /^[0-9a-fA-F]{128}$/;
// W2 (audit 3): Date.parse is lenient — "2026-06-12junk" parses, to a
// DIFFERENT day — so the anchor time-consistency window must only ever see
// the declared date as written. Calendar validity is not needed here: an
// impossible day fails Date.parse inside anchorTimeConsistent, fail-safe.
const DATE_YMD = /^\d{4}-\d{2}-\d{2}$/;
// V2 (audit 3): C0 control bytes (ESC included) plus DEL. The checked
// string fields are identifiers, timestamps, statuses — several are
// interpolated raw into the human-readable verdict, where a control byte
// would let a hostile export drive the verifier's terminal. Genuine values
// never contain one (SPEC §1 already bans U+0000 in every string).
// Widened by the external audit of 2026-08-02 (finding 2): C0 and DEL are
// not the whole hostile set. Every Unicode control (Cc: C0, DEL, C1),
// format (Cf: the bidi overrides and isolates, zero-width joiners, the
// BOM) and line/paragraph separator (Zl/Zp) is refused - a bidi override
// inside event_type renders in a terminal as a reversed, verdict-spoofing
// label. The checked fields are machine values (identifiers, timestamps,
// statuses); free-text members such as `label` are not checked here and
// are never rendered by the CLI.
const CONTROL_BYTES = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const isBase64 = (s: string): boolean => {
  try {
    atob(s);
    return true;
  } catch {
    return false;
  }
};

function checkHex(
  problems: string[],
  path: string,
  value: unknown,
  re: RegExp,
  bits: string,
): void {
  if (typeof value !== "string" || !re.test(value)) {
    problems.push(`${path}: expected ${bits} as lowercase/uppercase hex`);
  }
}

function checkString(problems: string[], path: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0) {
    problems.push(`${path}: expected a non-empty string`);
  } else if (CONTROL_BYTES.test(value)) {
    problems.push(`${path}: control bytes are not allowed`);
  }
}

// V1 (audit 3): JSON.parse turns the out-of-range literal 1e999 into
// Infinity, which RFC 8785 cannot represent — canonicalize() would throw
// inside the verifier (exit 1 with a stack trace instead of the contractual
// exit 4). A genuine export can never carry one: JSON.stringify never emits
// non-finite numbers. Iterative walk on purpose — hostile nesting depth must
// not crash the gate either.
function checkFinite(problems: string[], path: string, root: unknown): void {
  // This gate runs BEFORE any other defence, so it needs the guarantees the
  // search walk has (adversarial review 2026-08-02): a cyclic graph must
  // terminate, hostile accessors must never be invoked (Object.entries calls
  // getters), a throwing reflective step must not escape, and the whole walk
  // is bounded. Only JSON.parse output reaches it through the CLI; the panel
  // and library callers deserve the same floor.
  //
  // External audit 2026-08-03 (F5): the diagnostic path used to embed the
  // payload's own KEYS — the one sink of payload text this boundary had
  // left open (V2: the message is interpolated into the CLI's stderr and
  // into the panel's verifyExport error). The path now stops at the
  // documented container (`path`, e.g. `events[i].payload`) and continues
  // with opaque markers: canonical array indices stay (numeric), every
  // other key renders as `<member j>` — its position in own-key order. The
  // lost diagnostic precision is accepted and intentional: both consumers
  // only need WHERE in the export the problem sits, never the hostile key
  // text.
  const stack: [string, unknown][] = [[path, root]];
  const seen = new WeakSet<object>();
  let budget = 2_000_000;
  while (stack.length > 0) {
    // BT-36 (2026-08-21). This used to `return` silently on exhaustion, which
    // broke the repo's own "no silent caps" discipline in the one place it
    // mattered most: the exhausted walk reports NO non-finite number, so a
    // `1e999` planted past the budget flowed on to verifyChain, where
    // canonicalize() threw — and at the CLI that surfaced as exit 1 with a
    // stack trace instead of the contractual exit 4. An automation mapping
    // exit 4 to "reject" was therefore steerable by document size alone
    // (reproduced with a 4.2 MB document).
    //
    // Reaching the cap is now itself a form error. It is fail-closed and it
    // costs nothing honest: a genuine export never comes near two million
    // nodes in one container, and SPEC §8.1 class 6 requires a verifier to
    // report a document that exceeds a bound rather than truncate the check.
    if (budget-- <= 0) {
      problems.push(
        `${path}: too large to check for non-finite numbers ` +
          `(over 2000000 nodes in one container)`,
      );
      return;
    }
    const [p, v] = stack.pop() as [string, unknown];
    if (typeof v === "number") {
      if (!Number.isFinite(v)) {
        problems.push(`${p}: non-finite number (not representable in JSON, RFC 8785)`);
      }
      continue;
    }
    if (typeof v !== "object" || v === null) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    try {
      const keys = Reflect.ownKeys(v);
      for (let j = 0; j < keys.length; j++) {
        const key = keys[j];
        if (typeof key !== "string") continue;
        try {
          const d = Object.getOwnPropertyDescriptor(v, key);
          if (d !== undefined && d.enumerable === true && "value" in d) {
            const segment = Array.isArray(v) && /^(0|[1-9]\d*)$/.test(key)
              ? `[${key}]`
              : `.<member ${j}>`;
            stack.push([p + segment, d.value]);
          }
        } catch {
          // one unreadable property never invalidates the others
        }
      }
    } catch {
      // an object that refuses enumeration simply has no children here
    }
  }
}

/**
 * A provider-supplied DISPLAY string (adversarial review of the F2 remedy,
 * 2026-08-02). Machine identifiers are held to CONTROL_BYTES; a human name
 * minted by a third party — the TSA name read from its certificate — is
 * not one: a soft hyphen or a directional mark inside a genuine QTSP name
 * would otherwise make a real export unverifiable, a self-inflicted denial
 * of verification. Controls and line/paragraph separators stay refused (no
 * legitimate name carries them); everything else is tolerated here and
 * escaped by the renderer before it reaches a terminal. The class is a
 * SUBSET of what the token reader strips and of what the registry's own
 * CHECK constraint refuses, so the writer can never mint a value this gate
 * rejects — the inversion that would make a whole anchored day
 * unverifiable for every tenant.
 */
const DISPLAY_UNSAFE = /[\p{Cc}]/u;

function checkDisplayString(problems: string[], path: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0) {
    problems.push(`${path}: expected a non-empty string`);
  } else if (DISPLAY_UNSAFE.test(value)) {
    problems.push(`${path}: control characters are not allowed`);
  }
}
/**
 * Structural problems of a parsed humarch-export/v1 value; empty array means
 * the export is well-FORMED (it may still be tampered — run the verifier).
 * Only members the verifier consumes are checked; unknown members pass.
 */
export function exportShapeProblems(value: unknown): string[] {
  const problems: string[] = [];
  if (!isObject(value)) return ["export: not a JSON object"];
  const exp = value;

  if (exp.format !== "humarch-export/v1") {
    problems.push('format: not "humarch-export/v1"');
  }
  checkString(problems, "tenant_id", exp.tenant_id);
  if (exp.range != null && !isObject(exp.range)) {
    problems.push("range: expected an object");
  }

  if (exp.signing_keys != null) {
    if (!Array.isArray(exp.signing_keys)) {
      problems.push("signing_keys: expected an array");
    } else {
      exp.signing_keys.forEach((k, i) => {
        if (!isObject(k)) {
          problems.push(`signing_keys[${i}]: expected an object`);
          return;
        }
        checkString(problems, `signing_keys[${i}].signing_key_id`, k.signing_key_id);
        checkHex(
          problems,
          `signing_keys[${i}].public_key`,
          k.public_key,
          HEX_64,
          "64 hex chars (raw Ed25519 public key)",
        );
      });
    }
  }

  if (!Array.isArray(exp.events)) {
    problems.push("events: expected an array");
  } else {
    // External audit 2026-08-02, finding 1 (layer 2). Within one export a
    // sequence_number and an event_id are unique by construction (the
    // registry holds `unique (tenant_id, sequence_number)` and event_id is a
    // primary key), so a repetition is a form error — and a dangerous one:
    // verifyChain verifies a POSITIONAL prefix of the sorted events, while a
    // consumer reading "sequence ≤ verified_through" as "verified" credits a
    // duplicated, tampered event with integrity it never had. Refusing the
    // shape here (exit 4) closes that reading at the boundary, independently
    // of the positional fix in find.ts — the same defence-in-depth pairing
    // as the duplicate anchor date (W3) below.
    const seenSequences = new Set<number>();
    const seenEventIds = new Set<string>();
    exp.events.forEach((ev, i) => {
      if (!isObject(ev)) {
        problems.push(`events[${i}]: expected an object`);
        return;
      }
      if (typeof ev.event_id === "string") {
        if (seenEventIds.has(ev.event_id)) {
          problems.push(`events[${i}].event_id: duplicate event_id in the export`);
        } else {
          seenEventIds.add(ev.event_id);
        }
      }
      if (typeof ev.sequence_number === "number") {
        if (seenSequences.has(ev.sequence_number)) {
          problems.push(
            `events[${i}].sequence_number: duplicate sequence number in the export`,
          );
        } else {
          seenSequences.add(ev.sequence_number);
        }
      }
      for (
        const f of [
          "event_id",
          "tenant_id",
          "received_at",
          "occurred_at",
          "source",
          "event_type",
          "signing_key_id",
        ]
      ) {
        checkString(problems, `events[${i}].${f}`, ev[f]);
      }
      // W1 (audit 3): the verdict is ABOUT exp.tenant_id — the rendered
      // header, the genesis pre-image and the anchor binding all use it. An
      // event list that mixes tenants, or belongs to another tenant than the
      // export declares, is not a well-formed export of this chain: refuse to
      // issue a verdict under an attacker-chosen tenant label. (Fail-safe
      // even without this check: genesis hashes ev.tenant_id per event and
      // the anchor binding matches exp.tenant_id against committed entries —
      // the incoherence could mislead a reader, never mint a false VERIFIED.)
      if (
        typeof ev.tenant_id === "string" && typeof exp.tenant_id === "string" &&
        ev.tenant_id !== exp.tenant_id
      ) {
        problems.push(`events[${i}].tenant_id: does not match the export tenant_id`);
      }
      // Sequences are dense positive integers by construction (D5): floats,
      // zero/negatives and non-numbers are all form errors, not verdicts.
      // W9 (audit 3): also bound by Number.MAX_SAFE_INTEGER — above 2^53−1 the
      // double arithmetic loses precision (1e21 + 1 === 1e21, so the gap check
      // degenerates) and String(seq) in the pre-image turns to exponential
      // notation; genuine sequences live far inside the safe range (2^53−1
      // events is unreachable by definition), so reject the rest as a form
      // error rather than let it degrade the gate.
      if (
        !Number.isInteger(ev.sequence_number) || (ev.sequence_number as number) < 1 ||
        (ev.sequence_number as number) > Number.MAX_SAFE_INTEGER
      ) {
        problems.push(`events[${i}].sequence_number: expected a positive integer`);
      }
      // Presence (jcs throws on undefined, i.e. on a MISSING member) + V1:
      // every number the verifier will canonicalize must be finite.
      for (const f of ["actor", "subject", "payload"]) {
        if (!(f in ev)) problems.push(`events[${i}].${f}: missing`);
        else checkFinite(problems, `events[${i}].${f}`, ev[f]);
      }
      for (const f of ["payload_hash", "prev_hash", "event_hash"]) {
        checkHex(problems, `events[${i}].${f}`, ev[f], HEX_64, "64 hex chars (SHA-256)");
      }
      checkHex(
        problems,
        `events[${i}].signature`,
        ev.signature,
        HEX_128,
        "128 hex chars (Ed25519 signature)",
      );
    });
  }

  if (exp.anchors != null) {
    if (!Array.isArray(exp.anchors)) {
      problems.push("anchors: expected an array");
    } else {
      // W3 layer 2 (audit 3, reclassified 2026-07-19): an export has at most
      // one anchor per UTC day (one daily aggregate, D9), so two anchors
      // sharing a date is a form error, never a genuine export. Refusing it
      // here (exit 4) closes the chain↔anchor binding bypass at the shape
      // boundary, independently of the per-index binding fix in render.ts: a
      // decoy anchor cannot ride in on the real one's date.
      const seenDates = new Set<string>();
      exp.anchors.forEach((a, i) => {
        if (!isObject(a)) {
          problems.push(`anchors[${i}]: expected an object`);
          return;
        }
        if (typeof a.anchor_date !== "string" || !DATE_YMD.test(a.anchor_date)) {
          problems.push(`anchors[${i}].anchor_date: expected a YYYY-MM-DD date`);
        } else if (seenDates.has(a.anchor_date)) {
          problems.push(
            `anchors[${i}].anchor_date: duplicate anchor date (at most one anchor per UTC day, D9)`,
          );
        } else {
          seenDates.add(a.anchor_date);
        }
        checkString(problems, `anchors[${i}].ots_status`, a.ots_status);
        checkHex(
          problems,
          `anchors[${i}].aggregate_hash`,
          a.aggregate_hash,
          HEX_64,
          "64 hex chars (D9 aggregate)",
        );
        if (a.anchor_entries_for_aggregate != null) {
          if (!Array.isArray(a.anchor_entries_for_aggregate)) {
            problems.push(`anchors[${i}].anchor_entries_for_aggregate: expected an array`);
          } else {
            a.anchor_entries_for_aggregate.forEach((e, j) => {
              if (!isObject(e)) {
                problems.push(
                  `anchors[${i}].anchor_entries_for_aggregate[${j}]: expected an object`,
                );
                return;
              }
              checkString(
                problems,
                `anchors[${i}].anchor_entries_for_aggregate[${j}].tenant_id`,
                e.tenant_id,
              );
              checkHex(
                problems,
                `anchors[${i}].anchor_entries_for_aggregate[${j}].last_event_hash`,
                e.last_event_hash,
                HEX_64,
                "64 hex chars (SHA-256)",
              );
            });
          }
        }
        if (
          a.ots_file_base64 != null &&
          (typeof a.ots_file_base64 !== "string" || !isBase64(a.ots_file_base64))
        ) {
          problems.push(`anchors[${i}].ots_file_base64: expected a base64 string`);
        }
        // Dual anchor (D98, SPEC 1.3.0): OPTIONAL qualified_timestamp — the
        // shape gate stays additive (its absence is the pre-1.3 form).
        if (a.qualified_timestamp != null) {
          if (!isObject(a.qualified_timestamp)) {
            problems.push(`anchors[${i}].qualified_timestamp: expected an object`);
          } else {
            const qt = a.qualified_timestamp;
            if (typeof qt.token_base64 !== "string" || !isBase64(qt.token_base64)) {
              problems.push(
                `anchors[${i}].qualified_timestamp.token_base64: expected a base64 string`,
              );
            }
            checkDisplayString(problems, `anchors[${i}].qualified_timestamp.tsa_name`, qt.tsa_name);
            checkString(problems, `anchors[${i}].qualified_timestamp.policy_oid`, qt.policy_oid);
            checkString(problems, `anchors[${i}].qualified_timestamp.gen_time`, qt.gen_time);
          }
        }
      });
    }
  }

  // On-demand chain seals (D104, SPEC 1.5.0 §8 rule 12): OPTIONAL top-level
  // array — the gate stays additive (its absence is the pre-1.5 form).
  // Discipline mirrors the anchors': one seal per sealed head (a duplicate
  // sequence is the decoy-riding pattern W3 refuses on anchor dates), and
  // the declared ordering by sequence is a form fact, not a preference —
  // a reordered array reads as a different document.
  if (exp.chain_seals != null) {
    if (!Array.isArray(exp.chain_seals)) {
      problems.push("chain_seals: expected an array");
    } else {
      const seenSeq = new Set<number>();
      let prevSeq: number | null = null;
      // deno-lint-ignore no-explicit-any
      exp.chain_seals.forEach((s: any, i: number) => {
        if (!isObject(s)) {
          problems.push(`chain_seals[${i}]: expected an object`);
          return;
        }
        if (
          typeof s.sequence_number !== "number" || !Number.isInteger(s.sequence_number) ||
          s.sequence_number < 1
        ) {
          problems.push(`chain_seals[${i}].sequence_number: expected a positive integer`);
        } else if (seenSeq.has(s.sequence_number)) {
          problems.push(
            `chain_seals[${i}].sequence_number: duplicate sealed sequence (at most one seal per head, D104)`,
          );
        } else {
          seenSeq.add(s.sequence_number);
          if (prevSeq !== null && s.sequence_number < prevSeq) {
            problems.push(
              `chain_seals[${i}].sequence_number: seals must be ordered by sequence (§8 rule 12)`,
            );
          }
          prevSeq = s.sequence_number;
        }
        if (typeof s.token_base64 !== "string" || !isBase64(s.token_base64)) {
          problems.push(`chain_seals[${i}].token_base64: expected a base64 string`);
        }
        checkDisplayString(problems, `chain_seals[${i}].tsa_name`, s.tsa_name);
        checkString(problems, `chain_seals[${i}].policy_oid`, s.policy_oid);
        checkString(problems, `chain_seals[${i}].gen_time`, s.gen_time);
      });
    }
  }

  // Declared unavailable artifacts (D105, SPEC 1.6.0 §8 rule 14): OPTIONAL
  // top-level array — the gate stays additive (its absence is the pre-1.6
  // form). The array carries no proof and moves no verdict, so the checks
  // below are purely about FORM, rule-8 class: a closed `kind` enumeration,
  // one coordinate belonging to that kind, and no repeated (kind,
  // coordinate) pair — an artifact cannot be missing twice, and a repetition
  // is the same decoy-riding shape refused on event ids and sealed
  // sequences. The declared ORDERING is deliberately NOT checked: rule 14
  // binds exporters only there (rule-4 class), and refusing a document over
  // the order of a list that proves nothing would be a self-inflicted denial
  // of verification.
  if (exp.unavailable_artifacts != null) {
    if (!Array.isArray(exp.unavailable_artifacts)) {
      problems.push("unavailable_artifacts: expected an array");
    } else {
      const seenDeclarations = new Set<string>();
      // deno-lint-ignore no-explicit-any
      exp.unavailable_artifacts.forEach((u: any, i: number) => {
        const at = `unavailable_artifacts[${i}]`;
        if (!isObject(u)) {
          problems.push(`${at}: expected an object`);
          return;
        }
        const anchorKind = u.kind === "ots_receipt" || u.kind === "qualified_timestamp";
        if (!anchorKind && u.kind !== "chain_seal") {
          problems.push(
            `${at}.kind: expected "ots_receipt", "qualified_timestamp" or "chain_seal"`,
          );
          return;
        }
        let coordinate: string;
        if (anchorKind) {
          // A seal's coordinate on an anchor artifact (or the reverse below)
          // is a declaration nobody can act on: refuse the pairing, not just
          // the members, which are individually well-formed.
          if ("sequence_number" in u) {
            problems.push(`${at}.sequence_number: an ${u.kind} is declared by anchor_date`);
            return;
          }
          if (typeof u.anchor_date !== "string" || !DATE_YMD.test(u.anchor_date)) {
            problems.push(`${at}.anchor_date: expected a YYYY-MM-DD date`);
            return;
          }
          coordinate = u.anchor_date;
        } else {
          if ("anchor_date" in u) {
            problems.push(`${at}.anchor_date: a chain_seal is declared by sequence_number`);
            return;
          }
          if (
            !Number.isInteger(u.sequence_number) || (u.sequence_number as number) < 1 ||
            (u.sequence_number as number) > Number.MAX_SAFE_INTEGER
          ) {
            problems.push(`${at}.sequence_number: expected a positive integer`);
            return;
          }
          coordinate = String(u.sequence_number);
        }
        const key = `${u.kind}|${coordinate}`;
        if (seenDeclarations.has(key)) {
          problems.push(
            `${at}: duplicate declaration (an artifact cannot be unavailable twice, §8 rule 14)`,
          );
        } else {
          seenDeclarations.add(key);
        }
      });
    }
  }

  // SPEC §8.1 class 8 (v1.7): the non-finite refusal is NOT scoped to
  // actor/subject/payload. It used to be — the deep walk above runs on those
  // three containers only — which left every other position outside the letter
  // of the rule, `sequence_number: 1e999` among them: exactly the input the
  // rule exists for. Some of those positions happened to be caught by a
  // neighbouring type check; "happened to be" is not a gate, and a rule a
  // third party can only follow by also memorizing where it does not apply is
  // not one either.
  //
  // Runs LAST, and only when the precise walks found nothing. Order is the
  // whole design here: the per-container walks name `events[3].payload`, this
  // one can only say `export.<member 6>[0]`, and the CLI displays the FIRST
  // problem. Running this first would have quietly downgraded every existing
  // diagnostic to the opaque form — the F5 remedy's precision, undone as a
  // side effect of a coverage fix.
  if (!problems.some((p) => p.includes("non-finite"))) {
    checkFinite(problems, "export", exp);
  }

  return problems;
}
