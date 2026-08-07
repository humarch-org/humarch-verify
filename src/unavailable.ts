// humarch-verify/src/unavailable.ts — the §8 rule-14 self-declaration of
// omitted proof artifacts (D105, SPEC 1.6.0). ADDITIVE module: the normative
// verification routine (verify.ts, D63) is untouched and never imports this
// file, exactly like find.ts and trace.ts.
//
// What rule 14 is, and what this module must therefore refuse to be:
//
//   * A declaration is an assertion by WHOEVER PRODUCED the document about
//     that producer's own operational state — and that producer may be the
//     adversary. It is not evidence, and it is not an exemption. An attacker
//     who strips a genuine proof and adds the matching declaration must get
//     EXACTLY the outcome of the plain absence: same result, same exit code,
//     same VerdictProperties. Nothing here is wired into assess().
//   * The converse is equally true and equally load-bearing: the ABSENCE of
//     a declaration asserts nothing either (a pre-1.6 exporter, or one that
//     never attempted the resolution, omits silently as rule 13 allows). So
//     this module never reasons "no declaration ⇒ the artifact existed".
//   * Trap 11 (2026-07-29, "a public signature that PERMITS the unsafe call
//     is itself the defect"): the exported name says `declared`, the return
//     type carries no verdict field, and there is no code path by which a
//     caller can turn a declaration into a check. The rendering states who
//     is speaking on every line it prints.
//
// Defensive by contract: the CLI runs the shape gate first, but a library
// caller may not, so every read here is descriptor-only (hostile getters are
// never invoked), nothing throws, and both the read cap and the display cap
// are DECLARED in the output rather than silently applied (trap 8).

/** The three proof artifacts of this format (SPEC §8 rules 13-14). */
export const UNAVAILABLE_KINDS = ["ots_receipt", "qualified_timestamp", "chain_seal"] as const;
export type UnavailableKind = typeof UNAVAILABLE_KINDS[number];

/**
 * The semantics header, identical in the human and JSON renderings and pinned
 * verbatim by test — the sentence the whole feature hangs on (the
 * ANCESTRY_SEMANTICS pattern of D101).
 */
export const UNAVAILABLE_SEMANTICS =
  "Declared unavailable: the producer of this document states which proof artifacts it could not include; a declaration is not evidence and does not change this verification.";

/** The closing note, shared by both renderings. */
export const UNAVAILABLE_NOTE =
  "these are the producer's statements about its own export, not findings of this verifier: a declaration is not evidence that the artifact exists, and the same document without them reaches the same result and the same exit code";

/**
 * Declarations read from one document. A hostile export could carry an
 * unbounded array; reading is capped and the remainder is DECLARED.
 */
export const UNAVAILABLE_READ_CAP = 1000;

const DATE_YMD = /^\d{4}-\d{2}-\d{2}$/;

/** One declared omission: a kind and the single coordinate that kind takes. */
export interface DeclaredUnavailableEntry {
  kind: UnavailableKind;
  /** set for `ots_receipt` and `qualified_timestamp`, null for a seal */
  anchor_date: string | null;
  /** set for `chain_seal`, null for the two anchor artifacts */
  sequence_number: number | null;
  /**
   * The document contradicts itself: it DECLARES this artifact unavailable
   * and CARRIES it anyway (adversarial review, 2026-08-06). Rule 13/14
   * semantics make the state impossible — a declaration names what was
   * omitted — so nothing legitimate produces it, and it changes no outcome.
   * It is surfaced because leaving it silent hands a reader the one
   * "softening" rule 14 forbids: next to a `[WARN] … invalid` qualified
   * timestamp, an unqualified declaration invites re-reading a verification
   * FAILURE as a mere availability problem. Naming the contradiction closes
   * that reading without touching the verdict.
   */
  contradicted: boolean;
}

export interface DeclaredUnavailableReport {
  semantics: string;
  entries: DeclaredUnavailableEntry[];
  /**
   * Elements present but not readable as a rule-14 declaration. The CLI never
   * sees this non-zero (the shape gate exits 4 on such a document first); a
   * library caller that skipped the gate gets the count DECLARED rather than
   * a silently shorter list — the F4 discipline of `verifyChainSeals`, where
   * a present-but-unusable field became one declared row instead of `[]`.
   */
  unreadable: number;
  /** Elements beyond UNAVAILABLE_READ_CAP: declared, never dropped in silence. */
  truncated: number;
  note: string;
}

/**
 * Own enumerable DATA property of a container, defensively (the find.ts /
 * trace.ts twin): accessors are treated as absent — never invoked — and a
 * reflective step that throws yields `undefined`, never an escaping exception.
 */
function ownDataProp(container: unknown, key: string): unknown {
  if (typeof container !== "object" || container === null) return undefined;
  try {
    const d = Object.getOwnPropertyDescriptor(container, key);
    return d !== undefined && d.enumerable === true && "value" in d ? d.value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether the container DECLARES the member at all — `undefined` as a value
 * and "no such member" are the same thing to `ownDataProp`, and the shape
 * gate distinguishes them (it uses `in`). The coordinate-belongs-to-its-kind
 * rule has to read the same way in both places, or a value the CLI refuses as
 * malformed would be accepted by a library caller.
 */
function declaresMember(container: unknown, key: string): boolean {
  if (typeof container !== "object" || container === null) return false;
  try {
    return Object.getOwnPropertyDescriptor(container, key) !== undefined;
  } catch {
    return false;
  }
}

/** Own enumerable data elements of a value that claims to be an array. */
function dataElements(container: unknown): unknown[] {
  if (!Array.isArray(container)) return [];
  const out: unknown[] = [];
  let length = 0;
  try {
    length = container.length;
  } catch {
    return [];
  }
  if (!Number.isInteger(length) || length < 0) return [];
  // The same ceiling the declarations themselves get: a hostile document must
  // not turn a contradiction check into unbounded work.
  for (let i = 0; i < Math.min(length, UNAVAILABLE_READ_CAP); i++) {
    out.push(ownDataProp(container, String(i)));
  }
  return out;
}

/**
 * Does the document CARRY the anchor artifact it declares unavailable? Purely
 * a reading of the document against itself — no verification, no verdict.
 */
function carriesAnchorArtifact(exp: unknown, day: string, kind: string): boolean {
  const member = kind === "ots_receipt" ? "ots_file_base64" : "qualified_timestamp";
  return dataElements(ownDataProp(exp, "anchors")).some((a) =>
    ownDataProp(a, "anchor_date") === day && ownDataProp(a, member) !== undefined
  );
}

/** The seal twin of `carriesAnchorArtifact`. */
function carriesSeal(exp: unknown, sequence: number): boolean {
  return dataElements(ownDataProp(exp, "chain_seals")).some((s) =>
    ownDataProp(s, "sequence_number") === sequence
  );
}

/**
 * The declarations a document carries under §8 rule 14, as DECLARED FACTS.
 *
 * Returns null when the document carries no `unavailable_artifacts` member —
 * the pre-1.6 form, which must render byte-identically to before this
 * feature existed. A present-but-unusable member is NOT null: it yields a
 * report whose `unreadable` count says so.
 *
 * This function verifies nothing and can fail nothing. It reports what the
 * document says about itself.
 */
export function declaredUnavailableArtifacts(
  // deno-lint-ignore no-explicit-any
  exp: any,
): DeclaredUnavailableReport | null {
  const raw = ownDataProp(exp, "unavailable_artifacts");
  if (raw === undefined || raw === null) return null;

  const report: DeclaredUnavailableReport = {
    semantics: UNAVAILABLE_SEMANTICS,
    entries: [],
    unreadable: 0,
    truncated: 0,
    note: UNAVAILABLE_NOTE,
  };
  if (!Array.isArray(raw)) {
    report.unreadable = 1;
    return report;
  }

  let length = 0;
  try {
    length = raw.length;
  } catch {
    report.unreadable = 1;
    return report;
  }
  if (!Number.isInteger(length) || length < 0) {
    report.unreadable = 1;
    return report;
  }
  const read = Math.min(length, UNAVAILABLE_READ_CAP);
  report.truncated = length - read;

  for (let i = 0; i < read; i++) {
    const el = ownDataProp(raw, String(i));
    const kind = ownDataProp(el, "kind");
    const anchorDate = ownDataProp(el, "anchor_date");
    const sequence = ownDataProp(el, "sequence_number");

    if (
      typeof kind !== "string" ||
      !(UNAVAILABLE_KINDS as readonly string[]).includes(kind)
    ) {
      report.unreadable++;
      continue;
    }
    if (kind === "chain_seal") {
      // The coordinate must belong to the kind: a seal has no anchor date.
      if (
        declaresMember(el, "anchor_date") || typeof sequence !== "number" ||
        !Number.isInteger(sequence) || sequence < 1 || sequence > Number.MAX_SAFE_INTEGER
      ) {
        report.unreadable++;
        continue;
      }
      report.entries.push({
        kind,
        anchor_date: null,
        sequence_number: sequence,
        contradicted: carriesSeal(exp, sequence),
      });
      continue;
    }
    // Strict YYYY-MM-DD: Date.parse is lenient enough to accept a trailing
    // suffix and land on a DIFFERENT day (the W2 class), so the coordinate is
    // only ever the exact form the format declares.
    if (
      declaresMember(el, "sequence_number") || typeof anchorDate !== "string" ||
      !DATE_YMD.test(anchorDate)
    ) {
      report.unreadable++;
      continue;
    }
    report.entries.push({
      kind: kind as UnavailableKind,
      anchor_date: anchorDate,
      sequence_number: null,
      contradicted: carriesAnchorArtifact(exp, anchorDate, kind),
    });
  }
  return report;
}
