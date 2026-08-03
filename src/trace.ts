// humarch-verify/src/trace.ts — the --trace declared-ancestry walk (D101).
// ADDITIVE module: the normative verification routine (verify.ts, D63) is
// untouched and never imports this file. The walk is informative by design —
// it assembles the chain of ancestors the source DECLARED (SPEC 1.2.2
// `delegation`, SPEC 1.2.6 `execution`) and nothing else: no result of it
// may ever move the verdict, the exit code or the VerdictProperties (the
// --find-artifact/--tsa-trust neutrality pattern).
//
// Semantics, fixed by D101 and pinned by tests:
//   * DECLARED ancestry, never proven causation. Every hop is a reference
//     the child event declared at reception time; the registry records the
//     declaration (hashed, signed, chained) — it never establishes that the
//     referenced parent did anything. The rendering opens with that sentence
//     and the forbidden formulations are pinned out by test.
//   * HOP GRANULARITY is the load-bearing distinction: a hop is EXACT when
//     the child declares `delegation.parent.event_id` (one precise event),
//     and RUN-LEVEL when it declares only `delegation.parent.ref` — which
//     resolves to the SET of export events declaring that `execution.ref`.
//     A run hop with N members never pretends to be one event.
//   * The walk is PURE, ITERATIVE and BOUNDED: depth cap, member caps,
//     descriptor-only reads (hostile getters are never invoked, a throwing
//     reflective step never escapes). A cycle declared by the source is
//     data, not a crash: the walk reports the closing point and stops.
//   * Ref values (`parent.ref` / `parent.event_id` / `execution.ref` /
//     `root.ref`) are PAYLOAD TEXT: they cross into the result only through
//     terminalSafe (escape + length cap) — in the JSON output too. All
//     comparisons happen on the full raw strings; the cap is display-only.
//     No other payload text ever enters the result (V2 stays closed).
//   * Resolution shows what THIS export contains. An unresolved parent or
//     run is declared and is not tampering (SPEC 1.2.2): the ancestor may
//     simply lie outside the exported range.
import { verifiedPositionalPrefix } from "./find.ts";
import { terminalSafe } from "./render.ts";

/** Depth cap of one walk, in hops — declared in the output when reached. */
export const TRACE_DEPTH_CAP = 64;
/** Run members carried in the result (JSON); the human rendering shows 5. */
export const TRACE_MEMBER_CAP = 20;
/** Distinct diverging parents shown when a run's declarations disagree. */
export const TRACE_DISTINCT_CAP = 3;
/** Display cap of a sanitized payload ref (comparisons use full values). */
const REF_CAP = 64;

/**
 * The semantics header (D101), identical in the human and JSON renderings
 * and pinned verbatim by test. The one sentence the whole feature hangs on.
 */
export const ANCESTRY_SEMANTICS =
  "Declared ancestry: the chain shows what the source declared at reception time, not proven causation; times are reception times.";
/** The closing note, shared by both renderings. */
export const ANCESTRY_NOTE =
  'ancestry hops are declared references (SPEC 1.2.2/1.2.6): recorded at reception, never resolved at ingestion; encrypted payload.personal content is invisible to these arcs — an absent arc does not mean "no ancestor"';

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function isTraceTarget(value: string): boolean {
  return UUID_RE.test(value);
}

/** Shape-checked event fields plus the positional range mark — never payload. */
export interface TraceEventRef {
  event_id: string;
  event_type: string;
  sequence_number: number | null;
  received_at: string;
  /** true iff the event belongs to the prefix verifyChain actually verified */
  within_verified_range: boolean;
}

/** What the child declared about its parent (sanitized display copies). */
export interface DeclaredParent {
  ref: string | null;
  event_id: string | null;
}

export interface TraceEventNode {
  kind: "event";
  /** how the walk reached this node */
  hop: "start" | "exact";
  event: TraceEventRef;
  /** the event's own declared run (`payload.execution.ref`), sanitized */
  execution_ref: string | null;
  /** start node only: declared facts, printed and never checked */
  declared_root_ref: string | null;
  declared_depth: number | null;
  declared_parent: DeclaredParent | null;
  /** already printed earlier in this invocation (dedup / cycle marker) */
  repeated: boolean;
}

export interface TraceRunNode {
  kind: "run";
  /**
   * "run" when reached through the child's `delegation.parent.ref`;
   * "membership" when reached through the traced event's OWN
   * `execution.ref` (an event that declares no delegation of its own but
   * does declare the run it belongs to — the chain then continues from the
   * merged declarations of that run's members, which is exactly the
   * run-continuation rule applied to the event's own run). The two are
   * rendered with different words: a membership hop attributes the next
   * declaration to the run's events, never to the traced event itself.
   */
  hop: "run" | "membership";
  /** the declared run id, sanitized */
  ref: string;
  events_total: number;
  events_inside_verified_range: number;
  /** members in sequence order, capped at TRACE_MEMBER_CAP */
  members: TraceEventRef[];
  declared_parent: DeclaredParent | null;
  /** distinct (non-contradictory-merged) parent declarations found */
  distinct_parent_count: number;
  /** shown when the declarations disagree, up to TRACE_DISTINCT_CAP */
  distinct_parent_refs: string[];
  repeated: boolean;
}

/** A declared parent that no event (or run) of this export resolves. */
export interface TraceMissingNode {
  kind: "missing";
  hop: "exact" | "run";
  declared_event_id: string | null;
  declared_ref: string | null;
}

export type TraceNode = TraceEventNode | TraceRunNode | TraceMissingNode;

export type TraceEnd =
  | "root_of_declared_chain"
  | "parent_not_in_export"
  | "cycle_declared"
  | "depth_cap_reached"
  | "ambiguous_parents"
  | "continues_above"
  | "malformed_declaration"
  | "target_not_found";

export interface TraceResult {
  /** the requested event_id, lowercased */
  target: string;
  found_in_export: boolean;
  /** contested event first, root-most link last */
  chain: TraceNode[];
  end: TraceEnd;
}

/**
 * Own enumerable DATA property of a container, defensively (the find.ts
 * discipline): accessors are never invoked and a reflective step that throws
 * yields `undefined`, never an exception escaping to a stack trace.
 */
function dataProp(container: unknown, key: string): unknown {
  if (typeof container !== "object" || container === null) return undefined;
  try {
    const d = Object.getOwnPropertyDescriptor(container, key);
    return d !== undefined && d.enumerable === true && "value" in d ? d.value : undefined;
  } catch {
    return undefined;
  }
}

/** A usable declared identifier: a non-empty string. Anything else is "not declared". */
function usableString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

interface RawParent {
  ref: string | null;
  event_id: string | null;
}

type Delegation =
  | { state: "none" }
  | { state: "malformed" }
  | { state: "ok"; parent: RawParent };

/** The event's own `payload.delegation.parent`, raw and defensive. */
function rawDelegation(ev: unknown): Delegation {
  const del = dataProp(dataProp(ev, "payload"), "delegation");
  if (del === undefined || del === null) return { state: "none" };
  const parent = dataProp(del, "parent");
  if (typeof parent !== "object" || parent === null) return { state: "malformed" };
  const ref = usableString(dataProp(parent, "ref"));
  const event_id = usableString(dataProp(parent, "event_id"));
  if (ref === null && event_id === null) return { state: "malformed" };
  return { state: "ok", parent: { ref, event_id } };
}

function execRefOf(ev: unknown): string | null {
  return usableString(dataProp(dataProp(dataProp(ev, "payload"), "execution"), "ref"));
}

function rootRefOf(ev: unknown): string | null {
  return usableString(
    dataProp(dataProp(dataProp(dataProp(ev, "payload"), "delegation"), "root"), "ref"),
  );
}

function depthOf(ev: unknown): number | null {
  const d = dataProp(dataProp(dataProp(ev, "payload"), "delegation"), "depth");
  return typeof d === "number" && Number.isInteger(d) ? d : null;
}

/**
 * Merge the usable parent declarations of a run's members. Declarations that
 * do not contradict each other collapse into one parent (members of the same
 * run frequently differ only in completeness: some captured the 202 echo,
 * some declared only the run id — that is agreement, not divergence). Two
 * DIFFERENT refs, or two DIFFERENT event_ids, are a declared divergence: the
 * walk reports it and stops rather than choose. This is still purely
 * declarative — nothing is resolved or compared against resolved data.
 */
function mergeRunDeclarations(parents: RawParent[]): {
  state: "none" | "ok" | "ambiguous";
  parent?: RawParent;
  distinctCount: number;
  distinctDisplay: string[];
} {
  if (parents.length === 0) return { state: "none", distinctCount: 0, distinctDisplay: [] };
  const refs = new Set<string>();
  const ids = new Set<string>();
  const pairs = new Set<string>();
  for (const p of parents) {
    if (p.ref !== null) refs.add(p.ref);
    if (p.event_id !== null) ids.add(p.event_id.toLowerCase());
    pairs.add((p.event_id ?? "").toLowerCase() + "|" + (p.ref ?? ""));
  }
  if (refs.size <= 1 && ids.size <= 1) {
    return {
      state: "ok",
      parent: {
        ref: refs.size === 1 ? [...refs][0] : null,
        event_id: ids.size === 1 ? [...ids][0] : null,
      },
      distinctCount: pairs.size,
      distinctDisplay: [],
    };
  }
  // Diverging: show what disagrees — the refs when the run ids differ,
  // otherwise the event ids.
  const display = refs.size > 1 ? [...refs] : [...ids];
  return { state: "ambiguous", distinctCount: pairs.size, distinctDisplay: display };
}

type Cursor =
  | { type: "event"; index: number; hop: "start" | "exact" }
  | { type: "run"; ref: string; indices: number[]; hop: "run" | "membership" };

/**
 * The declared-ancestry chains of `targets` (contested event ids) inside
 * `exp`, walking `delegation`/`execution` arcs. Pure, iterative, bounded;
 * informative only — the caller's verdict and exit code never depend on it.
 *
 * `verifiedFrom`/`verifiedThrough` come from the chain verdict; every node
 * is positioned against the POSITIONAL verified prefix (the find.ts / audit
 * F1 computation, imported — never re-derived).
 */
export function traceAncestry(
  // deno-lint-ignore no-explicit-any
  exp: any,
  targets: string[],
  verifiedFrom: number | null,
  verifiedThrough: number | null,
): TraceResult[] {
  const { events, prefixLength } = verifiedPositionalPrefix(exp, verifiedFrom, verifiedThrough);

  // Lookup indexes, built once per invocation over the sorted list. Both
  // read only own data properties; both compare FULL raw strings.
  const byId = new Map<string, number>();
  const byRun = new Map<string, number[]>();
  events.forEach((ev, i) => {
    const id = usableString(dataProp(ev, "event_id"));
    if (id !== null && !byId.has(id.toLowerCase())) byId.set(id.toLowerCase(), i);
    const run = execRefOf(ev);
    if (run !== null) {
      const arr = byRun.get(run);
      if (arr) arr.push(i);
      else byRun.set(run, [i]);
    }
  });

  const eventRef = (i: number): TraceEventRef => {
    const ev = events[i];
    const seq = dataProp(ev, "sequence_number");
    return {
      event_id: String(dataProp(ev, "event_id") ?? ""),
      event_type: String(dataProp(ev, "event_type") ?? ""),
      sequence_number: typeof seq === "number" && Number.isFinite(seq) ? seq : null,
      received_at: String(dataProp(ev, "received_at") ?? ""),
      within_verified_range: i < prefixLength,
    };
  };

  // The one gate payload refs pass on their way OUT (D101 sanitization rule).
  const san = (v: string | null): string | null => v === null ? null : terminalSafe(v, REF_CAP);
  const sanParent = (p: RawParent): DeclaredParent => ({
    ref: san(p.ref),
    event_id: san(p.event_id),
  });

  // Nodes already printed by ANY chain of this invocation: a re-encounter
  // renders as "already shown above" instead of re-expanding (dedup).
  const printed = new Set<string>();
  const results: TraceResult[] = [];

  for (const rawTarget of targets) {
    const target = String(rawTarget).toLowerCase();
    const startIdx = byId.get(target);
    if (startIdx === undefined) {
      results.push({ target, found_in_export: false, chain: [], end: "target_not_found" });
      continue;
    }

    // Nodes of THIS chain: a re-encounter here is a declared cycle.
    const visited = new Set<string>();
    const chain: TraceNode[] = [];
    let end: TraceEnd | null = null;
    let cursor: Cursor = { type: "event", index: startIdx, hop: "start" };

    while (end === null) {
      const key = cursor.type === "event"
        ? "e:" + String(dataProp(events[cursor.index], "event_id") ?? "").toLowerCase()
        : "r:" + cursor.ref;
      const inThisChain = visited.has(key);
      const shownBefore = printed.has(key);

      let declared: Delegation | { state: "ambiguous" };
      let distinctCount = 0;
      let distinctDisplay: string[] = [];
      if (cursor.type === "event") {
        const ev = events[cursor.index];
        const d = rawDelegation(ev);
        declared = d;
        chain.push({
          kind: "event",
          hop: cursor.hop,
          event: eventRef(cursor.index),
          execution_ref: san(execRefOf(ev)),
          declared_root_ref: cursor.hop === "start" ? san(rootRefOf(ev)) : null,
          declared_depth: cursor.hop === "start" ? depthOf(ev) : null,
          declared_parent: d.state === "ok" ? sanParent(d.parent) : null,
          repeated: inThisChain || shownBefore,
        });
      } else {
        const usable: RawParent[] = [];
        for (const i of cursor.indices) {
          const d = rawDelegation(events[i]);
          if (d.state === "ok") usable.push(d.parent);
        }
        const merged = mergeRunDeclarations(usable);
        declared = merged.state === "ok"
          ? { state: "ok", parent: merged.parent as RawParent }
          : { state: merged.state };
        distinctCount = merged.distinctCount;
        distinctDisplay = merged.distinctDisplay;
        const members = cursor.indices.map(eventRef);
        chain.push({
          kind: "run",
          hop: cursor.hop,
          ref: san(cursor.ref) as string,
          events_total: members.length,
          events_inside_verified_range: members.filter((m) => m.within_verified_range).length,
          members: members.slice(0, TRACE_MEMBER_CAP),
          declared_parent: declared.state === "ok" ? sanParent(declared.parent) : null,
          distinct_parent_count: distinctCount,
          distinct_parent_refs: distinctDisplay.slice(0, TRACE_DISTINCT_CAP)
            .map((r) => san(r) as string),
          repeated: inThisChain || shownBefore,
        });
      }

      // A repeated node ends the chain: inside this chain it is a cycle the
      // source declared; across chains the ancestry was already printed.
      if (inThisChain) {
        end = "cycle_declared";
        break;
      }
      if (shownBefore) {
        end = "continues_above";
        break;
      }
      visited.add(key);
      printed.add(key);

      if (declared.state === "none") {
        // An event with no delegation of its own but with a declared
        // execution.ref continues through its OWN run (membership hop): the
        // contested event is typically an action, and the delegation is
        // typically declared once per run on the start event. The run node
        // wording keeps the attribution honest — the run's events declare
        // the next hop, not the traced event.
        if (cursor.type === "event") {
          const ownRun = execRefOf(events[cursor.index]);
          if (ownRun !== null) {
            if (chain.length > TRACE_DEPTH_CAP) {
              end = "depth_cap_reached";
              break;
            }
            cursor = {
              type: "run",
              ref: ownRun,
              indices: byRun.get(ownRun) ?? [cursor.index],
              hop: "membership",
            };
            continue;
          }
        }
        end = "root_of_declared_chain";
        break;
      }
      if (declared.state === "malformed") {
        end = "malformed_declaration";
        break;
      }
      if (declared.state === "ambiguous") {
        end = "ambiguous_parents";
        break;
      }
      const parent = declared.parent;

      // chain holds the start node plus (chain.length - 1) hops: following
      // one more would exceed the cap.
      if (chain.length > TRACE_DEPTH_CAP) {
        end = "depth_cap_reached";
        break;
      }

      if (parent.event_id !== null) {
        // EXACT hop: the child names the parent event. No fallback to the
        // run resolution when unresolved — the granularity stays the one
        // the child declared (D101).
        const idx = byId.get(parent.event_id.toLowerCase());
        if (idx === undefined) {
          chain.push({
            kind: "missing",
            hop: "exact",
            declared_event_id: san(parent.event_id),
            declared_ref: san(parent.ref),
          });
          end = "parent_not_in_export";
          break;
        }
        cursor = { type: "event", index: idx, hop: "exact" };
      } else {
        // RUN-LEVEL hop: the child names only the parent run.
        const indices = byRun.get(parent.ref as string);
        if (indices === undefined) {
          chain.push({
            kind: "missing",
            hop: "run",
            declared_event_id: null,
            declared_ref: san(parent.ref),
          });
          end = "parent_not_in_export";
          break;
        }
        cursor = { type: "run", ref: parent.ref as string, indices, hop: "run" };
      }
    }

    results.push({
      target,
      found_in_export: true,
      chain,
      end: end ?? "root_of_declared_chain",
    });
  }
  return results;
}
