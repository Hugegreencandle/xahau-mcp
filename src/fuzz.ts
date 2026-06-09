// Differential fuzzer for Hook accept/rollback decision boundaries.
//
// Runs a hook's REAL WebAssembly bytecode through the local Hook VM (runHook) against many
// DETERMINISTICALLY generated SandboxContexts, classifies each run as accept/rollback (skipping
// but COUNTING halted+degraded runs), then reports the discovered decision boundary per axis plus
// a few concrete accepting/rejecting sample inputs.
//
// DETERMINISM: every generated input is derived purely from the integer sample index via fixed
// mixed-radix sweeps over the requested axes. There is NO randomness and NO wall-clock/time source
// whatsoever, so results are fully reproducible across runs.
//
// HONESTY: this inherits the VM's simulated-environment caveat. The Amount axis varies the RAW
// bytes of an originating-txn field (it is NOT STAmount/XFL-encoded — that math is not implemented
// bit-exactly here), and the boundary is observed only over the generated inputs (not exhaustive,
// not a consensus-faithful xahaud replica).
import { runHook, type SandboxContext, type SandboxResult } from "./sandbox.js";
import { allTxTypes, txTypeValue } from "./defs.js";

const DEFAULT_SAMPLES = 64;
const MAX_SAMPLES = 512;
const MAX_TXTYPES = 32; // cap the all-tx-types sweep so a single axis can't dominate the budget
const AMOUNT_POINTS = 8; // fixed number of points in an Amount sweep
const SAMPLE_CAP = 3; // how many concrete accepting/rejecting examples to surface
const DEFAULT_AMOUNT_FIELD = 6; // sfAmount nth
const DEFAULT_ACCOUNT_FIELD = 1; // sfAccount nth (varied 20-byte id)
const DEFAULT_DESTINATION_FIELD = 3; // sfDestination nth

export interface FuzzKnobs {
  txTypes?: string[];
  amountMin?: number;
  amountMax?: number;
  amountField?: number;
  sweepAccount?: boolean;
  accountField?: number;
  sweepDestination?: boolean;
  destinationField?: number;
  paramSweep?: Record<string, string[]>; // otxn param name -> candidate hex values
  samples?: number;
}

export interface FuzzSample {
  index: number;
  varied: Record<string, unknown>; // only the fields that differ from base
  exit: SandboxResult["exit"];
  degraded: boolean;
  ctx: SandboxContext;
}

export interface AxisFinding {
  axis: string;
  accepted: (string | number)[];
  rejected: (string | number)[];
  flipPoint: string | null;
}

export interface FuzzResult {
  fidelity: "LOCAL_VM_FUZZ";
  samples: number;
  counts: { accept: number; rollback: number; halted: number; noExit: number; degraded: number };
  inconclusive: boolean;
  boundaries: string[];
  axisFindings: AxisFinding[];
  sampleAccepting: FuzzSample[];
  sampleRejecting: FuzzSample[];
  unsupportedCalls: string[];
  caveat: string;
}

interface Axis {
  name: string;
  // each entry produces a label (for findings) and a mutation applied to a draft ctx
  values: { label: string | number; apply: (ctx: MutableCtx) => void }[];
}

interface MutableCtx {
  txType?: string | number;
  otxnFields: Record<string, string>;
  otxnParams: Record<string, string>;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex").toUpperCase();

// 8-byte big-endian encoding of a non-negative drops integer (RAW field bytes — NOT STAmount).
function dropsToRawHex(drops: number): string {
  const n = BigInt(Math.max(0, Math.floor(drops)));
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return hex(out);
}

// Deterministic 20-byte account id derived purely from the sample index.
function accountIdFromIndex(i: number): string {
  const out = new Uint8Array(20);
  for (let b = 0; b < 20; b++) out[b] = (i * 31 + b * 7 + 1) & 0xff;
  return hex(out);
}

function buildAxes(knobs: FuzzKnobs): Axis[] {
  const axes: Axis[] = [];

  // --- txType axis ---
  const txNames = (knobs.txTypes && knobs.txTypes.length > 0)
    ? knobs.txTypes
    : allTxTypes().map((t) => t.name).slice(0, MAX_TXTYPES);
  if (txNames.length > 0) {
    axes.push({
      name: "txType",
      values: txNames.map((nm) => ({
        label: nm,
        apply: (ctx) => { ctx.txType = nm; },
      })),
    });
  }

  // --- Amount axis (raw field bytes sweep) ---
  if (knobs.amountMin !== undefined || knobs.amountMax !== undefined) {
    const lo = knobs.amountMin ?? 0;
    const hi = knobs.amountMax ?? Math.max(lo, lo + 1_000_000);
    const fld = String(knobs.amountField ?? DEFAULT_AMOUNT_FIELD);
    const points: number[] = [];
    if (hi <= lo) {
      points.push(lo);
    } else {
      for (let k = 0; k < AMOUNT_POINTS; k++) {
        points.push(Math.round(lo + ((hi - lo) * k) / (AMOUNT_POINTS - 1)));
      }
    }
    axes.push({
      name: "amount",
      values: points.map((p) => ({
        label: p,
        apply: (ctx) => { ctx.otxnFields[fld] = dropsToRawHex(p); },
      })),
    });
  }

  // --- account axis ---
  if (knobs.sweepAccount) {
    const fld = String(knobs.accountField ?? DEFAULT_ACCOUNT_FIELD);
    axes.push({
      name: "account",
      values: [0, 1, 2, 3].map((seed) => ({
        label: accountIdFromIndex(seed * 101),
        apply: (ctx) => { ctx.otxnFields[fld] = accountIdFromIndex(seed * 101); },
      })),
    });
  }

  // --- destination axis ---
  if (knobs.sweepDestination) {
    const fld = String(knobs.destinationField ?? DEFAULT_DESTINATION_FIELD);
    axes.push({
      name: "destination",
      values: [0, 1, 2, 3].map((seed) => ({
        label: accountIdFromIndex(seed * 211 + 5),
        apply: (ctx) => { ctx.otxnFields[fld] = accountIdFromIndex(seed * 211 + 5); },
      })),
    });
  }

  // --- named param axes ---
  if (knobs.paramSweep) {
    for (const [pname, candidates] of Object.entries(knobs.paramSweep)) {
      if (!candidates || candidates.length === 0) continue;
      axes.push({
        name: `param:${pname}`,
        values: candidates.map((hv) => ({
          label: hv,
          apply: (ctx) => { ctx.otxnParams[pname] = hv; },
        })),
      });
    }
  }

  return axes;
}

export function fuzzHook(wasmBytes: Uint8Array, base: SandboxContext = {}, knobs: FuzzKnobs = {}): FuzzResult {
  const samples = Math.min(Math.max(1, Math.floor(knobs.samples ?? DEFAULT_SAMPLES)), MAX_SAMPLES);
  const axes = buildAxes(knobs);

  const counts = { accept: 0, rollback: 0, halted: 0, noExit: 0, degraded: 0 };
  const unsupported = new Set<string>();
  const sampleAccepting: FuzzSample[] = [];
  const sampleRejecting: FuzzSample[] = [];

  // Per-axis tally of clean (accept|rollback only) outcomes keyed by the axis value label.
  // value label -> { accept, rollback }
  const axisTally = new Map<string, Map<string, { accept: number; rollback: number }>>();
  for (const ax of axes) axisTally.set(ax.name, new Map());

  // Mixed-radix decomposition of the sample index across axes — deterministic structured sweep.
  const radices = axes.map((a) => a.values.length);

  for (let i = 0; i < samples; i++) {
    const draft: MutableCtx = {
      txType: base.txType,
      otxnFields: { ...(base.otxnFields ?? {}) },
      otxnParams: { ...(base.otxnParams ?? {}) },
    };
    const varied: Record<string, unknown> = {};

    let rem = i;
    for (let a = 0; a < axes.length; a++) {
      const radix = radices[a] || 1;
      const pick = radix > 0 ? rem % radix : 0;
      rem = radix > 0 ? Math.floor(rem / radix) : rem;
      const choice = axes[a].values[pick];
      if (choice) {
        choice.apply(draft);
        varied[axes[a].name] = choice.label;
      }
    }

    const ctx: SandboxContext = {
      ...base,
      txType: draft.txType,
      otxnFields: draft.otxnFields,
      otxnParams: draft.otxnParams,
    };

    const r = runHook(wasmBytes, ctx);
    for (const u of r.unsupportedCalls) unsupported.add(u);
    if (r.degraded) counts.degraded++;

    const sample: FuzzSample = { index: i, varied, exit: r.exit, degraded: r.degraded, ctx };

    if (r.exit === "halted") { counts.halted++; continue; }
    if (r.exit === "no-exit-called") { counts.noExit++; continue; }
    // accept / rollback. Degraded runs still produced an exit but their fidelity is suspect; we
    // COUNT them but exclude degraded runs from the clean boundary tally to stay honest.
    if (r.exit === "accept") {
      counts.accept++;
      if (!r.degraded && sampleAccepting.length < SAMPLE_CAP) sampleAccepting.push(sample);
    } else {
      counts.rollback++;
      if (!r.degraded && sampleRejecting.length < SAMPLE_CAP) sampleRejecting.push(sample);
    }

    if (!r.degraded) {
      for (const a of axes) {
        const label = String(varied[a.name]);
        if (varied[a.name] === undefined) continue;
        const m = axisTally.get(a.name)!;
        const cell = m.get(label) ?? { accept: 0, rollback: 0 };
        if (r.exit === "accept") cell.accept++; else cell.rollback++;
        m.set(label, cell);
      }
    }
  }

  // Build per-axis findings from the clean tally.
  const axisFindings: AxisFinding[] = [];
  const boundaries: string[] = [];
  const cleanTotal = sampleAcceptingCleanCount(axisTally, axes) ;

  for (const ax of axes) {
    const m = axisTally.get(ax.name)!;
    if (m.size === 0) continue;
    const accepted: (string | number)[] = [];
    const rejected: (string | number)[] = [];
    // preserve the axis-declared order of labels for readability
    for (const v of ax.values) {
      const label = String(v.label);
      const cell = m.get(label);
      if (!cell) continue;
      if (cell.accept > 0 && cell.rollback === 0) accepted.push(v.label);
      else if (cell.rollback > 0 && cell.accept === 0) rejected.push(v.label);
      else if (cell.accept > 0 && cell.rollback > 0) {
        // mixed for this value across other axes — count as both
        accepted.push(v.label); rejected.push(v.label);
      }
    }

    let flipPoint: string | null = null;
    if (ax.name === "amount") {
      // numeric flip: highest accepted vs lowest rejected
      const accNums = accepted.filter((x) => typeof x === "number") as number[];
      const rejNums = rejected.filter((x) => typeof x === "number") as number[];
      if (accNums.length && rejNums.length) {
        const maxAcc = Math.max(...accNums);
        const minRej = Math.min(...rejNums);
        flipPoint = `Amount(raw bytes) accepted up to ${maxAcc} drops, rejected from ${minRej} drops`;
      }
    }
    if (!flipPoint && accepted.length && rejected.length) {
      flipPoint = `flips: accepts {${accepted.join(", ")}}, rejects {${rejected.join(", ")}}`;
    }

    axisFindings.push({ axis: ax.name, accepted, rejected, flipPoint });

    if (accepted.length && rejected.length) {
      boundaries.push(`${ax.name}: accepts [${accepted.join(", ")}], rejects [${rejected.join(", ")}]`);
    } else if (accepted.length && !rejected.length) {
      boundaries.push(`${ax.name}: accepts all swept values [${accepted.join(", ")}] (no rejection observed)`);
    } else if (!accepted.length && rejected.length) {
      boundaries.push(`${ax.name}: rejects all swept values [${rejected.join(", ")}] (no acceptance observed)`);
    }
  }

  const cleanRuns = counts.accept + counts.rollback - countDegradedExits(counts);
  const cleanDecisive = hasCleanDecision(axisTally, axes) || (boundaries.length > 0);
  const inconclusive = cleanRuns <= 0 || (!cleanDecisive && boundaries.length === 0 && (counts.degraded >= samples || counts.halted >= samples));

  // Overall summary boundary when one class dominates with no axis split.
  if (boundaries.length === 0 && !inconclusive) {
    if (counts.accept > 0 && counts.rollback === 0) boundaries.push("hook ACCEPTS across all generated inputs (no rejecting input found)");
    else if (counts.rollback > 0 && counts.accept === 0) boundaries.push("hook ROLLBACKS across all generated inputs (no accepting input found)");
    else if (counts.accept > 0 && counts.rollback > 0) boundaries.push(`mixed outcomes but no single-axis split isolated (accept=${counts.accept}, rollback=${counts.rollback})`);
  }

  const unsupportedCalls = [...unsupported];
  let caveat: string;
  if (inconclusive) {
    caveat = `INCONCLUSIVE: ${counts.halted >= samples ? "every run halted; " : ""}${counts.degraded >= samples ? "every run was DEGRADED; " : ""}${unsupportedCalls.length ? `hook relies on unsupported API(s) [${unsupportedCalls.join(", ")}] returning a sentinel, so no trustworthy accept/rollback decision could be observed. ` : "no clean accept/rollback decision could be observed. "}Cannot report a real decision boundary.`;
  } else {
    caveat = `Observed over ${samples} deterministically generated inputs (fully reproducible — no randomness, no clock). Amount axis varies RAW originating-field bytes (NOT STAmount/XFL-encoded). Boundary is not exhaustive; runs real bytecode in a simulated environment, not a consensus-faithful xahaud replica.${unsupportedCalls.length ? ` Note: ${counts.degraded} degraded run(s) using unsupported API(s) [${unsupportedCalls.join(", ")}] were counted but excluded from the boundary tally.` : ""}`;
  }

  // cleanTotal is intentionally informational; reference to avoid unused warning under strict tsc
  void cleanTotal;

  return {
    fidelity: "LOCAL_VM_FUZZ",
    samples,
    counts,
    inconclusive,
    boundaries,
    axisFindings,
    sampleAccepting,
    sampleRejecting,
    unsupportedCalls,
    caveat,
  };
}

// Count of clean accept|rollback exits is approximated by subtracting degraded exits from the
// accept+rollback totals; we only track degraded as a single counter, so we use it conservatively.
function countDegradedExits(counts: { degraded: number; halted: number; noExit: number }): number {
  // degraded includes halted; exit-bearing degraded = degraded - halted - noExit (clamped >= 0)
  return Math.max(0, counts.degraded - counts.halted - counts.noExit);
}

function hasCleanDecision(
  tally: Map<string, Map<string, { accept: number; rollback: number }>>,
  axes: Axis[],
): boolean {
  for (const ax of axes) {
    const m = tally.get(ax.name);
    if (m && m.size > 0) return true;
  }
  return false;
}

function sampleAcceptingCleanCount(
  tally: Map<string, Map<string, { accept: number; rollback: number }>>,
  axes: Axis[],
): number {
  let n = 0;
  for (const ax of axes) {
    const m = tally.get(ax.name);
    if (!m) continue;
    for (const cell of m.values()) n += cell.accept + cell.rollback;
  }
  return n;
}
