// VM-FIDELITY HARNESS (read-only, library — no network here).
//
// Purpose: measure how faithfully the local Hook VM (src/sandbox.ts) reproduces what REALLY happened
// on Xahau mainnet, using historical on-chain HookExecutions as ground truth. We reconstruct a
// SandboxContext from a real transaction, run the hook's real bytecode, and compare the VM's
// accept/rollback decision to what the chain recorded.
//
// HONESTY (this is a public tool):
//  - The agreement metric is computed ONLY over NON-degraded runs. A degraded run (the hook hit an
//    unsupported Hook-API call, or halted) yields agree:null and is EXCLUDED from the metric, never
//    counted as a match or a miss. Faking agreement on a run whose outcome the VM couldn't actually
//    determine would be a lie about correctness.
//  - We never sign/submit. This module touches no network; callers feed it fixtures or pre-fetched
//    transaction JSON + HookExecution entries.
import { encodeTxBlob } from "./codec.js";
import { stoFields, stoFieldRange } from "./sto.js";
import { runHook, type SandboxContext, type SandboxResult } from "./sandbox.js";
import { readWasm, hexToBytes } from "./wasm.js";
import { validateAddress } from "./util.js";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex").toUpperCase();

export interface OnChainHookExecution {
  HookResult?: number | string; // hook callback exit type (see mapping below)
  HookReturnCode?: number | string; // the i64 the hook passed to accept()/rollback()
  HookHash?: string;
  // some explorers also surface the engine result on the enclosing tx; callers may pass it through:
  engineResult?: string; // e.g. "tesSUCCESS" | "tecHOOK_REJECTED"
}

/**
 * EMPIRICAL HookResult -> accept/rollback MAPPING.
 *
 * Determined from real Xahau mainnet data (read-only `tx` lookups of transactions whose meta carry
 * HookExecutions):
 *  - The committed genesis-reward regression fixture (tests/regression.test.ts): a ClaimReward that
 *    SUCCEEDED on chain carries HookExecution.HookResult = 3, and the reward hook's only exit path is
 *    accept(). => HookResult 3 == ACCEPT.
 *  - A transaction whose engine result is tecHOOK_REJECTED (code 153) is one where a hook called
 *    rollback(); its HookExecution carries HookResult = 4. => HookResult 4 == ROLLBACK.
 *
 * These are the xahaud `hook_api::ExitType` values surfaced into metadata:
 *    ROLLBACK = 0  (hook errored / wasm trap / guard violation — treated as rollback by consensus)
 *    ACCEPT   = 3  (hook called accept())
 *    REJECT   = 4  (hook called rollback())
 * We map exit-type 3 -> accept and exit-types 0/4 -> rollback. Anything else (unexpected) -> unknown
 * so we never silently mis-score. Callers may instead/also pass engineResult; tesSUCCESS with a hook
 * present corroborates accept, tecHOOK_REJECTED corroborates rollback.
 */
export function onChainResult(he: OnChainHookExecution): { decision: "accept" | "rollback" | null; via: string } {
  const r = he.HookResult;
  if (r !== undefined && r !== null) {
    const n = typeof r === "string" ? Number(r) : r;
    if (n === 3) return { decision: "accept", via: "HookResult=3 (ACCEPT)" };
    if (n === 4) return { decision: "rollback", via: "HookResult=4 (ROLLBACK/reject)" };
    if (n === 0) return { decision: "rollback", via: "HookResult=0 (ROLLBACK/error)" };
  }
  // fall back to the engine result if the explorer gave us one
  const eng = he.engineResult;
  if (eng === "tesSUCCESS") return { decision: "accept", via: "engineResult=tesSUCCESS" };
  if (eng === "tecHOOK_REJECTED") return { decision: "rollback", via: "engineResult=tecHOOK_REJECTED" };
  return { decision: null, via: "indeterminate (no recognized HookResult/engineResult)" };
}

/**
 * Build a SandboxContext from a REAL transaction JSON.
 *
 * - txType    <- tx.TransactionType
 * - hookAccountId is supplied (20-byte hex of the account the hook is installed on)
 * - ledgerSeq <- tx.ledger_index if present
 * - otxnFields: encode the tx to its serialized blob, then for every top-level field present,
 *   key the field by its sfield CODE string ((typeCode<<16)|fieldCode) and value = the field's
 *   VALUE bytes (header + any VL prefix stripped) as hex. This matches exactly what the VM's
 *   `otxn_field(wp,wl,fid)` reads: it looks up `ctx.otxnFields[String(fid)]` where `fid` is the
 *   sfield code the hook passes in. (Verified in src/sandbox.ts.)
 */
export function reconstructContext(tx: Record<string, unknown>, hookAccountId: string, ledgerLastTime?: number, state?: Record<string, string>): SandboxContext {
  const txType = tx.TransactionType as string | undefined;
  const ledgerIndex = tx.ledger_index;
  const ledgerSeq = typeof ledgerIndex === "number" ? ledgerIndex : typeof ledgerIndex === "string" ? Number(ledgerIndex) : undefined;

  const otxnFields: Record<string, string> = {};
  let otxnBlob: string | undefined;
  try {
    const { txBlobHex } = encodeTxBlob(tx);
    otxnBlob = txBlobHex.toUpperCase();
    const blob = hexToBytes(txBlobHex);
    const fields = stoFields(blob);
    if (fields) {
      for (const f of fields) {
        // f.code is already (typeCode<<16)|fieldCode. Get the VALUE byte-range (skips header/VL prefix).
        const r = stoFieldRange(blob, f.code);
        if (!r) continue; // a field whose value sto.ts can't size exactly — skip (don't guess)
        otxnFields[String(f.code)] = hex(blob.slice(r.start, r.start + r.len));
      }
    }
  } catch {
    // un-encodable tx (e.g. partial JSON): leave otxnFields empty; the run will simply see no fields.
  }

  return {
    txType,
    hookAccountId,
    ledgerSeq: Number.isFinite(ledgerSeq) ? ledgerSeq : undefined,
    ledgerLastTime: typeof ledgerLastTime === "number" ? ledgerLastTime : (typeof tx.date === "number" ? tx.date : undefined),
    state: state && Object.keys(state).length ? { ...state } : undefined,
    otxnFields,
    otxnBlob,
  };
}

export interface CompareResult {
  agree: boolean | null; // null => excluded from the metric (VM run was degraded)
  vmExit: SandboxResult["exit"];
  onChain: { result: "accept" | "rollback" | null; resultVia: string; returnCode: string | null; hookHash: string | null };
  reason: string;
}

/**
 * Compare one VM run to one on-chain HookExecution entry.
 * - degraded VM run => agree:null (EXCLUDED from the agreement metric — never scored).
 * - else compare the VM exit (accept/rollback) to the empirically-mapped on-chain decision.
 */
export function compareToOnChain(vmResult: SandboxResult, hookExecution: OnChainHookExecution): CompareResult {
  const oc = onChainResult(hookExecution);
  const onChain = {
    result: oc.decision,
    resultVia: oc.via,
    returnCode: hookExecution.HookReturnCode === undefined || hookExecution.HookReturnCode === null ? null : String(hookExecution.HookReturnCode),
    hookHash: hookExecution.HookHash ?? null,
  };

  if (vmResult.degraded) {
    return { agree: null, vmExit: vmResult.exit, onChain, reason: `VM run DEGRADED (${vmResult.unsupportedCalls.length ? `unsupported: ${vmResult.unsupportedCalls.join(", ")}` : vmResult.exit}); excluded from fidelity metric.` };
  }
  if (oc.decision === null) {
    return { agree: null, vmExit: vmResult.exit, onChain, reason: `on-chain decision indeterminate (${oc.via}); excluded from fidelity metric.` };
  }
  if (vmResult.exit !== "accept" && vmResult.exit !== "rollback") {
    // non-degraded but the VM neither accepted nor rolled back (e.g. no-exit-called): cannot agree on a direction
    return { agree: null, vmExit: vmResult.exit, onChain, reason: `VM did not reach an accept/rollback (exit=${vmResult.exit}); excluded from fidelity metric.` };
  }
  const agree = vmResult.exit === oc.decision;
  return { agree, vmExit: vmResult.exit, onChain, reason: agree ? `VM ${vmResult.exit} matches on-chain ${oc.decision} (${oc.via}).` : `VM ${vmResult.exit} DISAGREES with on-chain ${oc.decision} (${oc.via}).` };
}

export interface FidelityCase {
  tx: Record<string, unknown>; // the real originating transaction JSON
  hookHash?: string; // the installed hook's hash (matched against HookExecution.HookHash)
  createCodeHex: string; // the hook's CreateCode (WASM) hex — the bytecode we execute
  hookExecution: OnChainHookExecution; // the single on-chain HookExecution we compare against
  hookAccountId: string; // 20-byte hex account the hook is installed on
  ledgerLastTime?: number; // parent-ledger close time (Ripple time) so ledger_last_time() is real, not degraded
  state?: Record<string, string>; // pre-execution on-chain hook state (32-byte key hex -> value hex)
}

export interface FidelityCaseResult {
  agree: boolean | null;
  degraded: boolean;
  vmExit: SandboxResult["exit"];
  onChainResult: "accept" | "rollback" | null;
  unsupportedCalls: string[];
  returnCode: string | null;
  reason: string;
}

/**
 * Run one fidelity case end-to-end: reconstruct the context from the real tx, execute the hook's
 * real bytecode, and compare to the on-chain HookExecution. No network access.
 */
export function runFidelityCase(caseObj: FidelityCase): FidelityCaseResult {
  const ctx = reconstructContext(caseObj.tx, caseObj.hookAccountId, caseObj.ledgerLastTime, caseObj.state);
  if (caseObj.hookHash) ctx.hookHash = caseObj.hookHash;

  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(caseObj.createCodeHex);
  } catch (e) {
    return { agree: null, degraded: true, vmExit: "halted", onChainResult: onChainResult(caseObj.hookExecution).decision, unsupportedCalls: [], returnCode: null, reason: `invalid createCodeHex: ${(e as Error).message}` };
  }
  const info = readWasm(bytes);
  if (!info.valid) {
    return { agree: null, degraded: true, vmExit: "halted", onChainResult: onChainResult(caseObj.hookExecution).decision, unsupportedCalls: [], returnCode: null, reason: `createCode is not valid WASM: ${info.reason ?? "unknown"}` };
  }

  const vm = runHook(bytes, ctx);
  const cmp = compareToOnChain(vm, caseObj.hookExecution);
  return {
    agree: cmp.agree,
    degraded: vm.degraded,
    vmExit: vm.exit,
    onChainResult: cmp.onChain.result,
    unsupportedCalls: vm.unsupportedCalls,
    returnCode: vm.returnCode,
    reason: cmp.reason,
  };
}

/* ===================== CORPUS-LEVEL FIDELITY REPORT ===================== */

/**
 * On-disk corpus shape produced by the corpus-builder (data/hook-corpus.json).
 * Each case is a REAL validated mainnet tx whose metadata carried HookExecutions.
 * `hookCode` is keyed by HookHash (deduped) => the CreateCode (WASM) hex we execute.
 * The provenance fields (_captured/_truncatedByRateLimit/...) are surfaced verbatim so the
 * report can be honest about how the corpus was gathered (rate-limit truncation, etc.).
 */
export interface CorpusCase {
  txHash: string;
  ledgerIndex?: number;
  ledgerCloseTime?: number; // Ripple time of the ledger close (feeds ledger_last_time)
  hookState?: Record<string, string>; // pre-execution on-chain hook state (key hex -> value hex)
  tx: Record<string, unknown>;
  hookAccount: string; // r-address the hook(s) are installed on
  hookExecutions: OnChainHookExecution[]; // one per hook that ran in this tx
  engineResult?: string; // enclosing-tx engine result, used as a corroborating fallback
}

export interface HookCorpus {
  _captured?: string;
  _source?: string;
  _note?: string;
  _truncatedByRateLimit?: boolean;
  _rateLimitedCalls?: number;
  _ledgersWalked?: number;
  cases: CorpusCase[];
  hookCode: Record<string, string>; // HookHash -> CreateCode (WASM) hex
}

export interface FidelityMismatch {
  txHash: string;
  hookHash: string | null;
  vmExit: SandboxResult["exit"];
  onChainResult: "accept" | "rollback" | null;
  reason: string;
}

export interface PerHookBreakdown {
  hookHash: string;
  total: number; // total executions of this hook in the corpus
  comparable: number; // non-degraded, scoreable runs
  agreements: number;
  agreementPct: number | null; // null when comparable === 0
  degraded: number;
}

export interface FidelityReport {
  total: number; // total HookExecution comparisons attempted (one per HE per case)
  comparable: number; // non-degraded, scoreable runs (the denominator of the metric)
  agreements: number;
  agreementPct: number | null; // agreements / comparable; null when comparable === 0
  degradedCount: number; // runs EXCLUDED because the VM run was degraded/halted/no-exit or on-chain indeterminate
  mismatches: FidelityMismatch[];
  perHook: PerHookBreakdown[];
  corpus: {
    cases: number;
    hookCodeCount: number;
    captured?: string;
    source?: string;
    truncatedByRateLimit?: boolean;
    rateLimitedCalls?: number;
    ledgersWalked?: number;
  };
  insufficient: boolean; // true when the corpus is empty/too tiny to measure anything
  headline: string;
}

const MIN_COMPARABLE = 1; // below this we say "insufficient corpus" rather than print a misleading %

function accountIdHexFromR(rAddr: string): string {
  // Reuse the project's address codec; fall back to a zero account if the r-address is unparseable
  // (a malformed account would just mean the hook sees no matching otxn account — never a crash).
  const v = validateAddress(rAddr);
  if (v.valid && "accountId" in v && typeof v.accountId === "string") return v.accountId;
  return "00".repeat(20);
}

/**
 * Aggregate fidelity across the whole corpus.
 *
 * HONEST CONTRACT:
 *  - One comparison per HookExecution per case (a tx can fire several hooks).
 *  - `agreementPct = agreements / comparable`, where COMPARABLE = non-degraded runs that reached an
 *    accept/rollback AND whose on-chain decision was determinable. Degraded/indeterminate/no-exit runs
 *    are counted in `degradedCount` and EXCLUDED from the metric — never scored as match or miss.
 *  - If `comparable < MIN_COMPARABLE` the report is flagged `insufficient` and the headline says so
 *    instead of printing a percentage the data can't support.
 */
export function fidelityReport(corpus: HookCorpus): FidelityReport {
  const cases = Array.isArray(corpus?.cases) ? corpus.cases : [];
  const hookCode = corpus?.hookCode ?? {};

  let total = 0;
  let comparable = 0;
  let agreements = 0;
  let degradedCount = 0;
  const mismatches: FidelityMismatch[] = [];
  const perHookMap = new Map<string, { total: number; comparable: number; agreements: number; degraded: number }>();

  const bump = (hash: string) => {
    let e = perHookMap.get(hash);
    if (!e) { e = { total: 0, comparable: 0, agreements: 0, degraded: 0 }; perHookMap.set(hash, e); }
    return e;
  };

  for (const cs of cases) {
    const hookAccountId = accountIdHexFromR(cs.hookAccount);
    const hes = Array.isArray(cs.hookExecutions) ? cs.hookExecutions : [];
    for (const he of hes) {
      total++;
      const hash = he.HookHash ?? null;
      const bucket = bump(hash ?? "(no-hook-hash)");
      bucket.total++;

      const code = hash ? hookCode[hash] : undefined;
      if (!code) {
        // No bytecode for this hook => we can't execute it => excluded (degraded-equivalent).
        // not a mismatch — an exclusion (we cannot run a hook whose bytecode we don't have)
        degradedCount++;
        bucket.degraded++;
        continue;
      }

      // Pass the enclosing-tx engineResult through so onChainResult has a corroborating fallback.
      const heWithEngine: OnChainHookExecution = he.engineResult === undefined && cs.engineResult ? { ...he, engineResult: cs.engineResult } : he;

      const res = runFidelityCase({
        tx: cs.tx,
        hookHash: hash ?? undefined,
        createCodeHex: code,
        hookExecution: heWithEngine,
        hookAccountId,
        ledgerLastTime: cs.ledgerCloseTime,
        state: cs.hookState,
      });

      if (res.agree === null) {
        degradedCount++;
        bucket.degraded++;
        continue;
      }
      comparable++;
      bucket.comparable++;
      if (res.agree) {
        agreements++;
        bucket.agreements++;
      } else {
        mismatches.push({ txHash: cs.txHash, hookHash: hash, vmExit: res.vmExit, onChainResult: res.onChainResult, reason: res.reason });
      }
    }
  }

  const perHook: PerHookBreakdown[] = [...perHookMap.entries()].map(([hookHash, e]) => ({
    hookHash,
    total: e.total,
    comparable: e.comparable,
    agreements: e.agreements,
    agreementPct: e.comparable > 0 ? round1(100 * e.agreements / e.comparable) : null,
    degraded: e.degraded,
  })).sort((a, b) => b.total - a.total);

  const agreementPct = comparable > 0 ? round1(100 * agreements / comparable) : null;
  const insufficient = comparable < MIN_COMPARABLE;

  const headline = insufficient
    ? `insufficient corpus: ${comparable} comparable real hook executions (of ${total} total; ${degradedCount} degraded/excluded) — not enough to measure VM fidelity.`
    : `VM agrees with on-chain on ${agreements}/${comparable} comparable real hook executions (${agreementPct}% ; ${degradedCount} degraded/excluded).`;

  return {
    total,
    comparable,
    agreements,
    agreementPct,
    degradedCount,
    mismatches,
    perHook,
    corpus: {
      cases: cases.length,
      hookCodeCount: Object.keys(hookCode).length,
      captured: corpus?._captured,
      source: corpus?._source,
      truncatedByRateLimit: corpus?._truncatedByRateLimit,
      rateLimitedCalls: corpus?._rateLimitedCalls,
      ledgersWalked: corpus?._ledgersWalked,
    },
    insufficient,
    headline,
  };
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}
