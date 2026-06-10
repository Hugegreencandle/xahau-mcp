// HOOK EXECUTION POST-MORTEM (read-only).
//
// Purpose: take a REAL Xahau transaction hash, fetch it (with its meta.HookExecutions + engine
// result), and for every hook that fired, run that hook's REAL bytecode through the local VM and
// compare the VM's accept/rollback DIRECTION to what the chain actually recorded. Answers
// "why did this transaction's hooks accept / roll back, and would the local VM have agreed?".
//
// HONESTY (this is a public tool):
//  - The on-chain decision is the AUTHORITY. The VM run is a best-effort local reproduction and is
//    ALWAYS labeled `fidelity: "LOCAL_VM"`. We never claim the VM result overrides the chain.
//  - `agree` is null (not false) whenever the VM run is degraded/halted/no-exit OR the on-chain
//    decision is indeterminate — exactly the fidelity.ts contract. A run we couldn't truly decide is
//    excluded from the agreement tally, never scored as a match or a miss.
//  - No network access lives in this module's core function: callers inject a `fetchTx` (and an
//    optional `fetchHookDefinition`) so unit tests can drive it from committed real data offline.
//    index.ts wires those to the SERIAL, rate-limited read-only RPC client.
import { reconstructContext, compareToOnChain, onChainResult, type OnChainHookExecution } from "./fidelity.js";
import { runHook, type SandboxResult } from "./sandbox.js";
import { readWasm, hexToBytes } from "./wasm.js";
import { validateAddress, rippleTime } from "./util.js";

export type Network = "mainnet" | "testnet";

/** One normalized on-chain HookExecution (flattened from the live wrapped shape or the corpus shape). */
interface NormalizedHE extends OnChainHookExecution {
  HookAccount?: string; // r-address the hook is installed on (live meta surfaces this)
  HookReturnString?: string; // hex the hook passed to accept()/rollback() as its return string
  position: number; // position in the meta.HookExecutions array
}

/** Per-hook post-mortem entry returned to the caller. */
export interface HookPostmortem {
  position: number;
  hookHash: string | null;
  onChainDecision: "accept" | "rollback" | null;
  onChainDecisionVia: string;
  hookReturnCode: string | null;
  hookReturnString: string | null;
  vmResult: {
    exit: SandboxResult["exit"] | null;
    returnCode: string | null;
    returnString: string | null;
    stateWrites: { key: string; value: string }[];
    emitted: string[];
    trace: string[];
    degraded: boolean;
    unsupportedCalls: string[];
    fidelity: "LOCAL_VM";
  };
  agree: boolean | null;
  reason: string;
}

export interface PostmortemResult {
  txHash: string;
  engineResult: string | null;
  transactionType: string | null;
  ledger: number | null;
  date: { ripple: number | null; iso: string | null };
  hookPostmortems: HookPostmortem[];
  summary: string;
}

export interface PostmortemDeps {
  /** Fetch the validated transaction JSON (must include meta/metaData with HookExecutions + TransactionResult). */
  fetchTx: (txHash: string, network: Network) => Promise<Record<string, unknown>>;
  /** Fetch a HookDefinition's CreateCode (WASM) hex by hash; null when not found. Called at most once per unique hash. */
  fetchHookDefinition: (hookHash: string, network: Network) => Promise<string | null>;
  /** Optional: wait between serial RPC calls (rate-limit spacing). No-op in tests. */
  sleep?: (ms: number) => Promise<void>;
}

const SPACING_MS = 1100;

/** Decode a hex string to UTF-8 if it is valid printable-ish UTF-8, else return the raw uppercase hex. */
export function decodeHexString(hex: string | null | undefined): string | null {
  if (!hex || typeof hex !== "string") return null;
  const s = hex.replace(/^0x/i, "");
  if (s.length === 0) return null;
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return s; // not even hex — surface verbatim
  const buf = Buffer.from(s, "hex");
  const utf8 = buf.toString("utf-8");
  // Round-trip check: if re-encoding yields the same bytes AND the string has no replacement chars
  // or control chars (besides tab/newline), treat it as text. Otherwise keep the raw hex (honest).
  const roundTrips = Buffer.from(utf8, "utf-8").equals(buf);
  const printable = !/[�]/.test(utf8) && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(utf8);
  return roundTrips && printable ? utf8 : s.toUpperCase();
}

/** Normalize meta.HookExecutions (live wrapped or already-flat corpus form) to a flat array. */
export function normalizeHookExecutions(raw: unknown): NormalizedHE[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((w, i) => {
    // Live form: { HookExecution: { HookAccount, HookHash, HookResult, HookReturnCode, HookReturnString } }
    const inner = (w as { HookExecution?: Record<string, unknown> })?.HookExecution ?? (w as Record<string, unknown>);
    return {
      position: i,
      HookAccount: typeof inner.HookAccount === "string" ? inner.HookAccount : undefined,
      HookHash: typeof inner.HookHash === "string" ? inner.HookHash : undefined,
      HookResult: inner.HookResult as number | string | undefined,
      HookReturnCode: inner.HookReturnCode as number | string | undefined,
      HookReturnString: typeof inner.HookReturnString === "string" ? inner.HookReturnString : undefined,
    };
  });
}

function accountIdHexFromR(rAddr: string | undefined): string {
  if (!rAddr) return "00".repeat(20);
  const v = validateAddress(rAddr);
  if (v.valid && "accountId" in v && typeof (v as { accountId?: unknown }).accountId === "string") {
    return (v as { accountId: string }).accountId;
  }
  return "00".repeat(20);
}

/**
 * Run a full post-mortem for one transaction.
 *
 * Serial-RPC budget (when wired to the real client in index.ts): exactly 1 `tx` call + 1
 * `ledger_entry` call per UNIQUE HookHash (deduplicated), each spaced >= 1100ms.
 */
export async function hookExecutionPostmortem(
  txHash: string,
  network: Network,
  deps: PostmortemDeps,
): Promise<PostmortemResult> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  // (1) fetch the tx (+ meta).
  const txDoc = await deps.fetchTx(txHash, network);
  const meta = (txDoc.meta ?? txDoc.metaData) as Record<string, unknown> | undefined;
  const engineResult = (meta?.TransactionResult as string | undefined) ?? null;
  const transactionType = (txDoc.TransactionType as string | undefined) ?? null;
  const ledgerRaw = txDoc.ledger_index ?? txDoc.inLedger ?? txDoc.ledgerIndex;
  const ledger = typeof ledgerRaw === "number" ? ledgerRaw : typeof ledgerRaw === "string" && ledgerRaw.trim() !== "" ? Number(ledgerRaw) : null;

  // (2) ledger close time -> Ripple time + ISO (feeds ledger_last_time so the VM isn't degraded on it).
  const rippleDate = typeof txDoc.date === "number" ? txDoc.date : null;
  let dateIso: string | null = null;
  if (rippleDate !== null) {
    try { dateIso = rippleTime({ ripple: rippleDate }).iso; } catch { dateIso = null; }
  }

  const hookExecs = normalizeHookExecutions(meta?.HookExecutions);

  // (4) dedup HookHash -> fetch CreateCode once each (serial, spaced).
  const uniqueHashes = [...new Set(hookExecs.map((h) => h.HookHash).filter((h): h is string => !!h))];
  const codeByHash = new Map<string, string | null>();
  for (const h of uniqueHashes) {
    await sleep(SPACING_MS); // space EVERY definition read — including the first, from the upstream tx fetch
    let code: string | null = null;
    try { code = await deps.fetchHookDefinition(h, network); } catch { code = null; }
    codeByHash.set(h, code && code.length ? code : null);
  }

  // (5/6) build a post-mortem per HookExecution entry.
  const postmortems: HookPostmortem[] = hookExecs.map((he) => {
    const heWithEngine: OnChainHookExecution = he.engineResult === undefined && engineResult ? { ...he, engineResult } : he;
    const oc = onChainResult(heWithEngine);
    const hookHash = he.HookHash ?? null;
    const hookReturnCode = he.HookReturnCode === undefined || he.HookReturnCode === null ? null : String(he.HookReturnCode);
    const hookReturnString = decodeHexString(he.HookReturnString);

    const code = hookHash ? codeByHash.get(hookHash) ?? null : null;

    // Honest degradation: no bytecode for this hook -> we cannot run it; agree:null, degraded:true.
    if (!code) {
      return {
        position: he.position,
        hookHash,
        onChainDecision: oc.decision,
        onChainDecisionVia: oc.via,
        hookReturnCode,
        hookReturnString,
        vmResult: {
          exit: null, returnCode: null, returnString: null, stateWrites: [], emitted: [], trace: [],
          degraded: true, unsupportedCalls: [], fidelity: "LOCAL_VM",
        },
        agree: null,
        reason: hookHash
          ? `no CreateCode available for hook ${hookHash} (HookDefinition not found / dereferenced); VM run skipped, excluded from agreement.`
          : `HookExecution has no HookHash; cannot identify bytecode; VM run skipped, excluded from agreement.`,
      };
    }

    // validate WASM before executing, so a bad CreateCode degrades honestly rather than throwing.
    let bytes: Uint8Array;
    try { bytes = hexToBytes(code); } catch (e) {
      return degradedEntry(he, hookHash, oc, hookReturnCode, hookReturnString, `invalid CreateCode hex: ${(e as Error).message}`);
    }
    const info = readWasm(bytes);
    if (!info.valid) {
      return degradedEntry(he, hookHash, oc, hookReturnCode, hookReturnString, `CreateCode is not valid WASM: ${info.reason ?? "unknown"}`);
    }

    // hook account: prefer the per-execution HookAccount; else the tx Account (hook on the sender).
    const hookAccountR = he.HookAccount ?? (txDoc.Account as string | undefined);
    const hookAccountId = accountIdHexFromR(hookAccountR);
    const ctx = reconstructContext(txDoc, hookAccountId, rippleDate ?? undefined);
    if (hookHash) ctx.hookHash = hookHash;

    const vm = runHook(bytes, ctx);
    const cmp = compareToOnChain(vm, heWithEngine);

    return {
      position: he.position,
      hookHash,
      onChainDecision: oc.decision,
      onChainDecisionVia: oc.via,
      hookReturnCode,
      hookReturnString,
      vmResult: {
        exit: vm.exit,
        returnCode: vm.returnCode,
        returnString: vm.returnString,
        stateWrites: vm.stateWrites,
        emitted: vm.emitted,
        trace: vm.trace,
        degraded: vm.degraded,
        unsupportedCalls: vm.unsupportedCalls,
        fidelity: "LOCAL_VM",
      },
      agree: cmp.agree,
      reason: cmp.reason,
    };
  });

  // (7) summary string.
  const fired = postmortems.length;
  const accepted = postmortems.filter((p) => p.onChainDecision === "accept").length;
  const rolledBack = postmortems.filter((p) => p.onChainDecision === "rollback").length;
  const comparable = postmortems.filter((p) => p.agree !== null);
  const agreed = comparable.filter((p) => p.agree === true).length;
  const summary = fired === 0
    ? `No HookExecutions recorded for ${txHash} (engine result ${engineResult ?? "unknown"}). No hooks fired.`
    : `${fired} hook(s) fired. On-chain: ${accepted} accepted / ${rolledBack} rolled back. ` +
      `VM agreed with ${agreed} of ${comparable.length} comparable run(s)` +
      `${comparable.length < fired ? ` (${fired - comparable.length} excluded as degraded/indeterminate)` : ""}. ` +
      `Engine result: ${engineResult ?? "unknown"}.`;

  return {
    txHash,
    engineResult,
    transactionType,
    ledger,
    date: { ripple: rippleDate, iso: dateIso },
    hookPostmortems: postmortems,
    summary,
  };
}

function degradedEntry(
  he: NormalizedHE,
  hookHash: string | null,
  oc: { decision: "accept" | "rollback" | null; via: string },
  hookReturnCode: string | null,
  hookReturnString: string | null,
  reason: string,
): HookPostmortem {
  return {
    position: he.position,
    hookHash,
    onChainDecision: oc.decision,
    onChainDecisionVia: oc.via,
    hookReturnCode,
    hookReturnString,
    vmResult: {
      exit: null, returnCode: null, returnString: null, stateWrites: [], emitted: [], trace: [],
      degraded: true, unsupportedCalls: [], fidelity: "LOCAL_VM",
    },
    agree: null,
    reason,
  };
}
