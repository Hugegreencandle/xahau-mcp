// SARIF-lite Hook static-analysis / security rule engine.
// Pure rule functions over a decoded WASM + optional SetHook params. The first
// Hooks-specific analyzer of its kind. Rule IDs: HOOK-* (WASM/static), SETHOOK-* (param-shape).
import { readWasm, hexToBytes, base64ToBytes, type WasmInfo } from "./wasm.js";
import { isKnownHookApi } from "./hookapi.js";
import { decodeHookOn } from "./hookon.js";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export interface Finding { ruleId: string; severity: Severity; message: string; location?: { detail?: string } }

export interface HookGrant { HookGrant: { Authorize?: string; HookHash?: string } }
export interface AnalyzeContext {
  wasm: WasmInfo;
  hookOn?: string;
  namespace?: string;
  parameters?: unknown[];
  grants?: HookGrant[];
  flags?: number;
  existingNamespaces?: string[]; // other hooks already on the target account (for NS collision)
}

interface Rule {
  id: string; severity: Severity; title: string; category: string;
  requires: "wasm" | "sethook";
  check: (ctx: AnalyzeContext) => Finding | Finding[] | null;
}

const OVERSIZE_BYTES = 64 * 1024;
const MEMORY_PAGE_CEIL = 2;
const PSEUDO_TX = new Set(["Amendment", "Fee", "UNLModify", "UNLReport"]);

const importNames = (w: WasmInfo) => new Set(w.imports.filter((i) => i.kind === "func").map((i) => i.name));
const exportNames = (w: WasmInfo) => new Set(w.exports.filter((e) => e.kind === "func").map((e) => e.name));

export const RULES: Rule[] = [
  {
    id: "HOOK-001-NO-EXIT", severity: "CRITICAL", title: "Hook has no exit path (accept/rollback)", category: "control", requires: "wasm",
    check: (c) => { const im = importNames(c.wasm); return !im.has("accept") && !im.has("rollback") ? { ruleId: "HOOK-001-NO-EXIT", severity: "CRITICAL", message: "Hook imports neither accept() nor rollback(); it cannot legally terminate and the SetHook will be rejected or the hook will trap." } : null; },
  },
  {
    id: "HOOK-002-NO-HOOK-EXPORT", severity: "CRITICAL", title: "Missing exported hook() entry point", category: "control", requires: "wasm",
    check: (c) => !exportNames(c.wasm).has("hook") ? { ruleId: "HOOK-002-NO-HOOK-EXPORT", severity: "CRITICAL", message: "No exported `hook` function. Every Hook must export hook() (cbak() is optional)." } : null,
  },
  {
    id: "HOOK-003-EMIT-NO-CBAK", severity: "INFO", title: "emit() without a cbak() callback (advisory)", category: "etxn", requires: "wasm",
    check: (c) => importNames(c.wasm).has("emit") && !exportNames(c.wasm).has("cbak") ? { ruleId: "HOOK-003-EMIT-NO-CBAK", severity: "INFO", message: "Hook calls emit() but exports no cbak(). cbak() is optional; this is fine unless you need to react to the emitted transaction's result." } : null,
  },
  {
    id: "HOOK-004-UNKNOWN-IMPORT", severity: "HIGH", title: "Imports an unknown/forbidden env function", category: "imports", requires: "wasm",
    check: (c) => c.wasm.imports.filter((i) => i.kind === "func" && i.module === "env" && !isKnownHookApi(i.name))
      .map((i) => ({ ruleId: "HOOK-004-UNKNOWN-IMPORT", severity: "HIGH" as const, message: `Imports env.${i.name}, which is not a known Hook API function; SetHook will likely be rejected.`, location: { detail: i.name } })),
  },
  {
    id: "HOOK-005-GUARD-MISSING", severity: "HIGH", title: "Loop without a guard (_g) call", category: "control", requires: "wasm",
    check: (c) => c.wasm.loopCount > 0 && c.wasm.guardCallCount === 0 ? { ruleId: "HOOK-005-GUARD-MISSING", severity: "HIGH", message: `Found ${c.wasm.loopCount} loop opcode(s) but no _g() guard call. Every loop must be guarded or the hook is rejected for unbounded execution.${c.wasm.scanComplete ? "" : " (opcode scan was partial — verify manually.)"}` } : null,
  },
  {
    id: "HOOK-006-HOOKON-TOO-BROAD", severity: "MEDIUM", title: "HookOn fires on an over-broad set", category: "hookon", requires: "sethook",
    check: (c) => { if (!c.hookOn) return null; const { firesOn, count } = decodeHookOn(c.hookOn); const pseudo = firesOn.filter((t) => PSEUDO_TX.has(t)); if (pseudo.length) return { ruleId: "HOOK-006-HOOKON-TOO-BROAD", severity: "MEDIUM", message: `HookOn fires on pseudo-transaction type(s) ${pseudo.join(", ")}, which user hooks should not target.` }; return count >= 40 ? { ruleId: "HOOK-006-HOOKON-TOO-BROAD", severity: "MEDIUM", message: `HookOn fires on ${count} transaction types — likely broader than intended (extra execution + fees).` } : null; },
  },
  {
    id: "HOOK-007-DANGEROUS-GRANT", severity: "HIGH", title: "HookGrant authorizes another account", category: "grants", requires: "sethook",
    check: (c) => (c.grants ?? []).filter((g) => g.HookGrant?.Authorize)
      .map((g) => ({ ruleId: "HOOK-007-DANGEROUS-GRANT", severity: "HIGH" as const, message: `HookGrant authorizes ${g.HookGrant.Authorize} to modify this hook's state — privilege-escalation surface; confirm it is intended.`, location: { detail: g.HookGrant.Authorize } })),
  },
  {
    id: "HOOK-008-STATE-UNBOUNDED", severity: "LOW", title: "Hook-state write — confirm bounds (advisory)", category: "state", requires: "wasm",
    check: (c) => { const im = importNames(c.wasm); const foreign = im.has("state_foreign_set"); if (im.has("state_set") || foreign) return { ruleId: "HOOK-008-STATE-UNBOUNDED", severity: foreign ? "MEDIUM" : "LOW", message: `Hook writes state via ${foreign ? "state_foreign_set (writes to ANOTHER account — confirm the HookGrant and bounds)" : "state_set; confirm value sizes are bounded to avoid reserve/bloat"}.` }; return null; },
  },
  {
    id: "HOOK-009-EMIT-COUNT-RESERVE", severity: "MEDIUM", title: "emit() without etxn_reserve()", category: "etxn", requires: "wasm",
    check: (c) => { const im = importNames(c.wasm); return im.has("emit") && !im.has("etxn_reserve") ? { ruleId: "HOOK-009-EMIT-COUNT-RESERVE", severity: "MEDIUM", message: "Hook calls emit() but never calls etxn_reserve(); emitted transactions must be reserved or the emit fails." } : null; },
  },
  {
    id: "HOOK-010-REENTRANCY-EMIT", severity: "MEDIUM", title: "Possible emission loop (emit + cbak + hook_again)", category: "etxn", requires: "wasm",
    check: (c) => { const im = importNames(c.wasm); const ex = exportNames(c.wasm); return im.has("emit") && ex.has("cbak") && im.has("hook_again") ? { ruleId: "HOOK-010-REENTRANCY-EMIT", severity: "MEDIUM", message: "Hook combines emit(), cbak() and hook_again(); verify this cannot form an unbounded emission/re-execution loop." } : null; },
  },
  {
    id: "HOOK-011-OVERSIZE-WASM", severity: "LOW", title: "Large CreateCode (SetHook fee)", category: "size", requires: "wasm",
    check: (c) => c.wasm.byteSize > OVERSIZE_BYTES ? { ruleId: "HOOK-011-OVERSIZE-WASM", severity: "LOW", message: `WASM is ${c.wasm.byteSize} bytes (> ${OVERSIZE_BYTES}); SetHook fee scales with size — consider trimming.` } : null,
  },
  {
    id: "HOOK-012-FLOAT-USAGE", severity: "INFO", title: "Uses the XFL float API (advisory)", category: "float", requires: "wasm",
    check: (c) => [...importNames(c.wasm)].some((n) => n.startsWith("float_")) ? { ruleId: "HOOK-012-FLOAT-USAGE", severity: "INFO", message: "Hook uses the float_* (XFL) API. Reminder: handle results only with float_* operations (never native arithmetic) and compare via float_compare." } : null,
  },
  {
    id: "HOOK-013-MEMORY-EXCESS", severity: "LOW", title: "Declares excess linear memory", category: "size", requires: "wasm",
    check: (c) => c.wasm.memory && c.wasm.memory.min > MEMORY_PAGE_CEIL ? { ruleId: "HOOK-013-MEMORY-EXCESS", severity: "LOW", message: `Declares ${c.wasm.memory.min} memory pages (> ${MEMORY_PAGE_CEIL}); hooks rarely need this much.` } : null,
  },
  {
    id: "SETHOOK-001-NS-COLLISION", severity: "MEDIUM", title: "HookNamespace collides with an installed hook", category: "sethook", requires: "sethook",
    check: (c) => c.namespace && (c.existingNamespaces ?? []).includes(c.namespace) ? { ruleId: "SETHOOK-001-NS-COLLISION", severity: "MEDIUM", message: `HookNamespace ${c.namespace} is already used by another hook on this account; state will be shared/overwritten.` } : null,
  },
  {
    id: "SETHOOK-002-MISSING-NAMESPACE", severity: "INFO", title: "State used without an explicit namespace (advisory)", category: "sethook", requires: "sethook",
    check: (c) => { const im = importNames(c.wasm); const usesState = im.has("state") || im.has("state_set"); return usesState && !c.namespace ? { ruleId: "SETHOOK-002-MISSING-NAMESPACE", severity: "INFO", message: "Hook uses state but no explicit HookNamespace was supplied; a default namespace will be used. Set one to isolate this hook's state from others on the account." } : null; },
  },
  {
    id: "SETHOOK-003-HOOKON-EMPTY", severity: "INFO", title: "HookOn fires on nothing (inert)", category: "hookon", requires: "sethook",
    check: (c) => { if (!c.hookOn) return null; return decodeHookOn(c.hookOn).count === 0 ? { ruleId: "SETHOOK-003-HOOKON-EMPTY", severity: "INFO", message: "HookOn fires on zero transaction types; the hook is inert as configured." } : null; },
  },
];

export function listRules() {
  return RULES.map((r) => ({ ruleId: r.id, severity: r.severity, title: r.title, category: r.category, requires: r.requires }));
}

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function runRules(ctx: AnalyzeContext, opts: { sethook: boolean }): { findings: Finding[]; summary: Record<Severity, number> } {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    if (rule.requires === "sethook" && !opts.sethook) continue;
    const res = rule.check(ctx);
    if (!res) continue;
    if (Array.isArray(res)) findings.push(...res);
    else findings.push(res);
  }
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const summary: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) summary[f.severity]++;
  return { findings, summary };
}

/** Decode a hex/base64 CreateCode into WasmInfo (helper for tools). */
export function decodeCreateCode(input: { wasmHex?: string; wasmBase64?: string }): WasmInfo {
  if (input.wasmHex) return readWasm(hexToBytes(input.wasmHex));
  if (input.wasmBase64) return readWasm(base64ToBytes(input.wasmBase64));
  throw new Error("provide wasmHex or wasmBase64");
}
