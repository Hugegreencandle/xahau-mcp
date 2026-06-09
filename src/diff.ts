// Compare two Hook versions (e.g. before/after an upgrade): what imports/exports/HookOn/size/
// capabilities changed. Offline, structural — surfaces the security-relevant deltas of a SetHook upgrade.
import type { WasmInfo } from "./wasm.js";
import { decodeHookOn } from "./hookon.js";

const fImports = (w: WasmInfo) => new Set(w.imports.filter((i) => i.kind === "func").map((i) => i.name));
const fExports = (w: WasmInfo) => new Set(w.exports.filter((e) => e.kind === "func").map((e) => e.name));
const diffSets = (a: Set<string>, b: Set<string>) => ({ added: [...b].filter((x) => !a.has(x)).sort(), removed: [...a].filter((x) => !b.has(x)).sort() });

const SENSITIVE = new Set(["emit", "state_foreign_set", "hook_again", "util_verify", "state_set"]);

export interface HookDiff {
  byteSizeBefore: number; byteSizeAfter: number; byteSizeDelta: number;
  imports: { added: string[]; removed: string[] };
  exports: { added: string[]; removed: string[] };
  firesOn: { added: string[]; removed: string[] } | null;
  instructionDelta: number;
  loopDelta: number; guardDelta: number;
  newSensitiveCapabilities: string[];
  summary: string;
}

export function diffHooks(a: WasmInfo, b: WasmInfo, hookOnA?: string, hookOnB?: string): HookDiff {
  const imports = diffSets(fImports(a), fImports(b));
  const exports = diffSets(fExports(a), fExports(b));
  const firesOn = hookOnA !== undefined && hookOnB !== undefined
    ? diffSets(new Set(decodeHookOn(hookOnA).firesOn), new Set(decodeHookOn(hookOnB).firesOn))
    : null;
  const newSensitiveCapabilities = imports.added.filter((n) => SENSITIVE.has(n));

  const parts: string[] = [];
  parts.push(`size ${a.byteSize}B → ${b.byteSize}B (${b.byteSize - a.byteSize >= 0 ? "+" : ""}${b.byteSize - a.byteSize})`);
  if (imports.added.length) parts.push(`new API calls: ${imports.added.join(", ")}`);
  if (imports.removed.length) parts.push(`removed API calls: ${imports.removed.join(", ")}`);
  if (exports.added.length) parts.push(`new exports: ${exports.added.join(", ")}`);
  if (exports.removed.length) parts.push(`removed exports: ${exports.removed.join(", ")}`);
  if (firesOn?.added.length) parts.push(`now ALSO fires on: ${firesOn.added.join(", ")}`);
  if (firesOn?.removed.length) parts.push(`no longer fires on: ${firesOn.removed.join(", ")}`);
  if (newSensitiveCapabilities.length) parts.push(`⚠ gains security-sensitive capability: ${newSensitiveCapabilities.join(", ")} — review before upgrading`);
  if (parts.length === 1) parts.push("no structural change to imports/exports/HookOn");

  return {
    byteSizeBefore: a.byteSize, byteSizeAfter: b.byteSize, byteSizeDelta: b.byteSize - a.byteSize,
    imports, exports, firesOn, instructionDelta: b.instructionCount - a.instructionCount,
    loopDelta: b.loopCount - a.loopCount, guardDelta: b.guardCallCount - a.guardCallCount,
    newSensitiveCapabilities,
    summary: parts.join(" · "),
  };
}
