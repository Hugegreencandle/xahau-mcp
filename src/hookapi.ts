// Loads the Hook API catalog (data/hook-api.json) — the analyzer's reference for which
// `env` imports are legitimate and which carry security hazards.
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA = join(__dirname, "..", "data");

export interface Hazard { ruleId: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; note: string; }
export interface HookApiFn {
  name: string; module: string; category: string;
  isExit: boolean; isGuard: boolean; hazards: Hazard[];
}

const FILE = join(DATA, "hook-api.json");
export const HOOKAPI_AVAILABLE = existsSync(FILE);

const raw: { count: number; functions: HookApiFn[] } = HOOKAPI_AVAILABLE
  ? JSON.parse(readFileSync(FILE, "utf-8"))
  : { count: 0, functions: [] };

export const HOOK_FUNCTIONS: HookApiFn[] = raw.functions;
const byName = new Map<string, HookApiFn>();
for (const f of HOOK_FUNCTIONS) byName.set(f.name, f);

export function lookupHookApi(name: string): HookApiFn | undefined {
  return byName.get(name);
}
export function isKnownHookApi(name: string): boolean {
  return byName.has(name);
}
export function hookApiCount(): number {
  return HOOK_FUNCTIONS.length;
}
