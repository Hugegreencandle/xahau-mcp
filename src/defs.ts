// Loads the offline Xahau definitions + Hook API catalog + governance/endpoint constants.
// Mirrors the hieroglyph-mcp data-loader pattern: synchronous readFileSync at module init,
// indexes built once. dist/defs.js -> ../data ; src/defs.ts (vitest) -> ../data both resolve.
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA = join(__dirname, "..", "data");

function load<T>(file: string): T {
  return JSON.parse(readFileSync(join(DATA, file), "utf-8")) as T;
}
function has(file: string): boolean {
  return existsSync(join(DATA, file));
}

export interface Definitions {
  hash: string;
  native_currency_code: string;
  TYPES: Record<string, number>;
  LEDGER_ENTRY_TYPES: Record<string, number>;
  TRANSACTION_TYPES: Record<string, number>;
  TRANSACTION_RESULTS: Record<string, number>;
  TRANSACTION_FLAGS: Record<string, Record<string, number>>;
  FIELDS: [string, { nth: number; type: string; isVLEncoded: boolean; isSerialized: boolean; isSigningField: boolean }][];
}

export const DEFS_AVAILABLE = has("definitions.json");
export const HOOKAPI_AVAILABLE = has("hook-api.json");

export const DEFINITIONS: Definitions = DEFS_AVAILABLE ? load<Definitions>("definitions.json") : ({} as Definitions);

interface HookOnData {
  SETHOOK_BIT: number;
  txTypes: Record<string, number>;
}
export const HOOKON: HookOnData = DEFS_AVAILABLE ? load<HookOnData>("hookon-txtypes.json") : { SETHOOK_BIT: 22, txTypes: {} };

interface ErrorCodes {
  results: Record<string, number>;
}
const ERR: ErrorCodes = DEFS_AVAILABLE ? load<ErrorCodes>("error-codes.json") : { results: {} };

export type Endpoints = Record<string, { network_id: number; rpc: string[]; wss: string[] }>;
export const ENDPOINTS: Endpoints = has("endpoints.json")
  ? load<Endpoints>("endpoints.json")
  : {
      mainnet: { network_id: 21337, rpc: ["https://xahau.network"], wss: [] },        // Xahau mainnet
      testnet: { network_id: 21338, rpc: ["https://xahau-test.net"], wss: [] },       // Xahau testnet
      xrpl: { network_id: 0, rpc: ["https://s1.ripple.com:51234"], wss: [] },         // XRP Ledger mainnet
      "xrpl-test": { network_id: 1, rpc: ["https://s.altnet.rippletest.net:51234"], wss: [] }, // XRPL testnet
    };

export interface Governance {
  genesisAccount: string;
  governanceSeats: number;
  /** LEGACY-MISNAMED (kept for compatibility): the value is SECONDS, not ledgers — see rewardDelaySeconds. */
  rewardDelayLedgers: number;
  /** Genesis reward hook RD parameter in seconds (reward.c gates on ledger_last_time() - RewardTime >= RD). */
  rewardDelaySeconds?: number;
  rewardRateMonthly_doc: number;
  caveat: string;
}
export const GOVERNANCE: Governance | null = has("governance.json") ? load<Governance>("governance.json") : null;

// --- indexes (built once) ---
const txTypeByName = new Map<string, number>();
const txTypeByValue = new Map<number, string>();
for (const [name, value] of Object.entries(DEFINITIONS.TRANSACTION_TYPES ?? {})) {
  if (value < 0) continue;
  txTypeByName.set(name, value);
  txTypeByValue.set(value, name);
}
const resultByCode = new Map<number, string>();
for (const [name, code] of Object.entries(ERR.results)) resultByCode.set(code, name);

export function txTypeValue(name: string): number | undefined {
  return txTypeByName.get(name);
}
export function txTypeName(value: number): string | undefined {
  return txTypeByValue.get(value);
}
export function allTxTypes(): { name: string; value: number }[] {
  return [...txTypeByName.entries()].map(([name, value]) => ({ name, value })).sort((a, b) => a.value - b.value);
}
/** Decode an engine result code (number) or pass through a known name. */
export function decodeResult(code: number | string): { code: number | null; name: string | null; known: boolean } {
  if (typeof code === "number") {
    const name = resultByCode.get(code) ?? null;
    return { code, name, known: name !== null };
  }
  const c = ERR.results[code];
  return { code: c ?? null, name: code, known: c !== undefined };
}

export const DATA_GUARD = {
  content: [{ type: "text" as const, text: "Offline data not built. Run `npm run fetch:all` first." }],
  structuredContent: { available: false },
};
