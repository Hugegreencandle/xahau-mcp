import * as rpc from "./rpc.js";
import { accountIdToR } from "./util.js";
import type { SimDeps } from "./simulate.js";

export type Net = "mainnet" | "testnet";

// ---------------------------------------------------------------------------
// Read cache. The flight simulator makes the SAME ledger reads repeatedly
// (hook definitions, account info, state) across resolve rounds and across
// requests; against a single rate-limited mainnet node that serial latency is
// the #1 cost. This is a tiny TTL+LRU over rpc reads.
//
// CORRECTNESS (load-bearing): every key includes the pinned ledger
// (ledgerIndex|'validated') EXCEPT hook definitions, which are content-addressed
// by hash and therefore immutable forever. Pinned/historical reads are immutable
// -> long TTL; 'validated' reads get a short TTL so live data stays fresh.
// We never cache `undefined` (that's a transient "unavailable" signal, e.g. a
// rate-limit) — only real values and confirmed-absent `null`.
// ---------------------------------------------------------------------------
const CACHE_MAX = 5000;
const FOREVER = 0;                 // immutable (hook definitions)
const PINNED_TTL_MS = 3_600_000;   // historical/pinned reads — immutable in practice
const VALIDATED_TTL_MS = 4_000;    // 'validated' reads — keep live data fresh

type Entry = { v: unknown; exp: number };
const cache = new Map<string, Entry>();
const MISS = Symbol("miss");

function cacheGet(key: string): unknown | typeof MISS {
  const e = cache.get(key);
  if (!e) return MISS;
  if (e.exp !== FOREVER && e.exp < Date.now()) { cache.delete(key); return MISS; }
  cache.delete(key); cache.set(key, e); // LRU touch
  return e.v;
}
function cacheSet(key: string, v: unknown, ttlMs: number): void {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, { v, exp: ttlMs === FOREVER ? FOREVER : Date.now() + ttlMs });
}
async function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const hit = cacheGet(key);
  if (hit !== MISS) return hit as T;
  const v = await fn();
  if (v !== undefined) cacheSet(key, v, ttlMs); // never cache transient "unavailable"
  return v;
}

/** Clear the read cache (tests / long-running processes). */
export function clearSimCache(): void { cache.clear(); }

/**
 * Shared live wiring for the flight simulator (simulate_transaction / what_if).
 * Pins EVERY read to the simulation ledger so the installed hook chain, hook
 * definitions, parameters and account balance/sequence are read AS THEY WERE.
 *
 * Extracted from index.ts so the stdio MCP server AND the HTTP shim (src/http.ts)
 * share one source of truth — importing index.ts would boot the stdio transport.
 *
 * Inter-read spacing is XAHC_SIM_SPACING_MS (default the simulator's SPACING_MS;
 * set 0 for an own node, ~300 behind a public shared node).
 */
export function simDeps(network: Net, ledgerIndex?: number): SimDeps {
  const li = ledgerIndex !== undefined ? { ledger_index: ledgerIndex } : { ledger_index: "validated" as const };
  // ledger component of every cache key + the TTL bucket it selects
  const lk = ledgerIndex !== undefined ? String(ledgerIndex) : "validated";
  const ttl = ledgerIndex !== undefined ? PINNED_TTL_MS : VALIDATED_TTL_MS;
  const spacingEnv = process.env.XAHC_SIM_SPACING_MS;
  const spacingMs = spacingEnv !== undefined && spacingEnv !== "" ? Number(spacingEnv) : undefined;

  return {
    spacingMs: Number.isFinite(spacingMs as number) ? (spacingMs as number) : undefined,

    getAccountHooks: async (a) => cached(`${network}:${lk}:hooks:${a}`, ttl, async () => {
      try {
        const r = await rpc.rpc<{ account_objects: Record<string, any>[] }>("account_objects", { account: a, type: "hook", ...li }, network);
        const hookObj = r.account_objects.find((o: any) => o.LedgerEntryType === "Hook") as any;
        return (hookObj?.Hooks ?? []) as Record<string, any>[];
      } catch {
        // account doesn't exist (e.g. paying a not-yet-created destination) → no hooks
        return [] as Record<string, any>[];
      }
    }),

    // Hook definitions are content-addressed by hash -> immutable forever; key on
    // hash alone (no ledger), cache forever.
    getHookDefinition: async (hash) => cached(`${network}:hookdef:${hash}`, FOREVER, async () => {
      try { const r = await rpc.rpc<{ node: Record<string, any> }>("ledger_entry", { hook_definition: hash, ...li }, network); return r.node as Record<string, any>; }
      catch { return null; }
    }),

    getAccountInfo: async (a) => cached(`${network}:${lk}:acctinfo:${a}`, ttl, async () => {
      try { return await rpc.rpc<{ account_data: Record<string, unknown> }>("account_info", { account: a, ...li }, network); } catch { return null; }
    }),

    getHookState: async (acc, ns, key) => cached(`${network}:${lk}:hookstate:${acc}:${ns}:${key}`, ttl, async () => {
      const rAddr = accountIdToR(acc) ?? acc;
      try {
        const r = await rpc.rpc<{ node?: Record<string, unknown> }>("ledger_entry", { hook_state: { account: rAddr, key, namespace_id: ns }, ...li }, network);
        const d = r.node?.HookStateData;
        return typeof d === "string" ? d.toUpperCase() : undefined;
      } catch (e) {
        if (/entryNotFound/i.test((e as Error).message)) return null; // confirmed absent
        return undefined;
      }
    }),

    getLedgerObject: async (idx) => cached(`${network}:${lk}:ledgerobj:${idx}`, ttl, async () => {
      try {
        const r = await rpc.rpc<{ node_binary?: string; node?: { node_binary?: string } }>("ledger_entry", { index: idx, binary: true, ...li }, network);
        const b = r.node_binary ?? r.node?.node_binary;
        return typeof b === "string" ? b.toUpperCase() : undefined;
      } catch (e) {
        if (/entryNotFound/i.test((e as Error).message)) return null; // confirmed absent — faithful DOESNT_EXIST
        return undefined; // unavailable (rate limit etc.) — stays degraded
      }
    }),

    getLedgerInfo: async () => cached(`${network}:${lk}:ledgerinfo`, ttl, async () => {
      const r = await rpc.getLedger(ledgerIndex ?? "validated", network);
      const l = r.ledger as Record<string, any>;
      return { ledgerIndex: Number(l.ledger_index), closeTime: Number(l.close_time) };
    }),

    getFee: async () => cached(`${network}:fee`, VALIDATED_TTL_MS, async () => {
      try { const f = await rpc.getFee(network) as Record<string, any>; return Number(f?.drops?.base_fee ?? 100000); } catch { return 100000; }
    }),

    getAccountLines: async (a) => cached(`${network}:${lk}:lines:${a}`, ttl, async () => {
      try { const r = await rpc.getAccountLines(a, network) as Record<string, any>; return (r?.lines ?? []) as Record<string, any>[]; } catch { return []; }
    }),

    getReserves: async () => cached(`${network}:reserves`, VALIDATED_TTL_MS, async () => {
      try {
        const si = await rpc.getServerInfo(network) as Record<string, any>;
        const vl = (si?.info as any)?.validated_ledger ?? {};
        const base = BigInt(Math.round(Number(vl.reserve_base_xrp ?? 1) * 1_000_000));
        const inc = BigInt(Math.round(Number(vl.reserve_inc_xrp ?? 0.2) * 1_000_000));
        return { baseDrops: base, incDrops: inc };
      } catch { return { baseDrops: 1_000_000n, incDrops: 200_000n }; }
    }),
  };
}
