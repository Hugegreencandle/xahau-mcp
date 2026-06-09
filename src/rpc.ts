// Read-only Xahau JSON-RPC client over HTTPS (built-in fetch, zero deps).
// Multi-node failover; mainnet + testnet. This module NEVER signs or submits —
// it exposes only read methods. There is deliberately no `submit`/`sign` here.
import { ENDPOINTS } from "./defs.js";

export type Network = "mainnet" | "testnet";

export class RpcError extends Error {}

interface RpcResponse<T> { result: T & { status?: string; error?: string; error_message?: string } }

const TIMEOUT_MS = 8000;

/** Operator override: XAHAU_RPC_URLS / XAHAU_TEST_RPC_URLS (comma-separated) take priority for failover. */
function nodesFor(network: Network): string[] {
  const env = network === "mainnet" ? process.env.XAHAU_RPC_URLS : process.env.XAHAU_TEST_RPC_URLS;
  const override = (env ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  return [...override, ...ENDPOINTS[network].rpc.filter((u) => !override.includes(u))];
}

export async function rpc<T = Record<string, unknown>>(method: string, params: Record<string, unknown>, network: Network = "mainnet"): Promise<T> {
  const nodes = nodesFor(network);
  if (!nodes.length) throw new RpcError(`no RPC endpoints configured for ${network}`);
  let lastErr: unknown;
  for (const url of nodes) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method, params: [params] }),
        signal: ctrl.signal,
      }).finally(() => clearTimeout(timer));
      if (!res.ok) throw new RpcError(`${url} HTTP ${res.status}`);
      const json = (await res.json()) as RpcResponse<T>;
      const r = json.result;
      if (r?.status === "error") throw new RpcError(`${method}: ${r.error_message ?? r.error ?? "rpc error"}`);
      return r as T;
    } catch (e) {
      lastErr = e;
    }
  }
  throw new RpcError(`all ${network} nodes failed for ${method}: ${(lastErr as Error)?.message ?? lastErr}`);
}

export function endpointFor(network: Network): string {
  return ENDPOINTS[network].rpc[0] ?? "(none)";
}

// --- typed read helpers ---
export const getServerInfo = (network: Network) => rpc<{ info: Record<string, unknown> }>("server_info", {}, network);
export const getAccountInfo = (account: string, network: Network) =>
  rpc<{ account_data: Record<string, unknown> }>("account_info", { account, ledger_index: "validated" }, network);
export const getAccountObjects = (account: string, network: Network, type?: string) =>
  rpc<{ account_objects: Record<string, unknown>[] }>("account_objects", { account, ledger_index: "validated", ...(type ? { type } : {}) }, network);
export const getAccountNamespace = (account: string, namespace: string, network: Network) =>
  rpc<{ namespace_entries: Record<string, unknown>[] }>("account_namespace", { account, namespace_id: namespace, ledger_index: "validated" }, network);
export const getTx = (transaction: string, network: Network) =>
  rpc<Record<string, unknown>>("tx", { transaction, binary: false }, network);
export const getLedgerEntry = (params: Record<string, unknown>, network: Network) =>
  rpc<{ node: Record<string, unknown> }>("ledger_entry", { ...params, ledger_index: "validated" }, network);
export const getLedger = (ledgerIndex: string | number, network: Network) =>
  rpc<{ ledger: Record<string, unknown> }>("ledger", { ledger_index: ledgerIndex, transactions: false, expand: false }, network);
