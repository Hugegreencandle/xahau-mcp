import { describe, it, expect, beforeEach, vi } from "vitest";
import * as rpc from "../src/rpc.js";
import { simDeps, clearSimCache } from "../src/simdeps.js";

describe("simdeps read cache", () => {
  beforeEach(() => {
    clearSimCache();
    vi.restoreAllMocks();
  });

  it("caches hook definitions by hash (immutable, one RPC for repeat reads)", async () => {
    const spy = vi.spyOn(rpc, "rpc").mockResolvedValue({ node: { createCodeHex: "0061736D" } } as any);
    const d = simDeps("mainnet");
    await d.getHookDefinition("HASH_A");
    await d.getHookDefinition("HASH_A");
    expect(spy).toHaveBeenCalledTimes(1);
    await d.getHookDefinition("HASH_B");
    expect(spy).toHaveBeenCalledTimes(2); // different hash -> new read
  });

  it("keys 'validated' separately from a pinned ledger index", async () => {
    const spy = vi.spyOn(rpc, "rpc").mockResolvedValue({ account_data: { Balance: "1" } } as any);
    await simDeps("mainnet").getAccountInfo("rABC"); // validated
    await simDeps("mainnet", 100).getAccountInfo("rABC"); // pinned @100
    expect(spy).toHaveBeenCalledTimes(2); // different ledger key -> not a cache hit
    await simDeps("mainnet", 100).getAccountInfo("rABC"); // pinned @100 again -> cached
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("keys by network (mainnet vs testnet never collide)", async () => {
    const spy = vi.spyOn(rpc, "rpc").mockResolvedValue({ account_data: {} } as any);
    await simDeps("mainnet", 5).getAccountInfo("rX");
    await simDeps("testnet", 5).getAccountInfo("rX");
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("never caches a transient `undefined` (unavailable) result", async () => {
    const spy = vi.spyOn(rpc, "rpc").mockRejectedValue(new Error("rate limited")); // not entryNotFound -> undefined
    const d = simDeps("mainnet", 7);
    expect(await d.getLedgerObject("IDX")).toBeUndefined();
    expect(await d.getLedgerObject("IDX")).toBeUndefined();
    expect(spy).toHaveBeenCalledTimes(2); // re-fetched, not served stale undefined
  });

  it("caches confirmed-absent `null` (entryNotFound is stable at a pinned ledger)", async () => {
    const spy = vi.spyOn(rpc, "rpc").mockRejectedValue(new Error("entryNotFound"));
    const d = simDeps("mainnet", 9);
    expect(await d.getLedgerObject("IDX2")).toBeNull();
    expect(await d.getLedgerObject("IDX2")).toBeNull();
    expect(spy).toHaveBeenCalledTimes(1); // null cached
  });

  it("clearSimCache resets", async () => {
    const spy = vi.spyOn(rpc, "rpc").mockResolvedValue({ node: { createCodeHex: "00" } } as any);
    const d = simDeps("mainnet");
    await d.getHookDefinition("HASH_C");
    clearSimCache();
    await d.getHookDefinition("HASH_C");
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("reads XAHC_SIM_SPACING_MS into deps.spacingMs", () => {
    const prev = process.env.XAHC_SIM_SPACING_MS;
    process.env.XAHC_SIM_SPACING_MS = "0";
    expect(simDeps("mainnet").spacingMs).toBe(0);
    process.env.XAHC_SIM_SPACING_MS = "300";
    expect(simDeps("mainnet").spacingMs).toBe(300);
    delete process.env.XAHC_SIM_SPACING_MS;
    expect(simDeps("mainnet").spacingMs).toBeUndefined();
    if (prev !== undefined) process.env.XAHC_SIM_SPACING_MS = prev;
  });
});
