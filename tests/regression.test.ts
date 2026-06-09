import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runHook } from "../src/sandbox.js";
import { readWasm, hexToBytes } from "../src/wasm.js";

// Real, compiled Hook bytecode pulled from the Xahau MAINNET genesis account (rHb9CJ...).
// These prove the VM executes real toolchain WASM and reproduces the on-chain accept/rollback
// DIRECTION (the exact HookReturnCode depends on per-tx reward state we don't reconstruct, so we
// assert the decision direction + that the run is non-degraded, not the numeric code).
const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
const load = (n: string) => hexToBytes(readFileSync(join(DIR, n + ".hex"), "utf8").trim());

describe("real mainnet hook regression (genesis bytecode)", () => {
  it("governance hook is valid WASM with a hook() export (~8810B)", () => {
    const w = readWasm(load("genesis-governance"));
    expect(w.valid).toBe(true);
    expect(w.byteSize).toBe(8810);
    expect(w.exports.some((e) => e.name === "hook")).toBe(true);
  });

  it("reward hook is valid WASM (~3094B)", () => {
    const w = readWasm(load("genesis-reward"));
    expect(w.valid).toBe(true);
    expect(w.byteSize).toBe(3094);
  });

  it("reward hook @ ClaimReward -> ACCEPT, non-degraded (matches on-chain HookResult=3)", () => {
    const r = runHook(load("genesis-reward"), { txType: "ClaimReward", ledgerSeq: 23478900, hookAccountId: "00".repeat(20) });
    expect(r.exit).toBe("accept");
    expect(r.degraded).toBe(false);
    expect(r.unsupportedCalls).toEqual([]);
  });

  it("governance hook @ Invoke -> ROLLBACK, non-degraded (rejects a param-less Invoke)", () => {
    const r = runHook(load("genesis-governance"), { txType: "Invoke", ledgerSeq: 23478900, hookAccountId: "00".repeat(20) });
    expect(r.exit).toBe("rollback");
    expect(r.degraded).toBe(false);
  });
});
