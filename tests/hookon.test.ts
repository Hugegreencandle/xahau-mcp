import { describe, it, expect } from "vitest";
import { decodeHookOn, encodeHookOn } from "../src/hookon.js";
import { allTxTypes } from "../src/defs.js";

describe("HookOn inverted-mask encoding", () => {
  it("all-zero fires on every type EXCEPT SetHook (doc example)", () => {
    const { firesOn } = decodeHookOn("0".repeat(64));
    expect(firesOn).not.toContain("SetHook");
    expect(firesOn).toContain("Payment");
    expect(firesOn).toContain("Invoke");
    expect(firesOn.length).toBe(allTxTypes().length - 1);
  });

  it("encode∘decode is identity for a subset", () => {
    const want = ["Payment", "Invoke", "URITokenMint"];
    const { hookOn } = encodeHookOn(want);
    expect(decodeHookOn(hookOn).firesOn.sort()).toEqual([...want].sort());
  });

  it("SetHook bit is active-high (set => fires)", () => {
    const { hookOn, firesOn } = encodeHookOn(["SetHook"]);
    expect(firesOn).toEqual(["SetHook"]);
    expect(decodeHookOn(hookOn).firesOn).toEqual(["SetHook"]);
  });

  it("round-trips every single transaction type individually", () => {
    for (const { name } of allTxTypes()) {
      const { hookOn } = encodeHookOn([name]);
      expect(decodeHookOn(hookOn).firesOn).toEqual([name]);
    }
  });

  it("rejects unknown transaction types and bad hex", () => {
    expect(() => encodeHookOn(["NotARealTx"])).toThrow();
    expect(() => decodeHookOn("zz")).toThrow();
  });
});
