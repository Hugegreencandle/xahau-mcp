import { describe, it, expect } from "vitest";
import { explainAccount, type ExplainDeps } from "../src/explain.js";

const LEASE_B64 = "ZXZybGVhc2VMVFYAAQACCAFnfryy9275fVMVSdiyfVQGCiQYHkAAL9eUlAAAAAAAAAAAAAAAAAAAAAAA";
const LEASE_URI_HEX = Buffer.from(LEASE_B64, "utf-8").toString("hex").toUpperCase();

const noSleep = (_ms: number) => Promise.resolve();

function deps(over: Partial<ExplainDeps> = {}): ExplainDeps {
  return {
    getAccountInfo: async () => ({ account_data: { Balance: "12500000", Flags: 0, Sequence: 5 } }),
    getHookObjects: async () => [],
    getLines: async () => [],
    getUriTokens: async () => [],
    getRecentTx: async () => [],
    sleep: noSleep,
    ...over,
  };
}

describe("explain_account", () => {
  it("plain account: balance + single-master warning-note, no hooks/lines/tokens", async () => {
    const r = await explainAccount("rTest", deps());
    expect(r.balanceXah).toBe("12.5");
    expect(r.keySafety.masterDisabled).toBe(false);
    expect(r.keySafety.note).toMatch(/single master key/);
    expect(r.summary).toMatch(/12\.5 XAH/);
    expect(r.hooks.count).toBe(0);
  });

  it("detects an Evernode host (lease URITokens decoded) + hooks + activity", async () => {
    const r = await explainAccount("rHost", deps({
      getHookObjects: async () => [{ LedgerEntryType: "Hook", Hooks: [{ Hook: { HookHash: "AB".repeat(32), HookOn: "F".repeat(64) } }] }],
      getUriTokens: async () => [{ index: "01".repeat(32), URI: LEASE_URI_HEX }, { index: "02".repeat(32), URI: Buffer.from("https://x.com", "utf-8").toString("hex") }],
      getRecentTx: async () => [
        { tx: { TransactionType: "URITokenMint", date: 800000000 } },
        { tx: { TransactionType: "URITokenMint", date: 800000100 } },
        { tx: { TransactionType: "Payment", date: 800000200 } },
      ],
    }));
    expect(r.uriTokens.count).toBe(2);
    expect(r.uriTokens.evernodeLeases).toBe(1);
    expect(r.notes.join(" ")).toMatch(/Evernode/);
    expect(r.hooks.count).toBe(1);
    expect(r.recentActivity.byType.URITokenMint).toBe(2);
    expect(r.recentActivity.lastTxIso).toMatch(/^20/);
    expect(r.summary).toMatch(/Evernode lease/);
  });

  it("flags master-enabled-with-regular-key", async () => {
    const r = await explainAccount("rKey", deps({
      getAccountInfo: async () => ({ account_data: { Balance: "1000000", Flags: 0, RegularKey: "rRRR" } }),
    }));
    expect(r.warnings.join(" ")).toMatch(/master key enabled/);
  });

  it("master disabled reads as good practice", async () => {
    const r = await explainAccount("rSafe", deps({
      getAccountInfo: async () => ({ account_data: { Balance: "1000000", Flags: 0x00100000, RegularKey: "rRRR" } }),
    }));
    expect(r.keySafety.masterDisabled).toBe(true);
    expect(r.keySafety.note).toMatch(/good practice/);
    expect(r.warnings.length).toBe(0);
  });
});
