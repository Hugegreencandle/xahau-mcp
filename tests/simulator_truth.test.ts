import { describe, it, expect } from "vitest";
import { buildHookWasm } from "./fixtures.js";
import { runHook } from "../src/sandbox.js";
import { reconstructContext } from "../src/fidelity.js";
import { stoFieldsPartial } from "../src/sto.js";
import { encodeTxBlob } from "../src/codec.js";
import { hexToBytes } from "../src/wasm.js";
import { evernodeHostDiagnostics, type HostDeps } from "../src/evernodeHost.js";

const AMOUNT = (6 << 16) | 1;
const DESTINATION = (8 << 16) | 3;

// A cross-currency Payment carrying a Paths field (STPathSet, type 18) — the byte-walker can't size it.
const PATHS_PAYMENT = {
  TransactionType: "Payment",
  Account: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
  Destination: "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn",
  Amount: { currency: "USD", issuer: "rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B", value: "10" },
  SendMax: { currency: "USD", issuer: "rsP3mgGb2tcYUrxiLFiHJiQXhsziegtwBc", value: "11" },
  Paths: [[{ currency: "XRP" }, { account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp", currency: "USD", issuer: "rrrrrrrrrrrrrrrrrrrrBZbvji" }]],
  Sequence: 1,
  Fee: "12",
};

describe("H3 — partial otxn reconstruction is flagged degraded (no silent confident verdict)", () => {
  it("stoFieldsPartial collects fields before the unparseable PathSet, marks complete:false", () => {
    const { txBlobHex } = encodeTxBlob(PATHS_PAYMENT);
    const { fields, complete } = stoFieldsPartial(hexToBytes(txBlobHex));
    expect(complete).toBe(false);
    const codes = fields.map((f) => (f.typeCode << 16) | f.fieldCode);
    expect(codes).toContain(AMOUNT); // Amount (before Paths) still reconstructed
    expect(codes).toContain(DESTINATION); // Destination (before Paths) still reconstructed
  });

  it("reconstructContext keeps the earlier fields but sets otxnFieldsIncomplete on a Paths tx", () => {
    const ctx = reconstructContext(PATHS_PAYMENT, "00".repeat(20));
    expect(ctx.otxnFieldsIncomplete).toBe(true);
    expect(ctx.otxnFields?.[String(AMOUNT)]).toBeTruthy();
  });

  it("runHook forces degraded when otxnFieldsIncomplete is set", () => {
    const wasm = buildHookWasm({}); // no-op hook: exits 'no-exit-called', not otherwise degraded
    expect(runHook(wasm, {}).degraded).toBe(false);
    const flagged = runHook(wasm, { otxnFieldsIncomplete: true });
    expect(flagged.degraded).toBe(true);
    expect(flagged.caveat).toMatch(/PathSet|byte-walker/);
  });
});

describe("H6 — evernode: a node failure is not reported as 'not registered'", () => {
  const baseDeps = (regState: string | null | undefined): HostDeps => ({
    getAccountInfo: async () => ({ account_data: { Balance: "10000000" } }),
    getHookState: async () => regState, // governor reads all resolve to this
    getLines: async () => [],
    getUriTokens: async () => [],
    getCloseTime: async () => 800000000,
    sleep: async () => {},
  });

  it("throws an actionable error when the registration read is unavailable (undefined)", async () => {
    await expect(evernodeHostDiagnostics("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "mainnet", baseDeps(undefined)))
      .rejects.toThrow(/node unavailable|cannot determine host status/i);
  });

  it("still reports 'not registered' when the entry is confirmed absent (null)", async () => {
    const r = await evernodeHostDiagnostics("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "mainnet", baseDeps(null));
    expect(r.isRegisteredHost).toBe(false);
  });
});
