import { describe, it, expect } from "vitest";
import { xahAmount, decodeTxBlob, encodeTxBlob, decodeSetHook, decodeUriTokenId } from "../src/codec.js";

describe("codec", () => {
  it("converts XAH <-> drops", () => {
    expect(xahAmount("1", "xah").drops).toBe("1000000");
    expect(xahAmount("1.5", "xah").drops).toBe("1500000");
    expect(xahAmount("2500000", "drops").xah).toBe("2.5");
  });

  it("round-trips a Payment tx blob", () => {
    const tx = { TransactionType: "Payment", Account: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", Destination: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", Amount: "1000000", Fee: "12", Sequence: 1 };
    const { txBlobHex } = encodeTxBlob(tx);
    const back = decodeTxBlob(txBlobHex) as Record<string, unknown>;
    expect(back.TransactionType).toBe("Payment");
    expect(back.Amount).toBe("1000000");
  });

  it("decodes a SetHook JSON with HookOn", () => {
    const tx = { TransactionType: "SetHook", Account: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", Hooks: [{ Hook: { HookOn: "0".repeat(64), HookNamespace: "A".repeat(64) } }] };
    const d = decodeSetHook({ tx });
    expect(d.hooks.length).toBe(1);
    expect(d.hooks[0].hookOnDecoded?.firesOn).toContain("Payment");
    expect(d.hooks[0].namespace).toBe("A".repeat(64));
  });

  it("validates URIToken ids", () => {
    expect(decodeUriTokenId("A".repeat(64)).valid).toBe(true);
    expect(decodeUriTokenId("nope").valid).toBe(false);
  });
});
