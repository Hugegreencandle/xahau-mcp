import { describe, it, expect } from "vitest";
import { buildSetRemarksUnsigned, buildClawbackUnsigned, buildDeepFreezeUnsigned } from "../src/builders.js";

const ACCT = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const HOLDER = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
const OID = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";

describe("buildSetRemarksUnsigned", () => {
  it("builds canonical Remarks nesting with hex passthrough", () => {
    const r = buildSetRemarksUnsigned({ account: ACCT, objectId: OID, remarks: [{ name: "CAFE", value: "DEADBEEF" }] });
    expect(r.unsignedTx.TransactionType).toBe("SetRemarks");
    expect(r.unsignedTx.ObjectID).toBe(OID);
    expect(r.unsignedTx.Remarks).toEqual([{ Remark: { RemarkName: "CAFE", RemarkValue: "DEADBEEF" } }]);
  });

  it("UTF-8 encodes non-hex names/values", () => {
    const r = buildSetRemarksUnsigned({ account: ACCT, objectId: OID, remarks: [{ name: "title", value: "Hello" }] });
    const rem = (r.unsignedTx.Remarks as any[])[0].Remark;
    expect(rem.RemarkName).toBe(Buffer.from("title", "utf8").toString("hex").toUpperCase());
    expect(rem.RemarkValue).toBe(Buffer.from("Hello", "utf8").toString("hex").toUpperCase());
  });

  it("omits RemarkValue (delete) and flags it MEDIUM", () => {
    const r = buildSetRemarksUnsigned({ account: ACCT, objectId: OID, remarks: [{ name: "CAFE" }] });
    expect((r.unsignedTx.Remarks as any[])[0].Remark).toEqual({ RemarkName: "CAFE" });
    expect(r.preflightFindings?.some((f) => f.ruleId === "REMARK-DELETE")).toBe(true);
  });

  it("sets tfImmutable (Flags:1) and warns", () => {
    const r = buildSetRemarksUnsigned({ account: ACCT, objectId: OID, remarks: [{ name: "CAFE", value: "01", immutable: true }] });
    expect((r.unsignedTx.Remarks as any[])[0].Remark.Flags).toBe(1);
    expect(r.preflightFindings?.some((f) => f.ruleId === "REMARK-IMMUTABLE")).toBe(true);
  });

  it("rejects bad objectId, duplicate names, and >32 remarks", () => {
    expect(() => buildSetRemarksUnsigned({ account: ACCT, objectId: "ABC", remarks: [{ name: "CAFE", value: "01" }] })).toThrow(/64-char hex/);
    expect(() => buildSetRemarksUnsigned({ account: ACCT, objectId: OID, remarks: [{ name: "CAFE", value: "01" }, { name: "CAFE", value: "02" }] })).toThrow(/duplicate/);
    const many = Array.from({ length: 33 }, (_, i) => ({ name: i.toString(16).padStart(4, "0"), value: "01" }));
    expect(() => buildSetRemarksUnsigned({ account: ACCT, objectId: OID, remarks: many })).toThrow(/maximum of 32/);
  });
});

describe("buildClawbackUnsigned", () => {
  it("puts the HOLDER in Amount.issuer (canonical)", () => {
    const r = buildClawbackUnsigned({ account: ACCT, holder: HOLDER, currency: "USD", value: "100" });
    expect(r.unsignedTx.TransactionType).toBe("Clawback");
    expect(r.unsignedTx.Account).toBe(ACCT);
    expect(r.unsignedTx.Amount).toEqual({ currency: "USD", issuer: HOLDER, value: "100" });
    expect(r.preflightFindings?.some((f) => f.ruleId === "CLAWBACK-REQUIRES-OPT-IN")).toBe(true);
  });

  it("rejects native XAH, non-positive value, and self-clawback", () => {
    expect(() => buildClawbackUnsigned({ account: ACCT, holder: HOLDER, currency: "XAH", value: "1" })).toThrow(/native XAH/);
    expect(() => buildClawbackUnsigned({ account: ACCT, holder: HOLDER, currency: "USD", value: "0" })).toThrow(/positive/);
    expect(() => buildClawbackUnsigned({ account: ACCT, holder: ACCT, currency: "USD", value: "1" })).toThrow(/differ/);
  });
});

describe("buildDeepFreezeUnsigned", () => {
  it("maps actions to the correct TrustSet flags", () => {
    const cases: [string, number][] = [
      ["deep_freeze", 4194304], ["clear_deep_freeze", 8388608], ["freeze", 1048576], ["unfreeze", 2097152],
    ];
    for (const [action, flag] of cases) {
      const r = buildDeepFreezeUnsigned({ account: ACCT, counterparty: HOLDER, currency: "USD", action: action as any });
      expect(r.unsignedTx.TransactionType).toBe("TrustSet");
      expect(r.unsignedTx.Flags).toBe(flag);
      expect(r.unsignedTx.LimitAmount).toEqual({ currency: "USD", issuer: HOLDER, value: "0" });
    }
  });

  it("defaults to deep_freeze and warns about the dual-direction block", () => {
    const r = buildDeepFreezeUnsigned({ account: ACCT, counterparty: HOLDER, currency: "USD" });
    expect(r.unsignedTx.Flags).toBe(4194304);
    expect(r.preflightFindings?.some((f) => f.ruleId === "DEEPFREEZE-EFFECT")).toBe(true);
  });

  it("preserves a provided limitValue and rejects XAH / bad action", () => {
    const r = buildDeepFreezeUnsigned({ account: ACCT, counterparty: HOLDER, currency: "USD", limitValue: "1000" });
    expect((r.unsignedTx.LimitAmount as any).value).toBe("1000");
    expect(() => buildDeepFreezeUnsigned({ account: ACCT, counterparty: HOLDER, currency: "XAH" })).toThrow(/XAH/);
    expect(() => buildDeepFreezeUnsigned({ account: ACCT, counterparty: HOLDER, currency: "USD", action: "nope" as any })).toThrow(/action must be/);
  });
});
