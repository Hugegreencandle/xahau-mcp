import { describe, it, expect } from "vitest";
import { scorePayload } from "../src/scam.js";
import { encodeTxBlob, decodeTxBlob } from "../src/codec.js";

const R = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const R2 = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
const find = (r: ReturnType<typeof scorePayload>, id: string) => r.findings.find((f) => f.ruleId === id);

describe("scam_check", () => {
  it("(1) normal Payment with LastLedgerSequence => SAFE, score < 10", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "1000000", Fee: "12", Sequence: 1, LastLedgerSequence: 9000000 });
    expect(r.tier).toBe("SAFE");
    expect(r.dangerScore).toBeLessThan(10);
  });

  it("(2) SetHook tx => CAUTION or DANGER, RULE-1 triggered", () => {
    const r = scorePayload({ TransactionType: "SetHook", Account: R, LastLedgerSequence: 9000000, Hooks: [] });
    expect(["CAUTION", "DANGER"]).toContain(r.tier);
    expect(find(r, "SET_HOOK_NO_AUDIT")?.triggered).toBe(true);
  });

  it("(3) AccountDelete to a different address => DANGER, score >= 60", () => {
    const r = scorePayload({ TransactionType: "AccountDelete", Account: R, Destination: R2, LastLedgerSequence: 9000000 });
    expect(r.tier).toBe("DANGER");
    expect(r.dangerScore).toBeGreaterThanOrEqual(60);
    expect(find(r, "ACCOUNT_DELETE_OTHER_DEST")?.triggered).toBe(true);
  });

  it("(3b) AccountDelete to your OWN address does not fire the DANGER rule", () => {
    const r = scorePayload({ TransactionType: "AccountDelete", Account: R, Destination: R, LastLedgerSequence: 9000000 });
    expect(find(r, "ACCOUNT_DELETE_OTHER_DEST")?.triggered).toBe(false);
  });

  it("(4) SetRegularKey => HIGH finding triggered", () => {
    const r = scorePayload({ TransactionType: "SetRegularKey", Account: R, RegularKey: R2, LastLedgerSequence: 9000000 });
    const f = find(r, "SET_REGULAR_KEY");
    expect(f?.triggered).toBe(true);
    expect(f?.severity).toBe("HIGH");
  });

  it("(4b) SetRegularKey with no RegularKey => REMOVE_REGULAR_KEY fires too", () => {
    const r = scorePayload({ TransactionType: "SetRegularKey", Account: R, LastLedgerSequence: 9000000 });
    expect(find(r, "REMOVE_REGULAR_KEY")?.triggered).toBe(true);
  });

  it("(5) Payment > 10000 XAH => MEDIUM finding", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "20000000000", LastLedgerSequence: 9000000 });
    const f = find(r, "LARGE_PAYMENT");
    expect(f?.triggered).toBe(true);
    expect(f?.severity).toBe("MEDIUM");
  });

  it("(6) tx with no LastLedgerSequence => LOW finding RULE-7", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "1000000" });
    expect(find(r, "NO_LAST_LEDGER")?.triggered).toBe(true);
  });

  it("(7) pre-signed blob (has TxnSignature) => LOW RULE-8", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "1000000", LastLedgerSequence: 9000000, TxnSignature: "ABCD", SigningPubKey: "ED00" });
    expect(find(r, "ALREADY_SIGNED")?.triggered).toBe(true);
  });

  it("(8) txBlobHex input path works (round-trips a real blob)", () => {
    const { txBlobHex } = encodeTxBlob({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "1000000", Fee: "12", Sequence: 1, LastLedgerSequence: 9000000 });
    const tx = decodeTxBlob(txBlobHex) as Record<string, any>;
    const r = scorePayload(tx);
    expect(r.tx.TransactionType).toBe("Payment");
    expect(r.tier).toBe("SAFE");
  });

  it("(9) empty tx => no crash, no rule findings triggered (besides describe advisories)", () => {
    const r = scorePayload({});
    expect(r.findings.length).toBeGreaterThan(0); // findings array always populated
    const ruleHits = r.findings.filter((f) => !f.ruleId.startsWith("DESCRIBE_WARN_") && f.triggered);
    // only NO_LAST_LEDGER can legitimately fire on an empty object
    expect(ruleHits.every((f) => f.ruleId === "NO_LAST_LEDGER")).toBe(true);
  });

  it("(10) DANGER tier is never applied to a benign Payment", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "500000000", LastLedgerSequence: 9000000 });
    expect(r.tier).not.toBe("DANGER");
  });

  it("(11) every finding is labeled as a potential risk, not a confirmed scam", () => {
    const r = scorePayload({ TransactionType: "SetHook", Account: R, LastLedgerSequence: 9000000, Hooks: [] });
    for (const f of r.findings) {
      expect(f.explanation.toLowerCase()).toContain("potential risk");
    }
  });

  it("(12) dangerScore is capped at 100", () => {
    const r = scorePayload({ TransactionType: "AccountDelete", Account: R, Destination: R2 }); // 60 + 10 (no LLS) only, but verify cap holds generally
    expect(r.dangerScore).toBeLessThanOrEqual(100);
    // stack many: SetHook + no LLS + signed + describe warnings
    const r2 = scorePayload({ TransactionType: "SetHook", Account: R, Hooks: [], TxnSignature: "AB", SigningPubKey: "ED" });
    expect(r2.dangerScore).toBeLessThanOrEqual(100);
  });

  it("(13) verdict + summary are present human strings", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "1000000", LastLedgerSequence: 9000000 });
    expect(typeof r.verdict).toBe("string");
    expect(r.verdict.length).toBeGreaterThan(0);
    expect(r.summary).toContain("dangerScore");
  });

  it("(14) describe advisories do not double-count the no-expiry warning", () => {
    const r = scorePayload({ TransactionType: "Payment", Account: R, Destination: R2, Amount: "1000000" });
    const expiryAdvisories = r.findings.filter((f) => f.ruleId.startsWith("DESCRIBE_WARN_") && /never expires|LastLedgerSequence/i.test(f.explanation));
    expect(expiryAdvisories.length).toBe(0); // covered by RULE-7, suppressed in advisory fold
    expect(find(r, "NO_LAST_LEDGER")?.triggered).toBe(true);
  });
});
