import { describe, it, expect } from "vitest";
import { inspectEmitted } from "../src/emitted.js";
import { encodeTxBlob } from "../src/codec.js";

const ACC = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const ACC2 = "rNrJ8vB4ruKpkEfLW4iuPdRkP1ZtJayngu";

describe("inspect_emitted_tx", () => {
  it("decodes a real (round-tripped) emitted Payment + danger-scores it", () => {
    const { txBlobHex } = encodeTxBlob({ TransactionType: "Payment", Account: ACC, Destination: ACC2, Amount: "5000000", Sequence: 1, Fee: "10", LastLedgerSequence: 99 });
    const r = inspectEmitted([txBlobHex]);
    expect(r.count).toBe(1);
    expect(r.inspections[0].transactionType).toBe("Payment");
    expect(r.inspections[0].summary).toMatch(/send 5 XAH/);
    expect(r.inspections[0].dangerTier).toBe("SAFE");
    expect(r.headline).toMatch(/1\/1.*Payment/);
  });

  it("flags a dangerous emitted SetRegularKey", () => {
    const { txBlobHex } = encodeTxBlob({ TransactionType: "SetRegularKey", Account: ACC, RegularKey: ACC2, Sequence: 1, Fee: "10", LastLedgerSequence: 99 });
    const r = inspectEmitted([txBlobHex]);
    expect(r.inspections[0].dangerTier).not.toBe("SAFE");
    expect((r.inspections[0].warnings ?? []).join(" ")).toMatch(/sign/i);
  });

  it("reports an undecodable blob honestly (never silently dropped)", () => {
    const r = inspectEmitted(["DEADBEEF"]);
    expect(r.inspections[0].decoded).toBeNull();
    expect(r.inspections[0].decodeError).toMatch(/could not decode/);
    expect(r.headline).toMatch(/0\/1/);
  });

  it("mixed batch: worst tier dominates the headline", () => {
    const safe = encodeTxBlob({ TransactionType: "Payment", Account: ACC, Destination: ACC2, Amount: "1000000", Sequence: 1, Fee: "10", LastLedgerSequence: 99 }).txBlobHex;
    const risky = encodeTxBlob({ TransactionType: "SetRegularKey", Account: ACC, RegularKey: ACC2, Sequence: 1, Fee: "10", LastLedgerSequence: 99 }).txBlobHex;
    const r = inspectEmitted([safe, risky]);
    expect(r.headline).toMatch(/worst tier (CAUTION|DANGER)/);
  });
});
