import { describe, it, expect } from "vitest";
import { predictTransactor } from "../src/transactorLite.js";

const base = 1_000_000n;
const inc = 200_000n;
const sender = { Balance: "1000000000", OwnerCount: 2, Flags: 0 }; // 1000 XAH, reserve = base + 2*inc

describe("predictTransactor (approximate transactor model)", () => {
  it("native payment within balance -> tesSUCCESS with sender+dest deltas", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "5000000", Fee: "100000" }, sender, dest: { Flags: 0 }, reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.fidelity).toBe("APPROXIMATE");
    expect(p.predictedResult).toBe("tesSUCCESS");
    expect(p.deltas).toHaveLength(2);
  });

  it("amount beyond spendable -> tecUNFUNDED_PAYMENT", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "999000000", Fee: "100000" }, sender, dest: { Flags: 0 }, reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.predictedResult).toBe("tecUNFUNDED_PAYMENT");
  });

  it("destination requires a tag -> tecDST_TAG_NEEDED", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "5000000", Fee: "100000" }, sender, dest: { Flags: 0x00020000 }, reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.predictedResult).toBe("tecDST_TAG_NEEDED");
  });

  it("non-existent destination, amount below base reserve -> tecNO_DST_INSUF_XRP", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "500000", Fee: "100000" }, sender, dest: null, reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.predictedResult).toBe("tecNO_DST_INSUF_XRP");
  });

  it("IOU payment with no trustline -> tecPATH_DRY", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: { currency: "USD", issuer: "rI", value: "10" }, Fee: "100000" }, sender, dest: { Flags: 0 }, senderLines: [], reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.predictedResult).toBe("tecPATH_DRY");
  });

  it("IOU payment with sufficient line -> tesSUCCESS", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: { currency: "USD", issuer: "rI", value: "10" }, Fee: "100000" }, sender, dest: { Flags: 0 }, senderLines: [{ currency: "USD", account: "rI", balance: "50" }], reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.predictedResult).toBe("tesSUCCESS");
  });

  it("cross-currency (SendMax) -> UNSUPPORTED (pathfinding)", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: { currency: "USD", issuer: "rI", value: "10" }, SendMax: "20000000", Fee: "100000" }, sender, dest: { Flags: 0 }, senderLines: [], reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.fidelity).toBe("UNSUPPORTED");
  });

  it("new TrustSet -> tesSUCCESS with owner-reserve delta", () => {
    const p = predictTransactor({ tx: { TransactionType: "TrustSet", Account: "rA", LimitAmount: { currency: "USD", issuer: "rI", value: "100" }, Fee: "100000" }, sender, senderLines: [], reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.predictedResult).toBe("tesSUCCESS");
    expect(p.deltas.some((d) => d.asset === "owner reserve")).toBe(true);
  });

  it("unmodeled tx type -> UNSUPPORTED, null result", () => {
    const p = predictTransactor({ tx: { TransactionType: "OfferCreate", Account: "rA", Fee: "100000" }, sender, reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.fidelity).toBe("UNSUPPORTED");
    expect(p.predictedResult).toBeNull();
  });

  it("missing sender -> UNSUPPORTED", () => {
    const p = predictTransactor({ tx: { TransactionType: "Payment", Account: "rA", Amount: "1", Fee: "100000" }, sender: null, reserveBaseDrops: base, reserveIncDrops: inc });
    expect(p.fidelity).toBe("UNSUPPORTED");
  });
});
