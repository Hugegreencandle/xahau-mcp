import { describe, it, expect } from "vitest";
import { computeHookStateCost, MAX_SCALE, BYTES_PER_UNIT } from "../src/hookstate.js";
import { staticStakeholders } from "../src/simulate.js";

describe("computeHookStateCost", () => {
  it("computes capacity and reserve units at the default scale", () => {
    const r = computeHookStateCost({ entries: [{ valueBytes: 10 }, { valueBytes: 200 }], scale: 1 }) as any;
    expect(r.perEntryCapacityBytes).toBe(BYTES_PER_UNIT);
    expect(r.perEntryReserveUnits).toBe(1);
    expect(r.totalReserveUnits).toBe(2);
    expect(r.overflowCount).toBe(0);
  });

  it("scale multiplies both capacity and reserve units", () => {
    const r = computeHookStateCost({ entries: [{ valueBytes: 1 }], scale: 4 }) as any;
    expect(r.perEntryCapacityBytes).toBe(1024);
    expect(r.perEntryReserveUnits).toBe(4); // charged even for 1 byte
    expect(r.totalReserveUnits).toBe(4);
  });

  it("flags overflow and the minimum scale needed", () => {
    const r = computeHookStateCost({ entries: [{ valueBytes: 600 }], scale: 1 }) as any;
    expect(r.overflowCount).toBe(1);
    expect(r.minScaleNeeded).toBe(3); // ceil(600/256)
    expect(r.warning).toMatch(/raise scale to at least 3/);
  });

  it("optionally converts reserve units to XAH", () => {
    const r = computeHookStateCost({ entries: [{ valueBytes: 1 }, { valueBytes: 1 }], scale: 2, ownerReserveIncrementXah: 0.2 }) as any;
    expect(r.totalReserveUnits).toBe(4);
    expect(r.estimatedReserveXah).toBeCloseTo(0.8);
  });

  it("rejects bad scale and empty entries", () => {
    expect(() => computeHookStateCost({ entries: [{ valueBytes: 1 }], scale: MAX_SCALE + 1 })).toThrow(/scale/);
    expect(() => computeHookStateCost({ entries: [] })).toThrow(/at least one/);
    expect(() => computeHookStateCost({ entries: [{ valueBytes: -1 }] })).toThrow(/valueBytes/);
  });
});

describe("staticStakeholders", () => {
  const A = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
  const B = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
  const C = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW";

  it("returns originator + strong destination for Payment", () => {
    const r = staticStakeholders({ TransactionType: "Payment", Account: A, Destination: B });
    expect(r.stakeholderCount).toBe(2);
    expect(r.stakeholders[0]).toMatchObject({ account: A, role: "originator", strong: true });
    expect(r.stakeholders[1]).toMatchObject({ account: B, strong: true });
    expect(r.partial).toBe(false);
  });

  it("marks Remit Inform as a weak stakeholder", () => {
    const r = staticStakeholders({ TransactionType: "Remit", Account: A, Destination: B, Inform: C });
    const inform = r.stakeholders.find((s) => s.account === C)!;
    expect(inform.strong).toBe(false);
    expect(r.strongCount).toBe(2); // originator + destination
    expect(r.weakCount).toBe(1);
  });

  it("flags partial for tx types needing ledger lookups", () => {
    const r = staticStakeholders({ TransactionType: "EscrowFinish", Account: A });
    expect(r.partial).toBe(true);
    expect(r.notes.join(" ")).toMatch(/ledger objects/);
  });

  it("does not duplicate the originator if it also appears as a field", () => {
    const r = staticStakeholders({ TransactionType: "Payment", Account: A, Destination: A });
    expect(r.stakeholderCount).toBe(1);
  });

  it("adds the trustline issuer as a weak stakeholder for TrustSet", () => {
    const r = staticStakeholders({ TransactionType: "TrustSet", Account: A, LimitAmount: { currency: "USD", issuer: B, value: "100" } });
    const iss = r.stakeholders.find((s) => s.account === B)!;
    expect(iss).toMatchObject({ account: B, strong: false });
    expect(r.weakCount).toBe(1);
  });

  it("adds the holder (Amount.issuer) as a weak stakeholder for Clawback", () => {
    const r = staticStakeholders({ TransactionType: "Clawback", Account: A, Amount: { currency: "USD", issuer: B, value: "5" } });
    const holder = r.stakeholders.find((s) => s.account === B)!;
    expect(holder).toMatchObject({ account: B, strong: false });
  });

  it("adds each signer entry as a strong stakeholder for SignerListSet", () => {
    const r = staticStakeholders({
      TransactionType: "SignerListSet", Account: A,
      SignerEntries: [{ SignerEntry: { Account: B, SignerWeight: 1 } }, { SignerEntry: { Account: C, SignerWeight: 1 } }],
    });
    expect(r.stakeholders.find((s) => s.account === B)).toMatchObject({ strong: true });
    expect(r.stakeholders.find((s) => s.account === C)).toMatchObject({ strong: true });
    expect(r.strongCount).toBe(3); // originator + 2 signers
  });

  it("adds each mint destination as a weak stakeholder for GenesisMint", () => {
    const r = staticStakeholders({
      TransactionType: "GenesisMint", Account: A,
      GenesisMints: [{ GenesisMint: { Destination: B, Amount: "1000000" } }, { GenesisMint: { Destination: C, Amount: "2000000" } }],
    });
    expect(r.stakeholders.find((s) => s.account === B)).toMatchObject({ strong: false });
    expect(r.stakeholders.find((s) => s.account === C)).toMatchObject({ strong: false });
    expect(r.weakCount).toBe(2);
  });

  it("flags partial when a Remit carries URITokenIDs (per-URIToken issuer is ledger-derived)", () => {
    const r = staticStakeholders({ TransactionType: "Remit", Account: A, Destination: B, URITokenIDs: ["A".repeat(64)] });
    expect(r.partial).toBe(true);
    expect(r.notes.join(" ")).toMatch(/URIToken/);
  });
});
