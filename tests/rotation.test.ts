import { describe, it, expect } from "vitest";
import { buildSetRegularKeyUnsigned, buildDisableMasterUnsigned, buildSignerListSetUnsigned } from "../src/builders.js";

const A = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";   // valid r-addresses (genesis-style)
const B = "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH";

describe("rotation builders — safety", () => {
  it("SetRegularKey: assigns key, warns to test before disabling master", () => {
    const r = buildSetRegularKeyUnsigned({ account: A, regularKey: B, network: "mainnet" });
    expect(r.unsignedTx.TransactionType).toBe("SetRegularKey");
    expect(r.unsignedTx.RegularKey).toBe(B);
    expect(r.warning).toMatch(/TEST transaction|before you disable/i);
  });

  it("SetRegularKey: rejects self regular key", () => {
    expect(() => buildSetRegularKeyUnsigned({ account: A, regularKey: A })).toThrow(/differ/);
  });

  it("disable-master: FAILS CLOSED when no readiness supplied (audit #3)", () => {
    const r = buildDisableMasterUnsigned({ account: A, network: "mainnet" });   // readiness undefined
    expect(r.blocked).toBe(true);
    expect(r.warning).toMatch(/BLOCKED — no safety assessment/);
  });

  it("disable-master: BLOCKED when no PROVEN alternative signer", () => {
    const r = buildDisableMasterUnsigned({ account: A, network: "mainnet", readiness: { safeToDisable: false, reasons: ["no regular key and no signer list"] } });
    expect(r.blocked).toBe(true);
    expect(r.warning).toMatch(/BLOCKED — no PROVEN/);
  });

  it("disable-master: proceeds (irreversible warning) only when safeToDisable proven", () => {
    const r = buildDisableMasterUnsigned({ account: A, network: "mainnet", readiness: { safeToDisable: true, reasons: ["regular key has signed (PROVEN alternative)"] } });
    expect(r.blocked).toBe(false);
    expect(r.unsignedTx.SetFlag).toBe(4);     // asfDisableMaster
    expect(r.warning).toMatch(/IRREVERSIBLE/);
  });

  it("SignerListSet: rejects duplicate signers (audit #5)", () => {
    expect(() => buildSignerListSetUnsigned({ account: A, quorum: 2, signers: [{ account: B, weight: 1 }, { account: B, weight: 1 }] })).toThrow(/duplicate signer/);
  });

  it("SignerListSet: rejects unreachable quorum (lockout prevention)", () => {
    expect(() => buildSignerListSetUnsigned({ account: A, quorum: 5, signers: [{ account: B, weight: 1 }] })).toThrow(/unreachable quorum|locked out/);
  });

  it("SignerListSet: builds a reachable list; quorum 0 removes", () => {
    const r = buildSignerListSetUnsigned({ account: A, quorum: 1, signers: [{ account: B, weight: 1 }], network: "mainnet" });
    expect(r.unsignedTx.SignerQuorum).toBe(1);
    expect((r.unsignedTx.SignerEntries as any[]).length).toBe(1);
    const rm = buildSignerListSetUnsigned({ account: A, quorum: 0 });
    expect(rm.unsignedTx.SignerEntries).toBeUndefined();
  });
});
