// EscrowFinish / EscrowCancel stakeholders — xahaud applyHook.cpp:385-441 (20ec473be).
// Both code paths add the escrow's source/owner as a STRONG TSH (:416 / :436); the destination is
// STRONG for Finish and WEAK for Cancel (:419-420 / :437-439). The Xahau docs table
// (concepts/weak-and-strong.md) omits the owner; these tests follow the code.
import { describe, it, expect } from "vitest";
import { staticStakeholders, simulateTransaction, type SimDeps } from "../src/simulate.js";
import { encodeHookOn } from "../src/hookon.js";
import { buildBranchOnTxTypeHook, toHex } from "./fixtures.js";

const FINISHER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const OWNER = "rKQpd83hDpdyNGRbAaHavqkFri6TwyVG7h";
const finish = { TransactionType: "EscrowFinish", Account: FINISHER, Owner: OWNER, OfferSequence: 7, Fee: "12", Sequence: 1 };
const cancel = { ...finish, TransactionType: "EscrowCancel" };

describe("staticStakeholders — escrow owner from tx.Owner", () => {
  it("EscrowFinish by a third party: Owner is a STRONG stakeholder, still partial (destination)", () => {
    const r = staticStakeholders(finish);
    expect(r.stakeholders).toContainEqual({ account: OWNER, role: "TSH:Owner", strong: true });
    expect(r.partial).toBe(true);
    expect(r.notes.join(" ")).toMatch(/Destination is also a STRONG stakeholder/);
    expect(r.notes.join(" ")).toMatch(/can roll back \(reject\) this finish/);
  });

  it("EscrowCancel: Owner is STRONG too (not weak); destination flagged WEAK and unresolved", () => {
    const r = staticStakeholders(cancel);
    expect(r.stakeholders).toContainEqual({ account: OWNER, role: "TSH:Owner", strong: true });
    expect(r.partial).toBe(true);
    expect(r.notes.join(" ")).toMatch(/Destination is also a WEAK stakeholder/);
    expect(r.notes.join(" ")).not.toMatch(/reject\) this finish/);
  });

  it("owner finishing their own escrow: owner is the originator, not added twice", () => {
    const r = staticStakeholders({ ...finish, Account: OWNER });
    expect(r.stakeholders).toEqual([{ account: OWNER, role: "originator", strong: true }]);
    expect(r.partial).toBe(true);
  });

  it("EscrowID form: owner is the escrow object's Account (not tied to tx.Owner) — flagged, not guessed", () => {
    const { OfferSequence: _s, ...byId } = finish;
    const r = staticStakeholders({ ...byId, EscrowID: "AB".repeat(32) });
    expect(r.stakeholders.map((s) => s.account)).toEqual([FINISHER]);
    expect(r.partial).toBe(true);
    expect(r.notes.join(" ")).toMatch(/EscrowID/);
  });

  it("missing Owner: no stakeholders beyond the originator, stated", () => {
    const { Owner: _o, ...noOwner } = finish;
    const r = staticStakeholders(noOwner);
    expect(r.stakeholders.map((s) => s.account)).toEqual([FINISHER]);
    expect(r.notes.join(" ")).toMatch(/no Owner r-address/);
  });
});

describe("simulate_transaction — the escrow owner's hook runs STRONG and can reject a third-party finish", () => {
  const OWNER_HOOK = "CC".repeat(32);
  // rolls back unless otxn_type()==0 (Payment) → rolls back EscrowFinish (2) and EscrowCancel (4)
  const REJECTOR = toHex(buildBranchOnTxTypeHook(0));
  const deps: SimDeps = {
    getAccountHooks: async (a) => a === OWNER ? [{ Hook: { HookHash: OWNER_HOOK, HookOn: encodeHookOn(["EscrowFinish", "EscrowCancel"]).hookOn } }] : [],
    getHookDefinition: async (h) => h === OWNER_HOOK ? { CreateCode: REJECTOR } : null,
    getAccountInfo: async () => ({ account_data: { Balance: "999000000", Sequence: 1, Flags: 0 } }),
    getHookState: async () => null,
    getLedgerObject: async () => null,
    getLedgerInfo: async () => ({ ledgerIndex: 100, closeTime: 800000000 }),
    getFee: async () => 12,
    sleep: () => Promise.resolve(),
  };

  it("EscrowFinish: owner hook rollback → WOULD_FAIL_HOOKS (before: owner never simulated)", async () => {
    const s = await simulateTransaction(finish, deps);
    const run = s.hookRuns.find((r) => r.account === OWNER)!;
    expect(run.role).toBe("TSH:Owner (strong)");
    expect(run.strong).toBe(true);
    expect(run.exit).toBe("rollback");
    expect(s.verdict).toBe("WOULD_FAIL_HOOKS");
    expect(s.notes.join(" ")).toMatch(/NOT simulated \(honest gap\)/); // destination still unresolved
  });

  it("EscrowCancel: owner is strong for Cancel as well → its rollback also rejects", async () => {
    const s = await simulateTransaction(cancel, deps);
    expect(s.hookRuns.find((r) => r.account === OWNER)!.strong).toBe(true);
    expect(s.verdict).toBe("WOULD_FAIL_HOOKS");
  });

  it("EscrowID form: owner hook NOT run (owner not derivable) — no false rejection", async () => {
    const { OfferSequence: _s, ...byId } = finish;
    const s = await simulateTransaction({ ...byId, EscrowID: "AB".repeat(32) }, deps);
    expect(s.hookRuns.find((r) => r.account === OWNER)).toBeUndefined();
    expect(s.notes.join(" ")).toMatch(/EscrowID/);
  });
});

describe("hostile self-review regressions (2.2.0)", () => {
  it("neither OfferSequence nor EscrowID: xahaud computes no stakeholders (applyHook.cpp:397-398) — owner NOT added", () => {
    const { OfferSequence: _s, ...bare } = finish;
    const r = staticStakeholders(bare);
    expect(r.stakeholders.map((s) => s.account)).toEqual([FINISHER]);
    expect(r.notes.join(" ")).toMatch(/temMALFORMED/);
  });
  it("non-string Owner is treated as absent, not coerced", () => {
    const r = staticStakeholders({ ...finish, Owner: 5 });
    expect(r.stakeholders.map((s) => s.account)).toEqual([FINISHER]);
  });
});
