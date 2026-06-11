import { describe, it, expect } from "vitest";
import { diagnoseFailedTx, interpretHookMessage, type DiagnoseDeps } from "../src/diagnose.js";

const HASH = "AB".repeat(32);
const hex = (s: string) => Buffer.from(s, "utf-8").toString("hex").toUpperCase();

const deps = (result: Record<string, any> | null): DiagnoseDeps => ({ getTx: async () => result });

describe("interpretHookMessage", () => {
  it("parses the genesis reward wait message into a claimable-at date", () => {
    const m = interpretHookMessage("You must wait 0086400 seconds", 834361232);
    expect(m).toMatch(/86400 seconds early/);
    expect(m).toMatch(/2026-/); // 834361232 + 86400 + epoch lands in 2026
    expect(m).toMatch(/reward_status/);
  });
  it("explains governance-disabled and pass-through messages", () => {
    expect(interpretHookMessage("Reward: Rewards are disabled by governance.", 0)).toMatch(/switched off by governance/);
    expect(interpretHookMessage("Reward: Passing non-claim txn", 0)).toMatch(/not the cause/);
    expect(interpretHookMessage("something else entirely", 0)).toBeNull();
  });
});

describe("diagnose_failed_tx", () => {
  it("not found: triage covers expiry, wrong network, never-submitted", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps(null));
    expect(d.found).toBe(false);
    expect(d.summary).toMatch(/NOT FOUND/);
    expect(d.summary).toMatch(/21337/);
    expect(d.fixes.join(" ")).toMatch(/testnet/);
    expect(d.fixes.join(" ")).toMatch(/prepare_transaction/);
  });

  it("tecHOOK_REJECTED by the reward hook: decoded return string + claimable-at interpretation", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: true, date: 834361232,
      tx_json: { TransactionType: "ClaimReward", Account: "rUser", Issuer: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" },
      meta: {
        TransactionResult: "tecHOOK_REJECTED",
        HookExecutions: [{ HookExecution: {
          HookAccount: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
          HookHash: "610F33B8EBF7EC795F822A454FB852156AEFE50BE0CB8326338A81CD74801864",
          HookResult: 4, HookReturnCode: "a3",
          HookReturnString: hex("You must wait 1234567 seconds"),
        }}],
      },
    }));
    expect(d.failed).toBe(true);
    expect(d.engineResult).toBe("tecHOOK_REJECTED");
    expect(d.engineResultCode).toBe(153);
    expect(d.hookRejections).toHaveLength(1);
    expect(d.hookRejections[0].hookLabel).toMatch(/genesis reward/);
    expect(d.hookRejections[0].returnString).toBe("You must wait 1234567 seconds");
    expect(d.hookRejections[0].interpretation).toMatch(/1234567 seconds early/);
    expect(d.notes.join(" ")).toMatch(/FEE WAS BURNED/);
  });

  it("accepting hook executions are not listed as rejections", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: true,
      tx_json: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "1000000" },
      meta: { TransactionResult: "tesSUCCESS", HookExecutions: [{ HookExecution: { HookResult: 3, HookHash: "00".repeat(32) } }] },
    }));
    expect(d.failed).toBe(false);
    expect(d.hookRejections).toHaveLength(0);
    expect(d.summary).toMatch(/SUCCEEDED/);
  });

  it("partial payment trap: tesSUCCESS but delivered < requested", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: true,
      tx_json: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "100000000", Flags: 0x00020000 },
      meta: { TransactionResult: "tesSUCCESS", delivered_amount: "25000000" },
    }));
    expect(d.failed).toBe(false);
    expect(d.partialDelivery).not.toBeNull();
    expect(d.summary).toMatch(/PARTIAL PAYMENT/);
    expect(d.fixes.join(" ")).toMatch(/delivered_amount/);
  });

  it("tecNO_DST: concrete cause + reserve fix", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: true,
      tx_json: { TransactionType: "Payment", Account: "rA", Destination: "rGone", Amount: "500000" },
      meta: { TransactionResult: "tecNO_DST" },
    }));
    expect(d.failed).toBe(true);
    expect(d.causes[0]).toMatch(/destination account does not exist/);
    expect(d.fixes[0]).toMatch(/base reserve/);
  });

  it("tefMAX_LEDGER: expired — rebuild guidance", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: true,
      tx_json: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "1" },
      meta: { TransactionResult: "tefMAX_LEDGER" },
    }));
    expect(d.causes[0]).toMatch(/LastLedgerSequence passed/);
    expect(d.notes.join(" ")).toMatch(/no fee was burned/);
  });

  it("terQUEUED is explained as not-a-failure", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: false,
      tx_json: { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "1" },
      meta: { TransactionResult: "terQUEUED" },
    }));
    expect(d.causes[0]).toMatch(/not a failure/);
    expect(d.notes.join(" ")).toMatch(/NOT yet validated/);
  });

  it("unknown tec code falls back to result-class explanation", async () => {
    const d = await diagnoseFailedTx(HASH, "mainnet", deps({
      validated: true,
      tx_json: { TransactionType: "Invoke", Account: "rA" },
      meta: { TransactionResult: "tecINTERNAL" },
    }));
    expect(d.failed).toBe(true);
    expect(d.causes[0]).toMatch(/tecINTERNAL/);
    expect(d.notes.join(" ")).toMatch(/FEE WAS BURNED/);
  });
});
