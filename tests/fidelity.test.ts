import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pkg from "xrpl-accountlib";
import { reconstructContext, compareToOnChain, onChainResult, runFidelityCase } from "../src/fidelity.js";
import { runHook, type SandboxResult } from "../src/sandbox.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
const loadHex = (n: string) => readFileSync(join(DIR, n + ".hex"), "utf8").trim();

const LIBS = (pkg as unknown as { libraries: { rippleAddressCodec: { decodeAccountID: (s: string) => Uint8Array } } }).libraries;
const accIdHex = (r: string) => Buffer.from(LIBS.rippleAddressCodec.decodeAccountID(r)).toString("hex").toUpperCase();

// sfield codes ((typeCode<<16)|nth): Account = (8<<16)|1, Amount = (6<<16)|1, Destination = (8<<16)|3
const ACCOUNT_CODE = (8 << 16) | 1;
const AMOUNT_CODE = (6 << 16) | 1;
const DEST_CODE = (8 << 16) | 3;

const ACCOUNT_R = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const DEST_R = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

describe("fidelity: reconstructContext (sto round-trip from real tx JSON)", () => {
  const tx = {
    TransactionType: "Payment",
    Account: ACCOUNT_R,
    Destination: DEST_R,
    Amount: "1000000",
    Fee: "12",
    Sequence: 1,
    ledger_index: 5_000_000,
  };
  const ctx = reconstructContext(tx, "00".repeat(20));

  it("carries txType and ledgerSeq from the tx", () => {
    expect(ctx.txType).toBe("Payment");
    expect(ctx.ledgerSeq).toBe(5_000_000);
  });

  it("maps the Account field by its sfield code to the 20-byte AccountID value", () => {
    expect(ctx.otxnFields?.[String(ACCOUNT_CODE)]).toBe(accIdHex(ACCOUNT_R));
    expect(ctx.otxnFields?.[String(ACCOUNT_CODE)]).toHaveLength(40); // 20 bytes
  });

  it("maps the Destination field by its sfield code", () => {
    expect(ctx.otxnFields?.[String(DEST_CODE)]).toBe(accIdHex(DEST_R));
  });

  it("maps the Amount field by its sfield code to its 8-byte native value (round-trips through the VM)", () => {
    const amt = ctx.otxnFields?.[String(AMOUNT_CODE)];
    expect(amt).toBeDefined();
    expect(amt).toHaveLength(16); // native amount = 8 bytes
    // top bit of the first byte is the "not-XRP" flag = 0 for native; the positive-sign bit is set => 0x40
    expect(amt!.slice(0, 2)).toBe("40");
    // the field is keyed exactly as the VM's otxn_field reads it: ctx.otxnFields[String(sfieldCode)]
    expect(Object.keys(ctx.otxnFields!)).toContain(String(AMOUNT_CODE));
  });

  it("sets otxnBlob to the full serialized tx", () => {
    expect(ctx.otxnBlob).toMatch(/^[0-9A-F]+$/);
    // blob must contain the encoded account id
    expect(ctx.otxnBlob).toContain(accIdHex(ACCOUNT_R));
  });
});

describe("fidelity: onChainResult mapping (empirically determined)", () => {
  it("HookResult=3 => accept", () => {
    expect(onChainResult({ HookResult: 3 }).decision).toBe("accept");
    expect(onChainResult({ HookResult: "3" }).decision).toBe("accept");
  });
  it("HookResult=4 => rollback (reject)", () => {
    expect(onChainResult({ HookResult: 4 }).decision).toBe("rollback");
  });
  it("HookResult=0 => rollback (error)", () => {
    expect(onChainResult({ HookResult: 0 }).decision).toBe("rollback");
  });
  it("engineResult fallback when HookResult absent", () => {
    expect(onChainResult({ engineResult: "tesSUCCESS" }).decision).toBe("accept");
    expect(onChainResult({ engineResult: "tecHOOK_REJECTED" }).decision).toBe("rollback");
  });
  it("returns null (never silently mis-scores) for unrecognized data", () => {
    expect(onChainResult({}).decision).toBeNull();
    expect(onChainResult({ HookResult: 99 }).decision).toBeNull();
  });
});

describe("fidelity: compareToOnChain (mapping + degraded exclusion)", () => {
  const nonDegradedAccept: SandboxResult = {
    exit: "accept", returnCode: "3", returnString: null, stateWrites: [], stateApplied: true,
    emitted: [], trace: [], guardCalls: 0, unsupportedCalls: [], fidelity: "LOCAL_VM", degraded: false,
    wantedKeylets: [], caveat: "",
  };

  it("scores agree:true when VM accept matches on-chain accept", () => {
    const c = compareToOnChain(nonDegradedAccept, { HookResult: 3 });
    expect(c.agree).toBe(true);
    expect(c.onChain.result).toBe("accept");
  });

  it("scores agree:false when VM accept disagrees with on-chain rollback", () => {
    const c = compareToOnChain(nonDegradedAccept, { HookResult: 4 });
    expect(c.agree).toBe(false);
  });

  it("EXCLUDES a degraded VM run (agree:null) — never scored as match or miss", () => {
    const degraded: SandboxResult = { ...nonDegradedAccept, degraded: true, unsupportedCalls: ["meta_slot"] };
    const c = compareToOnChain(degraded, { HookResult: 3 });
    expect(c.agree).toBeNull();
    expect(c.reason).toMatch(/DEGRADED/);
  });

  it("EXCLUDES when on-chain decision is indeterminate (agree:null)", () => {
    const c = compareToOnChain(nonDegradedAccept, {});
    expect(c.agree).toBeNull();
  });

  it("EXCLUDES a non-degraded run that never reached accept/rollback (agree:null)", () => {
    const noExit: SandboxResult = { ...nonDegradedAccept, exit: "no-exit-called" };
    const c = compareToOnChain(noExit, { HookResult: 3 });
    expect(c.agree).toBeNull();
  });
});

describe("fidelity: runFidelityCase over a REAL mainnet hook fixture", () => {
  // The genesis reward hook ACCEPTS a ClaimReward (see tests/regression.test.ts). On chain that
  // success carries HookResult=3. A non-degraded VM run should therefore AGREE.
  it("reward hook @ ClaimReward agrees with on-chain accept (HookResult=3), non-degraded", () => {
    const res = runFidelityCase({
      tx: { TransactionType: "ClaimReward", Account: ACCOUNT_R, ledger_index: 23_478_900 },
      createCodeHex: loadHex("genesis-reward"),
      hookExecution: { HookResult: 3, HookReturnCode: 0, HookHash: "AB".repeat(16) },
      hookAccountId: "00".repeat(20),
    });
    expect(res.degraded).toBe(false);
    expect(res.vmExit).toBe("accept");
    expect(res.onChainResult).toBe("accept");
    expect(res.agree).toBe(true);
  });

  it("if the on-chain record claimed rollback, a non-degraded accepting run reports agree:false (honest disagreement)", () => {
    const res = runFidelityCase({
      tx: { TransactionType: "ClaimReward", Account: ACCOUNT_R, ledger_index: 23_478_900 },
      createCodeHex: loadHex("genesis-reward"),
      hookExecution: { HookResult: 4 },
      hookAccountId: "00".repeat(20),
    });
    expect(res.degraded).toBe(false);
    expect(res.agree).toBe(false);
  });

  it("invalid createCode => degraded, agree:null (excluded)", () => {
    const res = runFidelityCase({
      tx: { TransactionType: "Payment", Account: ACCOUNT_R, ledger_index: 1 },
      createCodeHex: "DEADBEEF",
      hookExecution: { HookResult: 3 },
      hookAccountId: "00".repeat(20),
    });
    expect(res.degraded).toBe(true);
    expect(res.agree).toBeNull();
  });

  it("sanity: a direct runHook with the reconstructed context reaches accept", () => {
    const ctx = reconstructContext({ TransactionType: "ClaimReward", Account: ACCOUNT_R, ledger_index: 23_478_900 }, "00".repeat(20));
    const vm = runHook(new Uint8Array(Buffer.from(loadHex("genesis-reward"), "hex")), ctx);
    expect(vm.exit).toBe("accept");
  });
});
