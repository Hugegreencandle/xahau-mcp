// Named-hook firing rule — xahaud Transactor.cpp:1357-1369 (executeHookChain) / :286-298
// (calculateHookChainFee), introduced by 663ed4edb "Named Hook (#718)". A Hook object with a
// non-empty HookName fires only for a tx carrying the byte-identical sfHookName.
//
// Fixture: LITERAL testnet RPC captures (tests/fixtures-named-hook/testnet-accept-hook.json),
// fetched read-only 2026-09-30. The chain itself recorded the ground truth:
//   8F67F380… Invoke, no HookName   → 0 HookExecutions
//   BD79993A… Invoke, HookName "accept" → 1 HookExecution (68A7D6BD…, HookResult 3 = accept)
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { simulateTransaction, type SimDeps } from "../src/simulate.js";
import { encodeTxBlob } from "../src/codec.js";
import { gradeSignals } from "../src/quantum.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = JSON.parse(readFileSync(join(HERE, "fixtures-named-hook", "testnet-accept-hook.json"), "utf8"));
const HOOK_ACCOUNT = "rKQpd83hDpdyNGRbAaHavqkFri6TwyVG7h";
const HOOK_HASH = "68A7D6BD77FB98A7E05E0BFD12180352903F131B2780F848267C37DC0837707C";
const HOOK_OBJ = FX.accountHooks.account_objects[0];
const DEF = FX.hookDefinition.node;

/** Strip signature/response-only fields: the simulator takes an UNSIGNED tx. */
function unsigned(r: Record<string, any>): Record<string, unknown> {
  const { meta: _m, hash: _h, TxnSignature: _s, SigningPubKey: _p, ctid: _c, date: _d, inLedger: _i, ledger_index: _l, status: _st, validated: _v, ...tx } = r;
  return tx;
}

function deps(hooksByAccount: Record<string, Record<string, unknown>[]>, defs: Record<string, Record<string, unknown>> = { [HOOK_HASH]: DEF }): SimDeps {
  return {
    getAccountHooks: async (a) => hooksByAccount[a] ?? [],
    getHookDefinition: async (h) => defs[h] ?? null,
    getAccountInfo: async () => ({ account_data: { Balance: "999000000", Sequence: 844072033, Flags: 0 } }),
    getHookState: async () => null,
    getLedgerObject: async () => null,
    getLedgerInfo: async () => ({ ledgerIndex: 12764480, closeTime: 844072133 }),
    getFee: async () => 10,
    sleep: () => Promise.resolve(),
  };
}

const onChainHooks = { [HOOK_ACCOUNT]: HOOK_OBJ.Hooks };

describe("fixture sanity — the chain's own verdicts", () => {
  it("hook object carries HookName 'accept'; no-name tx ran 0 hooks, named tx ran it", () => {
    expect(HOOK_OBJ.Hooks[0].Hook.HookName).toBe("616363657074");
    expect(FX.txNoHookName.HookName).toBeUndefined();
    expect(FX.txNoHookName.meta.HookExecutions ?? []).toHaveLength(0);
    expect(FX.txWithHookName.HookName).toBe("616363657074");
    expect(FX.txWithHookName.meta.HookExecutions).toHaveLength(1);
    expect(FX.txWithHookName.meta.HookExecutions[0].HookExecution.HookHash).toBe(HOOK_HASH);
  });
});

describe("simulate_transaction — named-hook rule reproduces the testnet result", () => {
  it("Invoke WITHOUT HookName: named hook does not fire (chain: 0 executions)", async () => {
    const s = await simulateTransaction(unsigned(FX.txNoHookName), deps(onChainHooks));
    const run = s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!;
    expect(run.fired).toBe(false);
    expect(run.skippedReason).toMatch(/requires HookName 616363657074 \("accept"\)/);
    expect(run.skippedReason).toMatch(/carries no HookName/);
    expect(run.requiredHookName).toBe("616363657074");
    expect(s.verdict).toBe("NO_HOOKS_FIRE");
  });

  it("Invoke WITH HookName 'accept': the hook fires and accepts (chain: HookResult 3)", async () => {
    const s = await simulateTransaction(unsigned(FX.txWithHookName), deps(onChainHooks));
    const run = s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!;
    expect(run.fired).toBe(true);
    expect(run.skippedReason).toBeUndefined();
    expect(run.exit).toBe("accept");
    expect(s.verdict).toBe("WOULD_PASS_HOOKS");
    expect(s.staticChecks.find((c) => c.name === "HookName")?.status).toBe("WARN");
  });

  it("different name (case differs in the BYTES, 'Accept'): not fired", async () => {
    const tx = { ...unsigned(FX.txWithHookName), HookName: "416363657074" };
    const s = await simulateTransaction(tx, deps(onChainHooks));
    const run = s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!;
    expect(run.fired).toBe(false);
    expect(run.skippedReason).toMatch(/carries 416363657074 \("Accept"\)/);
  });

  it("hex CASE is irrelevant (same bytes): lowercase hex on the tx still fires", async () => {
    const tx = { ...unsigned(FX.txWithHookName), HookName: "616363657074".toLowerCase() };
    const hooks = { [HOOK_ACCOUNT]: [{ Hook: { ...HOOK_OBJ.Hooks[0].Hook, HookName: "616363657074".toUpperCase() } }] };
    const s = await simulateTransaction(tx, deps(hooks));
    expect(s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!.fired).toBe(true);
  });

  it("empty HookName on the hook = no requirement: fires with or without a tx HookName", async () => {
    const hooks = { [HOOK_ACCOUNT]: [{ Hook: { HookHash: HOOK_HASH, HookName: "" } }] };
    for (const tx of [unsigned(FX.txNoHookName), unsigned(FX.txWithHookName)]) {
      const s = await simulateTransaction(tx, deps(hooks));
      expect(s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!.fired).toBe(true);
    }
  });

  it("tx carries a HookName but the hook is unnamed: fires (no requirement)", async () => {
    const hooks = { [HOOK_ACCOUNT]: [{ Hook: { HookHash: HOOK_HASH } }] };
    const s = await simulateTransaction(unsigned(FX.txWithHookName), deps(hooks));
    expect(s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!.fired).toBe(true);
  });

  it("empty HookName on the tx does not satisfy a named hook", async () => {
    const tx = { ...unsigned(FX.txWithHookName), HookName: "" };
    const s = await simulateTransaction(tx, deps(onChainHooks));
    const run = s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!;
    expect(run.fired).toBe(false);
    expect(run.skippedReason).toMatch(/an empty HookName/);
  });

  it("multiple hooks with different names: only the matching one fires, per position", async () => {
    const OTHER = "11".repeat(32);
    const hooks = { [HOOK_ACCOUNT]: [
      { Hook: { HookHash: OTHER, HookName: "7061796D656E74" } },   // "payment"
      { Hook: { HookHash: HOOK_HASH, HookName: "616363657074" } },  // "accept"
      { Hook: { HookHash: HOOK_HASH } },                             // unnamed
    ] };
    const s = await simulateTransaction(unsigned(FX.txWithHookName), deps(hooks, { [HOOK_HASH]: DEF, [OTHER]: DEF }));
    expect(s.hookRuns.map((r) => [r.position, r.fired])).toEqual([[0, false], [1, true], [2, true]]);
    expect(s.hookRuns[0].skippedReason).toMatch(/"payment"/);
  });

  it("applies to TSH chains too (strong Destination of an Invoke) — no strong/weak exemption", async () => {
    const SENDER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
    const tx = { TransactionType: "Invoke", Account: SENDER, Destination: HOOK_ACCOUNT, Fee: "39", Sequence: 1 };
    const s = await simulateTransaction(tx, deps(onChainHooks));
    const run = s.hookRuns.find((r) => r.account === HOOK_ACCOUNT)!;
    expect(run.role).toMatch(/TSH:Destination \(strong\)/);
    expect(run.fired).toBe(false);
    const s2 = await simulateTransaction({ ...tx, HookName: "616363657074" }, deps(onChainHooks));
    expect(s2.hookRuns.find((r) => r.account === HOOK_ACCOUNT)!.fired).toBe(true);
  });

  it("the name check wins over HookOn (checked first, same as xahaud)", async () => {
    // AccountSet is excluded by this hook's HookOn; without a name it would say 'HookOn does not include'
    const tx = { ...unsigned(FX.txNoHookName), TransactionType: "AccountSet" };
    const s = await simulateTransaction(tx, deps(onChainHooks));
    expect(s.hookRuns[0].skippedReason).toMatch(/requires HookName/);
  });

  it("candidate code can declare a HookName and is gated the same way", async () => {
    const opts = { candidateHooks: { [HOOK_ACCOUNT]: { createCodeHex: DEF.CreateCode, hookName: "616363657074" } } };
    const off = await simulateTransaction(unsigned(FX.txNoHookName), deps({}), opts);
    expect(off.hookRuns[0].fired).toBe(false);
    const on = await simulateTransaction(unsigned(FX.txWithHookName), deps({}), opts);
    expect(on.hookRuns[0].fired).toBe(true);
  });
});

describe("tx HookName preflight (Transactor.cpp:152-160, SetHook::validateHookName)", () => {
  const base = unsigned(FX.txWithHookName);
  it("too short (<4 bytes) → FAIL temMALFORMED", async () => {
    const s = await simulateTransaction({ ...base, HookName: "616263" }, deps(onChainHooks));
    expect(s.staticChecks.find((c) => c.name === "HookName")).toMatchObject({ status: "FAIL" });
  });
  it("too long (>16 bytes) → FAIL", async () => {
    const s = await simulateTransaction({ ...base, HookName: "61".repeat(17) }, deps(onChainHooks));
    expect(s.staticChecks.find((c) => c.name === "HookName")?.detail).toMatch(/17 bytes/);
  });
  it("invalid UTF-8 → FAIL", async () => {
    const s = await simulateTransaction({ ...base, HookName: "FFFEFDFC" }, deps(onChainHooks));
    expect(s.staticChecks.find((c) => c.name === "HookName")?.detail).toMatch(/UTF-8/);
  });
  it("plain text instead of hex → FAIL with the hex hint, and the named hook does not fire", async () => {
    const s = await simulateTransaction({ ...base, HookName: "accept" }, deps(onChainHooks));
    expect(s.staticChecks.find((c) => c.name === "HookName")?.detail).toMatch(/616363657074/);
    expect(s.hookRuns.find((r) => r.hookHash === HOOK_HASH)!.fired).toBe(false);
  });
});

describe("codec carries sfHookName into the otxn blob the hook reads", () => {
  it("HookName (Blob, nth 97 — live server_definitions) is serialized, not dropped", () => {
    const { txBlobHex } = encodeTxBlob({ TransactionType: "Invoke", Account: HOOK_ACCOUNT, Fee: "39", Sequence: 1, HookName: "616363657074" });
    // Blob type 7, field 97 → header 0x70 0x61, then VL length 06
    expect(txBlobHex).toContain("706106616363657074");
  });
});

describe("quantum_grade — a NAMED proven guard is bypassable and earns nothing", () => {
  it("hookOnStatus 'named' scores zero and says why", () => {
    const g = gradeSignals({ masterDisabled: false, hasRegularKey: false, hasMultiSig: false, signerCount: 0, hasProvenQuantumHook: false, hookOnStatus: "named" });
    expect(g.score).toBe(0);
    expect(g.signals.join(" ")).toMatch(/HookName/);
  });
});
