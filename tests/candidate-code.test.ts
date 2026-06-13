import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { simulateTransaction, type SimDeps } from "../src/simulate.js";

// Candidate-code simulation: a NOT-YET-DEPLOYED hook runs against the live ledger
// (here, stubbed) + TSH chain, by overriding the account's on-ledger hook chain.
// Real hook bytecode from the committed fidelity corpus drives the VM; stub deps
// keep it deterministic and offline.

const CORPUS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "data", "hook-corpus.json");
const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8")) as { hookCode?: Record<string, string> };
const candidateCode = Object.values(corpus.hookCode ?? {})[0];

const SENDER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const DEST = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

function stubDeps(): SimDeps {
  return {
    getAccountHooks: async () => [], // no on-ledger hooks — candidate must supply the chain
    getHookDefinition: async () => null,
    getAccountInfo: async () => ({ account_data: { Balance: "100000000", Sequence: 1 } }),
    getHookState: async () => null,
    getLedgerObject: async () => null,
    getLedgerInfo: async () => ({ ledgerIndex: 1_000_000, closeTime: 760_000_000 }),
    getFee: async () => 100000,
    spacingMs: 0,
  };
}

const tx = { TransactionType: "Payment", Account: SENDER, Destination: DEST, Amount: "5000000", Sequence: 1, Fee: "100000" };

describe("candidate-code simulation (simulate an undeployed wasm)", () => {
  it("has corpus bytecode to drive the VM", () => {
    expect(typeof candidateCode).toBe("string");
    expect(candidateCode.startsWith("0061736D")).toBe(true); // \0asm magic
  });

  it("WITHOUT candidate: no hooks fire (account has none on ledger)", async () => {
    const sim = await simulateTransaction(tx, stubDeps());
    expect(sim.verdict).toBe("NO_HOOKS_FIRE");
    expect(sim.hookRuns.length).toBe(0);
  });

  it("WITH candidate: the not-yet-deployed code runs against the chain", async () => {
    const sim = await simulateTransaction(tx, stubDeps(), {
      candidateHooks: { [SENDER]: { createCodeHex: candidateCode } },
    });
    // the candidate replaced the (empty) on-ledger chain and actually ran
    const run = sim.hookRuns.find((r) => r.hookHash === "CANDIDATE");
    expect(run).toBeDefined();
    expect(run!.fired).toBe(true);
    expect(run!.role).toBe("originator");
    // it's flagged as candidate / not-yet-on-ledger in the notes
    expect(sim.notes.some((n) => n.toLowerCase().includes("candidate"))).toBe(true);
    // verdict reflects the candidate's decision, not NO_HOOKS_FIRE
    expect(sim.verdict).not.toBe("NO_HOOKS_FIRE");
  });

  it("a candidate WITH a HookOn that excludes the tx type does NOT fire", async () => {
    // HookOn all-ones = fires on nothing (active-low) -> the candidate is gated out
    const sim = await simulateTransaction(tx, stubDeps(), {
      candidateHooks: { [SENDER]: { createCodeHex: candidateCode, hookOn: "F".repeat(64) } },
    });
    const run = sim.hookRuns.find((r) => r.hookHash === "CANDIDATE");
    expect(run?.fired).toBe(false);
  });
});
