import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { simulateTransaction, type SimDeps } from "../src/simulate.js";
import { encodeHookOn } from "../src/hookon.js";
import { validateAddress } from "../src/util.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(join(HERE, "..", "data", "hook-corpus.json"), "utf8"));
const REWARD_WASM_HEX = readFileSync(join(HERE, "fixtures-wasm", "genesis-reward.hex"), "utf8").trim();

const HEARTBEAT_HASH = Object.keys(corpus.hookCode).find((h: string) => h.startsWith("1F7C84"))!;
const cs = corpus.cases.find((c: any) => c.hookExecutions.some((h: any) => h.HookHash === HEARTBEAT_HASH));
const GOVERNOR_PARAM = [{ HookParameter: { HookParameterName: "4556520100000000000000000000000000000000000000000000000000000001", HookParameterValue: "77C6E707430AC26716121F50539634E4024FB457" } }];
const PAYMENT_MASK = encodeHookOn(["Payment"]).hookOn;
const CLAIM_MASK = encodeHookOn(["ClaimReward"]).hookOn;

const noSleep = (_ms: number) => Promise.resolve();

/** Offline deps that serve the committed corpus — the simulator replays REAL mainnet conditions. */
function corpusDeps(over: Partial<SimDeps> = {}): SimDeps {
  return {
    getAccountHooks: async (a) => a === cs.hookAccount
      ? [{ Hook: { HookHash: HEARTBEAT_HASH, HookOn: PAYMENT_MASK } }]
      : [],
    getHookDefinition: async (hash) => hash === HEARTBEAT_HASH
      ? { CreateCode: corpus.hookCode[HEARTBEAT_HASH], HookOn: PAYMENT_MASK, HookParameters: GOVERNOR_PARAM }
      : null,
    getAccountInfo: async () => ({ account_data: { Balance: "999000000", Sequence: 1, Flags: 0 } }),
    getHookState: async (acc, ns, key) => {
      const v = (cs.foreignState ?? {})[`${acc}|${ns}|${key}`];
      return v === undefined ? undefined : v; // corpus composite hit or unavailable
    },
    getLedgerObject: async (idx) => (cs.keyletBlobs ?? {})[idx] ?? null,
    getLedgerInfo: async () => ({ ledgerIndex: cs.ledgerIndex, closeTime: cs.ledgerCloseTime }),
    getFee: async () => 10,
    sleep: noSleep,
    ...over,
  };
}

describe("simulate_transaction — replays a REAL mainnet hook execution from the corpus", () => {
  it("heartbeat Payment: WOULD_PASS_HOOKS, matching what the chain recorded (HookResult=3)", async () => {
    const s = await simulateTransaction(cs.tx, corpusDeps(), { ledgerIndex: cs.ledgerIndex, closeTime: cs.ledgerCloseTime });
    const run = s.hookRuns.find((r) => r.hookHash === HEARTBEAT_HASH)!;
    expect(run.fired).toBe(true);
    expect(run.role).toMatch(/TSH:Destination \(strong\)/);
    expect(run.exit).toBe("accept");
    expect(run.degraded).toBe(false);
    expect(s.verdict).toBe("WOULD_PASS_HOOKS");
    expect(s.summary).toMatch(/PREFLIGHT: PASS/);
  });

  it("hook whose HookOn does not include the tx type is reported as not fired", async () => {
    const s = await simulateTransaction({ ...cs.tx, TransactionType: "AccountSet" }, corpusDeps({
      // sender (originator) carries the hook now; AccountSet not in the Payment-only mask
      getAccountHooks: async (a) => a === cs.tx.Account ? [{ Hook: { HookHash: HEARTBEAT_HASH, HookOn: PAYMENT_MASK } }] : [],
    }));
    const run = s.hookRuns.find((r) => r.hookHash === HEARTBEAT_HASH);
    expect(run?.fired).toBe(false);
    expect(s.verdict).toBe("NO_HOOKS_FIRE");
  });
});

describe("simulate_transaction — strong rollback path (real genesis reward bytecode)", () => {
  const ISSUER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
  const issuerId = (validateAddress(ISSUER) as any).accountId as string;
  const ZERO_NS = "0".repeat(64);

  function rewardDeps(rrHex: string): SimDeps {
    return corpusDeps({
      getAccountHooks: async (a) => a === ISSUER ? [{ Hook: { HookHash: "AA".repeat(32), HookOn: CLAIM_MASK, HookNamespace: ZERO_NS } }] : [],
      getHookDefinition: async () => ({ CreateCode: REWARD_WASM_HEX, HookOn: CLAIM_MASK, HookNamespace: ZERO_NS }),
      // own-state lazy resolution: serve RR/RD from the zero namespace
      getHookState: async (acc, ns, key) => {
        if (acc === issuerId && ns === ZERO_NS) {
          if (key.endsWith("5252")) return rrHex;
          if (key.endsWith("5244")) return "00806AACAF3C0956"; // 2,600,000 s
        }
        return null; // confirmed absent
      },
    });
  }

  const claim = { TransactionType: "ClaimReward", Account: "rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", Issuer: ISSUER, Fee: "8630" };

  it("rewards disabled by governance (RR=0): WOULD_FAIL_HOOKS with the hook's own message", async () => {
    const s = await simulateTransaction(claim, rewardDeps("0000000000000000"), { ledgerIndex: 23488087, closeTime: 834361232 - 946684800 + 946684800 });
    expect(s.verdict).toBe("WOULD_FAIL_HOOKS");
    const run = s.hookRuns.find((r) => r.fired)!;
    expect(run.exit).toBe("rollback");
    expect(run.returnString).toMatch(/disabled by governance/);
    expect(s.summary).toMatch(/WOULD FAIL/);
    expect(s.summary).toMatch(/tecHOOK_REJECTED/);
  });
});

describe("simulate_transaction — static preflights", () => {
  it("flags expired LastLedgerSequence and missing destination", async () => {
    const s = await simulateTransaction(
      { TransactionType: "Payment", Account: cs.tx.Account, Destination: "rrrrrrrrrrrrrrrrrrrrBZbvji", Amount: "500000", LastLedgerSequence: 5 },
      corpusDeps({ getAccountInfo: async (a) => a === cs.tx.Account ? { account_data: { Balance: "999000000", Sequence: 1, Flags: 0 } } : null }),
    );
    const names = s.staticChecks.filter((c) => c.status === "FAIL").map((c) => c.name);
    expect(names).toContain("LastLedgerSequence");
    expect(s.staticChecks.find((c) => c.name === "destination exists")).toBeDefined();
  });
});

describe("TIME MACHINE — replays the real mainnet ClaimReward and reproduces its GenesisMint TO THE DROP", () => {
  // Real claim 2A096461C98A76909018459B1657C842AADFA2522D7E25D90FD732125C1CB79B (ledger 23488087).
  // ALL inputs below were captured live from mainnet at the PRE-EXECUTION ledger 23488086:
  // the claimer's binary account root, the genesis RR/RD hook state, the parent close time.
  // The on-chain emitted GenesisMint paid EXACTLY 72251963 drops. The simulator must emit the same.
  const ISSUER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
  const ZERO_NS = "0".repeat(64);
  const ACCT_ROOT_IDX = "720FBEF287D1673D5BB890E1327E94CE4EFE9021626303C5CC816D8C809BD9C6";
  const UNLREPORT_IDX = "61E32E7A24A238F1C619D5F9DDCC41A94B33B66C0163F7EFCC8A19C9FD6F28DC"; // reward.c's fixed keylet — absent at this ledger
  const ACCT_ROOT_BIN =
    "1100612200000000242EF46AE325015AF7C72D000000002062319234EE2063015AF7C62064015AF7C730610000000000000013306200000000000195E8306400000000000054615581369F793A79CBDE71F88300B0A9B6EE0DC5D0DCA760927C7A8A247B1F45F6B962400000050BDCC15B81148595DFB39458654A89166742FBEF1B7D3D73C11A";
  const RR = "55554025A6D7CB53"; // captured at ledger 23488086 (== compiled default)
  const RD = "00806AACAF3C0956";
  const CLOSE_TIME = 834361240;
  const REWARD_HASH = "610F33B8EBF7EC795F822A454FB852156AEFE50BE0CB8326338A81CD74801864";
  const issuerId = (validateAddress(ISSUER) as any).accountId as string;

  function timeMachineDeps(): SimDeps {
    return corpusDeps({
      getAccountHooks: async (a) => a === ISSUER ? [{ Hook: { HookHash: REWARD_HASH, HookOn: CLAIM_MASK, HookNamespace: ZERO_NS } }] : [],
      getHookDefinition: async () => ({ CreateCode: REWARD_WASM_HEX, HookOn: CLAIM_MASK, HookNamespace: ZERO_NS }),
      getAccountInfo: async () => ({ account_data: { Balance: "21673853275", Sequence: 787770083, Flags: 0 } }),
      getHookState: async (acc, ns, key) => {
        if (acc === issuerId && ns === ZERO_NS) {
          if (key.endsWith("5252")) return RR;
          if (key.endsWith("5244")) return RD;
        }
        return null;
      },
      getLedgerObject: async (idx) => idx === ACCT_ROOT_IDX ? ACCT_ROOT_BIN : idx === UNLREPORT_IDX ? null : undefined,
      getLedgerInfo: async () => ({ ledgerIndex: 23488086, closeTime: CLOSE_TIME }),
    });
  }

  it("emits a decodable GenesisMint of exactly 72251963 drops to the claimer, non-degraded", async () => {
    const tx = { TransactionType: "ClaimReward", Account: "rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", Issuer: ISSUER, Fee: "8630", Sequence: 787770083 };
    const s = await simulateTransaction(tx, timeMachineDeps(), { ledgerIndex: 23488087, closeTime: CLOSE_TIME });
    expect(s.verdict).toBe("WOULD_PASS_HOOKS");
    const run = s.hookRuns.find((r) => r.fired)!;
    expect(run.exit).toBe("accept");
    expect(run.degraded).toBe(false);
    expect(run.returnString).toMatch(/Emitted reward txn successfully/);
    expect(run.syntheticCalls).toContain("etxn_details"); // disclosed synthetic, decodable
    const emit = (run.emitted!.inspections[0] as any).decoded;
    expect(emit.TransactionType).toBe("GenesisMint");
    const gm = emit.GenesisMints[0].GenesisMint;
    expect(gm.Amount).toBe("72251963"); // == the real on-chain emission, to the drop
    expect(gm.Destination).toBe("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6");
    expect(s.summary).toMatch(/1 transaction\(s\) would be emitted/);
  });
});
