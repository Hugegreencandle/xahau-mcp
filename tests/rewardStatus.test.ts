import { describe, it, expect } from "vitest";
import {
  rewardStatus, parseGenesisRewardParams, describeParams,
  GENESIS_ACCOUNT, DEFAULT_REWARD_RATE_XFL, DEFAULT_REWARD_DELAY_XFL,
  type RewardStatusDeps,
} from "../src/rewardStatus.js";
import { floatSet, floatInt, floatDivide, floatMultiply } from "../src/xfl.js";

const noSleep = (_ms: number) => Promise.resolve();

// Live mainnet values captured 2026-06-11 (genesis zero-namespace hook state).
const RR_LIVE_LE = "55554025A6D7CB53"; // XFL 0.00333333333 — equals reward.c DEFAULT_REWARD_RATE
const RD_LIVE_LE = "00806AACAF3C0956"; // XFL 2600000 (seconds) — equals reward.c DEFAULT_REWARD_DELAY

const NS = (rr = RR_LIVE_LE, rd = RD_LIVE_LE) => [
  { HookStateKey: "00".repeat(30) + "5252", HookStateData: rr },
  { HookStateKey: "00".repeat(30) + "5244", HookStateData: rd },
  { HookStateKey: "00".repeat(30) + "4D43", HookStateData: "14" }, // MC member count — must be ignored
];

// Real opted-in mainnet account shape captured 2026-06-11 (rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6).
const OPTED_IN = {
  account_data: {
    Balance: "21746096608", Flags: 0,
    RewardAccumulator: "54a9", RewardLgrFirst: 23488087, RewardLgrLast: 23488088,
    RewardTime: 834361232,
  },
};

function deps(over: Partial<RewardStatusDeps> = {}): RewardStatusDeps {
  return {
    getAccountInfo: async () => OPTED_IN,
    getGenesisNamespace: async () => NS(),
    getValidatedLedger: async () => ({ ledgerIndex: 23516916, closeTime: 834465122 }),
    sleep: noSleep,
    ...over,
  };
}

describe("parseGenesisRewardParams", () => {
  it("decodes live RR/RD little-endian and they equal the reward.c compiled defaults", () => {
    const { rr, rd } = parseGenesisRewardParams(NS());
    expect(rr).toBe(DEFAULT_REWARD_RATE_XFL);
    expect(rd).toBe(DEFAULT_REWARD_DELAY_XFL);
  });

  it("ignores non-RR/RD keys and non-8-byte data", () => {
    const { rr, rd } = parseGenesisRewardParams([
      { HookStateKey: "00".repeat(30) + "4D43", HookStateData: "14" },
      { HookStateKey: "00".repeat(30) + "5252", HookStateData: "AB" }, // wrong size
    ]);
    expect(rr).toBeNull();
    expect(rd).toBeNull();
  });
});

describe("describeParams", () => {
  it("live/default params: 0.333…% per claim, 2,600,000 s ≈ 30.09 days, enabled", () => {
    const p = describeParams(DEFAULT_REWARD_RATE_XFL, DEFAULT_REWARD_DELAY_XFL);
    expect(p.enabled).toBe(true);
    expect(p.misconfigured).toBe(false);
    expect(p.rewardDelaySeconds).toBe(2600000);
    expect(p.rewardDelayDays).toBeCloseTo(30.09, 2);
    expect(p.rewardRate).toBeCloseTo(0.00333333333, 10);
    expect(p.source).toBe("genesis-hook-state-live");
  });

  it("canonical-zero RR => disabled (reward.c 'disabled by governance')", () => {
    const p = describeParams(0n, DEFAULT_REWARD_DELAY_XFL);
    expect(p.enabled).toBe(false);
  });

  it("RR > 1 => misconfigured (reward.c sanity rollback)", () => {
    const p = describeParams(floatSet(0, 2n), DEFAULT_REWARD_DELAY_XFL);
    expect(p.misconfigured).toBe(true);
  });

  it("missing state => documented-defaults source", () => {
    const p = describeParams(null, null);
    expect(p.source).toBe("documented-defaults");
    expect(p.rewardDelaySeconds).toBe(2600000);
  });
});

describe("reward.c formula — on-chain ground truth", () => {
  // Real mainnet ClaimReward 2A096461C98A76909018459B1657C842AADFA2522D7E25D90FD732125C1CB79B
  // (ledger 23488087, rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6). Pre-claim AccountRoot (meta PreviousFields):
  // RewardAccumulator=0x5461, RewardLgrFirst=22738886, RewardLgrLast=22738887, Balance=21673853275,
  // Fee=8630. The hook's emitted GenesisMint paid EXACTLY 72251963 drops (verified on-chain 2026-06-11).
  it("reproduces the real emitted GenesisMint amount to the drop", () => {
    const accum = 0x5461n + 21673n * BigInt(23488087 - 22738887); // balXAH=21673853275/1e6 truncated
    const elapsed = BigInt(23488087 - 22738886);
    const reward = floatInt(floatMultiply(DEFAULT_REWARD_RATE_XFL, floatDivide(floatSet(0, accum), floatSet(0, elapsed))), 6, true);
    expect(reward).toBe(72243333n);
    expect(reward + 8630n).toBe(72251963n); // + fee refund == on-chain GenesisMint.Amount
  });
});

describe("reward_status", () => {
  it("opted-in, waiting: real mainnet numbers — correct accrual (reward.c formula) and countdown", async () => {
    const r = await rewardStatus("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", "mainnet", deps());
    expect(r.optedIn).toBe(true);
    expect(r.eligibility!.eligibleNow).toBe(false);
    // closeTime 834465122 - RewardTime 834361232 = 103890 s elapsed; 2600000 - 103890 = 2496110 s left
    expect(r.eligibility!.secondsRemaining).toBe(2496110);
    expect(r.eligibility!.missedPeriods).toBe(0);
    expect(r.unsignedTx).toBeNull();

    // independent reward.c replication: bal=21746 XAH (21746096608/1e6 truncated);
    // accum = 0x54a9 + 21746*(23516916-23488088); elapsed = 23516916-23488087
    const accum = 0x54a9n + 21746n * BigInt(23516916 - 23488088);
    const elapsed = BigInt(23516916 - 23488087);
    const expectDrops = floatInt(floatMultiply(DEFAULT_REWARD_RATE_XFL, floatDivide(floatSet(0, accum), floatSet(0, elapsed))), 6, true);
    expect(r.accrual!.accruedDrops).toBe(expectDrops.toString());
    expect(r.accrual!.accruedXah).toBeGreaterThan(0);
    expect(r.accrual!.fidelity).toBe("REWARD_HOOK_FORMULA");
    expect(r.summary).toMatch(/opted in/);
  });

  it("opted-in, eligible: claim template (Issuer = genesis) + overdue warning after a missed period", async () => {
    const r = await rewardStatus("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", "mainnet", deps({
      // 3 full periods elapsed since RewardTime => eligible, 2 missed
      getValidatedLedger: async () => ({ ledgerIndex: 23516916, closeTime: 834361232 + 3 * 2600000 }),
    }));
    expect(r.eligibility!.eligibleNow).toBe(true);
    expect(r.eligibility!.secondsRemaining).toBe(0);
    expect(r.eligibility!.missedPeriods).toBe(2);
    expect(r.warnings.join(" ")).toMatch(/OVERDUE/);
    expect(r.unsignedTxPurpose).toBe("claim");
    expect((r.unsignedTx as any).Issuer).toBe(GENESIS_ACCOUNT);
    expect((r.unsignedTx as any).TransactionType).toBe("ClaimReward");
  });

  it("not opted in: opt-in template + how-to summary", async () => {
    const r = await rewardStatus("rNotOptedIn11111111111111111", "mainnet", deps({
      getAccountInfo: async () => ({ account_data: { Balance: "5000000", Flags: 0 } }),
    }));
    expect(r.optedIn).toBe(false);
    expect(r.unsignedTxPurpose).toBe("opt-in");
    expect((r.unsignedTx as any).Issuer).toBe(GENESIS_ACCOUNT);
    expect(r.summary).toMatch(/NOT opted in/);
    expect(r.notes.join(" ")).toMatch(/Flags=1/); // opt-out shape documented
  });

  it("rewards disabled by governance (RR zeroed) => warning, not eligible", async () => {
    const r = await rewardStatus("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", "mainnet", deps({
      getGenesisNamespace: async () => NS("0000000000000000"),
    }));
    expect(r.params.enabled).toBe(false);
    expect(r.eligibility!.eligibleNow).toBe(false);
    expect(r.warnings.join(" ")).toMatch(/DISABLED by governance/);
  });

  it("genesis state unreadable => documented defaults + graceful note (same fallback as reward.c)", async () => {
    const r = await rewardStatus("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", "mainnet", deps({
      getGenesisNamespace: async () => { throw new Error("rate limited"); },
    }));
    expect(r.params.source).toBe("documented-defaults");
    expect(r.notes.join(" ")).toMatch(/documented defaults/);
    expect(r.accrual).not.toBeNull();
  });

  it("RewardAccumulator hex parses (lowercase, as served by xahaud)", async () => {
    const r = await rewardStatus("rDBLQvA747zGP8DB856hxQ8NkxCgtGsVE6", "mainnet", deps());
    expect(r.fields!.rewardAccumulator).toBe("54a9");
    // 0x54a9 = 21673 — would be NaN if parsed as decimal; accrual present proves hex parse
    expect(r.accrual!.avgBalanceXah).toBeGreaterThan(20000); // dominated by 21746-XAH balance over elapsed ledgers
  });
});
