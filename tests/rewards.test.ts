import { describe, it, expect } from "vitest";
import { computeReward } from "../src/rewards.js";

describe("computeReward", () => {
  it("is not eligible before the reward delay elapses", () => {
    const r = computeReward({ balanceXAH: 1000, rewardLgrFirst: 100, currentLedger: 200, rewardDelayLedgers: 1000, rewardRateMonthly: 0.01 });
    expect(r.eligibleToClaim).toBe(false);
    expect(r.claimableXAH).toBe(0);
  });

  it("applies the time-weighted model once eligible", () => {
    const r = computeReward({ balanceXAH: 1000, rewardLgrFirst: 0, currentLedger: 2000, rewardDelayLedgers: 1000, rewardRateMonthly: 0.01 });
    expect(r.eligibleToClaim).toBe(true);
    // 1000 XAH * 0.01 * (2000/1000) = 20
    expect(r.claimableXAH).toBeCloseTo(20, 6);
    expect(r.fidelity).toBe("DOCUMENTED_MODEL");
  });

  it("uses the accumulator for a time-weighted average balance when provided", () => {
    // accumulator in drops*ledgers; avg = acc/elapsed/1e6
    const r = computeReward({ balanceXAH: 0, rewardAccumulator: 500 * 1e6 * 1000, rewardLgrFirst: 0, currentLedger: 1000, rewardDelayLedgers: 1000, rewardRateMonthly: 0.02 });
    expect(r.avgBalanceXAH).toBeCloseTo(500, 3);
    expect(r.claimableXAH).toBeCloseTo(500 * 0.02 * 1, 4);
  });
});
