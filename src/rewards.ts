// Network-reward (XAH) accrual model. Xahau pays a periodic, balance-weighted reward
// claimed via the ClaimReward transaction, governed by the Genesis Hook. The exact on-chain
// emission is authoritative; this applies the DOCUMENTED time-weighted model and labels fidelity.
import { GOVERNANCE } from "./defs.js";

export interface RewardInput {
  balanceXAH: number;
  rewardAccumulator?: number; // sum over ledgers of balance (drops*ledgers), if known
  rewardLgrFirst: number;
  rewardLgrLast?: number;
  currentLedger: number;
  rewardDelayLedgers?: number;
  rewardRateMonthly?: number;
}

export function computeReward(inp: RewardInput) {
  const rewardDelay = inp.rewardDelayLedgers ?? GOVERNANCE?.rewardDelayLedgers ?? 2_600_000;
  const rate = inp.rewardRateMonthly ?? GOVERNANCE?.rewardRateMonthly_doc ?? 0.00333333333;
  const elapsedLedgers = Math.max(0, inp.currentLedger - inp.rewardLgrFirst);
  const periodsElapsed = elapsedLedgers / rewardDelay;
  const eligible = elapsedLedgers >= rewardDelay;

  // Time-weighted average balance if an accumulator is supplied, else the current balance.
  const avgBalanceXAH = inp.rewardAccumulator && elapsedLedgers > 0
    ? inp.rewardAccumulator / elapsedLedgers / 1_000_000
    : inp.balanceXAH;

  const claimableXAH = eligible ? avgBalanceXAH * rate * periodsElapsed : 0;

  return {
    claimableXAH: Number(claimableXAH.toFixed(6)),
    eligibleToClaim: eligible,
    elapsedLedgers,
    periodsElapsed: Number(periodsElapsed.toFixed(4)),
    avgBalanceXAH: Number(avgBalanceXAH.toFixed(6)),
    rewardDelayLedgers: rewardDelay,
    rewardRateMonthly: rate,
    formula: "claimable = avgBalance * rewardRateMonthly * (elapsedLedgers / rewardDelayLedgers), eligible only once elapsedLedgers >= rewardDelayLedgers",
    fidelity: "DOCUMENTED_MODEL",
    caveat: "Approximation of the Genesis Hook's reward logic. The on-chain hook is authoritative and parameters can be changed by governance; verify against live account reward fields before relying on a figure.",
  };
}
