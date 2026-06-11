// reward_status — Balance Adjustment (network reward) doctor. The #1 retail confusion on Xahau:
// "am I opted in, how much XAH have I accrued, when can I claim, why is the claim button greyed?"
// (community auto-claim xApps exist precisely because late claiming forfeits yield).
//
// This replicates the genesis reward hook's math EXACTLY — canonical source:
// Xahau/xahaud hook/genesis/reward.c — using the SAME XFL routines as the local VM (src/xfl.ts),
// over live values: the account's RewardLgrFirst/RewardLgrLast/RewardAccumulator/RewardTime fields
// and the genesis hook state's RR (reward rate) / RD (reward delay, SECONDS) XFL parameters.
//
// Verified mechanics (reward.c + ClaimReward.cpp, fetched 2026-06-11):
//  - Opt-in / claim: ClaimReward with Issuer = genesis; doApply RESETS LgrFirst/LgrLast=cur ledger,
//    Accumulator=0, RewardTime=parent close (Ripple time). Opt-out: Flags=1 (tfOptOut), NO Issuer.
//  - Gate: ledger_last_time() - RewardTime >= float_int(RD,0,0) — SECONDS (mainnet 2,600,000 ≈ 30.09d).
//  - Reward: accum += balXAH * (cur - LgrLast); reward = RR * (accum / (cur - LgrFirst)); + fee refund.
//    PER CLAIM — no period multiplier: waiting 2 periods still pays once. Claim late = lose yield.
//  - Disabled when RR<=0 or RD<=0; misconfigured (hook rolls back) when RR>1 or RD<1.
// Network access is injected (explain.ts pattern) so unit tests run offline; live wiring in index.ts
// is strictly serial — exactly 3 RPC reads per invocation.
import { floatSet, floatInt, floatDivide, floatMultiply, decode } from "./xfl.js";
import { buildClaimRewardUnsigned } from "./builders.js";
import type { Network } from "./rpc.js";

export const GENESIS_ACCOUNT = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
export const GENESIS_NAMESPACE = "0".repeat(64);
// Hook state keys are 32 bytes, ASCII key right-aligned (zero-left-padded): "RR" / "RD".
export const RR_KEY_SUFFIX = "5252";
export const RD_KEY_SUFFIX = "5244";
// Defaults compiled into reward.c — used only if the state keys are missing (same graceful fallback).
export const DEFAULT_REWARD_RATE_XFL = 6038156834009797973n; // 0.00333333333
export const DEFAULT_REWARD_DELAY_XFL = 6199553087261802496n; // 2600000 (seconds)

const RIPPLE_EPOCH = 946684800;

export interface RewardStatusDeps {
  getAccountInfo: (a: string) => Promise<Record<string, any>>;
  /** namespace_entries of the genesis account's zero namespace (where RR/RD live). */
  getGenesisNamespace: () => Promise<Record<string, any>[]>;
  /** current validated ledger: sequence + close time (Ripple time, seconds). */
  getValidatedLedger: () => Promise<{ ledgerIndex: number; closeTime: number }>;
  sleep?: (ms: number) => Promise<void>;
}

export interface RewardParams {
  rewardRate: number; // per-claim rate as a fraction (e.g. 0.00333333333)
  rewardRatePctPerClaim: string;
  rewardDelaySeconds: number;
  rewardDelayDays: number;
  source: "genesis-hook-state-live" | "documented-defaults";
  enabled: boolean; // RR>0 && RD>0 (reward.c rolls back "disabled by governance" otherwise)
  misconfigured: boolean; // reward.c sanity: RR negative, RR>1 or RD<1 → hook rolls back
}

export interface RewardStatus {
  address: string;
  network: string;
  optedIn: boolean;
  summary: string;
  balanceXah: number | null;
  fields: {
    rewardLgrFirst: number | null;
    rewardLgrLast: number | null;
    rewardAccumulator: string | null; // hex, as on-ledger
    rewardTime: number | null; // Ripple time, seconds
    rewardTimeIso: string | null;
  } | null;
  params: RewardParams;
  eligibility: {
    eligibleNow: boolean;
    secondsRemaining: number;
    nextClaimIso: string | null;
    overdueSeconds: number; // how long PAST eligible (late claiming forfeits yield)
    missedPeriods: number; // full reward periods forfeited by not claiming
  } | null;
  accrual: {
    accruedXah: number; // EXACT reward.c figure (excl. fee refund, which is added at claim time)
    accruedDrops: string;
    avgBalanceXah: number; // time-weighted average the hook pays on
    elapsedLedgers: number;
    formula: string;
    fidelity: "REWARD_HOOK_FORMULA";
    caveat: string;
  } | null;
  unsignedTx: Record<string, unknown> | null; // opt-in (not opted in) or claim (eligible) ClaimReward
  unsignedTxPurpose: "opt-in" | "claim" | null;
  warnings: string[];
  notes: string[];
}

const SPACING_MS = 1100;

/** Parse the genesis namespace entries into live RR/RD XFL values (LE 8-byte hook state data). */
export function parseGenesisRewardParams(entries: Record<string, any>[]): { rr: bigint | null; rd: bigint | null } {
  let rr: bigint | null = null;
  let rd: bigint | null = null;
  for (const e of entries) {
    const key = String(e.HookStateKey ?? "").toUpperCase();
    const data = String(e.HookStateData ?? "");
    if (!/^[0-9a-fA-F]{16}$/.test(data)) continue; // RR/RD are exactly 8 bytes
    if (key.endsWith(RR_KEY_SUFFIX)) rr = leUint64(data);
    else if (key.endsWith(RD_KEY_SUFFIX)) rd = leUint64(data);
  }
  return { rr, rd };
}

/** hook state() reads the 8-byte value into a WASM little-endian int64. */
function leUint64(hex: string): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(parseInt(hex.slice(i * 2, i * 2 + 2), 16));
  return v;
}

export function describeParams(rr: bigint | null, rd: bigint | null): RewardParams {
  const source: RewardParams["source"] = rr !== null && rd !== null ? "genesis-hook-state-live" : "documented-defaults";
  const rrX = rr ?? DEFAULT_REWARD_RATE_XFL;
  const rdX = rd ?? DEFAULT_REWARD_DELAY_XFL;
  // reward.c, mirrored exactly: canonical-zero RR/RD ("xfl <= 0" on the int64) => DISABLED;
  // the separate sanity check (RR negative via float_sign, RR>1, RD<1, required_delay<0) => the
  // hook rolls back "incorrectly configured" => MISCONFIGURED.
  const rrF = decode(rrX);
  const rdF = decode(rdX);
  const enabled = !rrF.zero && !rdF.zero;
  const delayInt = enabled ? floatInt(rdX, 0, false) : 0n; // negative => CANT_RETURN_NEGATIVE sentinel
  const delaySeconds = delayInt > 0n ? Number(delayInt) : 0;
  const rate = rrF.zero ? 0 : rrF.sign * Number(rrF.mant) * Math.pow(10, rrF.exp);
  const misconfigured = enabled && (rrF.sign < 0 || rate > 1 || delayInt <= 0n);
  return {
    rewardRate: rate,
    rewardRatePctPerClaim: `${(rate * 100).toFixed(6).replace(/0+$/, "").replace(/\.$/, "")}%`,
    rewardDelaySeconds: delaySeconds,
    rewardDelayDays: Math.round((delaySeconds / 86400) * 100) / 100,
    source,
    enabled,
    misconfigured,
  };
}

export async function rewardStatus(address: string, network: Network, deps: RewardStatusDeps): Promise<RewardStatus> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const warnings: string[] = [];
  const notes: string[] = [];

  const info = await deps.getAccountInfo(address);
  const a = (info.account_data ?? info) as Record<string, any>;
  const balanceDrops = typeof a.Balance === "string" ? BigInt(a.Balance) : null;
  const balanceXah = balanceDrops !== null ? Number(balanceDrops) / 1e6 : null;

  await sleep(SPACING_MS);
  let rrLive: bigint | null = null;
  let rdLive: bigint | null = null;
  try {
    const entries = await deps.getGenesisNamespace();
    const p = parseGenesisRewardParams(entries);
    rrLive = p.rr;
    rdLive = p.rd;
  } catch {
    notes.push("could not read live genesis hook state — using the documented defaults compiled into reward.c (same graceful fallback the hook itself uses)");
  }
  const params = describeParams(rrLive, rdLive);
  if (!params.enabled) warnings.push("network rewards are DISABLED by governance (RR or RD <= 0) — the reward hook rolls back every claim");
  if (params.misconfigured) warnings.push("reward parameters look misconfigured (reward.c sanity check would roll back claims)");

  await sleep(SPACING_MS);
  const { ledgerIndex: cur, closeTime } = await deps.getValidatedLedger();

  const optedIn = a.RewardLgrFirst !== undefined && a.RewardTime !== undefined;
  if (!optedIn) {
    const optIn = buildClaimRewardUnsigned({ account: address, issuer: GENESIS_ACCOUNT, network });
    return {
      address, network, optedIn: false,
      summary: `${address} is NOT opted in to Xahau network rewards (no reward fields on the account root). Opt in by signing+submitting the included ClaimReward (Issuer = genesis); accrual starts at the opt-in ledger. Current rate: ${params.rewardRatePctPerClaim} of your time-weighted average balance every ${params.rewardDelayDays} days.`,
      balanceXah, fields: null, params, eligibility: null, accrual: null,
      unsignedTx: optIn.unsignedTx, unsignedTxPurpose: "opt-in",
      warnings, notes: [...notes, "to opt OUT later: ClaimReward with Flags=1 (tfOptOut) and NO Issuer"],
    };
  }

  const first = Number(a.RewardLgrFirst);
  const last = Number(a.RewardLgrLast ?? a.RewardLgrFirst);
  const time = Number(a.RewardTime);
  const accumHex: string | null = typeof a.RewardAccumulator === "string" ? a.RewardAccumulator : null;
  if (accumHex === null) notes.push("RewardAccumulator field missing — the reward hook would treat the next ClaimReward as a setup transaction");

  // ---- eligibility (reward.c: ledger_last_time() - RewardTime >= float_int(RD,0,0)) ----
  const elapsedSeconds = closeTime - time;
  const eligibleNow = params.enabled && !params.misconfigured && elapsedSeconds >= params.rewardDelaySeconds;
  const secondsRemaining = eligibleNow ? 0 : Math.max(0, params.rewardDelaySeconds - elapsedSeconds);
  const overdueSeconds = eligibleNow ? elapsedSeconds - params.rewardDelaySeconds : 0;
  const missedPeriods = params.rewardDelaySeconds > 0 ? Math.floor(overdueSeconds / params.rewardDelaySeconds) : 0;
  const nextClaimIso = new Date((time + params.rewardDelaySeconds + RIPPLE_EPOCH) * 1000).toISOString();
  if (missedPeriods >= 1) {
    warnings.push(`claim is ${missedPeriods} full reward period(s) OVERDUE — the hook pays the per-claim rate ONCE regardless of how long you waited, so each missed period is forfeited yield (~${params.rewardRatePctPerClaim} of your average balance each)`);
  }

  // ---- accrual (reward.c math, bit-for-bit via the same XFL routines as the VM) ----
  let accrual: RewardStatus["accrual"] = null;
  const elapsed = cur - first;
  if (balanceDrops !== null && accumHex !== null && elapsed > 0) {
    const balXah = balanceDrops / 1_000_000n; // hook: bal /= 1000000 (integer truncation)
    let accum = BigInt(`0x${accumHex === "" ? "0" : accumHex}`);
    const sinceLast = BigInt(cur - last);
    if (balXah > 0n && sinceLast > 0n) accum += balXah * sinceLast; // "we need to add the final block ourselves"
    const xflAccum = floatSet(0, accum);
    const xflElapsed = floatSet(0, BigInt(elapsed));
    const rrX = rrLive ?? DEFAULT_REWARD_RATE_XFL;
    const xflReward = floatMultiply(rrX, floatDivide(xflAccum, xflElapsed));
    const rewardDrops = xflReward > 0n ? floatInt(xflReward, 6, true) : 0n;
    const avg = elapsed > 0 ? Number(accum) / elapsed : 0;
    accrual = {
      accruedXah: Number(rewardDrops) / 1e6,
      accruedDrops: rewardDrops.toString(),
      avgBalanceXah: Math.round(avg * 1e6) / 1e6,
      elapsedLedgers: elapsed,
      formula: "reward = RR * ((RewardAccumulator + balXAH*(cur-RewardLgrLast)) / (cur-RewardLgrFirst)); paid once per claim, plus the claim tx fee refunded",
      fidelity: "REWARD_HOOK_FORMULA",
      caveat: "Exact re-implementation of the genesis reward hook (Xahau/xahaud hook/genesis/reward.c) using the same XFL routines as this server's VM, over live ledger values. The figure moves with every ledger until you claim; the on-chain emission is authoritative. The claim tx fee is refunded on top.",
    };
  }

  const accruedStr = accrual ? `~${accrual.accruedXah.toFixed(6)} XAH accrued` : "accrual not computable";
  const whenStr = !params.enabled
    ? "rewards disabled by governance"
    : eligibleNow
      ? missedPeriods >= 1 ? `claimable NOW (overdue ${missedPeriods} period(s) — claim to stop forfeiting yield)` : "claimable NOW"
      : `claimable in ${humanDuration(secondsRemaining)} (${nextClaimIso.slice(0, 16)}Z)`;
  const summary = `${address} is opted in ✓ · ${accruedStr} · ${whenStr} · rate ${params.rewardRatePctPerClaim} per ${params.rewardDelayDays}-day period (${params.source}).`;

  const claim = eligibleNow ? buildClaimRewardUnsigned({ account: address, issuer: GENESIS_ACCOUNT, network }) : null;
  return {
    address, network, optedIn: true, summary, balanceXah,
    fields: {
      rewardLgrFirst: first, rewardLgrLast: last, rewardAccumulator: accumHex,
      rewardTime: time, rewardTimeIso: new Date((time + RIPPLE_EPOCH) * 1000).toISOString(),
    },
    params,
    eligibility: { eligibleNow, secondsRemaining, nextClaimIso, overdueSeconds, missedPeriods },
    accrual,
    unsignedTx: claim?.unsignedTx ?? null,
    unsignedTxPurpose: claim ? "claim" : null,
    warnings, notes,
  };
}

function humanDuration(s: number): string {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
