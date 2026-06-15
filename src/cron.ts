// Cron tooling for Xahau (Cron amendment, 2025.10.27). A Cron lets a Hook schedule future
// self-invocations (like a Linux cronjob): when due, the network inserts a `Cron` pseudo-transaction
// whose Owner points at the Hook account. Configured via CronSet; max 256 repeats; extend with another
// CronSet before they run out.
//
//  - build_cronset  : assemble an UNSIGNED CronSet (StartTime / DelaySeconds / RepeatCount, or tfCronUnset to cancel)
//  - listCronJobs   : read an account's Cron ledger objects (account_objects, filtered client-side)
//  - monitorCronHealth : flag Crons whose remaining RepeatCount is near exhaustion
//
// Read-only/no-custody: build_cronset returns unsigned JSON only; never signs, never holds a key.
import { ENDPOINTS } from "./defs.js";
import { validateAddress } from "./util.js";
import { getAccountObjects, type Network } from "./rpc.js";
import type { Finding } from "./analyzer.js";
import type { BuildResult } from "./builders.js";

/** Ripple epoch (2000-01-01 UTC) in unix seconds. */
export const RIPPLE_EPOCH = 946684800;
/** Maximum repeats a single Cron may hold (protocol limit). */
export const MAX_REPEATS = 256;
export const TF_CRON_UNSET = 1;

const SIGN =
  "This transaction is UNSIGNED. Sign it OFFLINE with your own key — e.g. via the xaman (Xumm) app, or xrpl-accountlib `sign()` in a secure local environment — then submit. NEVER paste a secret/seed into this tool or any prompt. Verify NetworkID, Account, Fee, Sequence and LastLedgerSequence before signing.";

const rippleToIso = (rt?: number): string | null =>
  typeof rt === "number" ? new Date((rt + RIPPLE_EPOCH) * 1000).toISOString() : null;

export function buildCronSet(input: {
  account: string;
  startTime?: number;       // Ripple-epoch seconds; 0 (or omitted) = ASAP
  startInSeconds?: number;  // convenience: schedule for now + N seconds
  delaySeconds?: number;    // interval between repeats
  repeatCount?: number;     // 0..256; omit for a one-off
  cancel?: boolean;         // tfCronUnset: remove the account's Cron
  nowUnix?: number;         // for deterministic startInSeconds (defaults to wall clock)
  network?: Network;
}): BuildResult {
  const network = input.network ?? "testnet";
  if (!validateAddress(input.account).valid) throw new Error("account is not a valid r-address / X-address");

  const tx: Record<string, unknown> = {
    TransactionType: "CronSet",
    Account: input.account.trim(),
    NetworkID: ENDPOINTS[network].network_id,
  };
  const findings: Finding[] = [];

  if (input.cancel) {
    tx.Flags = TF_CRON_UNSET;
    findings.push({ ruleId: "CRON-UNSET", severity: "MEDIUM", message: "tfCronUnset — this removes the account's existing Cron. No further scheduled invocations will fire." });
    return { unsignedTx: tx, network, signingInstructions: SIGN + " tfCronUnset cancels the existing Cron.", preflightFindings: findings };
  }

  let startTime = input.startTime;
  if (startTime === undefined && input.startInSeconds !== undefined) {
    const now = input.nowUnix ?? Math.floor(Date.now() / 1000);
    startTime = now - RIPPLE_EPOCH + input.startInSeconds;
  }
  if (startTime !== undefined) {
    if (!Number.isInteger(startTime) || startTime < 0) throw new Error("startTime must be a non-negative integer (Ripple-epoch seconds; 0 = ASAP)");
    tx.StartTime = startTime;
  } else {
    tx.StartTime = 0; // ASAP
  }

  if (input.repeatCount !== undefined) {
    if (!Number.isInteger(input.repeatCount) || input.repeatCount < 0 || input.repeatCount > MAX_REPEATS) throw new Error(`repeatCount must be an integer 0–${MAX_REPEATS}`);
    tx.RepeatCount = input.repeatCount;
  }
  if (input.delaySeconds !== undefined) {
    if (!Number.isInteger(input.delaySeconds) || input.delaySeconds < 0) throw new Error("delaySeconds must be a non-negative integer (seconds between repeats)");
    tx.DelaySeconds = input.delaySeconds;
  }

  const recurring = input.repeatCount !== undefined && input.repeatCount > 0;
  if (recurring && input.delaySeconds === undefined) {
    findings.push({ ruleId: "CRON-NO-DELAY", severity: "MEDIUM", message: "RepeatCount > 0 but no DelaySeconds — a recurring Cron needs an interval between runs." });
  }
  if (input.repeatCount === undefined && input.delaySeconds === undefined) {
    findings.push({ ruleId: "CRON-ONE-OFF", severity: "INFO", message: "No RepeatCount/DelaySeconds → one-off Cron (fires once)." });
  }
  findings.push({ ruleId: "CRON-NEEDS-HOOK", severity: "INFO", message: "A Cron only does something if the account has a Hook installed to act on the resulting Cron pseudo-transaction." });
  findings.push({ ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." });

  return {
    unsignedTx: tx,
    network,
    signingInstructions: SIGN + ` CronSet schedules Hook self-invocation. Max ${MAX_REPEATS} repeats; extend later with another CronSet. StartTime is Ripple-epoch seconds (0 = ASAP).`,
    preflightFindings: findings,
  };
}

export interface CronSummary {
  owner: unknown;
  startTime: number | null;
  startTimeIso: string | null;
  delaySeconds: number | null;
  repeatCount: number | null;
  /** EARLIEST possible fire time = max(StartTime, now). This is a lower bound only: it ignores
   *  DelaySeconds and how many of RepeatCount have already elapsed, so a recurring Cron's actual
   *  next fire can be later. Not a precise next-fire prediction. */
  earliestFireIso: string | null;
  raw: Record<string, unknown>;
}

/** Decode a Cron ledger object into convenience fields (best-effort) while passing raw through. */
export function summarizeCron(obj: Record<string, unknown>, nowUnix: number): CronSummary {
  const startTime = typeof obj.StartTime === "number" ? (obj.StartTime as number) : null;
  const startUnix = startTime !== null ? startTime + RIPPLE_EPOCH : null;
  return {
    owner: obj.Owner ?? obj.Account ?? null,
    startTime,
    startTimeIso: rippleToIso(startTime ?? undefined),
    delaySeconds: typeof obj.DelaySeconds === "number" ? (obj.DelaySeconds as number) : null,
    repeatCount: typeof obj.RepeatCount === "number" ? (obj.RepeatCount as number) : null,
    // EARLIEST possible fire: lower bound only — ignores DelaySeconds and elapsed repeats.
    earliestFireIso: startUnix !== null ? new Date(Math.max(startUnix, nowUnix) * 1000).toISOString() : null,
    raw: obj,
  };
}

export interface CronAlert { level: "WARN"; reason: string; cron: CronSummary }

/** Pure: flag Crons whose remaining repeats are at/below the threshold. */
export function computeCronAlerts(crons: CronSummary[], lowThreshold: number): CronAlert[] {
  const alerts: CronAlert[] = [];
  for (const c of crons) {
    if (typeof c.repeatCount === "number" && c.repeatCount > 0 && c.repeatCount <= lowThreshold) {
      alerts.push({ level: "WARN", reason: `only ${c.repeatCount} repeat(s) left — extend with a CronSet before it exhausts`, cron: c });
    }
  }
  return alerts;
}

export async function listCronJobs(account: string, network: Network) {
  if (!validateAddress(account).valid) throw new Error("account is not a valid r-address / X-address");
  const r = await getAccountObjects(account, network); // no type filter — filter client-side for portability
  const objs = (r.account_objects ?? []) as Record<string, unknown>[];
  const crons = objs.filter((o) => o.LedgerEntryType === "Cron");
  const now = Math.floor(Date.now() / 1000);
  return {
    account, network,
    count: crons.length,
    crons: crons.map((c) => summarizeCron(c, now)),
    summary: `${crons.length} Cron object(s) on ${account}`,
    note: crons.length ? "Decoded fields are best-effort; raw ledger object included per entry." : "No Cron objects found. The account may have none, or this node may predate the Cron amendment.",
  };
}

export async function monitorCronHealth(account: string, network: Network, lowThreshold = 8) {
  const list = await listCronJobs(account, network);
  const alerts = computeCronAlerts(list.crons, lowThreshold);
  return {
    account, network,
    cronCount: list.count,
    lowThreshold,
    healthy: alerts.length === 0,
    alerts,
    summary: alerts.length
      ? `${alerts.length} Cron(s) near exhaustion on ${account} (≤${lowThreshold} repeats left)`
      : `${list.count} Cron(s) on ${account}, none near exhaustion`,
  };
}
