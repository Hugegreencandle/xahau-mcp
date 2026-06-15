import { describe, it, expect } from "vitest";
import { buildCronSet, summarizeCron, computeCronAlerts, RIPPLE_EPOCH, MAX_REPEATS } from "../src/cron.js";

const ACCT = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

describe("buildCronSet", () => {
  it("builds a recurring CronSet with explicit StartTime", () => {
    const r = buildCronSet({ account: ACCT, startTime: 816348759, repeatCount: 3, delaySeconds: 120, network: "mainnet" });
    expect(r.unsignedTx).toMatchObject({
      TransactionType: "CronSet", Account: ACCT, NetworkID: 21337,
      StartTime: 816348759, RepeatCount: 3, DelaySeconds: 120,
    });
    expect(JSON.stringify(r.unsignedTx)).not.toMatch(/TxnSignature|SigningPubKey/);
  });

  it("defaults StartTime to 0 (ASAP) and flags a one-off", () => {
    const r = buildCronSet({ account: ACCT });
    expect(r.unsignedTx.StartTime).toBe(0);
    expect(r.unsignedTx.RepeatCount).toBeUndefined();
    expect(r.preflightFindings?.some((f) => f.ruleId === "CRON-ONE-OFF")).toBe(true);
  });

  it("computes StartTime from startInSeconds with injected now", () => {
    const now = 1_800_000_000; // fixed unix
    const r = buildCronSet({ account: ACCT, startInSeconds: 600, nowUnix: now });
    expect(r.unsignedTx.StartTime).toBe(now - RIPPLE_EPOCH + 600);
  });

  it("cancel sets tfCronUnset and warns", () => {
    const r = buildCronSet({ account: ACCT, cancel: true });
    expect(r.unsignedTx.Flags).toBe(1);
    expect(r.unsignedTx.StartTime).toBeUndefined();
    expect(r.preflightFindings?.some((f) => f.ruleId === "CRON-UNSET")).toBe(true);
  });

  it("warns when recurring but no DelaySeconds", () => {
    const r = buildCronSet({ account: ACCT, repeatCount: 5 });
    expect(r.preflightFindings?.some((f) => f.ruleId === "CRON-NO-DELAY")).toBe(true);
  });

  it("rejects out-of-range repeatCount and bad inputs", () => {
    expect(() => buildCronSet({ account: ACCT, repeatCount: MAX_REPEATS + 1 })).toThrow(/0–256/);
    expect(() => buildCronSet({ account: ACCT, delaySeconds: -1 })).toThrow(/delaySeconds/);
    expect(() => buildCronSet({ account: ACCT, startTime: -5 })).toThrow(/startTime/);
    expect(() => buildCronSet({ account: "nope" })).toThrow(/valid r-address/);
  });
});

describe("summarizeCron", () => {
  it("decodes StartTime to ISO and estimates next fire", () => {
    const startTime = 816348759;
    const obj = { LedgerEntryType: "Cron", Owner: ACCT, StartTime: startTime, DelaySeconds: 120, RepeatCount: 3 };
    const now = startTime + RIPPLE_EPOCH - 1000; // before start
    const s = summarizeCron(obj, now);
    expect(s.owner).toBe(ACCT);
    expect(s.repeatCount).toBe(3);
    expect(s.startTimeIso).toBe(new Date((startTime + RIPPLE_EPOCH) * 1000).toISOString());
    expect(s.nextFireIso).toBe(new Date((startTime + RIPPLE_EPOCH) * 1000).toISOString());
    expect(s.raw).toBe(obj);
  });

  it("handles missing fields gracefully", () => {
    const s = summarizeCron({ LedgerEntryType: "Cron" }, 0);
    expect(s.startTime).toBeNull();
    expect(s.nextFireIso).toBeNull();
    expect(s.repeatCount).toBeNull();
  });
});

describe("computeCronAlerts", () => {
  const mk = (repeatCount: number | null) => summarizeCron({ StartTime: 1, RepeatCount: repeatCount ?? undefined } as any, 0);
  it("warns only on low-but-nonzero remaining repeats", () => {
    const crons = [mk(2), mk(50), mk(0), mk(null)];
    const alerts = computeCronAlerts(crons, 8);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].reason).toMatch(/2 repeat/);
  });
  it("no alerts when all healthy", () => {
    expect(computeCronAlerts([mk(100), mk(20)], 8)).toHaveLength(0);
  });
});
