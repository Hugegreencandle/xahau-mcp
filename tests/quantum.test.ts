import { describe, it, expect } from "vitest";
import { gradeSignals, classifyHndl, accountIdFromPubkey, assessCoverage, aggregateScorecard } from "../src/quantum.js";
import type { ScorecardRow } from "../src/quantum.js";

describe("quantum_grade scoring", () => {
  it("master enabled, nothing else = LOW (exposed)", () => {
    const g = gradeSignals({ masterDisabled: false, hasRegularKey: false, hasMultiSig: false, signerCount: 0 });
    expect(g.score).toBe(0);
    expect(g.tier).toBe("LOW");
  });

  it("master disabled + multisig = HIGH", () => {
    const g = gradeSignals({ masterDisabled: true, hasRegularKey: false, hasMultiSig: true, signerCount: 3 });
    expect(g.score).toBe(75);
    expect(g.tier).toBe("HIGH");
  });

  it("regular key only = MEDIUM band lower edge", () => {
    const g = gradeSignals({ masterDisabled: false, hasRegularKey: true, hasMultiSig: false, signerCount: 0 });
    expect(g.score).toBe(25);
    expect(g.tier).toBe("LOW");
  });

  it("master disabled + regular key = MEDIUM", () => {
    const g = gradeSignals({ masterDisabled: true, hasRegularKey: true, hasMultiSig: false, signerCount: 0 });
    expect(g.score).toBe(65);
    expect(g.tier).toBe("MEDIUM");
  });

  it("always recommends a Hook PQC-policy angle", () => {
    const g = gradeSignals({ masterDisabled: true, hasRegularKey: true, hasMultiSig: true, signerCount: 2 });
    expect(g.recommendations.some((r) => /Hook/.test(r))).toBe(true);
  });

  it("de-alarm: master-active signal is neutral, not alarm language", () => {
    const g = gradeSignals({ masterDisabled: false, hasRegularKey: false, hasMultiSig: false, signerCount: 0 });
    const masterSignal = g.signals.find((s) => /master key active/.test(s));
    expect(masterSignal).toBeTruthy();
    // no alarm words anywhere in the signals
    expect(g.signals.join(" ")).not.toMatch(/exposed|ENABLED|vulnerable|at risk|HNDL target/i);
  });

  it("de-alarm: tierLabel maps to hardening language", () => {
    expect(gradeSignals({ masterDisabled: false, hasRegularKey: false, hasMultiSig: false, signerCount: 0 }).tierLabel).toBe("BASELINE");
    expect(gradeSignals({ masterDisabled: true, hasRegularKey: true, hasMultiSig: false, signerCount: 0 }).tierLabel).toBe("HARDENED");
    expect(gradeSignals({ masterDisabled: true, hasRegularKey: false, hasMultiSig: true, signerCount: 3 }).tierLabel).toBe("WELL HARDENED");
  });

  it("honesty: recommends a proven quantum-policy Hook when absent", () => {
    const g = gradeSignals({ masterDisabled: true, hasRegularKey: true, hasMultiSig: true, signerCount: 2 });
    expect(g.recommendations.some((r) => /PROVEN quantum-policy Hook|qkey_guard/.test(r))).toBe(true);
  });

  it("step-4: proven quantum hook adds +30 and recommendation drops", () => {
    const base = gradeSignals({ masterDisabled: false, hasRegularKey: true, hasMultiSig: false, signerCount: 0 });
    const withHook = gradeSignals({ masterDisabled: false, hasRegularKey: true, hasMultiSig: false, signerCount: 0, hasProvenQuantumHook: true });
    expect(withHook.score).toBe(base.score + 30);                       // 25 -> 55
    expect(withHook.tier).toBe("MEDIUM");                                // 55 in [35,70)
    expect(withHook.signals.some((s) => /PROVEN quantum-policy Hook/.test(s))).toBe(true);
    expect(withHook.recommendations.some((r) => /qkey_guard/.test(r))).toBe(false); // no longer recommended
  });

  it("step-4: score caps at 100 with all signals", () => {
    const g = gradeSignals({ masterDisabled: true, hasRegularKey: true, hasMultiSig: true, signerCount: 3, hasProvenQuantumHook: true });
    expect(g.score).toBe(100);   // 40+35+25+30 = 130 -> capped 100
    expect(g.tier).toBe("HIGH");
  });
});

describe("HNDL exposure classifier", () => {
  const ME = "rTESTaccount";
  const PK_MASTER = "ED" + "AA".repeat(32);
  const ACC = accountIdFromPubkey(PK_MASTER);             // master pubkey hashes to THIS accountId
  const PK_REGULAR = "ED" + "BB".repeat(32);              // a different (regular) key

  it("derive: pubkey -> accountID is RIPEMD160(SHA256(pubkey))", () => {
    expect(ACC).toBe("862A19A6D8060DEC41266AAE38E133522EA9C9EE");
    expect(accountIdFromPubkey(PK_REGULAR)).not.toBe(ACC);
  });

  it("never-signed account => exposureClass none, not exposed", () => {
    const c = classifyHndl(ME, ACC, [{ account: "rSomeoneElse", signingPubKey: PK_MASTER }]); // only INCOMING
    expect(c.exposed).toBe(false);
    expect(c.exposureClass).toBe("none");
    expect(c.signedTxCount).toBe(0);
  });

  it("master-signed self tx => master exposed (irreversible class)", () => {
    const c = classifyHndl(ME, ACC, [{ account: ME, signingPubKey: PK_MASTER, ledger: 100 }]);
    expect(c.masterExposed).toBe(true);
    expect(c.exposureClass).toBe("master");
    expect(c.firstExposureLedger).toBe(100);
  });

  it("regular-key-only self tx => regular exposed, NOT master", () => {
    const c = classifyHndl(ME, ACC, [{ account: ME, signingPubKey: PK_REGULAR, ledger: 50 }]);
    expect(c.masterExposed).toBe(false);
    expect(c.regularExposed).toBe(true);
    expect(c.exposureClass).toBe("regular");
  });

  it("multi-signed self tx (empty SigningPubKey + Signers) => multisig exposed", () => {
    const c = classifyHndl(ME, ACC, [{ account: ME, signingPubKey: "", signers: [{ signingPubKey: PK_REGULAR }] }]);
    expect(c.multisigExposed).toBe(true);
    expect(c.exposureClass).toBe("multisig");
  });

  it("priority: master beats regular/multisig when both present", () => {
    const c = classifyHndl(ME, ACC, [
      { account: ME, signingPubKey: PK_REGULAR, ledger: 200 },
      { account: ME, signingPubKey: PK_MASTER, ledger: 300 },
      { account: ME, signingPubKey: "", signers: [{ signingPubKey: PK_REGULAR }], ledger: 400 },
    ]);
    expect(c.exposureClass).toBe("master");
    expect(c.regularExposed && c.multisigExposed && c.masterExposed).toBe(true);
    expect(c.firstExposureLedger).toBe(200);   // earliest exposing tx
  });

  it("empty SigningPubKey with NO signers (anomaly) => not counted as exposure", () => {
    const c = classifyHndl(ME, ACC, [{ account: ME, signingPubKey: "" }]);
    expect(c.exposed).toBe(false);
    expect(c.signedTxCount).toBe(1);   // counted as originated, but no key revealed
  });
});

describe("HNDL coverage proof (audit MUST-FIX: no false 'safe')", () => {
  it("exposed => always conclusive regardless of coverage", () => {
    const cov = assessCoverage({ exposed: true, nodeEarliest: null, oldestTxLedger: null, newestTxLedger: null, accountLastLedger: null });
    expect(cov.conclusive).toBe(true);
  });

  it("both ends covered => negative is conclusive (NONE allowed)", () => {
    // node holds ledger 100 (older than account's first tx 500); scan reached account's last tx 900
    const cov = assessCoverage({ exposed: false, nodeEarliest: 100, oldestTxLedger: 500, newestTxLedger: 900, accountLastLedger: 900 });
    expect(cov.earlySideComplete).toBe(true);
    expect(cov.lateSideComplete).toBe(true);
    expect(cov.conclusive).toBe(true);
  });

  it("EARLY history pruned (node starts at/after account's first tx) => NOT conclusive", () => {
    // node earliest 500 == account's oldest seen tx 500: earlier txns may be pruned -> unknown
    const cov = assessCoverage({ exposed: false, nodeEarliest: 500, oldestTxLedger: 500, newestTxLedger: 900, accountLastLedger: 900 });
    expect(cov.earlySideComplete).toBe(false);
    expect(cov.conclusive).toBe(false);   // <- the false-"safe" the audit caught, now UNKNOWN
  });

  it("scan didn't reach latest activity (truncation/early-stop) => NOT conclusive", () => {
    const cov = assessCoverage({ exposed: false, nodeEarliest: 100, oldestTxLedger: 500, newestTxLedger: 800, accountLastLedger: 900 });
    expect(cov.lateSideComplete).toBe(false);
    expect(cov.conclusive).toBe(false);
  });

  it("unknown node history (server_info failed) => NOT conclusive", () => {
    const cov = assessCoverage({ exposed: false, nodeEarliest: null, oldestTxLedger: 500, newestTxLedger: 900, accountLastLedger: 900 });
    expect(cov.earlySideComplete).toBe(false);
    expect(cov.conclusive).toBe(false);
  });
});

describe("quantum scorecard aggregation", () => {
  const row = (o: Partial<ScorecardRow>): ScorecardRow => ({
    address: "r" + Math.abs((o.gradeScore ?? 0) * 7 + 1), exposureClass: "none", severity: "NONE", conclusive: true,
    balanceDrops: "0", balanceAtRiskDrops: "0", gradeScore: 0, gradeTier: "LOW", hasProvenQuantumHook: false, masterDisabled: false, ...o,
  });

  it("buckets by class; non-conclusive 'none' => unknown, never none", () => {
    const a = aggregateScorecard([
      row({ exposureClass: "master", severity: "CRITICAL", balanceDrops: "1000000", balanceAtRiskDrops: "1000000" }),
      row({ exposureClass: "regular", severity: "RECOVERABLE", balanceDrops: "500000", balanceAtRiskDrops: "500000" }),
      row({ exposureClass: "none", severity: "NONE", conclusive: true }),
      row({ exposureClass: "none", severity: "UNKNOWN", conclusive: false }),  // <- must bucket as unknown
    ]);
    expect(a.byExposureClass).toEqual({ master: 1, regular: 1, multisig: 0, none: 1, unknown: 1 });
    expect(a.exposedCount).toBe(2);          // master + regular (unknown-none is NOT counted exposed)
    expect(a.masterExposedCount).toBe(1);
    expect(a.unknownCount).toBe(1);
  });

  it("sums balances with BigInt (no float drift) and at-risk", () => {
    const a = aggregateScorecard([
      row({ exposureClass: "master", balanceDrops: "9999999999999999", balanceAtRiskDrops: "9999999999999999" }),
      row({ exposureClass: "none", balanceDrops: "1", balanceAtRiskDrops: "0" }),
    ]);
    expect(a.totalBalanceDrops).toBe("10000000000000000");
    expect(a.balanceAtRiskDrops).toBe("9999999999999999");
    expect(a.masterExposedBalanceDrops).toBe("9999999999999999");
  });

  it("topExposedByBalance sorts desc and excludes 'none'", () => {
    const a = aggregateScorecard([
      row({ exposureClass: "regular", balanceAtRiskDrops: "100" }),
      row({ exposureClass: "master", balanceAtRiskDrops: "900" }),
      row({ exposureClass: "none", balanceAtRiskDrops: "0" }),
      row({ exposureClass: "multisig", balanceAtRiskDrops: "500" }),
    ]);
    expect(a.topExposedByBalance.map((r) => r.balanceAtRiskDrops)).toEqual(["900", "500", "100"]);
  });

  it("percentages computed over sample size", () => {
    const a = aggregateScorecard([
      row({ exposureClass: "master" }), row({ exposureClass: "master" }),
      row({ exposureClass: "none" }), row({ exposureClass: "none" }),
    ]);
    expect(a.exposedPct).toBe(50);
    expect(a.masterExposedPct).toBe(50);
  });
});
