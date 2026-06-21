import { describe, it, expect } from "vitest";
import { gradeSignals } from "../src/quantum.js";

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
