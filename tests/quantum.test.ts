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

  it("honesty: Hook recommendation states enforcement is unproven/unscored", () => {
    const g = gradeSignals({ masterDisabled: true, hasRegularKey: true, hasMultiSig: true, signerCount: 2 });
    expect(g.recommendations.some((r) => /not scored|proven/.test(r))).toBe(true);
  });
});
