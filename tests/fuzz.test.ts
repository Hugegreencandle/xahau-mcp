import { describe, it, expect } from "vitest";
import { fuzzHook } from "../src/fuzz.js";
import { buildExitHook, buildBranchOnTxTypeHook } from "./fixtures.js";

describe("Hook differential fuzzer", () => {
  it("classifies an always-accept hook: all accept, none reject, conclusive", () => {
    const r = fuzzHook(buildExitHook("accept", 5), {}, { txTypes: ["Payment", "AccountSet", "OfferCreate"], samples: 16 });
    expect(r.fidelity).toBe("LOCAL_VM_FUZZ");
    expect(r.inconclusive).toBe(false);
    expect(r.counts.rollback).toBe(0);
    expect(r.counts.accept).toBeGreaterThan(0);
    expect(r.counts.halted).toBe(0);
    expect(r.counts.degraded).toBe(0);
    expect(r.sampleAccepting.length).toBeGreaterThan(0);
    expect(r.sampleRejecting.length).toBe(0);
    // boundary summary should say it accepts across inputs
    expect(r.boundaries.join(" ")).toMatch(/accept/i);
  });

  it("classifies an always-rollback hook: all rollback, none accept", () => {
    const r = fuzzHook(buildExitHook("rollback", 9), {}, { txTypes: ["Payment", "AccountSet"], samples: 12 });
    expect(r.inconclusive).toBe(false);
    expect(r.counts.accept).toBe(0);
    expect(r.counts.rollback).toBeGreaterThan(0);
    expect(r.sampleRejecting.length).toBeGreaterThan(0);
    expect(r.sampleAccepting.length).toBe(0);
    expect(r.boundaries.join(" ")).toMatch(/rollback|reject/i);
  });

  it("finds the txType flip point of an input-dependent hook", () => {
    // accepts iff otxn_type() == 3 (AccountSet), else rollbacks
    const r = fuzzHook(buildBranchOnTxTypeHook(3), {}, {
      txTypes: ["Payment", "AccountSet", "OfferCreate", "EscrowFinish"],
      samples: 16,
    });
    expect(r.inconclusive).toBe(false);
    expect(r.counts.accept).toBeGreaterThan(0);
    expect(r.counts.rollback).toBeGreaterThan(0);
    const txAxis = r.axisFindings.find((a) => a.axis === "txType");
    expect(txAxis).toBeDefined();
    expect(txAxis!.accepted).toContain("AccountSet");
    expect(txAxis!.rejected).toContain("Payment");
    expect(txAxis!.rejected).toContain("OfferCreate");
    // a concrete accepting sample varied txType to the accepting one
    expect(r.sampleAccepting.some((s) => s.varied.txType === "AccountSet")).toBe(true);
    expect(r.sampleRejecting.length).toBeGreaterThan(0);
    expect(r.boundaries.join(" ")).toMatch(/AccountSet/);
  });

  it("reports an Amount-axis boundary line referencing raw drops", () => {
    // always-accept hook still sweeps Amount; boundary should note it accepts across the range
    const r = fuzzHook(buildExitHook("accept", 1), {}, {
      txTypes: ["Payment"],
      amountMin: 0,
      amountMax: 1000000,
      samples: 8,
    });
    expect(r.inconclusive).toBe(false);
    const amtAxis = r.axisFindings.find((a) => a.axis === "amount");
    expect(amtAxis).toBeDefined();
    expect(amtAxis!.accepted.length).toBeGreaterThan(0);
  });

  it("is fully deterministic: identical args produce identical results", () => {
    const args = () => fuzzHook(buildBranchOnTxTypeHook(3), {}, {
      txTypes: ["Payment", "AccountSet", "OfferCreate"],
      amountMin: 0,
      amountMax: 500,
      samples: 24,
    });
    const a = args();
    const b = args();
    expect(JSON.stringify(b.counts)).toBe(JSON.stringify(a.counts));
    expect(JSON.stringify(b.boundaries)).toBe(JSON.stringify(a.boundaries));
    expect(JSON.stringify(b.axisFindings)).toBe(JSON.stringify(a.axisFindings));
    expect(JSON.stringify(b.sampleAccepting.map((s) => s.varied))).toBe(JSON.stringify(a.sampleAccepting.map((s) => s.varied)));
  });

  it("is honest when every run is degraded/halted (inconclusive)", () => {
    // a hook that calls an unsupported API then accepts -> degraded on every run
    const r = fuzzHook(buildExitHook("accept", 1, { extraImport: "meta_slot" }), {}, {
      txTypes: ["Payment", "AccountSet"],
      samples: 8,
    });
    expect(r.counts.degraded).toBe(r.samples);
    expect(r.unsupportedCalls).toContain("meta_slot");
    expect(r.inconclusive).toBe(true);
    expect(r.caveat).toMatch(/INCONCLUSIVE/);
  });
});
