import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fidelityReport, type HookCorpus } from "../src/fidelity.js";

// Loads the COMMITTED corpus and asserts structure (never a hard-coded percentage — the corpus can
// grow). The point is: it parses, every case's hook bytecode is present, and fidelityReport produces
// a sane shape with comparable <= total. If the corpus is empty/tiny the report says
// "insufficient corpus" and the test still passes.
const CORPUS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "data", "hook-corpus.json");

describe("fidelity corpus: committed data/hook-corpus.json", () => {
  it("exists and parses to the expected shape", () => {
    expect(existsSync(CORPUS_PATH)).toBe(true);
    const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as HookCorpus;
    expect(Array.isArray(corpus.cases)).toBe(true);
    expect(typeof corpus.hookCode).toBe("object");
    for (const cs of corpus.cases) {
      expect(typeof cs.txHash).toBe("string");
      expect(typeof cs.hookAccount).toBe("string");
      expect(Array.isArray(cs.hookExecutions)).toBe(true);
      expect(cs.tx && typeof cs.tx).toBe("object");
    }
  });

  it("every HookExecution's hook code is present in hookCode (or the case is honestly excludable)", () => {
    const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as HookCorpus;
    // For a corpus to be MEASURABLE, the hooks it scores must have bytecode. We assert that every
    // HookExecution that carries a HookHash has its CreateCode present (the builder dedupes code by
    // hash). HookExecutions without a hash are allowed but simply unscoreable.
    for (const cs of corpus.cases) {
      for (const he of cs.hookExecutions) {
        if (he.HookHash) {
          expect(Object.prototype.hasOwnProperty.call(corpus.hookCode, he.HookHash)).toBe(true);
          expect(typeof corpus.hookCode[he.HookHash]).toBe("string");
          expect(corpus.hookCode[he.HookHash].length).toBeGreaterThan(0);
        }
      }
    }
  });

  it("fidelityReport runs without throwing and returns a sane shape (comparable <= total)", () => {
    const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as HookCorpus;
    const rep = fidelityReport(corpus);

    // counts are non-negative integers and internally consistent
    expect(rep.total).toBeGreaterThanOrEqual(0);
    expect(rep.comparable).toBeLessThanOrEqual(rep.total);
    expect(rep.agreements).toBeLessThanOrEqual(rep.comparable);
    expect(rep.degradedCount).toBe(rep.total - rep.comparable);

    // agreementPct is either null (insufficient) or a 0..100 number consistent with the counts
    if (rep.comparable === 0) {
      expect(rep.agreementPct).toBeNull();
      expect(rep.insufficient).toBe(true);
      expect(rep.headline).toMatch(/insufficient corpus/i);
    } else {
      expect(rep.agreementPct).not.toBeNull();
      expect(rep.agreementPct!).toBeGreaterThanOrEqual(0);
      expect(rep.agreementPct!).toBeLessThanOrEqual(100);
      // pct ~= agreements/comparable (allow for 1-dp rounding)
      expect(Math.abs(rep.agreementPct! - (100 * rep.agreements) / rep.comparable)).toBeLessThan(0.2);
      expect(rep.headline).toMatch(/VM agrees with on-chain/);
    }

    // mismatches are well-formed and count consistently (every non-agreement that was comparable)
    expect(Array.isArray(rep.mismatches)).toBe(true);
    expect(rep.mismatches.length).toBe(rep.comparable - rep.agreements);
    for (const m of rep.mismatches) {
      expect(typeof m.txHash).toBe("string");
      expect(["accept", "rollback", "no-exit-called", "halted"]).toContain(m.vmExit);
    }

    // per-hook breakdown sums back to the totals
    const sumTotal = rep.perHook.reduce((a, h) => a + h.total, 0);
    const sumComparable = rep.perHook.reduce((a, h) => a + h.comparable, 0);
    const sumAgree = rep.perHook.reduce((a, h) => a + h.agreements, 0);
    expect(sumTotal).toBe(rep.total);
    expect(sumComparable).toBe(rep.comparable);
    expect(sumAgree).toBe(rep.agreements);
  });

  it("handles an empty corpus gracefully (insufficient, no throw)", () => {
    const rep = fidelityReport({ cases: [], hookCode: {} });
    expect(rep.total).toBe(0);
    expect(rep.comparable).toBe(0);
    expect(rep.agreementPct).toBeNull();
    expect(rep.insufficient).toBe(true);
    expect(rep.headline).toMatch(/insufficient corpus/i);
  });
});

describe("fidelity over the committed corpus (foreign-state reconstruction)", () => {
  // The committed corpus carries FULL pre-execution context (installed hook params, iteratively
  // pre-resolved foreign state, keylet blobs, otxn ids). With it, the VM must reproduce the
  // on-chain accept/rollback direction on EVERY comparable execution — this is the v1.7.0
  // milestone (Evernode heartbeat hook went 0% -> 100%) and a regression here means either the
  // VM or the resolve pipeline broke.
  it("agrees with on-chain on every comparable execution, 0 degraded", async () => {
    const { fidelityReport } = await import("../src/fidelity.js");
    const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
    const r = fidelityReport(corpus);
    expect(r.insufficient).toBe(false);
    expect(r.degradedCount).toBe(0);
    expect(r.comparable).toBe(r.total);
    expect(r.agreements).toBe(r.comparable);
    expect(r.agreementPct).toBe(100);
  });
});
