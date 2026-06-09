import { describe, it, expect } from "vitest";
import { listRules } from "../src/analyzer.js";
import { HOOK_FUNCTIONS, hookApiCount } from "../src/hookapi.js";
import { allTxTypes } from "../src/defs.js";

// Sanity-checks the offline data functions backing the MCP resources
// (xahau://rules, xahau://hook-api, xahau://tx-types). Fully offline.

describe("resource data sources", () => {
  it("listRules() returns a non-empty registry with stable shape", () => {
    const rules = listRules();
    expect(Array.isArray(rules)).toBe(true);
    expect(rules.length).toBeGreaterThan(0);
    for (const r of rules) {
      expect(typeof r.ruleId).toBe("string");
      expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(r.severity);
      expect(typeof r.title).toBe("string");
    }
    // rule ids are unique
    const ids = rules.map((r) => r.ruleId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("HOOK_FUNCTIONS is non-empty and matches hookApiCount()", () => {
    expect(Array.isArray(HOOK_FUNCTIONS)).toBe(true);
    expect(HOOK_FUNCTIONS.length).toBeGreaterThan(0);
    expect(HOOK_FUNCTIONS.length).toBe(hookApiCount());
    for (const f of HOOK_FUNCTIONS) {
      expect(typeof f.name).toBe("string");
    }
  });

  it("allTxTypes() returns name/value pairs", () => {
    const types = allTxTypes();
    expect(Array.isArray(types)).toBe(true);
    expect(types.length).toBeGreaterThan(0);
    for (const t of types) {
      expect(typeof t.name).toBe("string");
      expect(typeof t.value).toBe("number");
    }
  });

  it("each data source serializes to JSON (resource payload is JSON text)", () => {
    expect(() => JSON.stringify({ rules: listRules() })).not.toThrow();
    expect(() => JSON.stringify({ functions: HOOK_FUNCTIONS })).not.toThrow();
    expect(() => JSON.stringify({ txTypes: allTxTypes() })).not.toThrow();
  });
});
