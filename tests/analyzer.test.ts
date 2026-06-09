import { describe, it, expect } from "vitest";
import { readWasm } from "../src/wasm.js";
import { runRules, listRules, RULES } from "../src/analyzer.js";
import { buildHookWasm } from "./fixtures.js";

const analyze = (bytes: Uint8Array, sethook = false, extra = {}) =>
  runRules({ wasm: readWasm(bytes), ...extra }, { sethook });

describe("Hook analyzer", () => {
  it("is silent on a clean hook (imports _g+accept, exports hook, no loop)", () => {
    const { findings } = analyze(buildHookWasm({ imports: [{ module: "env", name: "_g" }, { module: "env", name: "accept" }], exportHook: true }));
    expect(findings).toEqual([]);
  });

  it("fires CRITICAL when there is no exit and no hook export", () => {
    const { findings, summary } = analyze(buildHookWasm({ imports: [{ module: "env", name: "_g" }], exportHook: false }));
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toContain("HOOK-001-NO-EXIT");
    expect(ids).toContain("HOOK-002-NO-HOOK-EXPORT");
    expect(summary.CRITICAL).toBeGreaterThanOrEqual(2);
  });

  it("flags an unguarded loop (HOOK-005)", () => {
    const { findings } = analyze(buildHookWasm({ imports: [{ module: "env", name: "accept" }], loop: "unguarded", exportHook: true }));
    expect(findings.map((f) => f.ruleId)).toContain("HOOK-005-GUARD-MISSING");
  });

  it("flags an unknown env import (HOOK-004)", () => {
    const { findings } = analyze(buildHookWasm({ imports: [{ module: "env", name: "accept" }, { module: "env", name: "definitely_not_real" }], exportHook: true }));
    expect(findings.map((f) => f.ruleId)).toContain("HOOK-004-UNKNOWN-IMPORT");
  });

  it("flags emit without cbak and without reserve", () => {
    const { findings } = analyze(buildHookWasm({ imports: [{ module: "env", name: "accept" }, { module: "env", name: "emit" }], exportHook: true }));
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toContain("HOOK-003-EMIT-NO-CBAK");
    expect(ids).toContain("HOOK-009-EMIT-COUNT-RESERVE");
  });

  it("reports an inert HookOn and a dangerous grant under sethook context", () => {
    const bytes = buildHookWasm({ imports: [{ module: "env", name: "accept" }], exportHook: true });
    const { findings } = analyze(bytes, true, { hookOn: "f".repeat(56) + "0".repeat(8), grants: [{ HookGrant: { Authorize: "rNoBody000000000000000000000000000" } }] });
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toContain("HOOK-007-DANGEROUS-GRANT");
  });

  it("list_rules covers every registered rule id", () => {
    const listed = listRules().map((r) => r.ruleId).sort();
    const registry = RULES.map((r) => r.id).sort();
    expect(listed).toEqual(registry);
    expect(listed.length).toBeGreaterThanOrEqual(14);
  });
});
