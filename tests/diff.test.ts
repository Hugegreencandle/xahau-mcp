import { describe, it, expect } from "vitest";
import { readWasm } from "../src/wasm.js";
import { diffHooks } from "../src/diff.js";
import { buildHookWasm } from "./fixtures.js";

describe("hook_diff", () => {
  it("flags a newly-gained sensitive capability (emit)", () => {
    const before = readWasm(buildHookWasm({ imports: [{ module: "env", name: "accept" }], exportHook: true }));
    const after = readWasm(buildHookWasm({ imports: [{ module: "env", name: "accept" }, { module: "env", name: "emit" }], exportHook: true, exportCbak: true }));
    const d = diffHooks(before, after);
    expect(d.imports.added).toContain("emit");
    expect(d.exports.added).toContain("cbak");
    expect(d.newSensitiveCapabilities).toContain("emit");
    expect(d.summary).toMatch(/security-sensitive/);
  });

  it("reports HookOn changes when both supplied", () => {
    const w = readWasm(buildHookWasm({ imports: [{ module: "env", name: "accept" }], exportHook: true }));
    // all-zero HookOn fires on ~everything; all-F fires on almost nothing -> a big delta
    const d = diffHooks(w, w, "0".repeat(64), "F".repeat(64));
    expect(d.firesOn).not.toBeNull();
    expect((d.firesOn!.added.length + d.firesOn!.removed.length)).toBeGreaterThan(0);
  });

  it("no structural change for identical hooks", () => {
    const w = readWasm(buildHookWasm({ imports: [{ module: "env", name: "accept" }], exportHook: true }));
    const d = diffHooks(w, w);
    expect(d.imports.added).toEqual([]);
    expect(d.imports.removed).toEqual([]);
    expect(d.byteSizeDelta).toBe(0);
  });
});
