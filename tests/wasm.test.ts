import { describe, it, expect } from "vitest";
import { readWasm } from "../src/wasm.js";
import { buildHookWasm } from "./fixtures.js";

describe("WASM reader", () => {
  it("emits valid modules (cross-checked with built-in WebAssembly)", () => {
    const bytes = buildHookWasm({ exportHook: true });
    expect(WebAssembly.validate(bytes)).toBe(true);
  });

  it("imports/exports match Node's WebAssembly reflection", () => {
    const bytes = buildHookWasm({ imports: [{ module: "env", name: "_g" }, { module: "env", name: "accept" }, { module: "env", name: "emit" }], exportHook: true, exportCbak: true });
    const mod = new WebAssembly.Module(bytes);
    const nodeImports = WebAssembly.Module.imports(mod).map((i) => i.name).sort();
    const nodeExports = WebAssembly.Module.exports(mod).map((e) => e.name).sort();
    const info = readWasm(bytes);
    expect(info.valid).toBe(true);
    expect(info.imports.map((i) => i.name).sort()).toEqual(nodeImports);
    expect(info.exports.map((e) => e.name).sort()).toEqual(nodeExports);
    expect(info.exports.some((e) => e.name === "hook")).toBe(true);
    expect(info.exports.some((e) => e.name === "cbak")).toBe(true);
  });

  it("counts a guarded loop and its _g call", () => {
    const info = readWasm(buildHookWasm({ loop: "guarded", exportHook: true }));
    expect(info.loopCount).toBe(1);
    expect(info.guardCallCount).toBe(1);
    expect(info.scanComplete).toBe(true);
  });

  it("counts an unguarded loop with zero guard calls", () => {
    const info = readWasm(buildHookWasm({ loop: "unguarded", exportHook: true }));
    expect(info.loopCount).toBe(1);
    expect(info.guardCallCount).toBe(0);
  });

  it("reports malformed input gracefully (no throw)", () => {
    const info = readWasm(new Uint8Array([1, 2, 3, 4]));
    expect(info.valid).toBe(false);
    expect(info.reason).toMatch(/magic/);
  });
});
