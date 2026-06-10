import { describe, it, expect } from "vitest";
import { readWasm, ensureMemoryExport } from "../src/wasm.js";
import { buildHookWasm } from "./fixtures.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

describe("ensureMemoryExport (VM memory shim)", () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
  const reward = new Uint8Array(Buffer.from(readFileSync(join(dir, "genesis-reward.hex"), "utf8").trim(), "hex"));

  it("adds a memory export to a real hook that has memory but doesn't export it", () => {
    const before = WebAssembly.Module.exports(new WebAssembly.Module(reward)).some((e) => e.kind === "memory");
    expect(before).toBe(false); // real mainnet hook exports only hook(), not memory
    const out = ensureMemoryExport(reward);
    expect(WebAssembly.validate(out)).toBe(true);
    const after = WebAssembly.Module.exports(new WebAssembly.Module(out));
    expect(after.some((e) => e.kind === "memory")).toBe(true); // now the VM can reach real linear memory
    expect(after.some((e) => e.name === "hook")).toBe(true);   // original export preserved
  });

  it("is idempotent + a no-op when memory is already exported", () => {
    const once = ensureMemoryExport(reward);
    const twice = ensureMemoryExport(once);
    expect(Buffer.from(twice).equals(Buffer.from(once))).toBe(true); // second pass changes nothing
  });
});

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
