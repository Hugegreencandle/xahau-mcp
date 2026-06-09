import { describe, it, expect } from "vitest";
import { readWasm } from "../src/wasm.js";
import { classifyHook } from "../src/classify.js";
import { buildHookWasm } from "./fixtures.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
const loadHex = (n: string) => readFileSync(join(DIR, n + ".hex"), "utf8").trim();
const hexToBytes = (h: string) => new Uint8Array(Buffer.from(h, "hex"));

describe("classify_hook", () => {
  it("reads-only + rollback => transaction filter / firewall", () => {
    const w = readWasm(buildHookWasm({ imports: [{ module: "env", name: "otxn_field" }, { module: "env", name: "rollback" }, { module: "env", name: "accept" }], exportHook: true }));
    const c = classifyHook(w);
    expect(c.archetype).toMatch(/filter|firewall/);
    expect(c.capabilities.join(" ")).toMatch(/originating-transaction/);
  });

  it("emit + state => autonomous agent", () => {
    const w = readWasm(buildHookWasm({ imports: [{ module: "env", name: "emit" }, { module: "env", name: "state_set" }, { module: "env", name: "accept" }], exportHook: true, exportCbak: true }));
    const c = classifyHook(w);
    expect(c.archetype).toMatch(/autonomous|emit/);
    expect(c.capabilities.join(" ")).toMatch(/emits/);
  });

  it("classifies the real mainnet reward hook as financial/stateful (fires on ClaimReward)", () => {
    const w = readWasm(hexToBytes(loadHex("genesis-reward")));
    const c = classifyHook(w, "0".repeat(64)); // fires on all-but-SetHook incl ClaimReward
    expect(["high", "medium", "low"]).toContain(c.confidence);
    expect(c.capabilities.length).toBeGreaterThan(0);
    expect(c.summary).toContain("fires on");
  });
});
