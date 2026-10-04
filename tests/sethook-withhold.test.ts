import { describe, it, expect } from "vitest";
import { buildSetHookUnsigned } from "../src/builders.js";
import { buildHookWasm } from "./fixtures.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex").toUpperCase();
const base = { account: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", namespace: "A".repeat(64), txTypes: ["Payment"] };
// No exit and no hook export -> CRITICAL (see analyzer.test.ts)
const critical = hex(buildHookWasm({ imports: [{ module: "env", name: "_g" }], exportHook: false }));
const clean = hex(buildHookWasm({ imports: [{ module: "env", name: "_g" }, { module: "env", name: "accept" }], exportHook: true }));

describe("build_sethook_unsigned withholds on CRITICAL", () => {
  it("withholds the tx but returns the findings", () => {
    const r = buildSetHookUnsigned({ ...base, createCodeHex: critical });
    expect(r.blocked).toBe(true);
    expect(r.withheld).toBe(true);
    expect(r.unsignedTx).toBeNull();
    expect(r.preflightSummary?.CRITICAL).toBeGreaterThan(0);
    expect(r.preflightFindings?.length).toBeGreaterThan(0);
    expect(r.warning).toMatch(/WITHHELD/);
  });

  it("builds only with an explicit override, and says so", () => {
    const r = buildSetHookUnsigned({ ...base, createCodeHex: critical, overrideCritical: true });
    expect(r.withheld).toBe(false);
    expect(r.overrideCritical).toBe(true);
    expect(r.unsignedTx).toMatchObject({ TransactionType: "SetHook" });
    expect(r.warning).toMatch(/overrideCritical/);
  });

  it("a non-true override value does not unlock the tx", () => {
    const r = buildSetHookUnsigned({ ...base, createCodeHex: critical, overrideCritical: "true" as unknown as boolean });
    expect(r.unsignedTx).toBeNull();
  });

  it("a clean hook builds normally without an override", () => {
    const r = buildSetHookUnsigned({ ...base, createCodeHex: clean });
    expect(r.blocked).toBe(false);
    expect(r.withheld).toBe(false);
    expect(r.overrideCritical).toBe(false);
    expect(r.unsignedTx).toMatchObject({ TransactionType: "SetHook" });
    expect(r.warning).toBeUndefined();
  });
});
