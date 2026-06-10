import { describe, it, expect } from "vitest";
import { runHook } from "../src/sandbox.js";
import { buildExitHook, buildHookWasm } from "./fixtures.js";

describe("Hook VM execution bounds", () => {
  it("refuses an unguarded loop before execution (honest halt)", () => {
    const r = runHook(buildHookWasm({ loop: "unguarded", exportHook: true }));
    expect(r.exit).toBe("halted");
    expect(String(r.returnString ?? "")).toMatch(/unguarded loop/);
  });

  it("a guarded SPINNING loop (maxiter=0) is stopped by the VM budget, not a hang", () => {
    const t0 = Date.now();
    const r = runHook(buildHookWasm({ loop: "guarded-spin", exportHook: true }));
    expect(Date.now() - t0).toBeLessThan(10_000); // bounded — returns rather than hanging
    expect(r.exit).toBe("halted");
    expect(String(r.returnString ?? "")).toMatch(/VM_BUDGET/);
    expect(String(r.returnString ?? "")).toMatch(/not a consensus limit/); // honest labeling
  });
});

describe("Hook VM (sandbox)", () => {
  it("runs real bytecode and captures an accept with its return code (state applied)", () => {
    const r = runHook(buildExitHook("accept", 42));
    expect(r.exit).toBe("accept");
    expect(r.returnCode).toBe("42");
    expect(r.fidelity).toBe("LOCAL_VM");
    expect(r.degraded).toBe(false);
    expect(r.stateApplied).toBe(true);
  });

  it("captures a rollback with its return code (state NOT applied)", () => {
    const r = runHook(buildExitHook("rollback", 7));
    expect(r.exit).toBe("rollback");
    expect(r.returnCode).toBe("7");
    expect(r.stateApplied).toBe(false);
  });

  it("records unsupported API calls and marks the run degraded", () => {
    const r = runHook(buildExitHook("accept", 1, { extraImport: "meta_slot" }));
    expect(r.exit).toBe("accept");
    expect(r.unsupportedCalls).toContain("meta_slot");
    expect(r.degraded).toBe(true);
  });

  it("HONESTY: a data-bearing stub called without ctx is recorded unsupported + degraded", () => {
    // otxn_id is only fake-safe if ctx supplies it; without it the run must be degraded
    const r = runHook(buildExitHook("accept", 1, { extraImport: "otxn_id" }));
    expect(r.unsupportedCalls).toContain("otxn_id");
    expect(r.degraded).toBe(true);
  });

  it("a supported call (util_sha512h) does NOT mark the run degraded", () => {
    const r = runHook(buildExitHook("accept", 1, { extraImport: "util_sha512h" }));
    expect(r.unsupportedCalls).not.toContain("util_sha512h");
    expect(r.degraded).toBe(false);
  });

  it("reports a hook that never calls accept/rollback", () => {
    // a plain hook export with an empty body returns without an exit call
    const r = runHook(buildHookWasm({ imports: [{ module: "env", name: "accept" }], exportHook: true }));
    expect(r.exit).toBe("no-exit-called");
  });
});
