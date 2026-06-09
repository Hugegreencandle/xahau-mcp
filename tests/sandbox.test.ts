import { describe, it, expect } from "vitest";
import { runHook } from "../src/sandbox.js";
import { buildExitHook, buildHookWasm } from "./fixtures.js";

describe("Hook VM (sandbox)", () => {
  it("runs real bytecode and captures an accept with its return code", () => {
    const r = runHook(buildExitHook("accept", 42));
    expect(r.exit).toBe("accept");
    expect(r.returnCode).toBe("42");
    expect(r.fidelity).toBe("LOCAL_VM");
    expect(r.degraded).toBe(false);
  });

  it("captures a rollback with its return code", () => {
    const r = runHook(buildExitHook("rollback", 7));
    expect(r.exit).toBe("rollback");
    expect(r.returnCode).toBe("7");
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
