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
    const r = runHook(buildExitHook("accept", 1, { extraImport: "slot_subfield" }));
    expect(r.exit).toBe("accept");
    expect(r.unsupportedCalls).toContain("slot_subfield");
    expect(r.degraded).toBe(true);
  });

  it("reports a hook that never calls accept/rollback", () => {
    // a plain hook export with an empty body returns without an exit call
    const r = runHook(buildHookWasm({ imports: [{ module: "env", name: "accept" }], exportHook: true }));
    expect(r.exit).toBe("no-exit-called");
  });
});
