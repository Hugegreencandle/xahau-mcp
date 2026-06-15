import { describe, it, expect } from "vitest";
import { runHook } from "../src/sandbox.js";
import { buildExitHook, buildHookWasm, buildReadFieldHook } from "./fixtures.js";

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

// Regression for the HIGH audit finding (src/sandbox.ts:211-222): read-side host fns must return
// TOO_SMALL (-4) when the guest buffer is smaller than the value, NOT silently truncate + return a
// positive length. The hook below rolls back when the read fn returns a negative code (the common
// defensive pattern) and accepts otherwise — so a truncation bug flips the accept/rollback verdict.
describe("Hook VM read-side TOO_SMALL semantics (audit HIGH regression)", () => {
  // 48-byte IOU STAmount field; hook hands otxn_field an 8-byte (wl=8) native-XRP-sized buffer.
  const IOU_AMOUNT_48 = "D0".repeat(48); // 48 bytes of hex, content irrelevant to size check

  it("otxn_field into an undersized buffer returns TOO_SMALL → hook rolls back (was: truncate→accept)", () => {
    const r = runHook(buildReadFieldHook("otxn_field", 8, 6), { otxnFields: { "6": IOU_AMOUNT_48 } });
    // Pre-fix: otxn_field truncated the 48-byte value to 8 bytes and returned 8 (positive) → accept.
    // Post-fix: returns TOO_SMALL (-4) and writes nothing → the rc<0 branch rolls back, matching xahaud.
    expect(r.exit).toBe("rollback");
    expect(r.returnCode).toBe("0"); // hook's own rollback code, proves the rc<0 branch was taken
  });

  it("otxn_field into an adequately-sized buffer is UNCHANGED → hook accepts", () => {
    // wl=48 holds the full 48-byte value; rc = +48 (>=0) → accept. Confirms the fix is size-gated only.
    const r = runHook(buildReadFieldHook("otxn_field", 48, 6), { otxnFields: { "6": IOU_AMOUNT_48 } });
    expect(r.exit).toBe("accept");
    expect(r.returnCode).toBe("1");
  });

  it("state into an undersized buffer returns TOO_SMALL → hook rolls back", () => {
    // state(wp=0, wl=8, kp=0, kl=6): reads a 6-byte key from guest memory (all zeros at boot);
    // padStateKey left-pads it to the 32-byte all-zero on-ledger key. Value is 40 bytes > 8 → TOO_SMALL.
    const key = "0".repeat(64); // 32 zero bytes
    const r = runHook(buildReadFieldHook("state", 8, 0, 6), { state: { [key]: "D0".repeat(40) } });
    expect(r.exit).toBe("rollback");
  });

  it("hook_param into an undersized buffer returns TOO_SMALL → hook rolls back", () => {
    // hook_param(wp=0, wl=8, kp=0, kl=6): the 6-byte param NAME read from guest memory is six zero
    // bytes → hex "000000000000". Value is 40 bytes > 8 → TOO_SMALL.
    const r = runHook(buildReadFieldHook("hook_param", 8, 0, 6), { hookParams: { "000000000000": "D0".repeat(40) } });
    expect(r.exit).toBe("rollback");
  });
});
