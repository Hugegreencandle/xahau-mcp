// Isolated, interruptible hook execution for the PUBLIC HTTP shim.
//
// runHook runs untrusted wasm synchronously in V8 — a recursive hook (one that
// never calls the _g guard, so GUARD_BUDGET/WALL_MS never fire) wedges the event
// loop and OOM-crashes the process. We run each execution on a throwaway worker
// thread with a hard wall-clock and a memory cap: a hang is terminate()'d, an
// allocation bomb trips the worker's heap limit (worker dies, main survives).
import { Worker } from "node:worker_threads";
import type { SandboxContext, SandboxResult } from "./sandbox.js";

const WORKER_URL = new URL("./runhook-worker.js", import.meta.url);

export const ISOLATE_TIMEOUT_MS = Number(process.env.XAHC_HOOK_TIMEOUT_MS ?? 3000);
export const ISOLATE_MEM_MB = Number(process.env.XAHC_HOOK_MEM_MB ?? 256);

/**
 * Run a hook in a memory-capped worker with a hard timeout. Resolves with the
 * SandboxResult, or rejects if the hook hangs (timeout), busts the memory cap
 * (worker exit), or throws. The main process is never blocked or crashed.
 */
export function runHookIsolated(
  bytes: Uint8Array,
  ctx: SandboxContext,
  timeoutMs: number = ISOLATE_TIMEOUT_MS,
  memMb: number = ISOLATE_MEM_MB,
): Promise<SandboxResult> {
  return new Promise<SandboxResult>((resolve, reject) => {
    const worker = new Worker(WORKER_URL, {
      resourceLimits: { maxOldGenerationSizeMb: memMb },
    });
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new Error(
        `hook execution exceeded ${timeoutMs}ms and was terminated — likely an infinite loop or unguarded recursion`,
      ))),
      timeoutMs,
    );
    worker.on("message", (m: { ok: boolean; result?: SandboxResult; error?: string }) =>
      finish(() => (m.ok ? resolve(m.result as SandboxResult) : reject(new Error(m.error ?? "hook worker error")))),
    );
    worker.on("error", (e) =>
      finish(() => {
        // V8 phrases the heap-cap kill as "reaching memory limit" — normalize to the
        // "memory cap" wording the shim classifies as a caller-caused 422, not a 500.
        const m = e?.message ?? "";
        reject(/memory limit|heap out of memory/i.test(m)
          ? new Error(`hook exceeded the ${memMb}MB memory cap and was terminated — likely unbounded allocation or recursion`)
          : e);
      }),
    );
    worker.on("exit", (code) => {
      if (!settled) {
        finish(() => reject(new Error(
          `hook worker exited (code ${code}) — likely exceeded the ${memMb}MB memory cap`,
        )));
      }
    });
    worker.postMessage({ bytes, ctx });
  });
}
