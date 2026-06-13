// Worker entry for isolated hook execution. runHook compiles + runs untrusted
// wasm SYNCHRONOUSLY in V8's engine; recursion (or any path that never calls the
// _g guard) cannot be interrupted from JS. Running it here, on a throwaway worker
// thread, lets the main process terminate() it on timeout / memory cap instead of
// wedging the event loop and OOM-crashing.
import { parentPort } from "node:worker_threads";
import { runHook } from "./sandbox.js";

parentPort!.on("message", (msg: { bytes: Uint8Array; ctx: Record<string, unknown> }) => {
  try {
    const result = runHook(msg.bytes, msg.ctx as never);
    parentPort!.postMessage({ ok: true, result });
  } catch (e) {
    parentPort!.postMessage({ ok: false, error: (e as Error).message });
  }
  // one-shot: the caller terminates us either way (so a hang is killable).
});
