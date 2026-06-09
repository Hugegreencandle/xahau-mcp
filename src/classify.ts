// Hook archetype / intent classifier. Infers what a Hook DOES, in plain English, purely from its
// structure (imported Hook-API functions, hook/cbak exports, HookOn, guard/loop/state/emit usage).
// Heuristic + offline — it reads the shape of the bytecode, it does not execute it.
import type { WasmInfo } from "./wasm.js";
import { decodeHookOn } from "./hookon.js";

export interface Classification {
  archetype: string;
  confidence: "high" | "medium" | "low";
  capabilities: string[];
  firesOn: string[] | null;
  behaviors: string[];
  summary: string;
}

const funcImports = (w: WasmInfo) => new Set(w.imports.filter((i) => i.kind === "func").map((i) => i.name));
const exportNames = (w: WasmInfo) => new Set(w.exports.filter((e) => e.kind === "func").map((e) => e.name));

export function classifyHook(w: WasmInfo, hookOn?: string): Classification {
  const im = funcImports(w);
  const ex = exportNames(w);
  const fires = hookOn ? decodeHookOn(hookOn).firesOn : null;

  const reads = im.has("otxn_field") || im.has("otxn_param") || im.has("otxn_type") || im.has("slot_subfield") || im.has("sto_subfield");
  const writesState = im.has("state_set") || im.has("state_foreign_set");
  const readsState = im.has("state") || im.has("state_foreign");
  const emits = im.has("emit");
  const computes = [...im].some((n) => n.startsWith("float_"));
  const foreignState = im.has("state_foreign_set") || im.has("state_foreign");
  const loops = w.loopCount > 0;
  const recursive = im.has("hook_again");
  const verifies = im.has("util_verify");

  const capabilities: string[] = [];
  if (reads) capabilities.push("reads originating-transaction fields/params");
  if (readsState) capabilities.push("reads hook state");
  if (writesState) capabilities.push(`writes hook state${foreignState ? " (incl. another account's, via grant)" : ""}`);
  if (emits) capabilities.push("emits its own transactions");
  if (computes) capabilities.push("does XFL float math");
  if (verifies) capabilities.push("verifies cryptographic signatures");
  if (recursive) capabilities.push("can re-trigger itself (hook_again)");

  const behaviors: string[] = [];
  if (!ex.has("hook")) behaviors.push("⚠ missing hook() entry point — likely invalid");
  if (emits && !ex.has("cbak")) behaviors.push("emits without a cbak() callback");
  if (loops && w.guardCallCount === 0) behaviors.push("⚠ has a loop with no guard (_g) — likely rejected");

  // archetype heuristics, most-specific first
  let archetype = "general hook";
  let confidence: Classification["confidence"] = "low";
  if (emits && (readsState || writesState)) { archetype = "autonomous agent (stateful + emits transactions)"; confidence = "high"; }
  else if (emits) { archetype = "forwarder / emitter (emits transactions in response to activity)"; confidence = "high"; }
  else if (computes && (writesState || readsState)) { archetype = "financial / accounting hook (stateful XFL math)"; confidence = "high"; }
  else if (writesState && reads) { archetype = "stateful processor (records/updates per-account state from incoming txns)"; confidence = "high"; }
  else if (reads && !writesState && !emits) { archetype = "transaction filter / firewall (accepts or rejects incoming txns by rule)"; confidence = "high"; }
  else if (writesState) { archetype = "state machine (maintains hook state)"; confidence = "medium"; }
  else if (verifies) { archetype = "authorizer (gates on signature verification)"; confidence = "medium"; }

  const firesTxt = fires ? (fires.length ? fires.join(", ") : "nothing (inert)") : "unknown (no HookOn supplied)";
  const summary =
    `This looks like a ${archetype}. It fires on: ${firesTxt}. ` +
    (capabilities.length ? `It ${capabilities.join("; ")}. ` : "It has no detectable side effects beyond accept/rollback. ") +
    (behaviors.length ? `Notes: ${behaviors.join("; ")}. ` : "") +
    `(Heuristic, from structure only — confirm with analyze_hook + execute_hook.)`;

  return { archetype, confidence, capabilities, firesOn: fires, behaviors, summary };
}
