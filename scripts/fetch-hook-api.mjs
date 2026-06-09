// Rebuilds data/hook-api.json (the analyzer's Hook API catalog + hazard metadata)
// from the canonical env-import list in Xahau/hooks-rs (c/extern.h). Run: npm run fetch:hookapi
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DATA = join(dirname(fileURLToPath(import.meta.url)), "..", "data");
const SRC = process.env.HOOKAPI_SRC || "https://raw.githubusercontent.com/Xahau/hooks-rs/main/hooks-rs/c/extern.h";

const h = await (await fetch(SRC)).text();
const names = [...new Set([...h.matchAll(/\n([a-z_][a-z0-9_]*)\s*\(/g)].map((m) => m[1]))].filter((n) => n !== "if" && n !== "for");

const catOf = (n) => {
  if (n === "_g" || n === "accept" || n === "rollback") return "control";
  if (n === "emit" || n.startsWith("etxn_")) return "etxn";
  if (n.startsWith("float_")) return "float";
  if (n.startsWith("hook_")) return "hook";
  if (n.startsWith("ledger_") || n === "fee_base") return "ledger";
  if (n.startsWith("otxn_")) return "otxn";
  if (n.startsWith("slot") || n === "meta_slot") return "slot";
  if (n.startsWith("state")) return "state";
  if (n.startsWith("sto_")) return "sto";
  if (n.startsWith("trace")) return "trace";
  if (n.startsWith("util_")) return "util";
  return "other";
};
const HAZ = {
  emit: [{ ruleId: "HOOK-003-EMIT-NO-CBAK", severity: "HIGH", note: "emit() requires an exported cbak()" }, { ruleId: "HOOK-009-EMIT-COUNT-RESERVE", severity: "MEDIUM", note: "each emit must be backed by etxn_reserve" }, { ruleId: "HOOK-010-REENTRANCY-EMIT", severity: "MEDIUM", note: "emit reachable from cbak can loop" }],
  state_set: [{ ruleId: "HOOK-008-STATE-UNBOUNDED", severity: "MEDIUM", note: "state_set value size is unbounded" }],
  state_foreign_set: [{ ruleId: "HOOK-008-STATE-UNBOUNDED", severity: "MEDIUM", note: "writes state on ANOTHER account; needs a HookGrant" }, { ruleId: "HOOK-007-DANGEROUS-GRANT", severity: "HIGH", note: "foreign-state writes depend on grants" }],
  hook_again: [{ ruleId: "HOOK-010-REENTRANCY-EMIT", severity: "MEDIUM", note: "re-triggers the hook; verify termination" }],
};
const floatHaz = [{ ruleId: "HOOK-012-FLOAT-USAGE", severity: "LOW", note: "XFL float result must use float_* ops, not native arithmetic" }];

const functions = names.sort().map((name) => {
  const category = catOf(name);
  return { name, module: "env", category, isExit: name === "accept" || name === "rollback", isGuard: name === "_g",
    hazards: HAZ[name] || (category === "float" && name !== "float_compare" ? floatHaz : []) };
});
mkdirSync(DATA, { recursive: true });
writeFileSync(join(DATA, "hook-api.json"), JSON.stringify({
  _source: "Xahau/hooks-rs c/extern.h (canonical env imports)", _captured: new Date().toISOString().slice(0, 10),
  _note: "guard function is _g(guard_id,maxiter); accept/rollback are the only legal exit functions.",
  count: functions.length, functions,
}));
console.log(`hook-api: ${functions.length} functions (guard=_g, exits=accept/rollback)`);
