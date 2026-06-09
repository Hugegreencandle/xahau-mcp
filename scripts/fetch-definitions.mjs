// Rebuilds data/definitions.json, data/hookon-txtypes.json and data/error-codes.json
// from a live Xahau node's `server_definitions` RPC. Run: npm run fetch:defs
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DATA = join(dirname(fileURLToPath(import.meta.url)), "..", "data");
const NODE = process.env.XAHAU_RPC || "https://xahau.network";

const res = await fetch(NODE, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ method: "server_definitions", params: [{}] }),
});
const raw = (await res.json()).result;
const captured = new Date().toISOString().slice(0, 10);
mkdirSync(DATA, { recursive: true });

writeFileSync(join(DATA, "definitions.json"), JSON.stringify({
  _source: `Xahau server_definitions (${NODE})`, _captured: captured,
  hash: raw.hash, native_currency_code: raw.native_currency_code,
  TYPES: raw.TYPES, LEDGER_ENTRY_TYPES: raw.LEDGER_ENTRY_TYPES,
  TRANSACTION_TYPES: raw.TRANSACTION_TYPES, TRANSACTION_RESULTS: raw.TRANSACTION_RESULTS,
  TRANSACTION_FLAGS: raw.TRANSACTION_FLAGS, FIELDS: raw.FIELDS,
}));

const txTypes = Object.fromEntries(Object.entries(raw.TRANSACTION_TYPES).filter(([, v]) => v >= 0));
writeFileSync(join(DATA, "hookon-txtypes.json"), JSON.stringify({
  _note: "HookOn is a 256-bit bitmap. bit n = transaction type whose value is n. INVERTED/active-low: bit SET(1)=does NOT fire; CLEAR(0)=fires. EXCEPTION: bit 22 (SetHook) is active-high. Verified vs xahau.network/docs/hooks/concepts/hookon-field.",
  SETHOOK_BIT: 22, txTypes,
}, null, 1));

writeFileSync(join(DATA, "error-codes.json"), JSON.stringify({ _source: "Xahau server_definitions TRANSACTION_RESULTS", results: raw.TRANSACTION_RESULTS }));

console.log(`definitions: ${Object.keys(raw.TRANSACTION_TYPES).length} tx types, ${raw.FIELDS.length} fields, ${Object.keys(raw.TRANSACTION_RESULTS).length} result codes (captured ${captured})`);
