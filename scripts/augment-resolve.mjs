// One-off: continue the iterative pre-resolve over an EXISTING data/hook-corpus.json
// (same logic as fetch-corpus.mjs stage 3b — no ledger re-walk). Serial + rate-limit tolerant.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DATA = join(dirname(fileURLToPath(import.meta.url)), "..", "data");
const NODE = process.env.XAHAU_RPC || "https://xahau.network";
const PAUSE_MS = 1300, BACKOFF_MS = 5000, MAX_RETRIES = 2;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rpcFull(method, params) {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    await sleep(PAUSE_MS);
    let bodyText;
    try {
      const res = await fetch(NODE, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ method, params: [params] }) });
      bodyText = await res.text();
    } catch { if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; } return null; }
    if (/rate limited/i.test(bodyText) && bodyText.trim().length < 64) { if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; } return null; }
    try { return JSON.parse(bodyText).result ?? null; } catch { if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; } return null; }
  }
  return null;
}

const { reconstructContext } = await import("../dist/fidelity.js");
const { runHook } = await import("../dist/sandbox.js");
const { hexToBytes } = await import("../dist/wasm.js");
const { validateAddress, accountIdToR } = await import("../dist/util.js");

const corpus = JSON.parse(readFileSync(join(DATA, "hook-corpus.json"), "utf8"));
let fetched = 0, absent = 0, keylets = 0;

for (const c of corpus.cases) {
  c.foreignState = c.foreignState ?? {};
  c.keyletBlobs = c.keyletBlobs ?? {};
  const v = validateAddress(c.hookAccount ?? "");
  const hookAccountId = v.valid && typeof v.accountId === "string" ? v.accountId : "00".repeat(20);
  for (const he of c.hookExecutions) {
    const code = he.HookHash ? corpus.hookCode[he.HookHash] : undefined;
    if (!code) continue;
    for (let round = 0; round < 10; round++) {
      const ctx = reconstructContext(c.tx, hookAccountId, c.ledgerCloseTime, c.hookState, c.foreignState, c.keyletBlobs, he.HookHash ? c.installedHookParams?.[he.HookHash] : undefined);
      if (he.HookHash) ctx.hookHash = he.HookHash;
      ctx.otxnId = c.txHash;
      let r;
      try { r = runHook(hexToBytes(code), ctx); } catch { break; }
      const wantsF = r.wantedForeignState.filter((k) => !(k in c.foreignState));
      const wantsK = r.wantedKeylets.filter((k) => !(k in c.keyletBlobs));
      if (!wantsF.length && !wantsK.length) break;
      let progressed = false;
      for (const composite of wantsF) {
        const [acc, ns, key] = composite.split("|");
        const rAddr = accountIdToR(acc);
        if (!rAddr) continue;
        const res = await rpcFull("ledger_entry", { hook_state: { account: rAddr, key, namespace_id: ns }, ledger_index: c.ledgerIndex - 1 });
        if (res === null) continue;
        if (res.status === "error" || res.error) { if (res.error === "entryNotFound") { c.foreignState[composite] = null; absent++; progressed = true; } continue; }
        const data = res.node?.HookStateData;
        if (typeof data === "string") { c.foreignState[composite] = data.toUpperCase(); fetched++; progressed = true; }
      }
      for (const idx of wantsK) {
        const res = await rpcFull("ledger_entry", { index: idx, binary: true, ledger_index: c.ledgerIndex - 1 });
        if (res === null) continue;
        const binHex = res.node_binary ?? res.node?.node_binary;
        if (typeof binHex === "string") { c.keyletBlobs[idx] = binHex.toUpperCase(); keylets++; progressed = true; }
      }
      if (!progressed) break;
    }
  }
  process.stderr.write(".");
}
console.error(`\n[augment] +${fetched} foreign entries, +${absent} confirmed-absent, +${keylets} keylets`);
writeFileSync(join(DATA, "hook-corpus.json"), JSON.stringify(corpus, null, 1));
console.error("[augment] wrote data/hook-corpus.json");
