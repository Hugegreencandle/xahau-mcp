// Collects a REAL Xahau mainnet hook corpus = historical on-chain HookExecutions (ground truth)
// for the VM-fidelity harness (src/fidelity.ts). Writes data/hook-corpus.json.
//
// STRICT READ-ONLY. This script ONLY calls read methods (ledger / ledger_entry). It NEVER signs or
// submits anything. The public node https://xahau.network rate-limits bursts (it returns the literal
// text "Rate limited", not JSON), so EVERY RPC is SERIAL with a >=1200ms pause; on a rate-limit hit we
// back off ~5s and retry a couple times, then skip. We do NOT parallelize and we do NOT hammer.
//
// HONESTY: we cap the corpus (~25 cases / ~60 ledgers walked). If rate-limiting truncates the run we
// keep what we collected and report it. We do not fabricate cases.
//
// Run: node scripts/fetch-corpus.mjs
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DATA = join(dirname(fileURLToPath(import.meta.url)), "..", "data");
const NODE = process.env.XAHAU_RPC || "https://xahau.network";

const PAUSE_MS = 1300;            // >=1200ms between every RPC
const BACKOFF_MS = 5000;          // wait after a rate-limit hit
const MAX_RETRIES = 2;            // retries per call after a rate-limit, then skip
const MAX_LEDGERS = 80;           // cap on ledgers walked
const MAX_CASES = 30;             // cap on corpus size
const MAX_PER_LEDGER = 3;         // spread across ledgers (diversity + rollback odds) instead of draining one

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let rateLimitedTotal = 0;
let truncatedByRateLimit = false;

// Serial RPC with rate-limit tolerance. Returns the `result` object, or null if it had to skip.
async function rpc(method, params) {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    await sleep(PAUSE_MS);
    let res, bodyText;
    try {
      res = await fetch(NODE, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method, params: [params] }),
      });
      bodyText = await res.text();
    } catch (e) {
      // network blip: brief back off + retry
      rateLimitedTotal++; // count as a transient failure for honesty
      if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; }
      return null;
    }
    // The public node returns the literal text "Rate limited" (NOT JSON) when throttled.
    if (/rate limited/i.test(bodyText) && bodyText.trim().length < 64) {
      rateLimitedTotal++;
      truncatedByRateLimit = true;
      if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; }
      return null;
    }
    let json;
    try { json = JSON.parse(bodyText); }
    catch { // unexpected non-JSON; treat like a rate-limit/transient and back off
      rateLimitedTotal++;
      if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; }
      return null;
    }
    const r = json.result;
    if (!r || r.status === "error") return null;
    return r;
  }
  return null;
}

// Like rpc() but returns the raw `result` object INCLUDING error results, so callers can tell
// entryNotFound (confirmed-absent — meaningful) from a rate-limit skip (null — unknown).
async function rpcFull(method, params) {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    await sleep(PAUSE_MS);
    let bodyText;
    try {
      const res = await fetch(NODE, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ method, params: [params] }) });
      bodyText = await res.text();
    } catch { rateLimitedTotal++; if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; } return null; }
    if (/rate limited/i.test(bodyText) && bodyText.trim().length < 64) {
      rateLimitedTotal++; truncatedByRateLimit = true;
      if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; }
      return null;
    }
    try { return JSON.parse(bodyText).result ?? null; } catch { rateLimitedTotal++; if (attempt < MAX_RETRIES) { await sleep(BACKOFF_MS); continue; } return null; }
  }
  return null;
}

// Strip a ledger-embedded (expand:true) transaction down to a clean tx_json:
// TransactionType + signing/content fields, dropping metaData/hash/inLedger/validated/date.
function cleanTx(t) {
  const drop = new Set(["metaData", "meta", "hash", "inLedger", "ledger_index", "validated", "date", "ledger_hash", "close_time_iso"]);
  const out = {};
  for (const [k, v] of Object.entries(t)) if (!drop.has(k)) out[k] = v;
  return out;
}

// Extract the HookExecution array from tx metadata, normalizing the {HookExecution:{...}} wrapper.
function extractHookExecutions(meta) {
  const arr = Array.isArray(meta?.HookExecutions) ? meta.HookExecutions : [];
  const out = [];
  for (const w of arr) {
    const he = w && w.HookExecution ? w.HookExecution : w;
    if (!he) continue;
    out.push({
      HookHash: he.HookHash ?? null,
      HookResult: he.HookResult ?? null,
      HookReturnCode: he.HookReturnCode ?? null,
      HookAccount: he.HookAccount ?? null,
    });
  }
  return out;
}

async function main() {
  console.error(`[corpus] node=${NODE}  pause=${PAUSE_MS}ms  cap=${MAX_CASES} cases / ${MAX_LEDGERS} ledgers`);

  // 1. current validated ledger index
  const tip = await rpc("ledger", { ledger_index: "validated", transactions: false, expand: false });
  if (!tip || !tip.ledger) {
    console.error("[corpus] could not read validated ledger tip (rate-limited or node error). Aborting.");
    process.exit(1);
  }
  const tipIndex = Number(tip.ledger.ledger_index ?? tip.ledger.seqNum);
  console.error(`[corpus] validated tip = ${tipIndex}`);

  const cases = [];
  const hookCode = {};      // hash -> createCodeHex (dedup)
  const hookSeen = new Set(); // hashes we've already tried to fetch (incl. failed)
  let ledgersWalked = 0;

  for (let li = tipIndex; li > tipIndex - MAX_LEDGERS && cases.length < MAX_CASES; li--) {
    const led = await rpc("ledger", { ledger_index: li, transactions: true, expand: true });
    ledgersWalked++;
    if (!led || !led.ledger || !Array.isArray(led.ledger.transactions)) continue;
    const ledgerCloseTime = led.ledger.close_time ?? null; // Ripple time of this ledger's close (real value for ledger_last_time)

    let perLedger = 0;
    for (const t of led.ledger.transactions) {
      if (cases.length >= MAX_CASES || perLedger >= MAX_PER_LEDGER) break;
      const meta = t.metaData || t.meta;
      const hookExecutions = extractHookExecutions(meta);
      if (!hookExecutions.length) continue;

      cases.push({
        txHash: t.hash,
        ledgerIndex: li,
        ledgerCloseTime,
        tx: cleanTx(t),
        hookAccount: hookExecutions[0].HookAccount ?? null,
        hookExecutions: hookExecutions.map(({ HookHash, HookResult, HookReturnCode }) => ({ HookHash, HookResult, HookReturnCode })),
        engineResult: meta?.TransactionResult ?? null,
      });
      perLedger++;
    }
  }

  console.error(`[corpus] collected ${cases.length} cases from ${ledgersWalked} ledgers walked`);

  // 2b. for each case, fetch the hook account's REAL hook state at the ledger BEFORE the case
  // (pre-execution state — the node is full-history so this is accurate, not current/approximate).
  for (const c of cases) {
    if (!c.hookAccount) { c.hookState = {}; continue; }
    const st = await rpc("account_objects", { account: c.hookAccount, type: "hook_state", ledger_index: c.ledgerIndex - 1 });
    const state = {};
    for (const o of st?.account_objects ?? []) {
      const k = o.HookStateKey, v = o.HookStateData;
      if (typeof k === "string" && typeof v === "string") state[k.toUpperCase()] = v.toUpperCase();
    }
    c.hookState = state;
  }
  console.error(`[corpus] fetched pre-execution hook state for ${cases.length} cases`);

  // 3. fetch each distinct HookHash's CreateCode (dedup; many cases share a hook)
  const distinctHashes = new Set();
  for (const c of cases) for (const he of c.hookExecutions) if (he.HookHash) distinctHashes.add(he.HookHash);
  console.error(`[corpus] ${distinctHashes.size} distinct hook hashes -> fetching CreateCode`);

  for (const hash of distinctHashes) {
    if (hookSeen.has(hash)) continue;
    hookSeen.add(hash);
    const def = await rpc("ledger_entry", { hook_definition: hash, ledger_index: "validated" });
    const code = def?.node?.CreateCode;
    if (code && typeof code === "string") hookCode[hash] = code.toUpperCase();
    else console.error(`[corpus] CreateCode unavailable for ${hash} (skipped)`);
  }

  // 3a. INSTALLED HOOK PARAMETERS per (hookAccount, hookHash): the Hook ledger object's
  // HookParameters override, falling back to the HookDefinition's defaults — hooks like Evernode's
  // read their governor address from these (hook_param), so the VM needs them to get anywhere.
  const paramCache = new Map(); // `${account}|${hash}` -> {nameHex: valueHex}
  const extractParams = (arr) => {
    const out = {};
    for (const w of arr ?? []) {
      const pp = w && w.HookParameter ? w.HookParameter : w;
      if (pp && typeof pp.HookParameterName === "string") out[pp.HookParameterName.toUpperCase()] = String(pp.HookParameterValue ?? "").toUpperCase();
    }
    return out;
  };
  for (const c of cases) {
    c.installedHookParams = c.installedHookParams ?? {};
    for (const he of c.hookExecutions) {
      if (!he.HookHash || c.installedHookParams[he.HookHash]) continue;
      const ck = `${c.hookAccount}|${he.HookHash}`;
      if (!paramCache.has(ck)) {
        let params = null;
        const hk = await rpcFull("ledger_entry", { hook: { account: c.hookAccount }, ledger_index: c.ledgerIndex - 1 });
        const hooksArr = hk?.node?.Hooks;
        if (Array.isArray(hooksArr)) {
          for (const w of hooksArr) {
            const h = w && w.Hook ? w.Hook : w;
            if (h?.HookHash === he.HookHash && Array.isArray(h.HookParameters) && h.HookParameters.length) { params = extractParams(h.HookParameters); break; }
          }
        }
        if (!params) {
          const def = await rpcFull("ledger_entry", { hook_definition: he.HookHash, ledger_index: "validated" });
          if (Array.isArray(def?.node?.HookParameters)) params = extractParams(def.node.HookParameters);
        }
        paramCache.set(ck, params ?? {});
      }
      c.installedHookParams[he.HookHash] = paramCache.get(ck);
    }
  }
  console.error(`[corpus] installed hook params fetched for ${paramCache.size} (account,hook) pair(s)`);

  // 3b. ITERATIVE PRE-RESOLVE: run each case's hook bytecode in the VM offline, collect the
  // foreign-state entries + slotted ledger objects it actually reads, fetch THOSE (and only those)
  // at the PRE-EXECUTION ledger (ledgerIndex - 1), and re-run — up to 3 rounds (a resolved read can
  // expose a further dependent read). entryNotFound is stored as null = CONFIRMED ABSENT (the VM's
  // DOESNT_EXIST is then faithful); a rate-limit skip stays unresolved (still degraded, honest).
  const { reconstructContext } = await import("../dist/fidelity.js");
  const { runHook } = await import("../dist/sandbox.js");
  const { hexToBytes } = await import("../dist/wasm.js");
  const { validateAddress, accountIdToR } = await import("../dist/util.js");
  let resolvedForeignTotal = 0, resolvedKeyletTotal = 0, confirmedAbsentTotal = 0;
  for (const c of cases) {
    c.foreignState = c.foreignState ?? {};
    c.keyletBlobs = c.keyletBlobs ?? {};
    const v = validateAddress(c.hookAccount ?? "");
    const hookAccountId = v.valid && typeof v.accountId === "string" ? v.accountId : "00".repeat(20);
    for (const he of c.hookExecutions) {
      const code = he.HookHash ? hookCode[he.HookHash] : undefined;
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
          if (res === null) continue; // rate-limited/skip — stays unresolved (degraded)
          if (res.status === "error" || res.error) {
            if (res.error === "entryNotFound") { c.foreignState[composite] = null; confirmedAbsentTotal++; progressed = true; }
            continue;
          }
          const data = res.node?.HookStateData;
          if (typeof data === "string") { c.foreignState[composite] = data.toUpperCase(); resolvedForeignTotal++; progressed = true; }
        }
        for (const idx of wantsK) {
          const res = await rpcFull("ledger_entry", { index: idx, binary: true, ledger_index: c.ledgerIndex - 1 });
          if (res === null) continue;
          const binHex = res.node_binary ?? res.node?.node_binary;
          if (typeof binHex === "string") { c.keyletBlobs[idx] = binHex.toUpperCase(); resolvedKeyletTotal++; progressed = true; }
        }
        if (!progressed) break;
      }
    }
  }
  console.error(`[corpus] pre-resolve: ${resolvedForeignTotal} foreign-state entries fetched, ${confirmedAbsentTotal} confirmed-absent, ${resolvedKeyletTotal} ledger objects slotted`);

  // 4. write data/hook-corpus.json
  mkdirSync(DATA, { recursive: true });
  const out = {
    _captured: new Date().toISOString(),
    _source: `Xahau mainnet validated ledgers via ${NODE} (read-only; historical HookExecutions as ground truth)`,
    _note: "Each case is a real validated tx whose metadata carried HookExecutions. hookCode is keyed by HookHash (deduped). Captured serially with >=1200ms RPC pacing; rate-limited calls were backed off and skipped.",
    _truncatedByRateLimit: truncatedByRateLimit,
    _rateLimitedCalls: rateLimitedTotal,
    _ledgersWalked: ledgersWalked,
    cases,
    hookCode,
  };
  writeFileSync(join(DATA, "hook-corpus.json"), JSON.stringify(out, null, 1));

  const withCode = new Set(Object.keys(hookCode)).size;
  console.error(`[corpus] WROTE data/hook-corpus.json`);
  console.error(`[corpus] cases=${cases.length}  distinctHooks=${distinctHashes.size}  hooksWithCreateCode=${withCode}  rateLimitedCalls=${rateLimitedTotal}  truncatedByRateLimit=${truncatedByRateLimit}`);
}

main().catch((e) => { console.error("[corpus] FATAL", e); process.exit(1); });
