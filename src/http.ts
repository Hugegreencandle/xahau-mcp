/**
 * HTTP shim over the flight simulator — the shared backbone for the public
 * "Simulate Any Hook" tool and the Xaman pre-sign panel.
 *
 * xahau-mcp is a stdio MCP server; browsers and webviews can't speak stdio.
 * This exposes the SAME simulateTransaction core (via simDeps) over plain HTTP.
 * Dependency-free (node:http), read-only, never signs or submits.
 *
 *   POST /simulate   { tx, network?, ledgerIndex?, candidateCode? }  -> Simulation
 *   POST /what-if    { txHash, overrides?, network? }                 -> Simulation (+ replay meta)
 *   POST /execute    { wasmHex, txType?, otxnFields?, ... }           -> SandboxResult (offline, no RPC)
 *   POST /analyze    { wasmHex, hookOn?, ... }                        -> { findings, summary } (offline)
 *   GET  /fidelity                                                    -> fidelity report (+ hash/lastRun)
 *   GET  /health                                                      -> { ok, ... }
 *
 * Run:  PORT=8787 node dist/http.js   (or `npm run http`)
 */
import http from "node:http";
import { readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { simulateTransaction } from "./simulate.js";
import { simDeps, type Net } from "./simdeps.js";
import { type SandboxContext } from "./sandbox.js";
import { runHookIsolated } from "./isolated.js";
import { hexToBytes } from "./wasm.js";
import { validateAddress } from "./util.js";
import { decodeCreateCode, runRules, type HookGrant } from "./analyzer.js";
import { fidelityReport, type HookCorpus } from "./fidelity.js";
import * as rpc from "./rpc.js";

const PORT = Number(process.env.PORT ?? 8787);
const MAX_BODY = 512 * 1024;       // 512 KB — a tx JSON is tiny, but /execute carries wasm hex (≤128 KiB wasm = 256 KiB hex)
const MAX_WASM_HEX = 262_144;      // 128 KiB of bytecode as hex (mirrors sandbox MAX_WASM_BYTES)

// Fidelity corpus + metadata, loaded once. Echoes coverageWarning verbatim so the
// "100% on 30 hooks" keystone never reads as a bare green number it isn't.
const CORPUS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "data", "hook-corpus.json");
let fidelityCache: { report: unknown; corpusHash: string; lastRun: string } | null = null;
function fidelity() {
  if (fidelityCache) return fidelityCache;
  const raw = readFileSync(CORPUS_PATH, "utf8");
  const corpus = JSON.parse(raw) as HookCorpus;
  fidelityCache = {
    report: fidelityReport(corpus),
    corpusHash: "sha256:" + createHash("sha256").update(raw).digest("hex").slice(0, 32),
    lastRun: statSync(CORPUS_PATH).mtime.toISOString(),
  };
  return fidelityCache;
}
const RL_WINDOW_MS = 60_000;
const RL_MAX = Number(process.env.RL_MAX ?? 20); // requests / IP / minute
const MAX_INFLIGHT = Number(process.env.MAX_INFLIGHT ?? 4); // sim is slow + RPC is rate-limited

const buckets = new Map<string, { count: number; reset: number }>();
let inflight = 0;

function rateLimited(ip: string): boolean {
  const now = Date.now();
  // sweep expired buckets so the map can't grow unbounded (one entry per IP)
  if (buckets.size > 4096) {
    for (const [k, v] of buckets) if (now > v.reset) buckets.delete(k);
  }
  const b = buckets.get(ip);
  if (!b || now > b.reset) { buckets.set(ip, { count: 1, reset: now + RL_WINDOW_MS }); return false; }
  b.count++;
  return b.count > RL_MAX;
}

const isHex = (s: string) => s.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(s);

function net(v: unknown): Net {
  return v === "testnet" ? "testnet" : "mainnet";
}

function send(res: http.ServerResponse, status: number, body: unknown) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "content-type",
    "cache-control": "no-store",
  });
  res.end(json);
}

function readBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let len = 0; const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      len += c.length;
      if (len > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error("invalid JSON body")); }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  // Only trust X-Forwarded-For behind a declared proxy (TRUST_PROXY=1); otherwise
  // it's an attacker-controlled header that defeats the rate limiter via rotation.
  const ip = (process.env.TRUST_PROXY
    ? (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim()
    : undefined) || req.socket.remoteAddress || "unknown";
  const url = (req.url ?? "/").split("?")[0];

  if (req.method === "OPTIONS") return send(res, 204, {});
  if (req.method === "GET" && url === "/health") {
    return send(res, 200, { ok: true, service: "xahau-mcp http shim", inflight, endpoints: ["/simulate", "/what-if", "/execute", "/analyze", "/fidelity"] });
  }
  if (req.method === "GET" && url === "/fidelity") {
    try { return send(res, 200, fidelity()); }
    catch (e) { console.error("fidelity error:", (e as Error).message); return send(res, 500, { error: "internal error" }); }
  }

  const POST_ROUTES = ["/simulate", "/what-if", "/execute", "/analyze"];
  if (req.method !== "POST" || !POST_ROUTES.includes(url)) {
    return send(res, 404, { error: "not found", try: [...POST_ROUTES.map((r) => `POST ${r}`), "GET /fidelity", "GET /health"] });
  }

  if (rateLimited(ip)) return send(res, 429, { error: `rate limited — max ${RL_MAX} req/min` });
  if (inflight >= MAX_INFLIGHT) return send(res, 503, { error: "simulator busy — retry shortly" });

  let body: any;
  try { body = await readBody(req); }
  catch (e) { return send(res, 400, { error: (e as Error).message }); }

  inflight++;
  try {
    // /execute — run a hook's bytecode in isolation (offline, no RPC). The differential
    // partner for `xahc verify`: same accept/rollback the local sim.rs should produce.
    if (url === "/execute") {
      const wasmHex = body?.wasmHex;
      if (typeof wasmHex !== "string" || !wasmHex) return send(res, 400, { error: "missing 'wasmHex'" });
      if (wasmHex.length > MAX_WASM_HEX) return send(res, 413, { error: `wasmHex too large (>128 KiB bytecode)` });
      if (!isHex(wasmHex)) return send(res, 400, { error: "wasmHex must be even-length hexadecimal" });
      const ctx: SandboxContext = {
        txType: body?.txType,
        otxnFields: body?.otxnFields,
        otxnParams: body?.otxnParams,
        hookAccountId: body?.hookAccountId,
        hookParams: body?.hookParams,
        state: body?.state,
        ledgerSeq: body?.ledgerSeq,
        feeBase: body?.feeBase,
      };
      // isolated: untrusted bytecode runs in a memory-capped worker with a hard
      // timeout, so an infinite loop / unguarded recursion can't wedge or OOM us.
      return send(res, 200, await runHookIsolated(hexToBytes(wasmHex), ctx));
    }

    // /analyze — the static rule engine over raw bytecode (offline, zero-RPC). Free,
    // instant top-of-funnel before the expensive /simulate.
    if (url === "/analyze") {
      const wasmHex = body?.wasmHex;
      if (typeof wasmHex !== "string" || !wasmHex) return send(res, 400, { error: "missing 'wasmHex'" });
      if (wasmHex.length > MAX_WASM_HEX) return send(res, 413, { error: `wasmHex too large (>128 KiB bytecode)` });
      if (!isHex(wasmHex)) return send(res, 400, { error: "wasmHex must be even-length hexadecimal" });
      const wasm = decodeCreateCode({ wasmHex });
      if (!wasm.valid) return send(res, 422, { error: wasm.reason ?? "invalid wasm", valid: false });
      const sethook = Boolean(body?.hookOn || body?.namespace || body?.grants);
      const { findings, summary } = runRules(
        { wasm, hookOn: body?.hookOn, namespace: body?.namespace, parameters: body?.parameters, grants: body?.grants as HookGrant[] | undefined, flags: body?.flags },
        { sethook },
      );
      return send(res, 200, { findings, summary });
    }

    if (url === "/simulate") {
      const tx = body?.tx;
      if (!tx || typeof tx !== "object") return send(res, 400, { error: "missing 'tx' object (unsigned transaction JSON)" });
      const network = net(body?.network);
      const ledgerIndex = Number.isFinite(body?.ledgerIndex) ? Number(body.ledgerIndex) : undefined;
      // candidate code = simulate a NOT-YET-DEPLOYED hook against the live ledger + TSH chain.
      // candidateCode (hex) applies to tx.Account; candidateHooks {r-addr -> {...}} is the full form.
      let candidateHooks = body?.candidateHooks as Record<string, any> | undefined;
      if (!candidateHooks && typeof body?.candidateCode === "string" && body.candidateCode) {
        if (body.candidateCode.length > MAX_WASM_HEX) return send(res, 413, { error: "candidateCode too large (>128 KiB bytecode)" });
        if (!isHex(body.candidateCode)) return send(res, 400, { error: "candidateCode must be even-length hexadecimal" });
        const acct = String((tx as Record<string, unknown>).Account ?? "");
        if (!validateAddress(acct).valid) return send(res, 400, { error: "candidateCode requires a valid tx.Account r-address" });
        candidateHooks = { [acct]: { createCodeHex: body.candidateCode, hookOn: body.candidateHookOn, namespace: body.candidateNamespace } };
      }
      const opts: Record<string, unknown> = {
        // isolate every hook execution in a worker so a malicious candidate (or a
        // hostile on-ledger hook) can't hang/OOM the shim.
        runHook: (b: Uint8Array, c: SandboxContext) => runHookIsolated(b, c),
      };
      if (ledgerIndex !== undefined) opts.ledgerIndex = ledgerIndex;
      if (candidateHooks) opts.candidateHooks = candidateHooks;
      const sim = await simulateTransaction(tx as Record<string, unknown>, simDeps(network, ledgerIndex), opts);
      return send(res, 200, sim);
    }

    // /what-if — counterfactual replay of a real historical tx (mirrors the MCP tool)
    const txHash = body?.txHash;
    if (typeof txHash !== "string" || txHash.length !== 64) return send(res, 400, { error: "missing 64-char 'txHash'" });
    const network = net(body?.network);
    const overrides = (body?.overrides && typeof body.overrides === "object") ? body.overrides : {};
    const real = await rpc.getTx(txHash, network) as Record<string, any>;
    const base = (real.tx_json ?? real) as Record<string, any>;
    const ledgerIndex = Number(real.ledger_index ?? base.ledger_index);
    if (!Number.isFinite(ledgerIndex)) return send(res, 422, { error: "could not determine the tx's ledger index" });
    const tx: Record<string, unknown> = { ...base, ...overrides };
    for (const k of ["TxnSignature", "SigningPubKey", "hash", "meta", "metaData", "date", "inLedger", "ledger_index", "validated"]) delete tx[k];
    const sim = await simulateTransaction(tx, simDeps(network, ledgerIndex - 1), {
      ledgerIndex: ledgerIndex - 1,
      runHook: (b: Uint8Array, c: SandboxContext) => runHookIsolated(b, c),
    });
    return send(res, 200, { ...sim, baseTxHash: txHash, overriddenFields: Object.keys(overrides), replayLedger: ledgerIndex - 1 });
  } catch (e) {
    const msg = (e as Error).message;
    // a hook that hangs / busts the memory cap is the CALLER's bytecode — safe to
    // surface as a 422. Anything else is internal: return generic, log server-side.
    if (/exceeded \d+ms|memory cap|infinite loop|unguarded recursion/i.test(msg)) {
      return send(res, 422, { error: msg });
    }
    console.error("shim error:", msg);
    return send(res, 500, { error: "internal error" });
  } finally {
    inflight--;
  }
});

server.listen(PORT, () => {
  console.error(`xahau-mcp http shim listening on :${PORT}  (RL ${RL_MAX}/min, ${MAX_INFLIGHT} concurrent)`);
});
