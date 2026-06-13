/**
 * HTTP shim over the flight simulator — the shared backbone for the public
 * "Simulate Any Hook" tool and the Xaman pre-sign panel.
 *
 * xahau-mcp is a stdio MCP server; browsers and webviews can't speak stdio.
 * This exposes the SAME simulateTransaction core (via simDeps) over plain HTTP.
 * Dependency-free (node:http), read-only, never signs or submits.
 *
 *   POST /simulate   { tx, network?, ledgerIndex? }      -> Simulation
 *   POST /what-if    { txHash, overrides?, network? }     -> Simulation (+ replay meta)
 *   GET  /health                                          -> { ok, ... }
 *
 * Run:  PORT=8787 node dist/http.js   (or `npm run http`)
 */
import http from "node:http";
import { simulateTransaction } from "./simulate.js";
import { simDeps, type Net } from "./simdeps.js";
import * as rpc from "./rpc.js";

const PORT = Number(process.env.PORT ?? 8787);
const MAX_BODY = 64 * 1024; // 64 KB — a tx JSON is tiny
const RL_WINDOW_MS = 60_000;
const RL_MAX = Number(process.env.RL_MAX ?? 20); // requests / IP / minute
const MAX_INFLIGHT = Number(process.env.MAX_INFLIGHT ?? 4); // sim is slow + RPC is rate-limited

const buckets = new Map<string, { count: number; reset: number }>();
let inflight = 0;

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || now > b.reset) { buckets.set(ip, { count: 1, reset: now + RL_WINDOW_MS }); return false; }
  b.count++;
  return b.count > RL_MAX;
}

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
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  const url = (req.url ?? "/").split("?")[0];

  if (req.method === "OPTIONS") return send(res, 204, {});
  if (req.method === "GET" && url === "/health") {
    return send(res, 200, { ok: true, service: "xahau-mcp http shim", inflight, endpoints: ["/simulate", "/what-if"] });
  }

  if (req.method !== "POST" || (url !== "/simulate" && url !== "/what-if")) {
    return send(res, 404, { error: "not found", try: ["POST /simulate", "POST /what-if", "GET /health"] });
  }

  if (rateLimited(ip)) return send(res, 429, { error: `rate limited — max ${RL_MAX} req/min` });
  if (inflight >= MAX_INFLIGHT) return send(res, 503, { error: "simulator busy — retry shortly" });

  let body: any;
  try { body = await readBody(req); }
  catch (e) { return send(res, 400, { error: (e as Error).message }); }

  inflight++;
  try {
    if (url === "/simulate") {
      const tx = body?.tx;
      if (!tx || typeof tx !== "object") return send(res, 400, { error: "missing 'tx' object (unsigned transaction JSON)" });
      const network = net(body?.network);
      const ledgerIndex = Number.isFinite(body?.ledgerIndex) ? Number(body.ledgerIndex) : undefined;
      const sim = await simulateTransaction(tx as Record<string, unknown>, simDeps(network, ledgerIndex), ledgerIndex !== undefined ? { ledgerIndex } : {});
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
    const sim = await simulateTransaction(tx, simDeps(network, ledgerIndex - 1), { ledgerIndex: ledgerIndex - 1 });
    return send(res, 200, { ...sim, baseTxHash: txHash, overriddenFields: Object.keys(overrides), replayLedger: ledgerIndex - 1 });
  } catch (e) {
    return send(res, 500, { error: (e as Error).message });
  } finally {
    inflight--;
  }
});

server.listen(PORT, () => {
  console.error(`xahau-mcp http shim listening on :${PORT}  (RL ${RL_MAX}/min, ${MAX_INFLIGHT} concurrent)`);
});
