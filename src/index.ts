#!/usr/bin/env node
// xahau-mcp — Model Context Protocol server for the Xahau network.
// The first MCP with offline Hook intelligence (WASM inspection + a Hooks-specific
// static-analysis rule engine), plus read-only ledger, codec, governance and unsigned-tx tooling.
// Strictly read-only toward the network; never signs or submits; no key custody.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { DEFS_AVAILABLE, HOOKAPI_AVAILABLE, allTxTypes, decodeResult, GOVERNANCE } from "./defs.js";
import * as rpc from "./rpc.js";
import { decodeHookOn, encodeHookOn } from "./hookon.js";
import { xahAmount, decodeTxBlob, encodeTxBlob, decodeSetHook, decodeUriTokenId } from "./codec.js";
import { readWasm, hexToBytes, base64ToBytes } from "./wasm.js";
import { lookupHookApi, hookApiCount } from "./hookapi.js";
import { decodeCreateCode, runRules, listRules, type HookGrant } from "./analyzer.js";
import { computeReward } from "./rewards.js";
import { governanceState, decodeB2M } from "./governance.js";
import { buildSetHookUnsigned, buildClaimRewardUnsigned, buildPaymentUnsigned } from "./builders.js";

const NET = z.enum(["mainnet", "testnet"]).default("mainnet");
type Net = "mainnet" | "testnet";

function ok(text: string, structured: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text }], structuredContent: structured };
}
function fail(text: string, structured: Record<string, unknown> = {}) {
  return { content: [{ type: "text" as const, text }], structuredContent: { error: text, ...structured } };
}

const server = new McpServer({ name: "xahau-mcp", version: "0.1.0" });

/* ===================== Tier A — Ledger / RPC (read-only) ===================== */

server.registerTool("xahau_server_info", {
  description: "Health, version, amendments and ledger range of a Xahau node (mainnet or testnet). Read-only.",
  inputSchema: { network: NET },
}, async ({ network }) => {
  try {
    const r = await rpc.getServerInfo(network as Net);
    const i = r.info as Record<string, any>;
    return ok(`${network} ${i.build_version} · ledgers ${i.complete_ledgers} · net ${i.network_id} · ${i.peers} peers`, {
      network, endpointUsed: rpc.endpointFor(network as Net), buildVersion: i.build_version,
      completeLedgers: i.complete_ledgers, networkId: i.network_id, peers: i.peers, amendmentBlocked: i.amendment_blocked ?? false,
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_account_info", {
  description: "Account root: balance, sequence, flags, regular key. Read-only.",
  inputSchema: { address: z.string().min(25).describe("r-address"), network: NET },
}, async ({ address, network }) => {
  try {
    const r = await rpc.getAccountInfo(address, network as Net);
    const a = r.account_data as Record<string, any>;
    return ok(`${address}: ${(Number(a.Balance) / 1e6).toFixed(6)} XAH · seq ${a.Sequence} · owners ${a.OwnerCount}`, {
      address, balanceXAH: Number(a.Balance) / 1e6, balanceDrops: a.Balance, sequence: a.Sequence,
      ownerCount: a.OwnerCount, flags: a.Flags, regularKey: a.RegularKey ?? null, hookStateCount: a.HookStateCount ?? 0,
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_account_objects", {
  description: "Ledger objects owned by an account, optionally filtered by type (hook, hook_state, uri_token, etc.). Read-only.",
  inputSchema: { address: z.string().min(25), type: z.string().optional(), network: NET },
}, async ({ address, type, network }) => {
  try {
    const r = await rpc.getAccountObjects(address, network as Net, type);
    return ok(`${address}: ${r.account_objects.length} object(s)${type ? ` of type ${type}` : ""}`, { address, count: r.account_objects.length, objects: r.account_objects });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_account_hooks", {
  description: "The Hooks installed on an account, with each HookOn bitmap decoded to the transaction types it fires on. Read-only.",
  inputSchema: { address: z.string().min(25), network: NET },
}, async ({ address, network }) => {
  try {
    const r = await rpc.getAccountObjects(address, network as Net, "hook");
    const hookObj = r.account_objects.find((o: any) => o.LedgerEntryType === "Hook") as any;
    const arr = (hookObj?.Hooks ?? []) as any[];
    const hooks = arr.map((e: any, i: number) => {
      const h = e.Hook ?? {};
      return { position: i, hookHash: h.HookHash ?? null, hookOn: h.HookOn ?? null,
        hookOnDecoded: h.HookOn ? decodeHookOn(h.HookOn).firesOn : null,
        namespace: h.HookNamespace ?? null, parameters: h.HookParameters ?? [], grants: h.HookGrants ?? [] };
    });
    return ok(`${address}: ${hooks.length} hook(s) installed`, { address, hooks });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_hook_definition", {
  description: "Fetch a HookDefinition ledger object by hash (CreateCode WASM, HookOn, fee, reference count). Read-only.",
  inputSchema: { hookHash: z.string().length(64), network: NET },
}, async ({ hookHash, network }) => {
  try {
    const r = await rpc.getLedgerEntry({ hook_definition: hookHash }, network as Net);
    const n = r.node as Record<string, any>;
    const code = n.CreateCode as string | undefined;
    return ok(`HookDefinition ${hookHash}: ${code ? code.length / 2 + " bytes WASM" : "no code"}`, {
      hookHash, createCodeHex: code ?? null, createCodeBytes: code ? code.length / 2 : 0,
      hookOn: n.HookOn ?? null, hookApiVersion: n.HookApiVersion ?? null, fee: n.Fee ?? null, referenceCount: n.ReferenceCount ?? null,
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_hook_state", {
  description: "Read Hook State entries for an account namespace (32-byte key→value map). Read-only.",
  inputSchema: { address: z.string().min(25), namespace: z.string().length(64).describe("32-byte HookNamespace hex"), network: NET },
}, async ({ address, namespace, network }) => {
  try {
    const r = await rpc.getAccountNamespace(address, namespace, network as Net);
    return ok(`${address} ns ${namespace.slice(0, 8)}…: ${r.namespace_entries.length} state entr(ies)`, { address, namespace, entries: r.namespace_entries });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_transaction", {
  description: "A validated transaction by hash, including Xahau HookExecutions metadata (hook return codes/strings). Read-only.",
  inputSchema: { txHash: z.string().length(64), network: NET },
}, async ({ txHash, network }) => {
  try {
    const tx = await rpc.getTx(txHash, network as Net) as Record<string, any>;
    const meta = tx.meta ?? tx.metaData;
    const hookExecs = meta?.HookExecutions ?? null;
    return ok(`${txHash}: ${tx.TransactionType} · result ${meta?.TransactionResult ?? "?"}${hookExecs ? ` · ${hookExecs.length} hook exec(s)` : ""}`, {
      txHash, transactionType: tx.TransactionType, result: meta?.TransactionResult, hookExecutions: hookExecs, tx,
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_ledger", {
  description: "Header/summary of a ledger (default the latest validated). Read-only.",
  inputSchema: { ledgerIndex: z.union([z.number(), z.string()]).default("validated"), network: NET },
}, async ({ ledgerIndex, network }) => {
  try {
    const r = await rpc.getLedger(ledgerIndex, network as Net);
    const l = r.ledger as Record<string, any>;
    return ok(`ledger ${l.ledger_index ?? l.seqNum} · closed ${l.close_time_human ?? "?"}`, { ledger: l });
  } catch (e) { return fail((e as Error).message); }
});

/* ===================== Tier B — Codec / decode (offline) ===================== */

server.registerTool("decode_hook_on", {
  description: "Decode a HookOn 256-bit bitmap into the set of transaction types the hook fires on. Handles the inverted/active-low encoding and the active-high SetHook bit. Offline.",
  inputSchema: { hookOn: z.string().describe("HookOn hex (up to 64 chars)") },
}, async ({ hookOn }) => {
  try { const d = decodeHookOn(hookOn); return ok(`Fires on ${d.count} type(s): ${d.firesOn.join(", ") || "(none)"}`, d); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("encode_hook_on", {
  description: "Build a canonical HookOn hex from a list of transaction types to fire on. Offline.",
  inputSchema: { txTypes: z.array(z.string()).min(1).describe("e.g. [\"Payment\",\"Invoke\"]") },
}, async ({ txTypes }) => {
  try { const e = encodeHookOn(txTypes); return ok(`HookOn ${e.hookOn} fires on: ${e.firesOn.join(", ")}`, e); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("decode_sethook", {
  description: "Decode a SetHook transaction (JSON or tx blob) into its hook definitions, each with HookOn decoded. Offline.",
  inputSchema: { tx: z.record(z.string(), z.unknown()).optional(), txBlobHex: z.string().optional() },
}, async ({ tx, txBlobHex }) => {
  try { const d = decodeSetHook({ tx: tx as Record<string, unknown> | undefined, txBlobHex }); return ok(`${d.transactionType}: ${d.hooks.length} hook(s)`, d); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("decode_tx_blob", {
  description: "Decode a Xahau transaction blob (hex) into JSON via the Xahau-aware binary codec. Offline.",
  inputSchema: { txBlobHex: z.string().min(2) },
}, async ({ txBlobHex }) => {
  try { const tx = decodeTxBlob(txBlobHex); return ok(`Decoded ${(tx as any).TransactionType ?? "object"}`, { tx }); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("encode_tx_blob", {
  description: "Encode a transaction JSON into an UNSIGNED Xahau binary blob (for inspection/round-trip; never signed). Offline.",
  inputSchema: { tx: z.record(z.string(), z.unknown()) },
}, async ({ tx }) => {
  try { return ok("Encoded (unsigned)", encodeTxBlob(tx as object)); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("decode_uritoken_id", {
  description: "Validate a URIToken ID and explain its structure (SHA512-Half of issuer||URI; not reversible offline). Offline.",
  inputSchema: { uriTokenId: z.string() },
}, async ({ uriTokenId }) => { const d = decodeUriTokenId(uriTokenId); return ok(d.note, d); });

server.registerTool("xah_amount", {
  description: "Convert between XAH and drops (1 XAH = 1,000,000 drops). Offline.",
  inputSchema: { value: z.union([z.string(), z.number()]), from: z.enum(["xah", "drops"]) },
}, async ({ value, from }) => { try { const a = xahAmount(value, from); return ok(`${a.xah} XAH = ${a.drops} drops`, a); } catch (e) { return fail((e as Error).message); } });

/* ===================== Tier C — Hook intelligence (the moat, offline) ===================== */

const WASM_IN = { wasmHex: z.string().optional(), wasmBase64: z.string().optional() };

server.registerTool("inspect_hook_wasm", {
  description: "Parse a Hook's CreateCode WASM (hex or base64): imports (Hook API functions), exports (hook/cbak), memory, custom sections, loop and guard(_g) counts. Offline, never executes the module.",
  inputSchema: WASM_IN,
}, async ({ wasmHex, wasmBase64 }) => {
  try {
    const bytes = wasmHex ? hexToBytes(wasmHex) : wasmBase64 ? base64ToBytes(wasmBase64) : null;
    if (!bytes) return fail("provide wasmHex or wasmBase64");
    const w = readWasm(bytes);
    if (!w.valid) return fail(w.reason ?? "invalid wasm", { valid: false });
    const ex = w.exports.map((e) => e.name);
    return ok(`WASM ${w.byteSize}B · ${w.imports.length} imports · exports [${ex.join(", ")}] · ${w.loopCount} loop(s)/${w.guardCallCount} guard(s)`, {
      valid: true, byteSize: w.byteSize, hasHook: ex.includes("hook"), hasCbak: ex.includes("cbak"),
      imports: w.imports, exports: w.exports, memory: w.memory, customSections: w.customSections,
      loopCount: w.loopCount, guardCallCount: w.guardCallCount, scanComplete: w.scanComplete,
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("analyze_hook", {
  description: "THE MOAT: run the Hook static-analysis / security rule engine over a CreateCode WASM (+ optional SetHook params) and return SARIF-lite findings. The first Hooks-specific analyzer. Offline.",
  inputSchema: {
    ...WASM_IN,
    hookOn: z.string().optional(), namespace: z.string().optional(),
    parameters: z.array(z.unknown()).optional(),
    grants: z.array(z.record(z.string(), z.unknown())).optional(),
    flags: z.number().optional(),
  },
}, async ({ wasmHex, wasmBase64, hookOn, namespace, parameters, grants, flags }) => {
  try {
    const wasm = decodeCreateCode({ wasmHex, wasmBase64 });
    if (!wasm.valid) return fail(wasm.reason ?? "invalid wasm", { valid: false });
    const sethook = Boolean(hookOn || namespace || grants);
    const { findings, summary } = runRules({ wasm, hookOn, namespace, parameters, grants: grants as HookGrant[] | undefined, flags }, { sethook });
    return ok(`${findings.length} finding(s): ${summary.CRITICAL}C/${summary.HIGH}H/${summary.MEDIUM}M/${summary.LOW}L/${summary.INFO}I`, {
      findings, summary,
      decoded: { byteSize: wasm.byteSize, hasHook: wasm.exports.some((e) => e.name === "hook"), hasCbak: wasm.exports.some((e) => e.name === "cbak"), loopCount: wasm.loopCount, guardCallCount: wasm.guardCallCount, hookOnDecoded: hookOn ? decodeHookOn(hookOn).firesOn : null },
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("audit_account_hooks", {
  description: "Fetch every hook on an account, pull each HookDefinition's WASM, and run the analyzer over all of them. Read-only network + offline analysis.",
  inputSchema: { address: z.string().min(25), network: NET },
}, async ({ address, network }) => {
  try {
    const r = await rpc.getAccountObjects(address, network as Net, "hook");
    const hookObj = r.account_objects.find((o: any) => o.LedgerEntryType === "Hook") as any;
    const arr = (hookObj?.Hooks ?? []) as any[];
    const results: any[] = [];
    for (let i = 0; i < arr.length; i++) {
      const h = arr[i].Hook ?? {};
      let createCode: string | undefined = h.CreateCode;
      if (!createCode && h.HookHash) {
        try { const def = await rpc.getLedgerEntry({ hook_definition: h.HookHash }, network as Net); createCode = (def.node as any).CreateCode; } catch { /* skip */ }
      }
      if (!createCode) { results.push({ position: i, hookHash: h.HookHash ?? null, note: "CreateCode unavailable", findings: [] }); continue; }
      const wasm = readWasm(hexToBytes(createCode));
      const { findings, summary } = runRules({ wasm, hookOn: h.HookOn, namespace: h.HookNamespace, grants: h.HookGrants }, { sethook: true });
      results.push({ position: i, hookHash: h.HookHash ?? null, byteSize: wasm.byteSize, findings, summary });
    }
    const total = results.reduce((n, r) => n + (r.findings?.length ?? 0), 0);
    return ok(`${address}: ${arr.length} hook(s), ${total} finding(s)`, { address, hooks: results });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("list_rules", {
  description: "Enumerate the Hook analyzer rule registry (id, severity, title, category). Offline.",
  inputSchema: {},
}, async () => { const rules = listRules(); return ok(`${rules.length} rules`, { rules }); });

server.registerTool("hook_dry_run", {
  description: "Honest STATIC dry-run: does this hook fire on a given transaction type (HookOn match), and what exit calls (accept/rollback) does its WASM contain? Labelled STATIC_ONLY — true execution requires xahaud. Offline.",
  inputSchema: { ...WASM_IN, hookOn: z.string(), candidateTxType: z.string().describe("e.g. \"Payment\"") },
}, async ({ wasmHex, wasmBase64, hookOn, candidateTxType }) => {
  try {
    const wasm = decodeCreateCode({ wasmHex, wasmBase64 });
    if (!wasm.valid) return fail(wasm.reason ?? "invalid wasm");
    const fires = decodeHookOn(hookOn).firesOn.includes(candidateTxType);
    const imports = new Set(wasm.imports.map((i) => i.name));
    const exits = ["accept", "rollback"].filter((n) => imports.has(n));
    return ok(`${fires ? "FIRES" : "does NOT fire"} on ${candidateTxType} · exits: ${exits.join("/") || "none"} · STATIC_ONLY`, {
      firesOnThisTx: fires, candidateTxType, staticExitCalls: exits, hasHook: wasm.exports.some((e) => e.name === "hook"),
      fidelity: "STATIC_ONLY", caveat: "HookOn match + presence of exit-call imports only. Actual accept/rollback outcome depends on runtime state and requires xahaud to execute.",
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("hook_api_lookup", {
  description: "Look up a Hook API function: category, exit/guard role, and security hazard metadata. Offline.",
  inputSchema: { name: z.string().describe("e.g. emit, state_set, _g, otxn_field") },
}, async ({ name }) => {
  const fn = lookupHookApi(name);
  if (!fn) return fail(`${name} is not a known Hook API function`, { known: false });
  return ok(`${name} · ${fn.category}${fn.isGuard ? " (guard)" : ""}${fn.isExit ? " (exit)" : ""} · ${fn.hazards.length} hazard(s)`, { known: true, ...fn });
});

/* ===================== Tier D — economics / governance ===================== */

server.registerTool("compute_reward", {
  description: "Project claimable XAH network reward using the documented time-weighted model. Supply reward fields directly, or an address to read them live. Labelled DOCUMENTED_MODEL.",
  inputSchema: {
    balanceXAH: z.number().optional(), rewardAccumulator: z.number().optional(),
    rewardLgrFirst: z.number().optional(), currentLedger: z.number().optional(),
    address: z.string().optional(), network: NET,
  },
}, async ({ balanceXAH, rewardAccumulator, rewardLgrFirst, currentLedger, address, network }) => {
  try {
    let bal = balanceXAH, acc = rewardAccumulator, first = rewardLgrFirst, cur = currentLedger;
    if (address) {
      const a = (await rpc.getAccountInfo(address, network as Net)).account_data as Record<string, any>;
      bal ??= Number(a.Balance) / 1e6;
      acc ??= a.RewardAccumulator ? Number(a.RewardAccumulator) : undefined;
      first ??= a.RewardLgrFirst ? Number(a.RewardLgrFirst) : undefined;
      const si = (await rpc.getServerInfo(network as Net)).info as Record<string, any>;
      cur ??= Number(String(si.complete_ledgers).split("-").pop());
    }
    if (bal === undefined || first === undefined || cur === undefined) return fail("need balanceXAH, rewardLgrFirst and currentLedger (or an address to read them live)");
    const res = computeReward({ balanceXAH: bal, rewardAccumulator: acc, rewardLgrFirst: first, currentLedger: cur });
    return ok(`${res.eligibleToClaim ? "claimable" : "not yet eligible"}: ~${res.claimableXAH} XAH (${res.fidelity})`, res);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("governance_state", {
  description: "Genesis Governance Game constants + a live read of the genesis account. Per-seat/topic decode not yet implemented (honest).",
  inputSchema: { network: NET },
}, async ({ network }) => { try { const g = await governanceState(network as Net); return ok(`genesis ${GOVERNANCE?.genesisAccount ?? "?"} · ${GOVERNANCE?.governanceSeats ?? "?"} seats`, g); } catch (e) { return fail((e as Error).message); } });

server.registerTool("decode_b2m", {
  description: "Heuristically classify a Burn2Mint-related transaction (XRPL↔Xahau bridge direction). Offline.",
  inputSchema: { tx: z.record(z.string(), z.unknown()) },
}, async ({ tx }) => { const d = decodeB2M(tx as Record<string, unknown>); return ok(`${d.transactionType}: ${d.direction}`, d); });

/* ===================== Tier E — unsigned tx builders (no keys) ===================== */

server.registerTool("build_sethook_unsigned", {
  description: "Assemble an UNSIGNED SetHook transaction from CreateCode + params, auto-running analyze_hook as preflight and flagging CRITICAL findings. Returns unsigned JSON + offline signing instructions. Never signs; testnet by default.",
  inputSchema: {
    account: z.string().min(25), createCodeHex: z.string().optional(), wasmHex: z.string().optional(),
    hookOn: z.string().optional(), txTypes: z.array(z.string()).optional(),
    namespace: z.string().describe("32-byte HookNamespace hex"),
    parameters: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
    grants: z.array(z.object({ authorize: z.string().optional(), hookHash: z.string().optional() })).optional(),
    flags: z.number().optional(), network: NET.default("testnet"),
  },
}, async (a) => {
  try { const r = buildSetHookUnsigned(a as any); return ok(`${r.blocked ? "⚠ CRITICAL preflight — " : ""}unsigned SetHook for ${a.account} (${r.network})`, r as any); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("build_claimreward_unsigned", {
  description: "Assemble an UNSIGNED ClaimReward transaction. Returns unsigned JSON + offline signing instructions. Never signs; testnet by default.",
  inputSchema: { account: z.string().min(25), issuer: z.string().optional(), network: NET.default("testnet") },
}, async (a) => { try { const r = buildClaimRewardUnsigned(a as any); return ok(`unsigned ClaimReward for ${a.account} (${r.network})`, r as any); } catch (e) { return fail((e as Error).message); } });

server.registerTool("build_payment_unsigned", {
  description: "Assemble an UNSIGNED XAH Payment (amount in drops). Returns unsigned JSON + offline signing instructions + payload preflight. Never signs; testnet by default.",
  inputSchema: { account: z.string().min(25), destination: z.string().min(25), amountXahDrops: z.string(), destinationTag: z.number().optional(), network: NET.default("testnet") },
}, async (a) => { try { const r = buildPaymentUnsigned(a as any); return ok(`unsigned Payment ${a.amountXahDrops} drops → ${a.destination} (${r.network})`, r as any); } catch (e) { return fail((e as Error).message); } });

/* ===================== smoke / main ===================== */

async function smoke() {
  const lines: string[] = [];
  lines.push(`defs loaded: ${DEFS_AVAILABLE} · tx types: ${allTxTypes().length}`);
  lines.push(`hook API: ${HOOKAPI_AVAILABLE} · ${hookApiCount()} functions`);
  lines.push(`rules: ${listRules().length}`);
  // HookOn round-trip
  const enc = encodeHookOn(["Payment", "Invoke"]);
  const dec = decodeHookOn(enc.hookOn);
  lines.push(`hookOn round-trip [Payment,Invoke] -> ${enc.hookOn.slice(0, 16)}… -> [${dec.firesOn.join(",")}]  ${dec.firesOn.includes("Payment") && dec.firesOn.includes("Invoke") && dec.firesOn.length === 2 ? "OK" : "FAIL"}`);
  lines.push(`result-code decode tecHOOK_REJECTED: ${decodeResult("tecHOOK_REJECTED").code}`);
  try { const i = (await rpc.getServerInfo("mainnet")).info as any; lines.push(`live mainnet read: ${i.build_version} ledgers ${i.complete_ledgers} OK`); }
  catch (e) { lines.push(`live mainnet read: SKIP (${(e as Error).message})`); }
  console.error("xahau-mcp smoke:\n  " + lines.join("\n  "));
}

async function main() {
  if (process.argv.includes("--smoke")) { await smoke(); return; }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
main().catch((e) => { console.error("fatal:", e); process.exit(1); });
