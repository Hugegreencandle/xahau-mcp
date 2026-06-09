#!/usr/bin/env node
// xahau-mcp — Model Context Protocol server for the Xahau network.
// The first MCP with offline Hook intelligence (WASM inspection + a Hooks-specific
// static-analysis rule engine), plus read-only ledger, codec, governance and unsigned-tx tooling.
// Strictly read-only toward the network; never signs or submits; no key custody.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { DEFS_AVAILABLE, HOOKAPI_AVAILABLE, allTxTypes, decodeResult, GOVERNANCE, ENDPOINTS } from "./defs.js";
import * as rpc from "./rpc.js";
import { decodeHookOn, encodeHookOn } from "./hookon.js";
import { xahAmount, decodeTxBlob, encodeTxBlob, decodeSetHook, decodeUriTokenId } from "./codec.js";
import { validateAddress, xaddressEncode, xaddressDecode, currencyCode, rippleTime, decodeAmount, describeTx } from "./util.js";
import { readWasm, hexToBytes, base64ToBytes } from "./wasm.js";
import { lookupHookApi, hookApiCount, HOOK_FUNCTIONS } from "./hookapi.js";
import { decodeCreateCode, runRules, listRules, type HookGrant } from "./analyzer.js";
import { runHook } from "./sandbox.js";
import { fuzzHook } from "./fuzz.js";
import { classifyHook } from "./classify.js";
import { diffHooks } from "./diff.js";
import { scaffoldHook } from "./scaffold.js";
import { computeReward } from "./rewards.js";
import { quantumGrade } from "./quantum.js";
import { governanceState, decodeB2M } from "./governance.js";
import { buildSetHookUnsigned, buildClaimRewardUnsigned, buildPaymentUnsigned, buildImportUnsigned } from "./builders.js";
import { fidelityReport, type HookCorpus } from "./fidelity.js";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(__dirname, "..", "data", "hook-corpus.json");

const NET = z.enum(["mainnet", "testnet"]).default("mainnet");
type Net = "mainnet" | "testnet";

function ok(text: string, structured: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text }], structuredContent: structured };
}
function fail(text: string, structured: Record<string, unknown> = {}) {
  return { content: [{ type: "text" as const, text }], structuredContent: { error: text, ...structured } };
}

const server = new McpServer({ name: "xahau-mcp", version: "0.9.0" });

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

server.registerTool("get_fee", {
  description: "Current network transaction fee (base fee in drops + load/queue state) — for building a tx with the right Fee. Read-only.",
  inputSchema: { network: NET },
}, async ({ network }) => {
  try {
    const r = await rpc.getFee(network as Net) as Record<string, any>;
    const base = r.drops?.base_fee ?? r.drops?.minimum_fee;
    return ok(`base fee ${base} drops · load factor ${r.current_queue_size ?? "?"}/${r.max_queue_size ?? "?"} queued`, { baseFeeDrops: base, openLedgerFeeDrops: r.drops?.open_ledger_fee, levels: r.levels, queue: { current: r.current_queue_size, max: r.max_queue_size }, raw: r });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_account_lines", {
  description: "Trustlines (issued-currency balances) held by an account. Read-only.",
  inputSchema: { address: z.string().min(25), network: NET },
}, async ({ address, network }) => {
  try { const r = await rpc.getAccountLines(address, network as Net); return ok(`${address}: ${r.lines.length} trustline(s)`, { address, lines: r.lines }); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_account_offers", {
  description: "Open DEX offers placed by an account. Read-only.",
  inputSchema: { address: z.string().min(25), network: NET },
}, async ({ address, network }) => {
  try { const r = await rpc.getAccountOffers(address, network as Net); return ok(`${address}: ${r.offers.length} open offer(s)`, { address, offers: r.offers }); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("get_account_uritokens", {
  description: "URITokens (Xahau-native NFTs) owned by an account, with each token's URI decoded from hex to text. Read-only.",
  inputSchema: { address: z.string().min(25), network: NET },
}, async ({ address, network }) => {
  try {
    const r = await rpc.getAccountObjects(address, network as Net, "uri_token");
    const tokens = r.account_objects.map((o: any) => ({
      uriTokenId: o.index, issuer: o.Issuer, owner: o.Owner ?? address, digest: o.Digest ?? null, flags: o.Flags ?? 0,
      uriHex: o.URI ?? null, uri: o.URI ? Buffer.from(o.URI, "hex").toString("utf-8") : null,
      amount: o.Amount ?? null, destination: o.Destination ?? null,
    }));
    return ok(`${address}: ${tokens.length} URIToken(s)`, { address, tokens });
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

server.registerTool("validate_address", {
  description: "Validate a Xahau/XRPL address (classic r-address or X-address) → type, account-id, embedded destination tag, network. Offline.",
  inputSchema: { address: z.string() },
}, async ({ address }) => { const v = validateAddress(address); return v.valid ? ok(`valid ${v.type}${"tag" in v && v.tag !== null ? ` (tag ${v.tag})` : ""}`, v) : fail((v as { reason: string }).reason, v); });

server.registerTool("xaddress", {
  description: "Encode a classic address + destination tag into an X-address, or decode an X-address back to classic + tag. Offline.",
  inputSchema: { address: z.string().describe("classic r-address (to encode) or X-address (to decode)"), tag: z.number().optional(), test: z.boolean().optional() },
}, async ({ address, tag, test }) => {
  try {
    if (address.trim().startsWith("X") || address.trim().startsWith("T")) { const d = xaddressDecode(address); return ok(`${d.classicAddress}${d.tag !== null ? ` tag ${d.tag}` : ""} (${d.network}net)`, d); }
    const e = xaddressEncode(address, tag ?? null, test ?? false); return ok(e.xAddress, e);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("currency_code", {
  description: "Convert a currency between 3-char ISO code (e.g. USD) and its 160-bit/40-hex form. Non-standard 160-bit codes pass through. Offline.",
  inputSchema: { input: z.string().describe("a 3-char code or a 40-hex currency") },
}, async ({ input }) => { try { const c = currencyCode(input); return ok(`${c.code ?? "(non-standard)"} = ${c.hex}`, c); } catch (e) { return fail((e as Error).message); } });

server.registerTool("ripple_time", {
  description: "Convert between Ripple time (seconds since 2000-01-01), Unix time, and ISO 8601. Xahau tx/ledger timestamps use Ripple time. Offline.",
  inputSchema: { ripple: z.number().optional(), unix: z.number().optional(), iso: z.string().optional() },
}, async ({ ripple, unix, iso }) => { try { const t = rippleTime({ ripple, unix, iso }); return ok(`ripple ${t.rippleTime} = ${t.iso}`, t); } catch (e) { return fail((e as Error).message); } });

server.registerTool("decode_amount", {
  description: "Decode an amount: native drops (digits), a serialized 8-byte native or 48-byte issued STAmount (hex), or an issued amount object {currency,issuer,value} → normalized value/currency/issuer. Offline.",
  inputSchema: { amount: z.union([z.string(), z.record(z.string(), z.unknown())]).describe("drops string, STAmount hex, or amount object") },
}, async ({ amount }) => {
  try { const d = decodeAmount(amount as any); return ok(d.type === "native" ? `${(d as any).xah} XAH (${(d as any).drops} drops)` : `${(d as any).value} ${(d as any).currency}${(d as any).issuer ? ` / ${(d as any).issuer}` : ""}`, d); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("decode_sign_request", {
  description: "Decode a sign request (a Xaman/Xumm payload's txjson, or a raw tx_blob hex) into the transaction plus a plain-English 'what you would be authorizing' summary and safety warnings (SetHook, AccountDelete, key changes, no-expiry, already-signed). Offline — understand before you sign.",
  inputSchema: { txjson: z.record(z.string(), z.unknown()).optional(), txBlobHex: z.string().optional() },
}, async ({ txjson, txBlobHex }) => {
  try {
    const tx = (txjson as Record<string, any> | undefined) ?? (txBlobHex ? (decodeTxBlob(txBlobHex) as Record<string, any>) : undefined);
    if (!tx) return fail("provide txjson or txBlobHex");
    const { summary, warnings } = describeTx(tx);
    const amountDecoded = tx.Amount !== undefined ? decodeAmount(tx.Amount) : null;
    return ok(`${summary}${warnings.length ? " ⚠ " + warnings.length + " warning(s)" : ""}`, { transactionType: tx.TransactionType, summary, warnings, amountDecoded, tx });
  } catch (e) { return fail((e as Error).message); }
});

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
      loopCount: w.loopCount, guardCallCount: w.guardCallCount, instructionCount: w.instructionCount, scanComplete: w.scanComplete,
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
  description: "Quick STATIC check: does this hook fire on a given transaction type (HookOn match) and what exit calls does its WASM contain? Labelled STATIC_ONLY. For REAL bytecode execution use execute_hook. Offline.",
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

server.registerTool("execute_hook", {
  description: "GROUNDBREAKING: actually RUN a Hook's real WebAssembly bytecode in a local VM against a simulated transaction + ledger state, and report the true accept/rollback decision, return code/string, state writes, emitted txns and execution trace. The first dev-accessible Hook simulator that needs no xahaud node. Implements a subset of the Hook API; unsupported calls are recorded (fidelity LOCAL_VM, never faked).",
  inputSchema: {
    ...WASM_IN,
    txType: z.string().optional().describe("originating tx type, e.g. \"Payment\""),
    otxnFields: z.record(z.string(), z.string()).optional().describe("field-id -> hex value of originating-txn fields the hook reads"),
    otxnParams: z.record(z.string(), z.string()).optional().describe("otxn param name -> hex value"),
    hookAccountId: z.string().optional().describe("20-byte account-id hex the hook is installed on"),
    hookParams: z.record(z.string(), z.string()).optional(),
    state: z.record(z.string(), z.string()).optional().describe("initial hook state: 32-byte key hex -> value hex"),
    keyletBlobs: z.record(z.string(), z.string()).optional().describe("32-byte ledger index hex -> serialized object hex, for slot_set"),
    otxnBlob: z.string().optional().describe("full originating-txn serialized blob hex (enables otxn_slot)"),
    ledgerSeq: z.number().optional(), feeBase: z.number().optional(),
    resolveKeylets: z.boolean().optional().describe("if true, fetch any slot_set'd ledger objects live and re-run (async pre-resolve)"),
    network: NET,
  },
}, async ({ wasmHex, wasmBase64, txType, otxnFields, otxnParams, hookAccountId, hookParams, state, keyletBlobs, otxnBlob, ledgerSeq, feeBase, resolveKeylets, network }) => {
  try {
    const bytes = wasmHex ? hexToBytes(wasmHex) : wasmBase64 ? base64ToBytes(wasmBase64) : null;
    if (!bytes) return fail("provide wasmHex or wasmBase64");
    const baseCtx = { txType, otxnFields, otxnParams, hookAccountId, hookParams, state, keyletBlobs, otxnBlob, ledgerSeq, feeBase };
    let r = runHook(bytes, baseCtx);
    let resolved: string[] = [];
    // async pre-resolve: fetch the ledger objects the hook tried to slot_set, then re-run once
    if (resolveKeylets && r.wantedKeylets.length) {
      const fetched: Record<string, string> = { ...(keyletBlobs ?? {}) };
      for (const idx of r.wantedKeylets) {
        try {
          const le = await rpc.getLedgerEntry({ index: idx, binary: true }, network as Net) as any;
          const binHex = le.node_binary ?? le.node?.node_binary;
          if (binHex) { fetched[idx] = binHex; resolved.push(idx); }
        } catch { /* leave unresolved */ }
      }
      if (resolved.length) r = runHook(bytes, { ...baseCtx, keyletBlobs: fetched });
    }
    const tail = r.degraded ? " ⚠ DEGRADED" : "";
    return ok(`${r.exit.toUpperCase()}${r.returnCode !== null ? ` code=${r.returnCode}` : ""}${r.returnString ? ` "${r.returnString}"` : ""} · ${r.stateWrites.length} state write(s) · ${r.emitted.length} emit(s)${resolved.length ? ` · resolved ${resolved.length} keylet(s)` : ""}${tail}`, { ...(r as unknown as Record<string, unknown>), resolvedKeylets: resolved });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("fuzz_hook", {
  description: "DIFFERENTIAL FUZZER: finds a Hook's accept/rollback decision boundary by running its REAL bytecode through the local VM against many DETERMINISTICALLY generated inputs (no randomness, no clock — fully reproducible). Sweeps axes you request: txType (a supplied list or all tx types), a raw otxn Amount-field byte range, otxn account/destination ids, and named otxn params. Reports counts {accept,rollback,halted,degraded}, per-axis boundary findings, and concrete accepting/rejecting sample inputs. Honest: degraded/halted runs are counted but excluded from the boundary; if every run degrades/halts it says INCONCLUSIVE and why. fidelity LOCAL_VM_FUZZ.",
  inputSchema: {
    ...WASM_IN,
    txTypes: z.array(z.string()).optional().describe("txType axis: tx types to sweep, e.g. [\"Payment\",\"Invoke\"]. Default: all known tx types (capped)."),
    amountMin: z.number().optional().describe("Amount axis low (raw drops; field bytes are NOT STAmount-encoded)"),
    amountMax: z.number().optional().describe("Amount axis high (raw drops)"),
    amountField: z.number().optional().describe("otxn field id to write the Amount sweep into (default 6)"),
    sweepAccount: z.boolean().optional().describe("also sweep a few deterministic account ids"),
    sweepDestination: z.boolean().optional().describe("also sweep a few deterministic destination ids"),
    paramSweep: z.record(z.string(), z.array(z.string())).optional().describe("named otxn params -> candidate hex values to sweep"),
    samples: z.number().optional().describe("number of generated inputs (default 64, max 512)"),
    // base context the sweeps mutate
    txType: z.string().optional().describe("base originating tx type"),
    otxnFields: z.record(z.string(), z.string()).optional(),
    otxnParams: z.record(z.string(), z.string()).optional(),
    hookAccountId: z.string().optional(),
    hookParams: z.record(z.string(), z.string()).optional(),
    state: z.record(z.string(), z.string()).optional(),
    ledgerSeq: z.number().optional(), feeBase: z.number().optional(),
  },
}, async ({ wasmHex, wasmBase64, txTypes, amountMin, amountMax, amountField, sweepAccount, sweepDestination, paramSweep, samples, txType, otxnFields, otxnParams, hookAccountId, hookParams, state, ledgerSeq, feeBase }) => {
  try {
    const bytes = wasmHex ? hexToBytes(wasmHex) : wasmBase64 ? base64ToBytes(wasmBase64) : null;
    if (!bytes) return fail("provide wasmHex or wasmBase64");
    const base = { txType, otxnFields, otxnParams, hookAccountId, hookParams, state, ledgerSeq, feeBase };
    const r = fuzzHook(bytes, base, { txTypes, amountMin, amountMax, amountField, sweepAccount, sweepDestination, paramSweep, samples });
    const head = r.inconclusive
      ? `INCONCLUSIVE over ${r.samples} inputs`
      : `${r.samples} inputs · accept=${r.counts.accept} rollback=${r.counts.rollback} halted=${r.counts.halted} degraded=${r.counts.degraded}`;
    const firstBoundary = r.boundaries.length ? ` · ${r.boundaries[0]}` : "";
    return ok(`${head}${firstBoundary}`, r as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("estimate_hook_fee", {
  description: "Estimate a Hook's cost signals from its WASM: byte size (drives the SetHook fee) and total static instruction count (a complexity/upper-bound proxy for execution fee). Labelled ESTIMATE — the on-ledger execution fee depends on the path actually executed. Offline.",
  inputSchema: WASM_IN,
}, async ({ wasmHex, wasmBase64 }) => {
  try {
    const bytes = wasmHex ? hexToBytes(wasmHex) : wasmBase64 ? base64ToBytes(wasmBase64) : null;
    if (!bytes) return fail("provide wasmHex or wasmBase64");
    const w = readWasm(bytes);
    if (!w.valid) return fail(w.reason ?? "invalid wasm");
    return ok(`${w.byteSize} bytes · ${w.instructionCount} static instructions${w.scanComplete ? "" : " (partial scan)"}`, {
      byteSize: w.byteSize, staticInstructionCount: w.instructionCount, loopCount: w.loopCount,
      scanComplete: w.scanComplete, fidelity: "ESTIMATE",
      note: "byteSize drives the one-time SetHook fee; staticInstructionCount is the total opcodes in all function bodies (a complexity proxy). The actual per-invocation execution fee depends on the code path executed at runtime and is not the static count.",
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("hook_report", {
  description: "One-call comprehensive report on a Hook: structure (imports/exports/size/instructions), a plain-English classification of what it does, the full security analysis (SARIF-lite findings + severity summary), HookOn decode, and a fee estimate. Combines inspect + classify + analyze + estimate. Offline.",
  inputSchema: { ...WASM_IN, hookOn: z.string().optional(), namespace: z.string().optional(), grants: z.array(z.record(z.string(), z.unknown())).optional() },
}, async ({ wasmHex, wasmBase64, hookOn, namespace, grants }) => {
  try {
    const w = decodeCreateCode({ wasmHex, wasmBase64 });
    if (!w.valid) return fail(w.reason ?? "invalid wasm", { valid: false });
    const cls = classifyHook(w, hookOn);
    const sethook = Boolean(hookOn || namespace || grants);
    const { findings, summary } = runRules({ wasm: w, hookOn, namespace, grants: grants as HookGrant[] | undefined }, { sethook });
    const ex = w.exports.map((e) => e.name);
    const verdict = summary.CRITICAL > 0 ? "❌ CRITICAL issues — do not install" : summary.HIGH > 0 ? "⚠ HIGH-severity issues — review before installing" : "✓ no high/critical findings (still test on testnet)";
    return ok(`${cls.archetype} · ${findings.length} finding(s) ${summary.CRITICAL}C/${summary.HIGH}H/${summary.MEDIUM}M · ${verdict}`, {
      verdict,
      structure: { byteSize: w.byteSize, instructionCount: w.instructionCount, hasHook: ex.includes("hook"), hasCbak: ex.includes("cbak"), imports: w.imports.filter((i) => i.kind === "func").map((i) => i.name), loopCount: w.loopCount, guardCallCount: w.guardCallCount },
      classification: cls,
      analysis: { findings, summary },
      hookOnDecoded: hookOn ? decodeHookOn(hookOn).firesOn : null,
      feeEstimate: { byteSize: w.byteSize, staticInstructionCount: w.instructionCount, note: "byteSize drives the SetHook fee; instruction count is a complexity proxy (ESTIMATE)." },
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("scaffold_hook", {
  description: "Generate a starter Xahau Hook in C for a stated intent (accept_all, firewall, payment_limit, require_dest_tag, state_counter, notary) — structurally valid (hook() entry, _g guards, accept/rollback) with build instructions. A STARTING POINT to compile + then verify with analyze_hook/execute_hook before deploying. Offline.",
  inputSchema: {
    archetype: z.enum(["accept_all", "firewall", "payment_limit", "require_dest_tag", "state_counter", "notary"]),
    blockTxType: z.string().optional().describe("for firewall: tx type to reject, e.g. Payment"),
    maxDrops: z.string().optional().describe("for payment_limit: max native drops to allow"),
  },
}, async ({ archetype, blockTxType, maxDrops }) => {
  try {
    const s = scaffoldHook({ archetype, blockTxType, maxDrops });
    return ok(`scaffolded ${archetype} hook (C, ${s.source.split("\n").length} lines) — compile, then analyze_hook/execute_hook before deploy`, s as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("classify_hook", {
  description: "Infer in plain English what a Hook DOES (firewall/filter, emitter, stateful processor, financial/XFL, authorizer, autonomous agent…) from its structure — imports, hook/cbak exports, HookOn, state/emit/float/guard usage. Heuristic, offline; does not execute the bytecode.",
  inputSchema: { ...WASM_IN, hookOn: z.string().optional() },
}, async ({ wasmHex, wasmBase64, hookOn }) => {
  try {
    const w = decodeCreateCode({ wasmHex, wasmBase64 });
    if (!w.valid) return fail(w.reason ?? "invalid wasm", { valid: false });
    const c = classifyHook(w, hookOn);
    return ok(`${c.archetype} (${c.confidence}) — ${c.summary}`, c as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("hook_diff", {
  description: "Compare two Hook versions (before/after an upgrade): imports/exports added or removed, HookOn changes, size/instruction deltas, and any newly-gained security-sensitive capability (emit, foreign-state write, hook_again, signature verify). Offline.",
  inputSchema: {
    beforeWasmHex: z.string().optional(), beforeWasmBase64: z.string().optional(), beforeHookOn: z.string().optional(),
    afterWasmHex: z.string().optional(), afterWasmBase64: z.string().optional(), afterHookOn: z.string().optional(),
  },
}, async ({ beforeWasmHex, beforeWasmBase64, beforeHookOn, afterWasmHex, afterWasmBase64, afterHookOn }) => {
  try {
    const a = decodeCreateCode({ wasmHex: beforeWasmHex, wasmBase64: beforeWasmBase64 });
    const b = decodeCreateCode({ wasmHex: afterWasmHex, wasmBase64: afterWasmBase64 });
    if (!a.valid || !b.valid) return fail("both before/after WASM must be valid", { beforeValid: a.valid, afterValid: b.valid });
    const d = diffHooks(a, b, beforeHookOn, afterHookOn);
    return ok(d.summary, d as unknown as Record<string, unknown>);
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

server.registerTool("quantum_grade", {
  description: "Grade a Xahau account for quantum (HNDL) readiness: master-key-disabled, regular key, multi-sign and installed hooks → 0-100 score + tier + recommendations. Ports the xrpl-audit quantum model to Xahau, with a Hook/PQC dimension. Read-only.",
  inputSchema: { address: z.string().min(25).describe("r-address"), network: NET },
}, async ({ address, network }) => {
  try { const g = await quantumGrade(address, network as Net); return ok(`${address}: ${g.tier} (${g.score}/100) — ${g.masterDisabled ? "master disabled" : "master ENABLED"}`, g); }
  catch (e) { return fail((e as Error).message); }
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

server.registerTool("build_import_unsigned", {
  description: "Assemble an UNSIGNED Import (Burn2Mint) transaction wrapping a HEX-encoded XPOP in the Blob field. Returns unsigned JSON + offline signing instructions. Never signs; testnet by default.",
  inputSchema: { account: z.string().min(25), xpopBlobHex: z.string().min(2).describe("HEX-encoded XPOP proof"), network: NET.default("testnet") },
}, async (a) => { try { const r = buildImportUnsigned(a as any); return ok(`unsigned Import for ${a.account} (${r.network}, ${a.xpopBlobHex.length / 2}B xpop)`, r as any); } catch (e) { return fail((e as Error).message); } });

server.registerTool("build_payment_unsigned", {
  description: "Assemble an UNSIGNED XAH Payment (amount in drops). Returns unsigned JSON + offline signing instructions + payload preflight. Never signs; testnet by default.",
  inputSchema: { account: z.string().min(25), destination: z.string().min(25), amountXahDrops: z.string(), destinationTag: z.number().optional(), network: NET.default("testnet") },
}, async (a) => { try { const r = buildPaymentUnsigned(a as any); return ok(`unsigned Payment ${a.amountXahDrops} drops → ${a.destination} (${r.network})`, r as any); } catch (e) { return fail((e as Error).message); } });

server.registerTool("prepare_transaction", {
  description: "Autofill an unsigned transaction with live network values — Sequence (from the account), Fee (current base fee), LastLedgerSequence (now + offset), and NetworkID — so it's ready to sign OFFLINE. Read-only: fetches values, fills the tx, but NEVER signs or submits.",
  inputSchema: { tx: z.record(z.string(), z.unknown()).describe("unsigned tx JSON; must include Account + TransactionType"), lastLedgerOffset: z.number().default(20), network: NET.default("testnet") },
}, async ({ tx, lastLedgerOffset, network }) => {
  try {
    const t = { ...(tx as Record<string, any>) };
    if (!t.Account || !t.TransactionType) return fail("tx must include Account and TransactionType");
    const net = network as Net;
    const [ai, fee, si] = await Promise.all([rpc.getAccountInfo(t.Account, net), rpc.getFee(net) as Promise<any>, rpc.getServerInfo(net) as Promise<any>]);
    const seq = (ai.account_data as any).Sequence;
    const baseFee = fee.drops?.base_fee ?? fee.drops?.minimum_fee ?? "10";
    const curLedger = Number(String(si.info.complete_ledgers).split("-").pop());
    if (t.Sequence === undefined) t.Sequence = seq;
    if (t.Fee === undefined) t.Fee = String(baseFee);
    if (t.LastLedgerSequence === undefined) t.LastLedgerSequence = curLedger + Math.max(1, lastLedgerOffset);
    if (t.NetworkID === undefined) t.NetworkID = ENDPOINTS[net].network_id;
    return ok(`prepared ${t.TransactionType} for ${t.Account}: seq ${t.Sequence}, fee ${t.Fee}, LLS ${t.LastLedgerSequence} (${net})`, {
      unsignedTx: t, network: net,
      autofilled: { sequence: t.Sequence, fee: t.Fee, lastLedgerSequence: t.LastLedgerSequence, networkId: t.NetworkID },
      signingInstructions: "Now SIGN this OFFLINE with your own key (xaman / xrpl-accountlib) and submit. This tool only filled in network values — it never signs or submits. NEVER paste a secret here.",
    });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("vm_fidelity_report", {
  description: "HONEST FIDELITY METRIC: measures how faithfully the local Hook VM reproduces what REALLY happened on Xahau mainnet. Loads a committed corpus (data/hook-corpus.json) of real validated transactions whose metadata carried HookExecutions, runs each hook's real bytecode through the local VM, and compares the VM's accept/rollback DIRECTION to the on-chain HookResult. The agreement % is computed ONLY over COMPARABLE (non-degraded, scoreable) runs; degraded/halted/indeterminate runs are reported separately and EXCLUDED — never counted as a match. Strictly offline; reads no network. If the corpus is empty/tiny it says 'insufficient corpus' rather than print an unsupported number.",
  inputSchema: { includeMismatches: z.boolean().default(true).describe("include the per-mismatch list (txHash/vmExit/onChainResult)") },
}, async ({ includeMismatches }) => {
  try {
    if (!existsSync(CORPUS_PATH)) return fail(`corpus not found at ${CORPUS_PATH}; run the corpus builder first.`);
    const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as HookCorpus;
    const rep = fidelityReport(corpus);
    const out: Record<string, unknown> = {
      total: rep.total,
      comparable: rep.comparable,
      agreements: rep.agreements,
      agreementPct: rep.agreementPct,
      degradedCount: rep.degradedCount,
      insufficient: rep.insufficient,
      perHook: rep.perHook,
      corpus: rep.corpus,
      headline: rep.headline,
    };
    if (includeMismatches) out.mismatches = rep.mismatches;
    return ok(rep.headline, out);
  } catch (e) { return fail((e as Error).message); }
});

/* ===================== Resources — offline reference data ===================== */
// SDK 1.29.0: server.registerResource(name, uri, { ...ResourceMetadata }, async (uri) => ({ contents: [...] }))

function jsonResource(uri: string, payload: unknown) {
  return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(payload, null, 2) }] };
}

server.registerResource(
  "analyzer-rules",
  "xahau://rules",
  { title: "Hook analyzer rule registry", description: "Every rule in the Hooks static-analysis / security engine (id, severity, title, category, requires). Offline.", mimeType: "application/json" },
  async (uri) => { const rules = listRules(); return jsonResource(uri.href, { count: rules.length, rules }); },
);

server.registerResource(
  "hook-api",
  "xahau://hook-api",
  { title: "Hook API catalog", description: "The Hook API functions (category, exit/guard role, hazard metadata) used by Xahau Hooks. Offline.", mimeType: "application/json" },
  async (uri) => jsonResource(uri.href, { count: hookApiCount(), functions: HOOK_FUNCTIONS }),
);

server.registerResource(
  "tx-types",
  "xahau://tx-types",
  { title: "Transaction-type table", description: "Xahau transaction types and their numeric codes (from network definitions). Offline.", mimeType: "application/json" },
  async (uri) => { const types = allTxTypes(); return jsonResource(uri.href, { count: types.length, txTypes: types }); },
);

/* ===================== Prompts — guided templates ===================== */
// SDK 1.29.0: server.registerPrompt(name, { title?, description?, argsSchema }, (args) => ({ messages: [...] }))

function userText(text: string) {
  return { role: "user" as const, content: { type: "text" as const, text } };
}

server.registerPrompt(
  "audit_hook",
  {
    title: "Audit a Hook's WASM",
    description: "Guide the agent through a full offline security audit of a Hook's CreateCode: inspect → analyze → summarize.",
    argsSchema: { wasmHex: z.string().describe("Hook CreateCode WASM as hex") },
  },
  ({ wasmHex }) => ({
    messages: [userText(
      `Perform a complete offline security audit of this Xahau Hook. Do it in three steps and report each:\n` +
      `1. Call \`inspect_hook_wasm\` with wasmHex="${wasmHex}" to read its imports, exports, memory, loop/guard counts.\n` +
      `2. Call \`analyze_hook\` with the same wasmHex to run the static-analysis rule engine and collect SARIF-lite findings.\n` +
      `3. Summarize: list every finding grouped by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), explain what each means in plain English, and give an overall risk verdict. Reference the \`xahau://rules\` resource for rule details. Stay strictly read-only; never sign or submit anything.`,
    )],
  }),
);

server.registerPrompt(
  "simulate_hook",
  {
    title: "Simulate a Hook's execution",
    description: "Guide the agent to run a Hook's real bytecode in the local VM, then fuzz its decision boundary.",
    argsSchema: {
      wasmHex: z.string().describe("Hook CreateCode WASM as hex"),
      txType: z.string().optional().describe("originating transaction type, e.g. Payment"),
    },
  },
  ({ wasmHex, txType }) => ({
    messages: [userText(
      `Simulate this Xahau Hook against a transaction using the local VM (no node required). Two steps:\n` +
      `1. Call \`execute_hook\` with wasmHex="${wasmHex}"${txType ? ` and txType="${txType}"` : ""} and report the true accept/rollback decision, return code/string, state writes, emitted txns and trace. Note the fidelity label and any DEGRADED runs.\n` +
      `2. Call \`fuzz_hook\` with the same wasmHex${txType ? ` and txType="${txType}"` : ""} to find the accept/rollback decision boundary across deterministically generated inputs. Report the counts {accept,rollback,halted,degraded}, the per-axis boundaries, and a concrete accepting and rejecting sample. If it reports INCONCLUSIVE, explain why. Stay read-only.`,
    )],
  }),
);

server.registerPrompt(
  "explain_hook",
  {
    title: "Explain a Hook in plain English",
    description: "Guide the agent to decode a Hook (by on-ledger hash or raw WASM) and explain what it does.",
    argsSchema: {
      hookHash: z.string().optional().describe("on-ledger HookDefinition hash (64 hex)"),
      wasmHex: z.string().optional().describe("Hook CreateCode WASM as hex"),
    },
  },
  ({ hookHash, wasmHex }) => {
    const source = hookHash
      ? `First call \`get_hook_definition\` with hookHash="${hookHash}" to fetch the on-ledger CreateCode WASM, then use that WASM for the next steps.`
      : wasmHex
        ? `Use this CreateCode WASM directly: wasmHex="${wasmHex}".`
        : `No hook was supplied — ask the user for a hookHash or wasmHex before continuing.`;
    return {
      messages: [userText(
        `Explain what this Xahau Hook does, for a non-expert. ${source}\n` +
        `Then: call \`inspect_hook_wasm\` to see its imports/exports; if a HookOn is available call \`decode_hook_on\` to learn which transaction types it fires on; look up unfamiliar Hook API functions with \`hook_api_lookup\` (or the \`xahau://hook-api\` resource). Finally write a clear plain-English explanation: what triggers it, what it reads, what it does, and whether it can accept or rollback transactions. Strictly read-only.`,
      )],
    };
  },
);

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
