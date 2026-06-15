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
import { validateAddress, xaddressEncode, xaddressDecode, currencyCode, rippleTime, decodeAmount, describeTx, accountIdToR } from "./util.js";
import { decodeXpop } from "./xpop.js";
import { decodeLeaseUri } from "./evernode.js";
import { explainAccount } from "./explain.js";
import { inspectEmitted } from "./emitted.js";
import { readWasm, hexToBytes, base64ToBytes } from "./wasm.js";
import { lookupHookApi, hookApiCount, HOOK_FUNCTIONS } from "./hookapi.js";
import { decodeCreateCode, runRules, listRules, type HookGrant } from "./analyzer.js";
import { runHook } from "./sandbox.js";
import { annotateHookTrace } from "./trace.js";
import { fuzzHook } from "./fuzz.js";
import { classifyHook } from "./classify.js";
import { diffHooks } from "./diff.js";
import { scaffoldHook } from "./scaffold.js";
import { computeReward } from "./rewards.js";
import { quantumGrade } from "./quantum.js";
import { governanceState, decodeB2M } from "./governance.js";
import { buildSetHookUnsigned, buildClaimRewardUnsigned, buildPaymentUnsigned, buildImportUnsigned, buildRemitUnsigned, buildSetRemarksUnsigned, buildClawbackUnsigned, buildDeepFreezeUnsigned } from "./builders.js";
import { fidelityReport, type HookCorpus } from "./fidelity.js";
import { hookExecutionPostmortem } from "./postmortem.js";
import { scorePayload } from "./scam.js";
import { EXECUTE_HOOK_OUT, ANALYZE_HOOK_OUT, CLASSIFY_HOOK_OUT, HOOK_DIFF_OUT, HOOK_REPORT_OUT, FIDELITY_OUT, QUANTUM_OUT, DECODE_HOOKON_OUT, ENCODE_HOOKON_OUT, DECODE_AMOUNT_OUT, VALIDATE_ADDRESS_OUT, DECODE_SIGNREQ_OUT, DECODE_XPOP_OUT, REWARD_STATUS_OUT, HOST_DIAGNOSTICS_OUT, DIAGNOSE_TX_OUT, SIMULATE_OUT } from "./outputSchemas.js";
import { rewardStatus, GENESIS_ACCOUNT, GENESIS_NAMESPACE } from "./rewardStatus.js";
import { evernodeHostDiagnostics, EVERNODE_GOVERNOR, EVERNODE_HOOK_NAMESPACE } from "./evernodeHost.js";
import { diagnoseFailedTx } from "./diagnose.js";
import { decodeGovernance } from "./governanceDecode.js";
import { simulateTransaction } from "./simulate.js";
import { simDeps } from "./simdeps.js";
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
  // isError marks this as a failed tool call so MCP clients (and agents) don't treat the error
  // payload as data. The SDK also skips outputSchema validation on isError results.
  return { content: [{ type: "text" as const, text }], structuredContent: { error: text, ...structured }, isError: true as const };
}

const server = new McpServer({ name: "xahau-mcp", version: "2.0.1" });

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

server.registerTool("explain_account", {
  description: "One-call plain-English account snapshot: balance, key-safety read (master/regular key), installed Hooks (+what they fire on), trustlines, URITokens (Evernode leases auto-decoded), and recent activity — plus warnings and notes. Read-only; exactly 5 serial RPC reads (>=1100ms apart).",
  inputSchema: { address: z.string().min(25).describe("r-address"), network: NET },
}, async ({ address, network }) => {
  try {
    const net = network as Net;
    const r = await explainAccount(address, {
      getAccountInfo: async (a) => (await rpc.getAccountInfo(a, net)) as Record<string, any>,
      getHookObjects: async (a) => (await rpc.getAccountObjects(a, net, "hook")).account_objects as Record<string, any>[],
      getLines: async (a) => (await rpc.getAccountLines(a, net)).lines as Record<string, any>[],
      getUriTokens: async (a) => (await rpc.getAccountObjects(a, net, "uri_token")).account_objects as Record<string, any>[],
      getRecentTx: async (a) => (await rpc.getAccountTx(a, net, 10)).transactions as Record<string, any>[],
    });
    return ok(r.summary, r as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
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
  outputSchema: DECODE_HOOKON_OUT,
}, async ({ hookOn }) => {
  try { const d = decodeHookOn(hookOn); return ok(`Fires on ${d.count} type(s): ${d.firesOn.join(", ") || "(none)"}`, d); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("encode_hook_on", {
  description: "Build a canonical HookOn hex from a list of transaction types to fire on. Offline.",
  inputSchema: { txTypes: z.array(z.string()).min(1).describe("e.g. [\"Payment\",\"Invoke\"]") },
  outputSchema: ENCODE_HOOKON_OUT,
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
  outputSchema: VALIDATE_ADDRESS_OUT,
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

server.registerTool("decode_result", {
  description: "Decode a transaction engine result code (e.g. 0/tesSUCCESS, 153/tecHOOK_REJECTED) ⇄ its name. Accepts a number or the result-code name. Offline.",
  inputSchema: { result: z.union([z.number(), z.string()]).describe("a result code number or name") },
}, async ({ result }) => { const d = decodeResult(result); return d.known ? ok(`${d.name} (${d.code})`, d) : fail(`unknown result code: ${result}`, d); });

server.registerTool("ripple_time", {
  description: "Convert between Ripple time (seconds since 2000-01-01), Unix time, and ISO 8601. Xahau tx/ledger timestamps use Ripple time. Offline.",
  inputSchema: { ripple: z.number().optional(), unix: z.number().optional(), iso: z.string().optional() },
}, async ({ ripple, unix, iso }) => { try { const t = rippleTime({ ripple, unix, iso }); return ok(`ripple ${t.rippleTime} = ${t.iso}`, t); } catch (e) { return fail((e as Error).message); } });

server.registerTool("decode_xpop", {
  description: "Decode an XPOP (Xahau Proof of Payment) — the proof blob inside an Import/Burn2Mint tx. Accepts the Import Blob hex (hex of the XPOP JSON) or the XPOP JSON itself. Returns the source ledger header, the decoded inner BURN transaction (type, burned drops = its Fee, target network), and the UNL validator set. Offline.",
  inputSchema: { xpop: z.union([z.string(), z.record(z.string(), z.unknown())]).describe("Import Blob hex, XPOP JSON string, or XPOP object") },
  outputSchema: DECODE_XPOP_OUT,
}, async ({ xpop }) => {
  try { const d = decodeXpop(xpop as string | Record<string, unknown>); return ok(d.summary, d as unknown as Record<string, unknown>); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("inspect_emitted_tx", {
  description: "Decode what a hook's emit() actually built: pass the emitted[] blob hex(es) from an execute_hook result → each decoded to tx JSON + a plain-English 'what it tries to send' summary + danger score (scam rules). Closes the loop on emitter hooks. Offline.",
  inputSchema: { emitted: z.array(z.string()).min(1).describe("emitted blob hex(es) from execute_hook's `emitted` array") },
}, async ({ emitted }) => {
  try { const r = inspectEmitted(emitted); return ok(r.headline, r as unknown as Record<string, unknown>); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("decode_lease_uri", {
  description: "Decode an Evernode lease URIToken URI (the `evrlease`/LTV format) → lease index, lease amount in EVR (XFL-decoded), half ToS hash, mint identifier, outbound IP. Accepts the on-chain URI hex, the base64 text, or raw buffer hex. Verified against the canonical evernode-js-client encoder + real mainnet leases. Offline.",
  inputSchema: { uri: z.string().describe("URIToken.URI hex, base64 text, or raw lease-buffer hex") },
}, async ({ uri }) => {
  const d = decodeLeaseUri(uri);
  return d.isEvernodeLease
    ? ok(`Evernode lease v${d.version} · index ${d.leaseIndex} · ${d.leaseAmountEvr} EVR${d.outboundIp ? ` · ip ${d.outboundIp}` : ""}`, d as unknown as Record<string, unknown>)
    : fail(d.reason ?? "not an Evernode lease", d as unknown as Record<string, unknown>);
});

server.registerTool("decode_amount", {
  description: "Decode an amount: native drops (digits), a serialized 8-byte native or 48-byte issued STAmount (hex), or an issued amount object {currency,issuer,value} → normalized value/currency/issuer. Offline.",
  inputSchema: { amount: z.union([z.string(), z.record(z.string(), z.unknown())]).describe("drops string, STAmount hex, or amount object") },
  outputSchema: DECODE_AMOUNT_OUT,
}, async ({ amount }) => {
  try { const d = decodeAmount(amount as any); return ok(d.type === "native" ? `${(d as any).xah} XAH (${(d as any).drops} drops)` : `${(d as any).value} ${(d as any).currency}${(d as any).issuer ? ` / ${(d as any).issuer}` : ""}`, d); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("decode_sign_request", {
  description: "Decode a sign request (a Xaman/Xumm payload's txjson, or a raw tx_blob hex) into the transaction plus a plain-English 'what you would be authorizing' summary and safety warnings (SetHook, AccountDelete, key changes, no-expiry, already-signed). Offline — understand before you sign.",
  inputSchema: { txjson: z.record(z.string(), z.unknown()).optional(), txBlobHex: z.string().optional() },
  outputSchema: DECODE_SIGNREQ_OUT,
}, async ({ txjson, txBlobHex }) => {
  try {
    const tx = (txjson as Record<string, any> | undefined) ?? (txBlobHex ? (decodeTxBlob(txBlobHex) as Record<string, any>) : undefined);
    if (!tx) return fail("provide txjson or txBlobHex");
    const { summary, warnings } = describeTx(tx);
    const amountDecoded = tx.Amount !== undefined ? decodeAmount(tx.Amount) : null;
    return ok(`${summary}${warnings.length ? " ⚠ " + warnings.length + " warning(s)" : ""}`, { transactionType: tx.TransactionType, summary, warnings, amountDecoded, tx });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("scam_check", {
  description: "Score a sign request (txjson or raw tx_blob hex) for risky patterns BEFORE signing: returns dangerScore 0-100, a SAFE/CAUTION/DANGER tier, a plain-English verdict, and per-rule findings (SetHook, AccountDelete-to-other, regular-key/signer-list changes, very large native payment, no-expiry replay risk, pre-signed blob). Offline + read-only. HONESTY: every finding is a POTENTIAL risk, NOT a confirmed scam — this tool does NOT consult any block list and NEVER verifies on-chain whether an address is malicious; it reads the transaction shape only. DANGER is reserved for near-universally-malicious/irreversible patterns.",
  inputSchema: { txjson: z.record(z.string(), z.unknown()).optional(), txBlobHex: z.string().optional() },
}, async ({ txjson, txBlobHex }) => {
  try {
    const tx = (txjson as Record<string, any> | undefined) ?? (txBlobHex ? (decodeTxBlob(txBlobHex) as Record<string, any>) : undefined);
    if (!tx) return fail("provide txjson or txBlobHex");
    const r = scorePayload(tx);
    return ok(`${r.tier} (score ${r.dangerScore}/100) — ${r.verdict}`, r as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

/* ===================== Tier C — Hook intelligence (the moat, offline) ===================== */

// 128 KiB byte ceiling (see MAX_WASM_BYTES in sandbox.ts) → 256 Ki hex chars / ~180 K base64 chars.
const WASM_IN = {
  wasmHex: z.string().max(262_144, "wasmHex too large (>128 KiB of bytecode)").optional(),
  wasmBase64: z.string().max(180_000, "wasmBase64 too large (>128 KiB of bytecode)").optional(),
};

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
  outputSchema: ANALYZE_HOOK_OUT,
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
  outputSchema: EXECUTE_HOOK_OUT,
}, async ({ wasmHex, wasmBase64, txType, otxnFields, otxnParams, hookAccountId, hookParams, state, keyletBlobs, otxnBlob, ledgerSeq, feeBase, resolveKeylets, network }) => {
  try {
    const bytes = wasmHex ? hexToBytes(wasmHex) : wasmBase64 ? base64ToBytes(wasmBase64) : null;
    if (!bytes) return fail("provide wasmHex or wasmBase64");
    const baseCtx = { txType, otxnFields, otxnParams, hookAccountId, hookParams, state, keyletBlobs, otxnBlob, ledgerSeq, feeBase };
    let r = runHook(bytes, baseCtx);
    const resolved: string[] = [];
    const resolvedForeign: string[] = [];
    // async pre-resolve (up to 2 rounds — a resolved read can expose a further dependent read):
    // fetch the ledger objects the hook slot_set AND the foreign-state entries it read, then re-run.
    if (resolveKeylets) {
      const fetchedKeylets: Record<string, string> = { ...(keyletBlobs ?? {}) };
      const fetchedForeign: Record<string, string | null> = {};
      for (let round = 0; round < 2 && (r.wantedKeylets.length || r.wantedForeignState.length); round++) {
        let progressed = false;
        for (const idx of r.wantedKeylets) {
          if (fetchedKeylets[idx]) continue;
          try {
            const le = await rpc.getLedgerEntry({ index: idx, binary: true }, network as Net) as any;
            const binHex = le.node_binary ?? le.node?.node_binary;
            if (binHex) { fetchedKeylets[idx] = binHex; resolved.push(idx); progressed = true; }
          } catch { /* leave unresolved */ }
        }
        for (const composite of r.wantedForeignState) {
          if (composite in fetchedForeign) continue;
          const [acc, ns, key] = composite.split("|");
          const rAddr = accountIdToR(acc);
          if (!rAddr) continue;
          try {
            const le = await rpc.getLedgerEntry({ hook_state: { account: rAddr, key, namespace_id: ns } }, network as Net) as any;
            const data = le.node?.HookStateData;
            fetchedForeign[composite] = typeof data === "string" ? data : null;
            resolvedForeign.push(composite); progressed = true;
          } catch (e) {
            // entryNotFound = CONFIRMED absent at this ledger (DOESNT_EXIST is then faithful); other errors stay unresolved
            if (String((e as Error).message).includes("entryNotFound")) { fetchedForeign[composite] = null; resolvedForeign.push(composite); progressed = true; }
          }
        }
        if (!progressed) break;
        r = runHook(bytes, { ...baseCtx, keyletBlobs: fetchedKeylets, foreignState: fetchedForeign });
      }
    }
    const tail = r.degraded ? " ⚠ DEGRADED" : "";
    return ok(`${r.exit.toUpperCase()}${r.returnCode !== null ? ` code=${r.returnCode}` : ""}${r.returnString ? ` "${r.returnString}"` : ""} · ${r.stateWrites.length} state write(s) · ${r.emitted.length} emit(s)${resolved.length ? ` · resolved ${resolved.length} keylet(s)` : ""}${resolvedForeign.length ? ` · resolved ${resolvedForeign.length} foreign-state entr(ies)` : ""}${tail}`, { ...(r as unknown as Record<string, unknown>), resolvedKeylets: resolved, resolvedForeignState: resolvedForeign });
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("annotate_hook_trace", {
  description: "Annotate the trace[] array from an execute_hook result. Each entry is \"label: HEXVALUE\" (the hook's trace() memory dump). Decodes each blob by byte-width: 8-byte → canonical XFL float (definite) else int64 (both endians) + native-drops reading; 4-byte → UInt32 (both endians) + Ripple-epoch ISO date if in range; 20-byte → candidate account-id → r-address (possible, since arbitrary bytes can coincidentally encode); 32-byte → possible tx/hook hash (heuristic); other widths → raw blob. The raw hex is ALWAYS preserved as the primary field; nothing is suppressed; confidence is 'definite' only for canonical XFL. Fully offline, no network.",
  inputSchema: {
    trace: z.array(z.string()).describe("trace[] from an execute_hook result; each element \"label: HEXVALUE\""),
  },
}, async ({ trace }) => {
  try {
    const r = annotateHookTrace(trace);
    return ok(`annotated ${r.decoded.length} trace entr${r.decoded.length === 1 ? "y" : "ies"}`, r as unknown as Record<string, unknown>);
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
  outputSchema: HOOK_REPORT_OUT,
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
  outputSchema: CLASSIFY_HOOK_OUT,
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
  outputSchema: HOOK_DIFF_OUT,
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
  description: "Project claimable XAH network reward using the documented time-weighted model. Supply reward fields directly, or an address to read them live. Labelled DOCUMENTED_MODEL. LEGACY approximation — prefer reward_status, which applies the exact genesis reward-hook formula with live parameters.",
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

server.registerTool("reward_status", {
  description: "Balance Adjustment doctor — the full answer to Xahau's most common retail question: is this account opted in to network rewards, how much XAH is accrued (EXACT genesis reward-hook formula — reward.c — with live RR/RD read from genesis hook state), when can it next claim, and is the claim overdue (late claiming forfeits yield — the hook pays the per-claim rate once regardless of wait). Returns an unsigned opt-in or claim ClaimReward when applicable. Read-only; 3 serial RPC reads.",
  inputSchema: { address: z.string().min(25).describe("r-address"), network: NET },
  outputSchema: REWARD_STATUS_OUT,
}, async ({ address, network }) => {
  try {
    const r = await rewardStatus(address, network as Net, {
      getAccountInfo: (a) => rpc.getAccountInfo(a, network as Net),
      getGenesisNamespace: () => rpc.getAccountNamespace(GENESIS_ACCOUNT, GENESIS_NAMESPACE, network as Net).then((x) => x.namespace_entries),
      getValidatedLedger: () => rpc.getLedger("validated", network as Net).then((x) => {
        const l = x.ledger as Record<string, any>;
        return { ledgerIndex: Number(l.ledger_index), closeTime: Number(l.close_time) };
      }),
    });
    return ok(r.summary, r as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("evernode_host_diagnostics", {
  description: "One-call health check for an Evernode host (the official docs' troubleshooting checklist, automated): registration entry on the governor namespace, heartbeat liveness vs the on-chain active rule (current moment − heartbeatFreq×momentSize), instance load, reputation byte, EVR trustline + balance, registration URIToken held, lease offers, machine specs + accumulated EVR reward. Layout verified against canonical evernode-js-client + live mainnet. Read-only; ~9 serial RPC reads (slow but thorough).",
  inputSchema: { address: z.string().min(25).describe("host r-address"), network: NET },
  outputSchema: HOST_DIAGNOSTICS_OUT,
}, async ({ address, network }) => {
  try {
    const gov = EVERNODE_GOVERNOR[network as keyof typeof EVERNODE_GOVERNOR];
    const r = await evernodeHostDiagnostics(address, network as string, {
      getAccountInfo: (a) => rpc.getAccountInfo(a, network as Net),
      getHookState: async (key) => {
        try {
          const e = await rpc.getLedgerEntry({ hook_state: { account: gov, key, namespace_id: EVERNODE_HOOK_NAMESPACE } }, network as Net);
          const d = (e.node as Record<string, unknown>)?.HookStateData;
          return typeof d === "string" && d.length ? d : null;
        } catch (err) {
          // entryNotFound = the state genuinely doesn't exist (null); any other failure = unavailable
          // (undefined) so the diagnostics layer doesn't misreport a node hiccup as "not registered".
          if (/entryNotFound/i.test((err as Error).message)) return null;
          return undefined;
        }
      },
      getLines: (a) => rpc.getAccountLines(a, network as Net).then((x) => x.lines),
      getUriTokens: (a) => rpc.getAccountObjects(a, network as Net, "uri_token").then((x) => x.account_objects),
      getCloseTime: () => rpc.getLedger("validated", network as Net).then((x) => Number((x.ledger as Record<string, any>).close_time)),
    });
    return ok(r.summary, r as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("diagnose_failed_tx", {
  description: "Why did my transaction fail? Plain-English diagnosis from ON-CHAIN facts: engine result decoded to cause + concrete fix (catalog of ~30 common Xahau failure codes), hook rollback return-strings decoded and interpreted (e.g. the genesis reward hook's 'You must wait N seconds' becomes a claimable-at date), the partial-payment trap on 'successful' Payments (delivered_amount vs Amount), and not-found triage (expired LastLedgerSequence / wrong network). 1 RPC read; authoritative — decodes what the chain recorded, re-executes nothing (use hook_execution_postmortem to replay hooks).",
  inputSchema: { txHash: z.string().length(64).describe("transaction hash"), network: NET },
  outputSchema: DIAGNOSE_TX_OUT,
}, async ({ txHash, network }) => {
  try {
    const d = await diagnoseFailedTx(txHash, network as string, {
      getTx: async (h) => {
        try { return await rpc.getTx(h, network as Net); }
        catch (e) { if (/txnNotFound|not found/i.test((e as Error).message)) return null; throw e; }
      },
    });
    return ok(d.summary, d as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});


server.registerTool("simulate_transaction", {
  description: "THE PRE-SIGN FLIGHT SIMULATOR — predict what Xahau will do with an UNSIGNED transaction before you sign it. Every hook the tx would trigger (originator chain first, then strong/weak transactional stakeholders — order canonical from xahaud Transactor.cpp/applyHook.cpp) runs as REAL bytecode against LIVE ledger state in the local VM (measured 100% agreement on 30 real mainnet hook executions — all accept-direction; rollback direction proven separately on real genesis bytecode). Reports per-hook accept/rollback + return strings, simulated state writes, decoded emitted transactions, labeled STATIC engine preflights (sequence/balance/destination/expiry), an APPROXIMATE transactor prediction (the stand-in for Xahau's missing `simulate` RPC — predicted engine_result + balance/reserve/trustline deltas for Payment/TrustSet against live state, labeled APPROXIMATE; other tx types UNSUPPORTED), and a scam score. Never signs, never submits. Slow but thorough (iterative state resolution, ~1.1s per read).",
  inputSchema: { tx: z.record(z.string(), z.unknown()).describe("unsigned transaction JSON (TransactionType, Account, ...)"), network: NET },
  outputSchema: SIMULATE_OUT,
}, async ({ tx, network }) => {
  try {
    const s = await simulateTransaction(tx as Record<string, unknown>, simDeps(network as Net));
    return ok(s.summary, s as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("what_if", {
  description: "TIME MACHINE — counterfactual replay of a REAL historical transaction: fetch it by hash, apply your field overrides (different Amount, Destination, params, ...), then run the full flight simulator AT THAT HISTORICAL LEDGER (hooks, state and parameters as they were). Answers 'what would have happened if this tx had been X?'. Read-only; nothing is signed or submitted.",
  inputSchema: {
    txHash: z.string().length(64).describe("real validated transaction hash"),
    overrides: z.record(z.string(), z.unknown()).optional().describe("fields to change on the tx before re-simulating (e.g. {\"Amount\": \"99000000\"})"),
    network: NET,
  },
  outputSchema: SIMULATE_OUT,
}, async ({ txHash, overrides, network }) => {
  try {
    const real = await rpc.getTx(txHash, network as Net) as Record<string, any>;
    const base = (real.tx_json ?? real) as Record<string, any>;
    const ledgerIndex = Number(real.ledger_index ?? base.ledger_index);
    if (!Number.isFinite(ledgerIndex)) return fail("could not determine the tx's ledger index");
    const tx: Record<string, unknown> = { ...base, ...(overrides ?? {}) };
    for (const k of ["TxnSignature", "SigningPubKey", "hash", "meta", "metaData", "date", "inLedger", "ledger_index", "validated"]) delete tx[k];
    const deps = simDeps(network as Net, ledgerIndex - 1); // pre-execution ledger, like the fidelity harness
    const s = await simulateTransaction(tx, deps, { ledgerIndex: ledgerIndex - 1 });
    return ok(`WHAT-IF @ ledger ${ledgerIndex - 1}${overrides && Object.keys(overrides).length ? ` with ${Object.keys(overrides).join(", ")} overridden` : " (faithful replay)"}: ${s.summary}`, { ...s, baseTxHash: txHash, overriddenFields: Object.keys(overrides ?? {}) } as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("quantum_grade", {
  description: "Grade a Xahau account for quantum (HNDL) readiness: master-key-disabled, regular key, multi-sign and installed hooks → 0-100 score + tier + recommendations. Ports the xrpl-audit quantum model to Xahau, with a Hook/PQC dimension. Read-only.",
  inputSchema: { address: z.string().min(25).describe("r-address"), network: NET },
  outputSchema: QUANTUM_OUT,
}, async ({ address, network }) => {
  try { const g = await quantumGrade(address, network as Net); return ok(`${address}: ${g.tier} (${g.score}/100) — ${g.masterDisabled ? "master disabled" : "master ENABLED"}`, g); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("governance_state", {
  description: "Genesis Governance Game — FULL live decode of the L1 table's hook state (layout canonical from xahaud hook/genesis/govern.c): all 20 seats and their members, member count, live reward rate/delay, every OPEN VOTE (who voted what, per topic) and every tally with its threshold (membership topics 80% of filled seats, everything else 100%) and whether it's reached. Plus the documented constants + a live genesis-account read. 2 RPC reads.",
  inputSchema: { network: NET },
}, async ({ network }) => {
  try {
    const g = await governanceState(network as Net);
    let decoded = null;
    try {
      const ns = await rpc.getAccountNamespace(GOVERNANCE?.genesisAccount ?? GENESIS_ACCOUNT, GENESIS_NAMESPACE, network as Net);
      decoded = decodeGovernance(ns.namespace_entries as { HookStateKey?: string; HookStateData?: string }[]);
    } catch (e) { (g as Record<string, unknown>).decodeError = (e as Error).message; }
    const merged = { ...g, ...(decoded ? { decoded, caveat: "Per-seat/topic/vote decode is live from the genesis hook state; layout verified against xahaud hook/genesis/govern.c. " } : {}) };
    return ok(decoded ? decoded.summary : `genesis ${GOVERNANCE?.genesisAccount ?? "?"} · ${GOVERNANCE?.governanceSeats ?? "?"} seats (decode unavailable)`, merged as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message); }
});

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
  inputSchema: { account: z.string().min(25), destination: z.string().min(25), amountDrops: z.string().describe("native amount in DROPS (1 XAH = 1,000,000 drops); use xah_amount to convert XAH→drops"), destinationTag: z.number().optional(), network: NET.default("testnet") },
}, async (a) => { try { const r = buildPaymentUnsigned(a as any); return ok(`unsigned Payment ${a.amountDrops} drops → ${a.destination} (${r.network})`, r as any); } catch (e) { return fail((e as Error).message); } });

server.registerTool("build_remit_unsigned", {
  description: "Assemble an UNSIGNED Remit (XLS-55) — Xahau's atomic multi-asset push payment. Send multiple currencies (native + issued) and/or transfer existing URITokens and/or mint a new URIToken to one Destination in a single all-or-nothing transaction. The transactor auto-creates missing trustlines, pays token reserves, and creates the destination account if absent (no partial payments, no pathing). Optionally Inform a third-party hook. Returns unsigned JSON + payload preflight + offline signing instructions. Never signs; testnet by default.",
  inputSchema: {
    account: z.string().min(25),
    destination: z.string().min(25),
    amounts: z.array(z.union([
      z.string().describe("native XAH amount in DROPS (integer string)"),
      z.object({ currency: z.string().describe("3-char ISO code or 40-hex currency"), issuer: z.string().min(25), value: z.string() }),
    ])).optional().describe("currencies to send; each becomes an AmountEntry"),
    uriTokenIds: z.array(z.string()).optional().describe("existing URIToken IDs (64-hex) to transfer to destination"),
    mintURIToken: z.object({ uri: z.string().describe("hex, or text (auto UTF-8→hex)"), digest: z.string().optional().describe("64-hex digest"), flags: z.number().optional() }).optional().describe("mint a new URIToken to the destination (e.g. a receipt)"),
    inform: z.string().optional().describe("third-party account to notify (weak TSH; its hook runs)"),
    blob: z.string().optional().describe("arbitrary hex payload"),
    invoiceId: z.string().optional().describe("64-hex InvoiceID"),
    destinationTag: z.number().optional(),
    network: NET.default("testnet"),
  },
}, async (a) => {
  try {
    const r = buildRemitUnsigned(a as any);
    const parts = [
      a.amounts?.length ? `${a.amounts.length} amount(s)` : null,
      a.uriTokenIds?.length ? `${a.uriTokenIds.length} URIToken(s)` : null,
      a.mintURIToken ? "mint URIToken" : null,
    ].filter(Boolean).join(" + ") || "no payload";
    return ok(`unsigned Remit (${parts}) → ${a.destination} (${r.network})`, r as any);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("build_set_remarks_unsigned", {
  description: "Assemble an UNSIGNED SetRemarks (Remarks amendment) — attach, update, or delete key-value remarks on a ledger object you own (or, for URITokens/trustlines, issue). Each remark: name (required), value (omit to DELETE), immutable (Flags:1 = permanent). Max 32 per object, names unique, 1–256 bytes each; cost +1 drop/byte. RemarkName/RemarkValue are hex (non-hex text is UTF-8 encoded). Powers dynamic NFTs and rich object annotations. Returns unsigned JSON + preflight. Never signs; testnet by default.",
  inputSchema: {
    account: z.string().min(25),
    objectId: z.string().describe("64-hex ledger object ID to annotate (AccountRoot, URIToken, Offer, Escrow, trustline, …)"),
    remarks: z.array(z.object({
      name: z.string().describe("RemarkName (hex or text)"),
      value: z.string().optional().describe("RemarkValue (hex or text); omit to DELETE this remark"),
      immutable: z.boolean().optional().describe("mark permanent (tfImmutable) — can never be changed/deleted"),
    })).min(1).max(32),
    network: NET.default("testnet"),
  },
}, async (a) => {
  try { const r = buildSetRemarksUnsigned(a as any); return ok(`unsigned SetRemarks (${a.remarks.length} remark(s)) on ${a.objectId.slice(0, 12)}… (${r.network})`, r as any); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("build_clawback_unsigned", {
  description: "Assemble an UNSIGNED Clawback — an issuer revokes previously-issued tokens from a holder (ported from XRPL). Account is the ISSUER; the holder is whom you claw from. NOTE: requires the issuer to have enabled clawback (AccountSet asfAllowTrustLineClawback) BEFORE issuing. Cannot claw native XAH. Returns unsigned JSON + preflight. Never signs; testnet by default.",
  inputSchema: {
    account: z.string().min(25).describe("the token issuer (you)"),
    holder: z.string().min(25).describe("the account to claw tokens back from"),
    currency: z.string().describe("3-char ISO code or 40-hex currency"),
    value: z.string().describe("amount to claw back (positive)"),
    network: NET.default("testnet"),
  },
}, async (a) => {
  try { const r = buildClawbackUnsigned(a as any); return ok(`unsigned Clawback ${a.value} ${a.currency} from ${a.holder} (${r.network})`, r as any); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("build_deepfreeze_unsigned", {
  description: "Assemble an UNSIGNED TrustSet that toggles a freeze on your trustline to a counterparty. action: deep_freeze (blocks holder sending AND receiving — needs DeepFreeze amendment), clear_deep_freeze, freeze (blocks sending only), unfreeze. Returns unsigned JSON + preflight. Never signs; testnet by default.",
  inputSchema: {
    account: z.string().min(25).describe("the issuer (you)"),
    counterparty: z.string().min(25).describe("the holder side of the trustline"),
    currency: z.string().describe("3-char ISO code or 40-hex currency (issued, not XAH)"),
    action: z.enum(["deep_freeze", "clear_deep_freeze", "freeze", "unfreeze"]).default("deep_freeze"),
    limitValue: z.string().optional().describe("your existing trust limit to preserve (defaults to \"0\")"),
    network: NET.default("testnet"),
  },
}, async (a) => {
  try { const r = buildDeepFreezeUnsigned(a as any); return ok(`unsigned TrustSet ${a.action ?? "deep_freeze"} ${a.currency} ↔ ${a.counterparty} (${r.network})`, r as any); }
  catch (e) { return fail((e as Error).message); }
});

server.registerTool("prepare_transaction", {
  description: "Autofill an unsigned transaction with live network values — Sequence (from the account), Fee (current base fee), LastLedgerSequence (now + offset), and NetworkID — so it's ready to sign OFFLINE. Read-only: fetches values, fills the tx, but NEVER signs or submits. Defaults to TESTNET — pass network:'mainnet' for a mainnet account (else you get a mainnet account's testnet Sequence/NetworkID or actNotFound).",
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
  outputSchema: FIDELITY_OUT,
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
      composition: rep.composition,
      coverageWarning: rep.coverageWarning,
      insufficient: rep.insufficient,
      perHook: rep.perHook,
      corpus: rep.corpus,
      headline: rep.headline,
    };
    if (includeMismatches) out.mismatches = rep.mismatches;
    return ok(rep.headline, out);
  } catch (e) { return fail((e as Error).message); }
});

server.registerTool("hook_execution_postmortem", {
  description: "POST-MORTEM a real Xahau transaction's hooks: fetch the tx (with meta.HookExecutions + engine result), then for EACH hook that fired, run its REAL bytecode through the local VM and compare the VM's accept/rollback DIRECTION to what the chain actually recorded. Answers 'why did these hooks accept/rollback, and would the VM agree?'. The on-chain decision is AUTHORITATIVE; the VM run is best-effort and always labeled fidelity=LOCAL_VM. `agree` is null (not false) when the VM run is degraded/halted/no-exit or the on-chain decision is indeterminate (e.g. no CreateCode available) — never scored as a match or miss. Read-only; never signs/submits. Serial rate-limited RPC: 1 `tx` call + 1 `ledger_entry` per UNIQUE HookHash (deduplicated), each >=1100ms apart; tolerates literal 'Rate limited' bodies via the shared client.",
  inputSchema: {
    txHash: z.string().length(64).describe("Xahau tx hash of the transaction to post-mortem"),
    network: NET,
  },
}, async ({ txHash, network }) => {
  try {
    const res = await hookExecutionPostmortem(txHash, network as Net, {
      fetchTx: (h, n) => rpc.getTx(h, n) as Promise<Record<string, unknown>>,
      fetchHookDefinition: async (hash, n) => {
        try {
          const r = await rpc.getLedgerEntry({ hook_definition: hash }, n);
          const code = (r.node as Record<string, unknown>)?.CreateCode;
          return typeof code === "string" ? code : null;
        } catch { return null; }
      },
    });
    return ok(res.summary, res as unknown as Record<string, unknown>);
  } catch (e) { return fail((e as Error).message, { txHash, network }); }
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
