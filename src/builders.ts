// Unsigned transaction builders. These NEVER accept a secret/seed and NEVER sign or submit.
// They return an unsigned tx JSON + instructions to sign OFFLINE (xaman / xrpl-accountlib).
import { ENDPOINTS } from "./defs.js";
import { encodeHookOn } from "./hookon.js";
import { decodeCreateCode, runRules, type Finding, type HookGrant } from "./analyzer.js";
import { validateAddress, currencyCode } from "./util.js";
import type { Network } from "./rpc.js";

const SIGNING_INSTRUCTIONS =
  "This transaction is UNSIGNED. Sign it OFFLINE with your own key — e.g. via the xaman (Xumm) app, or xrpl-accountlib `sign()` in a secure local environment — then submit. NEVER paste a secret/seed into this tool or any prompt. Verify NetworkID, Account, Fee, Sequence and LastLedgerSequence before signing.";

function base(account: string, network: Network) {
  return { Account: account, NetworkID: ENDPOINTS[network].network_id };
}

export interface BuildResult {
  unsignedTx: Record<string, unknown>;
  network: Network;
  signingInstructions: string;
  preflightFindings?: Finding[];
  preflightSummary?: Record<string, number>;
  blocked?: boolean;
  warning?: string;
}

export function buildSetHookUnsigned(input: {
  account: string;
  createCodeHex?: string;
  wasmHex?: string;
  hookOn?: string;
  txTypes?: string[];
  namespace: string;
  parameters?: { name: string; value: string }[];
  grants?: { authorize?: string; hookHash?: string }[];
  flags?: number;
  network?: Network;
}): BuildResult {
  const network = input.network ?? "testnet";
  const createCode = input.createCodeHex ?? input.wasmHex;
  if (!createCode) throw new Error("provide createCodeHex (or wasmHex)");
  const hookOn = input.hookOn ?? (input.txTypes ? encodeHookOn(input.txTypes).hookOn : undefined);
  if (!hookOn) throw new Error("provide hookOn or txTypes");

  // preflight static analysis
  const wasm = decodeCreateCode({ wasmHex: createCode });
  const grants: HookGrant[] = (input.grants ?? []).map((g) => ({ HookGrant: { Authorize: g.authorize, HookHash: g.hookHash } }));
  const { findings, summary } = runRules(
    { wasm, hookOn, namespace: input.namespace, parameters: input.parameters, grants, flags: input.flags },
    { sethook: true },
  );
  const blocked = summary.CRITICAL > 0;

  const Hook: Record<string, unknown> = {
    CreateCode: createCode.replace(/^0x/i, "").toUpperCase(),
    HookOn: hookOn,
    HookNamespace: input.namespace.replace(/^0x/i, "").toUpperCase(),
    HookApiVersion: 0,
  };
  if (input.flags !== undefined) Hook.Flags = input.flags;
  if (input.parameters?.length)
    Hook.HookParameters = input.parameters.map((p) => ({ HookParameter: { HookParameterName: p.name, HookParameterValue: p.value } }));
  if (grants.length) Hook.HookGrants = grants;

  return {
    unsignedTx: { TransactionType: "SetHook", ...base(input.account, network), Hooks: [{ Hook }] },
    network,
    signingInstructions: SIGNING_INSTRUCTIONS,
    preflightFindings: findings,
    preflightSummary: summary,
    blocked,
    warning: blocked
      ? "PREFLIGHT FOUND CRITICAL ISSUES — do NOT install this hook until they are resolved. Review preflightFindings."
      : undefined,
  };
}

export function buildImportUnsigned(input: { account: string; xpopBlobHex: string; network?: Network }): BuildResult {
  const network = input.network ?? "testnet";
  const blob = input.xpopBlobHex.trim().replace(/^0x/i, "").toUpperCase();
  if (!/^[0-9A-F]+$/.test(blob) || blob.length % 2 !== 0) throw new Error("xpopBlobHex must be the HEX-encoded XPOP (even-length hex)");
  return {
    unsignedTx: { TransactionType: "Import", ...base(input.account, network), Blob: blob },
    network,
    signingInstructions: SIGNING_INSTRUCTIONS + " For Import (Burn2Mint), the XPOP proves a validated burn on the source chain; the destination account need not yet exist on Xahau.",
  };
}

export function buildClaimRewardUnsigned(input: { account: string; issuer?: string; network?: Network }): BuildResult {
  const network = input.network ?? "testnet";
  const tx: Record<string, unknown> = { TransactionType: "ClaimReward", ...base(input.account, network) };
  if (input.issuer) tx.Issuer = input.issuer;
  return { unsignedTx: tx, network, signingInstructions: SIGNING_INSTRUCTIONS };
}

export function buildPaymentUnsigned(input: { account: string; destination: string; amountDrops: string; destinationTag?: number; network?: Network }): BuildResult {
  const network = input.network ?? "testnet";
  const findings: Finding[] = [];
  const tx: Record<string, unknown> = {
    TransactionType: "Payment", ...base(input.account, network),
    Destination: input.destination, Amount: input.amountDrops,
  };
  if (input.destinationTag !== undefined) tx.DestinationTag = input.destinationTag;
  findings.push({ ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." });
  return { unsignedTx: tx, network, signingInstructions: SIGNING_INSTRUCTIONS, preflightFindings: findings };
}

// ---- Remit (XLS-55): atomic multi-asset push payment ----
// Field names/nesting are canonical: Amounts = [{ AmountEntry: { Amount } }], MintURIToken = { URI, Digest?, Flags? },
// URITokenIDs = Vector256 of 64-hex IDs, plus Inform/Blob/InvoiceID/DestinationTag. Verified against the XLS-55
// standard and the repo's xahaud-sourced definitions.json. The transactor auto-creates missing trustlines,
// pays token reserves, and creates the destination account if absent. Atomic: all-or-nothing, no partial, no pathing.
export type RemitAmount = string | { currency: string; issuer: string; value: string };

const HEX = (s: string) => s.trim().replace(/^0x/i, "").toUpperCase();
const isHexEven = (s: string) => /^[0-9A-F]*$/.test(s) && s.length % 2 === 0;

function normalizeRemitAmount(a: RemitAmount, idx: number): string | Record<string, string> {
  if (typeof a === "string") {
    const s = a.trim();
    if (!/^\d+$/.test(s)) throw new Error(`amounts[${idx}]: native amount must be an integer string of drops (got "${a}")`);
    return s;
  }
  if (!a || !a.currency) throw new Error(`amounts[${idx}]: issued amount needs a currency`);
  if (!validateAddress(a.issuer ?? "").valid) throw new Error(`amounts[${idx}]: issuer is not a valid r-address`);
  if (a.value === undefined || a.value === "" || Number.isNaN(Number(a.value))) throw new Error(`amounts[${idx}]: issued amount needs a numeric value`);
  const cc = currencyCode(a.currency); // throws on a bad code; canonicalizes 3-char ⇄ 40-hex
  return { currency: cc.standard && cc.code ? cc.code : cc.hex, issuer: a.issuer.trim(), value: String(a.value) };
}

export function buildRemitUnsigned(input: {
  account: string;
  destination: string;
  amounts?: RemitAmount[];
  uriTokenIds?: string[];
  mintURIToken?: { uri: string; digest?: string; flags?: number };
  inform?: string;
  blob?: string;
  invoiceId?: string;
  destinationTag?: number;
  network?: Network;
}): BuildResult {
  const network = input.network ?? "testnet";
  const findings: Finding[] = [];

  if (!validateAddress(input.account).valid) throw new Error("account is not a valid r-address / X-address");
  if (!validateAddress(input.destination).valid) throw new Error("destination is not a valid r-address / X-address");
  if (input.account.trim() === input.destination.trim()) throw new Error("destination must differ from account");

  const tx: Record<string, unknown> = {
    TransactionType: "Remit", ...base(input.account, network), Destination: input.destination.trim(),
  };

  if (input.amounts?.length) {
    tx.Amounts = input.amounts.map((a, i) => ({ AmountEntry: { Amount: normalizeRemitAmount(a, i) } }));
  }

  if (input.uriTokenIds?.length) {
    tx.URITokenIDs = input.uriTokenIds.map((id, i) => {
      const h = HEX(id);
      if (!/^[0-9A-F]{64}$/.test(h)) throw new Error(`uriTokenIds[${i}] must be a 64-char hex (256-bit) URIToken ID`);
      return h;
    });
  }

  if (input.mintURIToken) {
    const m = input.mintURIToken;
    const raw = (m.uri ?? "").trim();
    if (!raw) throw new Error("mintURIToken.uri is required when minting");
    const maybeHex = HEX(raw);
    let uriHex: string;
    if (maybeHex.length > 0 && isHexEven(maybeHex)) {
      uriHex = maybeHex;
    } else {
      uriHex = Buffer.from(raw, "utf8").toString("hex").toUpperCase();
      findings.push({ ruleId: "REMIT-URI-ENCODED", severity: "LOW", message: `mintURIToken.uri was not even-length hex; UTF-8 encoded to ${uriHex.length / 2} bytes. Pass hex directly to avoid ambiguity.` });
    }
    const mint: Record<string, unknown> = { URI: uriHex };
    if (m.digest !== undefined) {
      const d = HEX(m.digest);
      if (!/^[0-9A-F]{64}$/.test(d)) throw new Error("mintURIToken.digest must be a 64-char hex (256-bit) digest");
      mint.Digest = d;
    }
    if (m.flags !== undefined) mint.Flags = m.flags;
    tx.MintURIToken = mint;
  }

  if (input.inform !== undefined) {
    if (!validateAddress(input.inform).valid) throw new Error("inform is not a valid r-address");
    tx.Inform = input.inform.trim();
  }
  if (input.blob !== undefined) {
    const b = HEX(input.blob);
    if (!isHexEven(b)) throw new Error("blob must be even-length hex");
    tx.Blob = b;
  }
  if (input.invoiceId !== undefined) {
    const v = HEX(input.invoiceId);
    if (!/^[0-9A-F]{64}$/.test(v)) throw new Error("invoiceId must be a 64-char hex (256-bit) value");
    tx.InvoiceID = v;
  }
  if (input.destinationTag !== undefined) tx.DestinationTag = input.destinationTag;

  if (!input.amounts?.length && !input.uriTokenIds?.length && !input.mintURIToken) {
    findings.push({ ruleId: "REMIT-EMPTY", severity: "MEDIUM", message: "Remit has no Amounts, URITokenIDs or MintURIToken — it will only create/touch the destination account (and pay its reserve). Confirm this is intended." });
  }
  findings.push({ ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." });

  return {
    unsignedTx: tx,
    network,
    signingInstructions: SIGNING_INSTRUCTIONS + " Remit is ATOMIC: every listed Amount/URIToken delivers together or the whole transaction fails (no partial payments, no pathing). The sender auto-pays any missing trustline and token reserves, and creates the destination account if it doesn't exist.",
    preflightFindings: findings,
  };
}

// ---- shared blob helper: pass even-length hex through; otherwise UTF-8 encode ----
function textOrHexToBlob(s: string): { hex: string; encoded: boolean } {
  const h = HEX(s);
  if (h.length > 0 && /^[0-9A-F]+$/.test(h) && h.length % 2 === 0) return { hex: h, encoded: false };
  return { hex: Buffer.from(s, "utf8").toString("hex").toUpperCase(), encoded: true };
}

// ---- SetRemarks (Remarks amendment): attach/update/delete key-value remarks on a ledger object ----
// Canonical per Xahau-Docs setremarks.md: Remarks = [{ Remark: { RemarkName, RemarkValue?, Flags? } }].
// Omit RemarkValue to DELETE a remark. Flags:1 = tfImmutable (permanent). Max 32, names unique, 1–256 bytes.
// You must be the object's owner (or, for URITokens/trustlines, its issuer). Cost +1 drop per remark byte.
export function buildSetRemarksUnsigned(input: {
  account: string;
  objectId: string;
  remarks: { name: string; value?: string; immutable?: boolean }[];
  network?: Network;
}): BuildResult {
  const network = input.network ?? "testnet";
  if (!validateAddress(input.account).valid) throw new Error("account is not a valid r-address / X-address");
  const oid = HEX(input.objectId);
  if (!/^[0-9A-F]{64}$/.test(oid)) throw new Error("objectId must be a 64-char hex (256-bit) ledger object ID");
  if (!input.remarks?.length) throw new Error("provide at least one remark");
  if (input.remarks.length > 32) throw new Error("a maximum of 32 remarks per object");

  const findings: Finding[] = [];
  const seen = new Set<string>();
  const Remarks = input.remarks.map((r, i) => {
    if (!r.name) throw new Error(`remarks[${i}]: name is required`);
    const name = textOrHexToBlob(r.name);
    if (name.hex.length / 2 < 1 || name.hex.length / 2 > 256) throw new Error(`remarks[${i}]: RemarkName must be 1–256 bytes`);
    if (seen.has(name.hex)) throw new Error(`remarks[${i}]: duplicate RemarkName (must be unique per object)`);
    seen.add(name.hex);
    const Remark: Record<string, unknown> = { RemarkName: name.hex };
    if (r.value !== undefined && r.value !== "") {
      const val = textOrHexToBlob(r.value);
      if (val.hex.length / 2 < 1 || val.hex.length / 2 > 256) throw new Error(`remarks[${i}]: RemarkValue must be 1–256 bytes`);
      Remark.RemarkValue = val.hex;
    } else {
      findings.push({ ruleId: "REMARK-DELETE", severity: "MEDIUM", message: `remarks[${i}] "${r.name}" has no value → this DELETES that remark from the object.` });
    }
    if (r.immutable) {
      Remark.Flags = 1; // tfImmutable
      findings.push({ ruleId: "REMARK-IMMUTABLE", severity: "MEDIUM", message: `remarks[${i}] "${r.name}" is marked IMMUTABLE — it can never be changed or deleted afterwards.` });
    }
    return { Remark };
  });
  findings.push({ ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." });

  return {
    unsignedTx: { TransactionType: "SetRemarks", ...base(input.account, network), ObjectID: oid, Remarks },
    network,
    signingInstructions: SIGNING_INSTRUCTIONS + " SetRemarks: you must be the owner of ObjectID (or its issuer for URITokens/trustlines). Cost is +1 drop per byte of all RemarkName/RemarkValue. Immutable remarks (Flags:1) are permanent. RemarkName/RemarkValue are hex; non-hex text is UTF-8 encoded.",
    preflightFindings: findings,
  };
}

// ---- Clawback (ported from XRPL): an issuer revokes previously-issued tokens from a holder ----
// Canonical XRPL/Xahau shape: Account = the ISSUER; Amount.issuer = the HOLDER being clawed from
// (counter-intuitive but correct). Requires the issuer to have set asfAllowTrustLineClawback. Cannot claw native XAH.
export function buildClawbackUnsigned(input: {
  account: string;
  holder: string;
  currency: string;
  value: string;
  network?: Network;
}): BuildResult {
  const network = input.network ?? "testnet";
  if (!validateAddress(input.account).valid) throw new Error("account (issuer) is not a valid r-address / X-address");
  if (!validateAddress(input.holder).valid) throw new Error("holder is not a valid r-address / X-address");
  if (input.account.trim() === input.holder.trim()) throw new Error("holder must differ from the issuer account");
  if (input.value === undefined || Number.isNaN(Number(input.value)) || Number(input.value) <= 0) throw new Error("value must be a positive amount to claw back");
  const cc = currencyCode(input.currency);
  const code = cc.standard && cc.code ? cc.code : cc.hex;
  if (code === "XAH") throw new Error("cannot claw back native XAH — Clawback applies to issued tokens only");

  const Amount = { currency: code, issuer: input.holder.trim(), value: String(input.value) };
  const findings: Finding[] = [
    { ruleId: "CLAWBACK-ISSUER-IS-HOLDER", severity: "INFO", message: "Amount.issuer is the HOLDER being clawed from (not you). The transaction Account is the token issuer." },
    { ruleId: "CLAWBACK-REQUIRES-OPT-IN", severity: "MEDIUM", message: "Clawback only works if the issuer account previously enabled it (AccountSet asfAllowTrustLineClawback / lsfAllowTrustLineClawback). It cannot be enabled after tokens are issued without clawback set first." },
    { ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." },
  ];
  return {
    unsignedTx: { TransactionType: "Clawback", ...base(input.account, network), Amount },
    network,
    signingInstructions: SIGNING_INSTRUCTIONS + " Clawback: Account must be the token issuer with clawback enabled. Amount.issuer is the holder being clawed from.",
    preflightFindings: findings,
  };
}

// ---- DeepFreeze / Freeze: a TrustSet that toggles a freeze flag on the issuer's trustline to a holder ----
// DeepFreeze (ported from XRPL) blocks the holder from BOTH sending and receiving the token; a normal freeze
// only blocks sending. Implemented as TrustSet flags (tfSetDeepFreeze etc.) — there is no separate tx type.
const FREEZE_FLAGS: Record<string, number> = {
  freeze: 1048576,            // tfSetFreeze
  unfreeze: 2097152,          // tfClearFreeze
  deep_freeze: 4194304,       // tfSetDeepFreeze
  clear_deep_freeze: 8388608, // tfClearDeepFreeze
};
export function buildDeepFreezeUnsigned(input: {
  account: string;
  counterparty: string;
  currency: string;
  action?: "deep_freeze" | "clear_deep_freeze" | "freeze" | "unfreeze";
  limitValue?: string;
  network?: Network;
}): BuildResult {
  const network = input.network ?? "testnet";
  const action = input.action ?? "deep_freeze";
  const flag = FREEZE_FLAGS[action];
  if (flag === undefined) throw new Error(`action must be one of: ${Object.keys(FREEZE_FLAGS).join(", ")}`);
  if (!validateAddress(input.account).valid) throw new Error("account (issuer) is not a valid r-address / X-address");
  if (!validateAddress(input.counterparty).valid) throw new Error("counterparty (holder) is not a valid r-address / X-address");
  if (input.account.trim() === input.counterparty.trim()) throw new Error("counterparty must differ from the issuer account");
  const cc = currencyCode(input.currency);
  const code = cc.standard && cc.code ? cc.code : cc.hex;
  if (code === "XAH") throw new Error("native XAH has no trustline to freeze — use an issued currency");

  const LimitAmount = { currency: code, issuer: input.counterparty.trim(), value: input.limitValue ?? "0" };
  const findings: Finding[] = [];
  if (action === "deep_freeze") findings.push({ ruleId: "DEEPFREEZE-EFFECT", severity: "MEDIUM", message: "Deep freeze blocks the holder from BOTH sending and receiving this token (a normal freeze only blocks sending). The trustline must already exist." });
  findings.push({ ruleId: "TRUSTSET-LIMIT", severity: "INFO", message: 'LimitAmount.value defaults to "0"; set limitValue to your existing trust limit to this counterparty if you have one, so this TrustSet does not also change the limit.' });
  findings.push({ ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." });

  return {
    unsignedTx: { TransactionType: "TrustSet", ...base(input.account, network), LimitAmount, Flags: flag },
    network,
    signingInstructions: SIGNING_INSTRUCTIONS + " This TrustSet toggles a freeze flag on your trustline to the counterparty. Deep freeze (tfSetDeepFreeze) requires the DeepFreeze amendment to be enabled.",
    preflightFindings: findings,
  };
}
