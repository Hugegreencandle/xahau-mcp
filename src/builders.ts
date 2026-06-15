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
