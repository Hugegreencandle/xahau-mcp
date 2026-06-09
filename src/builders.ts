// Unsigned transaction builders. These NEVER accept a secret/seed and NEVER sign or submit.
// They return an unsigned tx JSON + instructions to sign OFFLINE (xaman / xrpl-accountlib).
import { ENDPOINTS } from "./defs.js";
import { encodeHookOn } from "./hookon.js";
import { decodeCreateCode, runRules, type Finding, type HookGrant } from "./analyzer.js";
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

export function buildPaymentUnsigned(input: { account: string; destination: string; amountXahDrops: string; destinationTag?: number; network?: Network }): BuildResult {
  const network = input.network ?? "testnet";
  const findings: Finding[] = [];
  const tx: Record<string, unknown> = {
    TransactionType: "Payment", ...base(input.account, network),
    Destination: input.destination, Amount: input.amountXahDrops,
  };
  if (input.destinationTag !== undefined) tx.DestinationTag = input.destinationTag;
  findings.push({ ruleId: "TX-001-NO-LASTLEDGERSEQ", severity: "LOW", message: "Add a LastLedgerSequence before signing so the tx cannot be replayed indefinitely." });
  return { unsignedTx: tx, network, signingInstructions: SIGNING_INSTRUCTIONS, preflightFindings: findings };
}
