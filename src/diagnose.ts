// diagnose_failed_tx — "why did my transaction fail?" answered in plain English, from ON-CHAIN
// facts (authoritative): the validated tx's engine result, its meta (HookExecutions return
// strings, delivered_amount), and a cause/fix catalog for the common Xahau failure codes.
// This tool DECODES what the chain recorded — it does not re-execute anything. For replaying a
// rejected hook's real bytecode locally, point the user at hook_execution_postmortem.
// Read-only; network access injected (explain.ts pattern) so unit tests run offline.
import { decodeResult } from "./defs.js";
import { describeTx } from "./util.js";

const RIPPLE_EPOCH = 946684800;

// Known hook hashes (live mainnet, verified in the fidelity corpus) — labels only, never asserted
// as exhaustive: an unknown hash is reported as "unrecognized hook".
const KNOWN_HOOKS: Record<string, string> = {
  "610F33B8EBF7EC795F822A454FB852156AEFE50BE0CB8326338A81CD74801864": "Xahau genesis reward hook (Balance Adjustments)",
  "1F7C84E14313C4FF2D4F39535428BF10767CCF8E87EFB51306CC3F94D13439EC": "Evernode heartbeat hook",
  "B352CB9916C8CA2A47A500EBBD93EBADDC933FB82347B2B95E87B70186D06127": "Evernode registry hook",
};

// Cause/fix catalog for common engine results. Names from data/error-codes.json (the live
// server_definitions). Anything not listed falls back to the result-class explanation.
const CAUSES: Record<string, { cause: string; fix: string }> = {
  tecHOOK_REJECTED: { cause: "a Hook on the sending or receiving account ran and called rollback() — the hook itself vetoed this transaction", fix: "read the hook's return string below (it usually says why); fix the condition it names, or replay it locally with hook_execution_postmortem / execute_hook to step through the logic" },
  tecNO_DST: { cause: "the destination account does not exist on this network", fix: "fund the destination with at least the base reserve (1 XAH) first, or double-check the address and the network (mainnet 21337 vs testnet 21338)" },
  tecNO_DST_INSUF_NATIVE: { cause: "the destination account does not exist and the payment is too small to create it", fix: "send at least the base reserve (1 XAH) so the payment can create the account" },
  tecUNFUNDED_PAYMENT: { cause: "the sender's spendable balance (after the reserve) is smaller than the amount", fix: "lower the amount or top the account up — the base+owner reserve is not spendable" },
  tecDST_TAG_NEEDED: { cause: "the destination requires a destination tag (lsfRequireDestTag) and the payment has none", fix: "add the DestinationTag the recipient gave you (exchanges almost always require one)" },
  tecNO_LINE: { cause: "the needed trustline does not exist", fix: "the receiver must first TrustSet a line to the issuer for that currency" },
  tecPATH_DRY: { cause: "no liquidity/path could deliver the issued currency (often: the destination has no trustline, or order books are empty)", fix: "have the destination open a trustline to the issuer, or check that a path/market exists for the pair" },
  tecPATH_PARTIAL: { cause: "the full amount could not be delivered through the available paths", fix: "reduce the amount, or send with tfPartialPayment IF a partial delivery is acceptable (never for invoices/exchanges)" },
  tecINSUFFICIENT_RESERVE: { cause: "the account's balance can't cover the reserve the new object would require", fix: "add XAH or delete unused objects (offers, trustlines) to free reserve" },
  tecINSUF_RESERVE_LINE: { cause: "not enough reserve to create the trustline", fix: "top up the account — each trustline locks owner reserve" },
  tecINSUF_RESERVE_OFFER: { cause: "not enough reserve to place the offer", fix: "top up the account — each offer locks owner reserve" },
  tecNO_PERMISSION: { cause: "the account is not allowed to do this (e.g. deposit-auth on the destination, or a hook/permission gate)", fix: "check the destination's flags (DepositAuth) and any hooks on it" },
  tecNO_ENTRY: { cause: "the ledger object the transaction references does not exist", fix: "verify the id/sequence you referenced (offer, check, URIToken, …) is still live" },
  tecEXPIRED: { cause: "the object (offer/check/lease) had already expired", fix: "re-create it with a later (or no) expiration" },
  tecKILLED: { cause: "the offer was killed unfilled (tfImmediateOrCancel/tfFillOrKill semantics)", fix: "expected behavior for IoC/FoK when the book can't fill it — adjust price or flags" },
  tecDUPLICATE: { cause: "an identical object already exists", fix: "you may have already submitted this — check before re-creating" },
  tecHAS_OBLIGATIONS: { cause: "the account still has obligations (trustlines/issued tokens/objects) blocking deletion", fix: "clear trustlines and owned objects before AccountDelete" },
  tecTOO_SOON: { cause: "the operation was attempted before its allowed time (e.g. AccountDelete needs Sequence + 256 ledgers)", fix: "wait and retry later" },
  tefPAST_SEQ: { cause: "the Sequence was already used — the transaction is a duplicate or arrived after a same-sequence tx", fix: "rebuild with the account's current Sequence (prepare_transaction autofills it)" },
  tefMAX_LEDGER: { cause: "the transaction's LastLedgerSequence passed before it was included — it can never be applied", fix: "rebuild + re-sign with a fresh LastLedgerSequence (prepare_transaction)" },
  temBAD_FEE: { cause: "the Fee field is malformed (negative/non-native)", fix: "set a plain drops string fee (prepare_transaction autofills from the live network)" },
  temBAD_SEQUENCE: { cause: "the Sequence field is malformed or out of range relative to the account", fix: "rebuild with the current account Sequence" },
  temREDUNDANT: { cause: "the transaction does nothing (e.g. pay yourself the same currency)", fix: "check Account/Destination — they likely shouldn't match" },
  temDISABLED: { cause: "the needed amendment/feature is not enabled on this network", fix: "confirm the feature exists on this network (xahau_server_info → amendments)" },
  temINVALID_FLAG: { cause: "a flag combination is invalid for this transaction type", fix: "check the Flags value against the tx-type docs (e.g. ClaimReward: Issuer XOR Flags=1)" },
  terQUEUED: { cause: "not a failure — the transaction is QUEUED for a later ledger (open-ledger fee was high)", fix: "wait a few ledgers; raise Fee for immediate inclusion next time" },
  terPRE_SEQ: { cause: "a lower Sequence hasn't been processed yet — this tx is waiting on an earlier one", fix: "make sure the earlier tx lands first (it may have failed to broadcast)" },
  telINSUF_FEE_P: { cause: "the Fee didn't meet the network's current (possibly escalated) minimum at submission", fix: "refetch the fee and resubmit (prepare_transaction reads the live fee)" },
  telCAN_NOT_QUEUE_FEE: { cause: "the node could not queue the tx at this fee", fix: "raise the Fee or wait for the open-ledger fee to drop" },
  telNO_DST_PARTIAL: { cause: "partial payment cannot create a new account", fix: "drop tfPartialPayment or fund the destination first" },
};

const CLASS_TEXT: Record<string, { meaning: string; applied: string }> = {
  tes: { meaning: "success", applied: "the transaction WAS applied" },
  tec: { meaning: "claimed-fee failure", applied: "the transaction was included in a ledger and the FEE WAS BURNED, but it had no other effect" },
  tef: { meaning: "failure", applied: "the transaction can never apply (it was not included); no fee was burned" },
  tem: { meaning: "malformed", applied: "the transaction is structurally invalid and was never relayed; no fee was burned" },
  ter: { meaning: "retry", applied: "not applied YET — it may still apply in a later ledger" },
  tel: { meaning: "local error", applied: "the submitting node rejected it locally; it was not relayed; safe to fix and resubmit" },
};

const TF_PARTIAL_PAYMENT = 0x00020000;

export interface DiagnoseDeps {
  /** raw `tx` RPC result (tx_json/meta/validated) or null when txnNotFound. */
  getTx: (hash: string) => Promise<Record<string, any> | null>;
}

export interface HookRejection {
  hookAccount: string | null;
  hookHash: string | null;
  hookLabel: string | null; // known-hook label or null
  returnCode: string | null;
  returnString: string | null; // decoded utf-8
  interpretation: string | null; // extra parse for known messages (e.g. reward wait -> claimable date)
}

export interface TxDiagnosis {
  txHash: string;
  network: string;
  found: boolean;
  validated: boolean | null;
  engineResult: string | null;
  engineResultCode: number | null;
  resultClass: string | null; // tes/tec/tef/tem/ter/tel
  failed: boolean | null; // null when not found
  summary: string;
  whatItTried: string | null; // describeTx of the tx itself
  causes: string[];
  fixes: string[];
  hookRejections: HookRejection[];
  partialDelivery: { deliveredAmount: unknown; requestedAmount: unknown } | null;
  notes: string[];
}

const hexToUtf8 = (h: string) => { try { return Buffer.from(h, "hex").toString("utf-8").replace(/\0+$/g, "").replace(/\0/g, " "); } catch { return null; } };

/** Parse known hook return strings into actionable interpretations. */
export function interpretHookMessage(msg: string, txDateRipple?: number): string | null {
  // genesis reward hook: "You must wait NNNNNNN seconds"
  const wait = msg.match(/You must wait (\d+) seconds/);
  if (wait) {
    const secs = Number(wait[1]);
    const when = typeof txDateRipple === "number" ? new Date((txDateRipple + secs + RIPPLE_EPOCH) * 1000).toISOString() : null;
    return `the reward delay had not elapsed — the claim was ${secs} seconds early${when ? `; it became claimable around ${when.slice(0, 16)}Z` : ""} (check live with reward_status)`;
  }
  if (/Rewards are disabled by governance/.test(msg)) return "network rewards are switched off by governance (RR or RD is zero) — no claim can succeed until governance re-enables them";
  if (/Passing non-claim txn|Passing outgoing txn|Transaction is not handled/.test(msg)) return "the hook deliberately let this transaction pass — it is not the cause of a failure";
  return null;
}

export async function diagnoseFailedTx(txHash: string, network: string, deps: DiagnoseDeps): Promise<TxDiagnosis> {
  const notes: string[] = [];
  const r = await deps.getTx(txHash);

  if (!r) {
    return {
      txHash, network, found: false, validated: null, engineResult: null, engineResultCode: null,
      resultClass: null, failed: null,
      summary: `Transaction ${txHash.slice(0, 12)}… was NOT FOUND on ${network}. Most likely: (1) it was never successfully submitted, (2) its LastLedgerSequence expired before inclusion and it was dropped (most common with slow/offline signing), or (3) it went to the OTHER network — Xahau mainnet is NetworkID 21337, testnet 21338, and XRPL is a different chain entirely.`,
      whatItTried: null,
      causes: ["not found on this network's validated ledgers"],
      fixes: [
        `re-run this diagnosis with network="${network === "mainnet" ? "testnet" : "mainnet"}" to rule out the wrong-network case`,
        "if it expired: rebuild with prepare_transaction (fresh Sequence/LastLedgerSequence) and resubmit",
        "check the sending account's Sequence (get_account_info) — if it advanced, something else consumed the sequence",
      ],
      hookRejections: [], partialDelivery: null, notes,
    };
  }

  const tx = (r.tx_json ?? r) as Record<string, any>;
  const meta = (r.meta ?? r.metaData ?? {}) as Record<string, any>;
  const validated = r.validated === true;
  const engineResult: string | null = typeof meta.TransactionResult === "string" ? meta.TransactionResult : null;
  const dec = engineResult ? decodeResult(engineResult) : { code: null };
  const resultClass = engineResult ? engineResult.slice(0, 3) : null;
  const cls = resultClass ? CLASS_TEXT[resultClass] : undefined;
  const tt = typeof tx.TransactionType === "string" ? tx.TransactionType : "(unknown type)";
  const what = tt === "Payment"
    ? describeTx(tx).summary.replace(/^You would be authorizing /, "").replace(/\.$/, "")
    : `a ${tt} from ${tx.Account ?? "?"}`;
  const txDate = typeof r.date === "number" ? r.date : typeof tx.date === "number" ? tx.date : undefined;

  if (!validated) notes.push("this transaction is NOT yet validated — the result below is provisional and can still change");

  // ---- hook rejections (on-chain return strings — authoritative) ----
  const hookRejections: HookRejection[] = [];
  const hes = Array.isArray(meta.HookExecutions) ? meta.HookExecutions : [];
  for (const w of hes) {
    const he = (w as any)?.HookExecution ?? w;
    if (!he) continue;
    const resNum = typeof he.HookResult === "string" ? Number(he.HookResult) : he.HookResult;
    if (resNum === 3) continue; // accept — not a rejection
    const msg = typeof he.HookReturnString === "string" ? hexToUtf8(he.HookReturnString) : null;
    hookRejections.push({
      hookAccount: he.HookAccount ?? null,
      hookHash: he.HookHash ?? null,
      hookLabel: he.HookHash ? KNOWN_HOOKS[he.HookHash] ?? null : null,
      returnCode: he.HookReturnCode !== undefined && he.HookReturnCode !== null ? String(he.HookReturnCode) : null,
      returnString: msg,
      interpretation: msg ? interpretHookMessage(msg, txDate) : null,
    });
  }

  // ---- success path (incl. the classic partial-payment trap) ----
  if (resultClass === "tes") {
    let partialDelivery: TxDiagnosis["partialDelivery"] = null;
    const delivered = meta.delivered_amount ?? meta.DeliveredAmount;
    const requested = tx.Amount;
    const isPartialFlag = typeof tx.Flags === "number" && (tx.Flags & TF_PARTIAL_PAYMENT) !== 0;
    const differs = delivered !== undefined && requested !== undefined && JSON.stringify(delivered) !== JSON.stringify(requested);
    if (tx.TransactionType === "Payment" && (isPartialFlag || differs) && delivered !== undefined) {
      partialDelivery = { deliveredAmount: delivered, requestedAmount: requested };
    }
    return {
      txHash, network, found: true, validated, engineResult, engineResultCode: dec.code ?? null,
      resultClass, failed: false,
      summary: partialDelivery
        ? `This transaction SUCCEEDED (${engineResult}) but it was a PARTIAL PAYMENT: it delivered ${JSON.stringify(partialDelivery.deliveredAmount)} of the requested ${JSON.stringify(partialDelivery.requestedAmount)}. Always credit delivered_amount, never the Amount field.`
        : `This transaction SUCCEEDED (${engineResult}) — there is no failure to diagnose. It did: ${what}.`,
      whatItTried: what,
      causes: partialDelivery ? ["tfPartialPayment delivered less than the requested Amount"] : [],
      fixes: partialDelivery ? ["credit/verify using meta.delivered_amount; if a fixed amount was required, re-send the shortfall WITHOUT tfPartialPayment"] : [],
      hookRejections, partialDelivery, notes,
    };
  }

  // ---- failure path ----
  const known = engineResult ? CAUSES[engineResult] : undefined;
  const causes: string[] = [];
  const fixes: string[] = [];
  if (known) { causes.push(known.cause); fixes.push(known.fix); }
  else if (engineResult && cls) { causes.push(`${engineResult} (${cls.meaning}) — see the result-class note`); fixes.push("decode_result gives the code; consult the tx-type docs for this specific result"); }
  if (cls) notes.push(`${resultClass}-class: ${cls.applied}`);

  for (const h of hookRejections) {
    const label = h.hookLabel ? ` (${h.hookLabel})` : "";
    causes.push(`hook ${h.hookHash?.slice(0, 12) ?? "?"}…${label} on ${h.hookAccount ?? "?"} rolled back${h.returnString ? `: "${h.returnString}"` : ""}`);
    if (h.interpretation) fixes.push(h.interpretation);
  }
  if (engineResult === "tecHOOK_REJECTED" && !hookRejections.some((h) => h.interpretation)) {
    fixes.push("replay the rejecting hook locally: hook_execution_postmortem (this txHash) shows the rollback path with the real bytecode");
  }

  const headCause = causes[0] ?? "unrecognized failure";
  return {
    txHash, network, found: true, validated, engineResult, engineResultCode: dec.code ?? null,
    resultClass, failed: true,
    summary: `This transaction FAILED with ${engineResult ?? "(no result)"}: ${headCause}. It tried to: ${what}. ${cls ? cls.applied + "." : ""}${fixes.length ? ` Fix: ${fixes[0]}` : ""}`,
    whatItTried: what,
    causes, fixes, hookRejections, partialDelivery: null, notes,
  };
}
