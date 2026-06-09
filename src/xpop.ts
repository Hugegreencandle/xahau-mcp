// Decode an XPOP (Xahau Proof of Payment) — the proof blob inside an Import (Burn2Mint) transaction.
//
// VERIFIED against xahaud's canonical source (src/test/app/Import_test.cpp): the on-chain Import
// `Blob` is the XPOP **JSON object serialized to a string, then hex-encoded** — `syntaxCheckXPOP`
// parses `Blob raw(strJson.begin(), strJson.end())` as JSON. So: hex -> utf8 -> JSON.parse.
// Top-level shape: { ledger:{acroot,txroot,phash,close,coins,cres,flags,pclose,index},
//                    transaction:{blob,meta,proof}, validation:{data,unl} }.
import { decodeTxBlob } from "./codec.js";

function fromHex(hex: string): Buffer {
  const h = hex.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(h) || h.length % 2) throw new Error("not valid hex");
  return Buffer.from(h, "hex");
}

export interface XpopDecoded {
  ledger: Record<string, unknown> | null;
  ledgerIndex: number | null;
  innerTransaction: Record<string, unknown> | null; // the burned transaction, decoded
  innerTransactionType: string | null;
  burnedDrops: string | null; // the burn tx's Fee = the amount burned (to be minted on Xahau)
  targetNetworkId: number | null; // inner tx OperationLimit = the network the burn is destined for
  metaPresent: boolean;
  proofPresent: boolean;
  validators: { count: number; unlSequence: number | null; publicKeys: string[] } | null;
  warnings: string[];
  summary: string;
}

export function decodeXpop(input: string | Record<string, unknown>): XpopDecoded {
  const warnings: string[] = [];
  let xpop: Record<string, any>;
  if (typeof input === "object") {
    xpop = input as Record<string, any>;
  } else {
    const s = input.trim();
    if (s.startsWith("{")) {
      xpop = JSON.parse(s);
    } else {
      // hex of the JSON string (the on-chain Import.Blob form)
      const bytes = fromHex(s);
      xpop = JSON.parse(Buffer.from(bytes).toString("utf-8"));
    }
  }

  const ledger = (xpop.ledger as Record<string, unknown>) ?? null;
  if (!ledger) warnings.push("missing `ledger` section");
  const ledgerIndex = ledger && ledger.index !== undefined ? Number(ledger.index) : null;

  const txSec = xpop.transaction as Record<string, any> | undefined;
  let innerTransaction: Record<string, unknown> | null = null;
  let innerTransactionType: string | null = null;
  let burnedDrops: string | null = null;
  let targetNetworkId: number | null = null;
  if (!txSec) warnings.push("missing `transaction` section");
  else if (typeof txSec.blob === "string") {
    try {
      innerTransaction = decodeTxBlob(txSec.blob) as Record<string, unknown>;
      innerTransactionType = (innerTransaction.TransactionType as string) ?? null;
      burnedDrops = (innerTransaction.Fee as string) ?? null; // B2M: the burned amount is the tx Fee
      targetNetworkId = innerTransaction.OperationLimit !== undefined ? Number(innerTransaction.OperationLimit) : null;
    } catch (e) {
      warnings.push(`could not decode transaction.blob: ${(e as Error).message}`);
    }
  } else warnings.push("transaction.blob missing or not a hex string");

  const metaPresent = typeof txSec?.meta === "string" && txSec.meta.length > 0;
  const proofPresent = txSec?.proof !== undefined && txSec.proof !== null;

  // validation.unl carries the validator list (unl.blob is base64 JSON: { sequence, validators:[{validation_public_key,...}] })
  let validators: XpopDecoded["validators"] = null;
  const unl = (xpop.validation as Record<string, any> | undefined)?.unl;
  if (unl && typeof unl.blob === "string") {
    try {
      const decoded = JSON.parse(Buffer.from(unl.blob, "base64").toString("utf-8"));
      const list = Array.isArray(decoded.validators) ? decoded.validators : [];
      validators = {
        count: list.length,
        unlSequence: typeof decoded.sequence === "number" ? decoded.sequence : null,
        publicKeys: list.map((v: any) => v.validation_public_key).filter(Boolean),
      };
    } catch (e) {
      warnings.push(`could not decode validation.unl.blob (base64 JSON): ${(e as Error).message}`);
    }
  } else if (!xpop.validation) warnings.push("missing `validation` section");

  const summary =
    innerTransactionType
      ? `XPOP for a Burn2Mint: burns ${burnedDrops ?? "?"} drops via a ${innerTransactionType} on the source chain` +
        `${targetNetworkId !== null ? ` (target network ${targetNetworkId})` : ""}` +
        `${ledgerIndex !== null ? `, source ledger ${ledgerIndex}` : ""}` +
        `${validators ? `, ${validators.count} UNL validator(s)` : ""}.`
      : "XPOP decoded but the inner burn transaction could not be read.";

  return { ledger, ledgerIndex, innerTransaction, innerTransactionType, burnedDrops, targetNetworkId, metaPresent, proofPresent, validators, warnings, summary };
}
