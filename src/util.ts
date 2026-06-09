// Everyday encoding/validation helpers Xahau (and XRPL) developers reach for constantly.
// All offline, backed by xrpl-accountlib's address codec where relevant.
import pkg from "xrpl-accountlib";

const AC = (pkg as unknown as {
  libraries: {
    rippleAddressCodec: {
      isValidClassicAddress: (s: string) => boolean;
      isValidXAddress: (s: string) => boolean;
      decodeAccountID: (s: string) => Uint8Array;
      classicAddressToXAddress: (s: string, tag: number | false, test: boolean) => string;
      xAddressToClassicAddress: (s: string) => { classicAddress: string; tag: number | false; test: boolean };
    };
  };
}).libraries.rippleAddressCodec;

const RIPPLE_EPOCH = 946684800; // seconds between Unix epoch (1970) and Ripple epoch (2000-01-01)

export function validateAddress(address: string) {
  const a = address.trim();
  if (AC.isValidClassicAddress(a)) {
    const accountId = Buffer.from(AC.decodeAccountID(a)).toString("hex").toUpperCase();
    return { valid: true, type: "classic" as const, classicAddress: a, accountId, tag: null as number | null };
  }
  if (AC.isValidXAddress(a)) {
    const { classicAddress, tag, test } = AC.xAddressToClassicAddress(a);
    const accountId = Buffer.from(AC.decodeAccountID(classicAddress)).toString("hex").toUpperCase();
    return { valid: true, type: "x-address" as const, classicAddress, accountId, tag: tag === false ? null : tag, network: test ? "test" : "main" };
  }
  return { valid: false, type: "unknown" as const, reason: "not a valid classic r-address or X-address" };
}

export function xaddressEncode(classicAddress: string, tag: number | null, test = false) {
  if (!AC.isValidClassicAddress(classicAddress)) throw new Error("invalid classic address");
  return { xAddress: AC.classicAddressToXAddress(classicAddress, tag === null ? false : tag, test), classicAddress, tag, network: test ? "test" : "main" };
}

export function xaddressDecode(xAddress: string) {
  if (!AC.isValidXAddress(xAddress)) throw new Error("invalid X-address");
  const { classicAddress, tag, test } = AC.xAddressToClassicAddress(xAddress);
  return { classicAddress, tag: tag === false ? null : tag, network: test ? "test" : "main" };
}

/** 3-char ISO currency code <-> 160-bit (40-hex) currency. Non-standard codes pass through as hex. */
export function currencyCode(input: string) {
  const s = input.trim();
  if (/^[0-9a-fA-F]{40}$/.test(s)) {
    const bytes = Buffer.from(s, "hex");
    const std = bytes.subarray(0, 12).every((b) => b === 0) && bytes.subarray(15, 20).every((b) => b === 0);
    const ascii = bytes.subarray(12, 15);
    if (std && [...ascii].every((b) => (b >= 0x20 && b < 0x7f) || b === 0)) {
      return { hex: s.toUpperCase(), code: ascii.toString("ascii").replace(/\0+$/, ""), standard: true };
    }
    return { hex: s.toUpperCase(), code: null, standard: false, note: "non-standard / demurrage / 160-bit currency — no 3-char ASCII form" };
  }
  if (s.length >= 1 && s.length <= 3) {
    const ascii = Buffer.alloc(3);
    Buffer.from(s, "ascii").copy(ascii);
    const hex = Buffer.concat([Buffer.alloc(12), ascii, Buffer.alloc(5)]).toString("hex").toUpperCase();
    return { hex, code: s, standard: true };
  }
  throw new Error("provide a 3-char ISO code (e.g. USD) or a 40-hex currency");
}

/** Decode an amount: native drops (string), a serialized 8-byte native or 48-byte issued STAmount
 *  (hex), or an issued amount object {currency,issuer,value}. */
export function decodeAmount(input: string | { currency?: string; issuer?: string; value?: string }) {
  if (typeof input === "object") {
    const cur = input.currency ? currencyCode(input.currency).code ?? input.currency : undefined;
    return { type: "issued" as const, value: input.value ?? null, currency: cur ?? null, issuer: input.issuer ?? null };
  }
  const s = input.trim();
  if (/^\d+$/.test(s)) { const a = xahAmountLocal(s); return { type: "native" as const, drops: s, xah: a }; }
  const hex = s.replace(/^0x/i, "").toUpperCase();
  if (/^[0-9A-F]{16}$/.test(hex)) { // 8 bytes — native STAmount (top bits are flags, drops in low 62)
    const v = BigInt("0x" + hex) & ((1n << 62n) - 1n);
    return { type: "native" as const, drops: v.toString(), xah: xahAmountLocal(v.toString()) };
  }
  if (/^[0-9A-F]{96}$/.test(hex)) { // 48 bytes — issued: 8-byte XFL value + 20-byte currency + 20-byte issuer
    const b = Buffer.from(hex, "hex");
    const v = BigInt("0x" + hex.slice(0, 16));
    const sign = ((v >> 62n) & 1n) === 1n ? 1 : -1;
    const exp = Number((v >> 54n) & 0xffn) - 97;
    const mant = v & ((1n << 54n) - 1n);
    const value = mant === 0n ? "0" : `${sign < 0 ? "-" : ""}${mant.toString()}e${exp}`;
    const curHex = b.subarray(8, 28).toString("hex");
    const cur = currencyCode(curHex);
    const issuer = AC2.encodeAccountID(b.subarray(28, 48));
    return { type: "issued" as const, value, valueNote: "value = mantissa·10^exp (XFL-derived; verify for edge cases)", currency: cur.code ?? cur.hex, issuer };
  }
  throw new Error("provide drops (digits), an 8-byte/48-byte STAmount hex, or an {currency,issuer,value} object");
}

/** Plain-English summary + safety warnings for a transaction (what you'd be authorizing by signing). */
export function describeTx(tx: Record<string, any>): { summary: string; warnings: string[] } {
  const tt = tx.TransactionType as string | undefined;
  const acct = tx.Account as string | undefined;
  const warnings: string[] = [];
  let what = `a ${tt ?? "(unknown)"} transaction`;
  if (tt === "Payment") { const amt = tx.Amount; const a = typeof amt === "string" ? `${xahAmountLocal(amt)} XAH` : `${(amt as any)?.value} ${(amt as any)?.currency}`; what = `send ${a} to ${tx.Destination}`; }
  else if (tt === "SetHook") { what = "install / update / delete Hook(s) on the account"; warnings.push("⚠ installs on-ledger code that runs on your account's transactions — review the hook (analyze_hook / execute_hook) first"); }
  else if (tt === "TrustSet") { what = `set a trustline to ${(tx.LimitAmount as any)?.issuer} for ${(tx.LimitAmount as any)?.currency}`; }
  else if (tt === "AccountDelete") { what = `DELETE this account and send the remainder to ${tx.Destination}`; warnings.push("⚠ IRREVERSIBLE account deletion"); }
  else if (tt === "SetRegularKey") { what = tx.RegularKey ? `set the regular key to ${tx.RegularKey}` : "REMOVE the regular key"; warnings.push("⚠ changes who can sign for this account"); }
  else if (tt === "SignerListSet") { what = "change the multi-sign signer list"; warnings.push("⚠ changes who can sign for this account"); }
  else if (tt === "URITokenMint") { what = "mint a URIToken (NFT)"; }
  else if (tt === "Import") { what = "import (Burn2Mint) — mint XAH from a proven burn on another chain"; }
  if (tx.LastLedgerSequence === undefined) warnings.push("no LastLedgerSequence — the signed tx never expires (replay risk); run prepare_transaction");
  if (tx.TxnSignature || tx.SigningPubKey) warnings.push("this tx already carries a signature/pubkey — you are inspecting a SIGNED blob");
  return { summary: `You would be authorizing ${acct ? `${acct} to ` : ""}${what}.`, warnings };
}

function xahAmountLocal(drops: string): string {
  return (Number(BigInt(drops)) / 1_000_000).toString();
}
const AC2 = AC as unknown as { encodeAccountID: (b: Uint8Array) => string };

export function rippleTime(input: { ripple?: number; iso?: string; unix?: number }) {
  let rippleSecs: number;
  if (input.ripple !== undefined) rippleSecs = Math.floor(input.ripple);
  else if (input.unix !== undefined) rippleSecs = Math.floor(input.unix) - RIPPLE_EPOCH;
  else if (input.iso !== undefined) rippleSecs = Math.floor(Date.parse(input.iso) / 1000) - RIPPLE_EPOCH;
  else throw new Error("provide one of: ripple, unix, iso");
  const unix = rippleSecs + RIPPLE_EPOCH;
  return { rippleTime: rippleSecs, unix, iso: new Date(unix * 1000).toISOString() };
}
