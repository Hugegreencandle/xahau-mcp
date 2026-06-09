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

export function rippleTime(input: { ripple?: number; iso?: string; unix?: number }) {
  let rippleSecs: number;
  if (input.ripple !== undefined) rippleSecs = Math.floor(input.ripple);
  else if (input.unix !== undefined) rippleSecs = Math.floor(input.unix) - RIPPLE_EPOCH;
  else if (input.iso !== undefined) rippleSecs = Math.floor(Date.parse(input.iso) / 1000) - RIPPLE_EPOCH;
  else throw new Error("provide one of: ripple, unix, iso");
  const unix = rippleSecs + RIPPLE_EPOCH;
  return { rippleTime: rippleSecs, unix, iso: new Date(unix * 1000).toISOString() };
}
