// Evernode lease-token (URIToken) URI decoder.
// VERIFIED against the canonical encoder (EvernodeXRPL/evernode-js-client src/clients/host-client.js
// offerLease) and against real on-chain lease URITokens: the minted URI is the BASE64 TEXT of a
// 60-byte buffer:
//   <"evrlease" 8B> <"LTV" 3B> <version u16BE> <leaseIndex u16BE> <halfTosHash 16B>
//   <leaseAmount int64BE — an XFL float> <identifier u32BE (host sequence at mint)>
//   <ipData 17B: family u8 (0=none, 6=IPv6) + 16B address>
// On-chain the URIToken.URI hex therefore decodes to ASCII base64, which decodes to this buffer.
// Lease amount uses Xahau's XFL (bit62 sign, bits61-54 exp bias-97, low-54 mantissa).

const PREFIX = "evrlease";
const VERSION_TAG = "LTV";

export interface LeaseDecoded {
  isEvernodeLease: boolean;
  reason?: string;
  version?: number;
  leaseIndex?: number;
  halfTosHashHex?: string;
  leaseAmountEvr?: string; // decimal string, decoded from the XFL
  leaseAmountXflBits?: string;
  identifier?: number; // host account sequence when the lease was minted
  outboundIp?: string | null;
  totalBytes?: number;
}

function xflToDecimal(bits: bigint): string {
  if (bits === 0n) return "0";
  const sign = ((bits >> 62n) & 1n) === 1n ? "" : "-"; // bit62 SET = positive in XFL
  const exp = Number((bits >> 54n) & 0xffn) - 97;
  const mant = (bits & ((1n << 54n) - 1n)).toString();
  if (exp >= 0) return `${sign}${mant}${"0".repeat(exp)}`;
  const shift = -exp;
  if (shift >= mant.length) {
    const frac = `${"0".repeat(shift - mant.length)}${mant}`.replace(/0+$/, "");
    return `${sign}0.${frac || "0"}`;
  }
  const whole = mant.slice(0, mant.length - shift);
  const frac = mant.slice(mant.length - shift).replace(/0+$/, "");
  return `${sign}${whole}${frac ? "." + frac : ""}`;
}

/** Accepts the on-chain URI hex, the base64 text, or the raw buffer hex. */
export function decodeLeaseUri(input: string): LeaseDecoded {
  const s = input.trim();
  let buf: Buffer | null = null;

  // base64("evrlease"+…) always begins with these 10 chars (the 11th varies with the next byte).
  const B64_PREFIX = "ZXZybGVhc2";
  // 1) on-chain form: hex of the ASCII base64 text
  if (/^[0-9A-Fa-f]+$/.test(s) && s.length % 2 === 0) {
    const ascii = Buffer.from(s, "hex").toString("utf-8");
    if (ascii.startsWith(B64_PREFIX)) buf = Buffer.from(ascii, "base64");
    else if (s.toLowerCase().startsWith("6576726c65617365")) buf = Buffer.from(s, "hex"); // raw buffer hex
  }
  // 2) base64 text directly
  if (!buf && s.startsWith(B64_PREFIX)) buf = Buffer.from(s, "base64");

  if (!buf) return { isEvernodeLease: false, reason: "not an Evernode lease URI (no evrlease prefix in hex/base64/raw form)" };
  if (buf.slice(0, 8).toString("utf-8") !== PREFIX) return { isEvernodeLease: false, reason: "evrlease prefix mismatch after decode" };
  if (buf.length < 43) return { isEvernodeLease: false, reason: `buffer too short (${buf.length} bytes; expected >=43)` };
  if (buf.slice(8, 11).toString("utf-8") !== VERSION_TAG) return { isEvernodeLease: false, reason: "missing LTV version tag (pre-versioned lease URIs not supported)" };

  const xfl = buf.readBigInt64BE(31);
  const family = buf.length >= 44 ? buf[43] : 0;
  let outboundIp: string | null = null;
  if (family === 6 && buf.length >= 60) {
    const ip = buf.slice(44, 60);
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) parts.push(ip.readUInt16BE(i).toString(16));
    outboundIp = parts.join(":");
  }

  return {
    isEvernodeLease: true,
    version: buf.readUInt16BE(11),
    leaseIndex: buf.readUInt16BE(13),
    halfTosHashHex: buf.slice(15, 31).toString("hex").toUpperCase(),
    leaseAmountEvr: xflToDecimal(xfl),
    leaseAmountXflBits: xfl.toString(),
    identifier: buf.readUInt32BE(39),
    outboundIp,
    totalBytes: buf.length,
  };
}
