// Keylet derivation. A ledger object's index = SHA512-Half(spaceKey_uint16_BE || fields);
// a serialized keylet is [spaceKey_uint16_BE][32-byte index] (34 bytes).
// VERIFIED: accountKeylet(genesis accountID) === the live ledger account_root index.
// Only ACCOUNT is round-trip-verified here; other space keys exist but their per-type argument
// layouts are not verified, so the VM reports them unsupported rather than guess.
import { createHash } from "node:crypto";

const SPACE = { ACCOUNT: 0x61 }; // ledger-entry-type 'a' = ltACCOUNT_ROOT (0x0061)

export function keyletIndex(spaceKey: number, fields: Uint8Array): Uint8Array {
  const buf = new Uint8Array(2 + fields.length);
  buf[0] = (spaceKey >> 8) & 0xff;
  buf[1] = spaceKey & 0xff;
  buf.set(fields, 2);
  return Uint8Array.from(createHash("sha512").update(buf).digest().subarray(0, 32));
}

/** 34-byte serialized account keylet for a 20-byte account id. */
export function accountKeylet(accountId: Uint8Array): Uint8Array {
  const idx = keyletIndex(SPACE.ACCOUNT, accountId);
  const out = new Uint8Array(34);
  out[1] = SPACE.ACCOUNT;
  out.set(idx, 2);
  return out;
}

/** Extract the 32-byte index (hex, upper) from a keylet that may be 34 bytes ([type][index]) or 32. */
export function keyletToIndexHex(keylet: Uint8Array): string | null {
  const slice = keylet.length >= 34 ? keylet.subarray(keylet.length - 32) : keylet.length === 32 ? keylet : null;
  if (!slice) return null;
  return Buffer.from(slice).toString("hex").toUpperCase();
}
