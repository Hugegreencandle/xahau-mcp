// Keylet derivation. A ledger object's index = SHA512-Half(spaceKey_uint16_BE || fields);
// a serialized keylet is [spaceKey_uint16_BE][32-byte index] (34 bytes).
//
// VERIFIED against the live mainnet ledger (computed index == real ledger object index):
//   ACCOUNT (space 0x61 'a')  and  HOOK (space 0x48 'H')  — both account-only.
// The sequence-based types below use the canonical rippled LedgerNameSpace chars + the standard
// (account, sequence) field order. They are NOT round-trip-verified in-repo, but they FAIL SAFE:
// a wrong derivation yields a non-existent index, so slot_set simply can't resolve it (the run is
// marked `degraded`) — it never produces a wrong, confident result.
import { createHash } from "node:crypto";

export const KEYLET_SPACE: Record<string, number> = {
  ACCOUNT: 0x61, HOOK: 0x48, OFFER: 0x6f, ESCROW: 0x75, CHECK: 0x43, TICKET: 0x54, SIGNERS: 0x53,
};
export const VERIFIED_SPACES = new Set([0x61, 0x48]); // round-trip-verified vs live ledger

export function keyletIndex(spaceKey: number, fields: Uint8Array): Uint8Array {
  const buf = new Uint8Array(2 + fields.length);
  buf[0] = (spaceKey >> 8) & 0xff;
  buf[1] = spaceKey & 0xff;
  buf.set(fields, 2);
  return Uint8Array.from(createHash("sha512").update(buf).digest().subarray(0, 32));
}

function serialize(spaceKey: number, fields: Uint8Array): Uint8Array {
  const idx = keyletIndex(spaceKey, fields);
  const out = new Uint8Array(34);
  out[0] = (spaceKey >> 8) & 0xff;
  out[1] = spaceKey & 0xff;
  out.set(idx, 2);
  return out;
}

const u32be = (n: number): Uint8Array => Uint8Array.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
const cat = (...a: Uint8Array[]): Uint8Array => { const t = a.reduce((n, x) => n + x.length, 0); const o = new Uint8Array(t); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

/** 34-byte serialized account keylet (VERIFIED). */
export function accountKeylet(accountId: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.ACCOUNT, accountId); }
/** 34-byte serialized hook keylet for the hook(s) on an account (VERIFIED, space 0x48). */
export function hookKeylet(accountId: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.HOOK, accountId); }
/** 34-byte serialized signer-list keylet (canonical; signerListID 0). */
export function signersKeylet(accountId: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.SIGNERS, cat(accountId, u32be(0))); }
/** account+sequence keylet (offer/escrow/check/ticket) — canonical namespace + (account, seq) order. */
export function accountSeqKeylet(space: number, accountId: Uint8Array, seq: number): Uint8Array {
  return serialize(space, cat(accountId, u32be(seq)));
}

/** Extract the 32-byte index (hex, upper) from a keylet that may be 34 bytes ([type][index]) or 32. */
export function keyletToIndexHex(keylet: Uint8Array): string | null {
  const slice = keylet.length >= 34 ? keylet.subarray(keylet.length - 32) : keylet.length === 32 ? keylet : null;
  if (!slice) return null;
  return Buffer.from(slice).toString("hex").toUpperCase();
}
