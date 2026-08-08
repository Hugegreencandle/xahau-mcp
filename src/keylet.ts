// Keylet derivation. A ledger object's index = SHA512-Half(spaceKey_uint16_BE || fields);
// a serialized keylet is [spaceKey_uint16_BE][32-byte index] (34 bytes).
//
// VERIFIED against the live mainnet ledger (computed index == real ledger object index):
//   ACCOUNT (0x61 'a'), HOOK (0x48 'H'), OFFER (0x6F 'o', account+u32 seq),
//   LINE/RippleState (0x72 'r', sorted lowAccID+highAccID+currency160).
// The other sequence-based types (escrow/check/ticket) use the canonical rippled LedgerNameSpace
// chars + (account, sequence) order; not round-trip-verified in-repo, but they FAIL SAFE — a wrong
// derivation yields a non-existent index, so slot_set just can't resolve it (run marked `degraded`).
import { createHash } from "node:crypto";

// Namespace chars are xahaud LedgerNameSpace (include/xrpl/protocol/Indexes.h). The derivations
// below (indexHash = SHA512-Half(uint16_BE(ns) || fields)) are copied 1:1 from xahaud
// src/libxrpl/protocol/Indexes.cpp `keylet::*`. The AMENDMENTS singleton derivation is VERIFIED:
// keyletIndex(0x66) == the known on-ledger Amendments index (see keylet.test / amendments.ts).
export const KEYLET_SPACE: Record<string, number> = {
  ACCOUNT: 0x61, HOOK: 0x48, OFFER: 0x6f, LINE: 0x72, ESCROW: 0x75, CHECK: 0x43, TICKET: 0x54, SIGNERS: 0x53,
  // added 2026-08-08 from xahaud Indexes.cpp:
  OWNER_DIR: 0x4f, DIR_NODE: 0x64, HOOK_STATE: 0x76, HOOK_STATE_DIR: 0x4a, HOOK_DEFINITION: 0x44,
  EMITTED_TXN: 0x45, EMITTED_DIR: 0x46, NFTOKEN_OFFER: 0x71, PAYCHAN: 0x78, DEPOSIT_PREAUTH: 0x70,
  AMENDMENTS: 0x66, FEE_SETTINGS: 0x65, NEGATIVE_UNL: 0x4e, SKIP_LIST: 0x73, CRON: 0x4c,
};
// round-trip-verified vs live ledger (index == real object). AMENDMENTS added (verified vs the known singleton index).
export const VERIFIED_SPACES = new Set([0x61, 0x48, 0x6f, 0x72, 0x66]);

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
/** account+sequence keylet (offer/escrow/check/ticket) — (account, seq) order. OFFER is VERIFIED. */
export function accountSeqKeylet(space: number, accountId: Uint8Array, seq: number): Uint8Array {
  return serialize(space, cat(accountId, u32be(seq)));
}
/** offer keylet (VERIFIED): SHA512-Half(0x006F || owner || u32be(sequence)). */
export function offerKeylet(owner: Uint8Array, seq: number): Uint8Array { return accountSeqKeylet(KEYLET_SPACE.OFFER, owner, seq); }
/** trustline (RippleState) keylet (VERIFIED): low+high accounts sorted, then the 160-bit currency. */
export function lineKeylet(a: Uint8Array, b: Uint8Array, currency160: Uint8Array): Uint8Array {
  const [lo, hi] = Buffer.compare(Buffer.from(a), Buffer.from(b)) <= 0 ? [a, b] : [b, a];
  return serialize(KEYLET_SPACE.LINE, cat(lo, hi, currency160));
}

const u64be = (n: bigint): Uint8Array => { const o = new Uint8Array(8); for (let i = 7; i >= 0; i--) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
/** 34-byte keylet whose index IS the given 32-byte key (no hashing): child / unchecked / page(index=0). */
function rawKeylet(key: Uint8Array): Uint8Array { const o = new Uint8Array(34); o.set(key.subarray(0, 32), 2); return o; }

// ── added 2026-08-08, 1:1 from xahaud src/libxrpl/protocol/Indexes.cpp keylet::* ──
/** ownerDir(id) = indexHash(OWNER_DIR, account). */
export function ownerDirKeylet(id: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.OWNER_DIR, id); }
/** hookStateDir(id, ns) = indexHash(HOOK_STATE_DIR, account, ns). */
export function hookStateDirKeylet(id: Uint8Array, ns: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.HOOK_STATE_DIR, cat(id, ns)); }
/** hookState(id, key, ns) = indexHash(HOOK_STATE, account, key, ns). */
export function hookStateKeylet(id: Uint8Array, key: Uint8Array, ns: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.HOOK_STATE, cat(id, key, ns)); }
/** hookDefinition(hash) = indexHash(HOOK_DEFINITION, hash). */
export function hookDefinitionKeylet(hash: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.HOOK_DEFINITION, hash); }
/** emittedTxn(id) = indexHash(EMITTED_TXN, id). */
export function emittedTxnKeylet(id: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.EMITTED_TXN, id); }
/** depositPreauth(owner, preauthorized) = indexHash(DEPOSIT_PREAUTH, owner, preauthorized). */
export function depositPreauthKeylet(owner: Uint8Array, preauth: Uint8Array): Uint8Array { return serialize(KEYLET_SPACE.DEPOSIT_PREAUTH, cat(owner, preauth)); }
/** payChan(src, dst, seq) = indexHash(PAYMENT_CHANNEL, src, dst, u32be(seq)). */
export function paychanKeylet(src: Uint8Array, dst: Uint8Array, seq: number): Uint8Array { return serialize(KEYLET_SPACE.PAYCHAN, cat(src, dst, u32be(seq))); }
/** nftoffer(owner, seq) = indexHash(NFTOKEN_OFFER, owner, u32be(seq)). */
export function nftofferKeylet(owner: Uint8Array, seq: number): Uint8Array { return serialize(KEYLET_SPACE.NFTOKEN_OFFER, cat(owner, u32be(seq))); }
/** page(rootIndex, pageNo): pageNo==0 -> the root index itself; else indexHash(DIR_NODE, root, u64be(pageNo)). */
export function pageKeylet(root: Uint8Array, pageNo: bigint): Uint8Array { return pageNo === 0n ? rawKeylet(root) : serialize(KEYLET_SPACE.DIR_NODE, cat(root, u64be(pageNo))); }
/** child(key) / unchecked(key): the index IS the given 32-byte key. */
export function uncheckedKeylet(key: Uint8Array): Uint8Array { return rawKeylet(key); }
/** singletons: indexHash(NS) with no fields. amendments VERIFIED vs the known on-ledger index. */
export function amendmentsKeylet(): Uint8Array { return serialize(KEYLET_SPACE.AMENDMENTS, new Uint8Array(0)); }
export function feesKeylet(): Uint8Array { return serialize(KEYLET_SPACE.FEE_SETTINGS, new Uint8Array(0)); }
export function negativeUnlKeylet(): Uint8Array { return serialize(KEYLET_SPACE.NEGATIVE_UNL, new Uint8Array(0)); }
export function skipKeylet(): Uint8Array { return serialize(KEYLET_SPACE.SKIP_LIST, new Uint8Array(0)); }
export function emittedDirKeylet(): Uint8Array { return serialize(KEYLET_SPACE.EMITTED_DIR, new Uint8Array(0)); }
/** quality(dirIndex, q): the dir index with its LAST 8 bytes replaced by q (big-endian). xahaud keylet::quality. */
export function qualityKeylet(dirIndex: Uint8Array, q: bigint): Uint8Array {
  const idx = Uint8Array.from(dirIndex.subarray(0, 32)); idx.set(u64be(q), 24); return rawKeylet(idx);
}
/** cron(timestamp, id): index = ns[0:8] || u32be(ts) || (id ? indexHash(CRON, u32be(ts), id)[0:20] : zeros). xahaud keylet::cron. */
export function cronKeylet(timestamp: number, id: Uint8Array | null): Uint8Array {
  const ns = keyletIndex(KEYLET_SPACE.CRON, new Uint8Array(0)); // indexHash(CRON), 32B; first 8 used
  const h = new Uint8Array(32); h.set(ns.subarray(0, 8), 0); h.set(u32be(timestamp), 8);
  if (id) { const acc = keyletIndex(KEYLET_SPACE.CRON, cat(u32be(timestamp), id.subarray(0, 20))); h.set(acc.subarray(0, 20), 12); }
  return rawKeylet(h);
}

/** Extract the 32-byte index (hex, upper) from a keylet that may be 34 bytes ([type][index]) or 32. */
export function keyletToIndexHex(keylet: Uint8Array): string | null {
  const slice = keylet.length >= 34 ? keylet.subarray(keylet.length - 32) : keylet.length === 32 ? keylet : null;
  if (!slice) return null;
  return Buffer.from(slice).toString("hex").toUpperCase();
}
