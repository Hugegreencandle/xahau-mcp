// HookOn: a 256-bit bitmap selecting which transaction types a hook fires on.
// Semantics verified against http://xahau.network/docs/hooks/concepts/hookon-field/ :
//   - bit n corresponds to the transaction type whose numeric value is n.
//   - INVERTED / active-low: bit SET (1) => hook does NOT fire on that type; CLEAR (0) => fires.
//   - EXCEPTION: bit 22 (ttHOOK_SET / SetHook) is ACTIVE-HIGH: SET (1) => fires; CLEAR (0) => does not.
// Worked examples from the docs that this implementation satisfies:
//   "0x00..00" (all clear)            => fires on every type EXCEPT SetHook
//   ~(1<<22)  (all set except bit22)  => fires on nothing
//   ~(1<<22) & ~(1<<0)                => fires only on Payment (bit 0)
//   (1<<22)                           => fires on SetHook and all others
import { allTxTypes, txTypeValue, HOOKON } from "./defs.js";

const MASK256 = (1n << 256n) - 1n;
const SETHOOK_BIT = BigInt(HOOKON.SETHOOK_BIT ?? 22);

export function normalizeHookOnHex(hex: string): string {
  const clean = hex.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("HookOn must be a hex string");
  if (clean.length > 64) throw new Error("HookOn exceeds 256 bits (64 hex chars)");
  return clean.padStart(64, "0").toUpperCase();
}

function hexToBig(hex: string): bigint {
  return BigInt("0x" + normalizeHookOnHex(hex));
}
function bigToHex(v: bigint): string {
  return (v & MASK256).toString(16).toUpperCase().padStart(64, "0");
}
function bit(v: bigint, n: bigint): boolean {
  return ((v >> n) & 1n) === 1n;
}

/** Decode a HookOn hex into the set of transaction types the hook fires on. */
export function decodeHookOn(hex: string): { hookOn: string; firesOn: string[]; count: number } {
  const v = hexToBig(hex);
  const firesOn: string[] = [];
  for (const { name, value } of allTxTypes()) {
    const b = BigInt(value);
    const fires = b === SETHOOK_BIT ? bit(v, b) : !bit(v, b);
    if (fires) firesOn.push(name);
  }
  return { hookOn: normalizeHookOnHex(hex), firesOn, count: firesOn.length };
}

/** Encode a desired list of transaction types into a canonical HookOn hex. */
export function encodeHookOn(txTypes: string[]): { hookOn: string; firesOn: string[] } {
  const want = new Set<string>();
  for (const t of txTypes) {
    if (txTypeValue(t) === undefined) throw new Error(`Unknown transaction type: ${t}. Valid types: ${allTxTypes().map((x) => x.name).join(", ")}`);
    want.add(t);
  }
  // Start all-ones (everything active-low = disabled), then enable the desired types.
  let v = MASK256;
  for (const { name, value } of allTxTypes()) {
    const b = BigInt(value);
    if (b === SETHOOK_BIT) {
      if (want.has(name)) v |= 1n << b; // active-high: set to fire
      else v &= ~(1n << b); // clear to not fire
    } else if (want.has(name)) {
      v &= ~(1n << b); // active-low: clear to fire
    }
  }
  const hookOn = bigToHex(v);
  return { hookOn, firesOn: decodeHookOn(hookOn).firesOn };
}
