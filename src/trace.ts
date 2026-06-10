// Hook Trace Annotator — turns the raw `trace[]` array from an execute_hook result
// ("label: HEXVALUE" lines, where the hex is a memory dump the hook passed to trace())
// into human-readable interpretations. FULLY OFFLINE. Honest-by-design: the raw hex is
// always the primary field, every interpretation carries a confidence, and ambiguous
// blobs (addresses, hashes) are never claimed 'definite'.
//
// Endianness note (important, and verified against the VM): the local Hook VM's trace()
// emits the bytes EXACTLY as they sit in WASM linear memory, which is little-endian for
// native integers. STO/network serialization is big-endian. So for integer-width blobs we
// surface BOTH readings when they differ and label which is which, rather than guessing one.
import pkg from "xrpl-accountlib";
import * as xfl from "./xfl.js";

const AC = (pkg as unknown as {
  libraries: { rippleAddressCodec: {
    encodeAccountID: (b: Uint8Array) => string;
    isValidClassicAddress: (s: string) => boolean;
  }; };
}).libraries.rippleAddressCodec;

const RIPPLE_EPOCH = 946684800;
type Confidence = "definite" | "possible" | "heuristic";
export interface Decoded { label: string; raw: string; interpretation: string; confidence: Confidence; }
export interface TraceAnnotation { annotated: string[]; decoded: Decoded[]; }

const isHex = (s: string) => s.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(s);
const beU = (hex: string): bigint => (hex ? BigInt("0x" + hex) : 0n);
const leU = (hex: string): bigint => { const b = Buffer.from(hex, "hex"); let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
const isRippleEpoch = (n: bigint) => n >= 400_000_000n && n <= 900_000_000n;
const iso = (rippleSecs: bigint) => new Date(Number(rippleSecs + BigInt(RIPPLE_EPOCH)) * 1000).toISOString();

/** True iff `v` is a canonical (normalized) XFL: not-a-number bit clear and mantissa in [1e15, 1e16). */
function isCanonicalXfl(v: bigint): boolean {
  if (v === 0n) return false; // 0 is ambiguous with a zero int; don't claim XFL
  if (((v >> 63n) & 1n) === 1n) return false; // not-a-number flag set
  const f = xfl.decode(v);
  return !f.zero && f.mant >= 1_000_000_000_000_000n && f.mant < 10_000_000_000_000_000n;
}

function xflToString(v: bigint): string {
  const f = xfl.decode(v);
  return `${f.sign < 0 ? "-" : ""}${f.mant}e${f.exp}`;
}

function annotateEntry(label: string, rawHex: string): Decoded {
  const hex = rawHex.trim().replace(/^0x/i, "").toUpperCase();
  const D = (interpretation: string, confidence: Confidence): Decoded => ({ label, raw: hex, interpretation, confidence });

  if (hex === "") return D("empty value", "heuristic");
  if (!isHex(hex)) return D("not valid hex — raw passed through", "heuristic");

  const nbytes = hex.length / 2;

  // 8 bytes: try XFL first (canonical form), else show both endian int64 readings + native-drops.
  if (nbytes === 8) {
    const be = beU(hex);
    if (isCanonicalXfl(be)) {
      return D(`XFL float ${xflToString(be)} (canonical 8-byte enbase-10)`, "definite");
    }
    const le = leU(hex);
    const drops = le; // WASM-memory native amounts are little-endian; drops -> XAH (1e6 drops)
    const frac = (drops % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
    const xah = `${drops / 1_000_000n}${frac ? "." + frac : ""}`;
    return D(
      `8-byte blob. as int64: ${be} (big-endian) / ${le} (little-endian, WASM-memory order). ` +
      `if native drops (LE): ${drops} drops = ${xah} XAH. not canonical XFL.`,
      "heuristic",
    );
  }

  // 4 bytes: UInt32 (both endian) + optional Ripple-epoch time reading.
  if (nbytes === 4) {
    const be = beU(hex);
    const le = leU(hex);
    let interp = `UInt32 ${be} (big-endian) / ${le} (little-endian)`;
    const times: string[] = [];
    if (isRippleEpoch(be)) times.push(`BE as Ripple time = ${iso(be)}`);
    if (isRippleEpoch(le)) times.push(`LE as Ripple time = ${iso(le)}`);
    if (times.length) interp += ` · ${times.join("; ")}`;
    return D(interp, times.length ? "possible" : "heuristic");
  }

  // 20 bytes: candidate account-id. 'possible' — an arbitrary 20-byte blob can encode to a
  // valid address by coincidence, so never 'definite'.
  if (nbytes === 20) {
    try {
      const addr = AC.encodeAccountID(Buffer.from(hex, "hex"));
      if (AC.isValidClassicAddress(addr)) {
        return D(`possible account-id → address ${addr}`, "possible");
      }
    } catch { /* fall through */ }
    return D("20-byte blob (account-id width, but not a valid address)", "heuristic");
  }

  // 32 bytes: tx hash / hook hash / ledger index width.
  if (nbytes === 32) {
    return D("possible tx hash or hook hash (32-byte blob)", "heuristic");
  }

  return D(`raw blob (${nbytes} byte${nbytes === 1 ? "" : "s"})`, "heuristic");
}

/** Annotate a trace[] array from execute_hook. Each entry is "label: HEXVALUE". Offline. */
export function annotateHookTrace(trace: string[]): TraceAnnotation {
  const decoded: Decoded[] = [];
  const annotated: string[] = [];
  for (const entry of trace) {
    const idx = entry.indexOf(":");
    if (idx === -1) {
      // no colon — pass through untouched, raw is the whole entry
      decoded.push({ label: entry, raw: "", interpretation: "no ':' separator — raw pass-through", confidence: "heuristic" });
      annotated.push(entry);
      continue;
    }
    const label = entry.slice(0, idx).trim();
    const rawHex = entry.slice(idx + 1);
    const d = annotateEntry(label, rawHex);
    decoded.push(d);
    annotated.push(`${label}: ${d.raw} → ${d.interpretation} [${d.confidence}]`);
  }
  return { annotated, decoded };
}
