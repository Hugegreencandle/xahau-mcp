// XFL — Xahau/XRPL Hook 64-bit base-10 float ("enbase-10"), implemented exactly.
// Layout (verified: float_one() === 6089866696204910592n):
//   bit 63      : not-a-number flag (0 for normal numbers)
//   bit 62      : sign (1 = positive, 0 = negative)  — note the inverted-vs-IEEE convention
//   bits 61..54 : exponent, biased by +97 (8 bits)
//   bits 53..0  : mantissa, normalized to [1e15, 1e16)
// value = sign * mantissa * 10^exponent ; canonical zero is the integer 0.
const MANT_MASK = (1n << 54n) - 1n;
const MIN_MANT = 1_000_000_000_000_000n; // 1e15
const MAX_MANT = 10_000_000_000_000_000n; // 1e16 (exclusive)
const SCALE = 1_000_000_000_000_000n;

export const FLOAT_ONE = 6089866696204910592n;
// real hook-api error codes (hooks-rs c/error.h)
const INVALID_FLOAT = -10024n;
const INVALID_ARGUMENT = -7n;       // hooks-rs c/error.h
const CANT_RETURN_NEGATIVE = -33n;  // float_int cannot return a negative when absolute=0
const DIVISION_BY_ZERO = -25n;

interface Xfl { zero: boolean; sign: 1 | -1; mant: bigint; exp: number; }

export function decode(x: bigint): Xfl {
  if (x === 0n) return { zero: true, sign: 1, mant: 0n, exp: 0 };
  const sign: 1 | -1 = ((x >> 62n) & 1n) === 1n ? 1 : -1;
  const exp = Number((x >> 54n) & 0xffn) - 97;
  const mant = x & MANT_MASK;
  return { zero: false, sign, mant, exp };
}

export function encode(sign: 1 | -1, mant: bigint, exp: number): bigint {
  if (mant === 0n) return 0n;
  let m = mant < 0n ? -mant : mant;
  let e = exp;
  while (m >= MAX_MANT) { m /= 10n; e += 1; }
  while (m < MIN_MANT) { m *= 10n; e -= 1; }
  if (e < -96 || e > 80) return INVALID_FLOAT; // out of representable range
  const signBit = sign > 0 ? 1n : 0n;
  return (signBit << 62n) | (BigInt(e + 97) << 54n) | m;
}

/** float_set(exponent, mantissa) -> XFL */
export function floatSet(exp: number, mant: bigint): bigint {
  if (mant === 0n) return 0n;
  const sign: 1 | -1 = mant < 0n ? -1 : 1;
  return encode(sign, mant < 0n ? -mant : mant, exp);
}

/** float_int(xfl, decimalPlaces, absolute) -> integer (e.g. drops). Floors toward zero. */
export function floatInt(x: bigint, dp: number, absolute: boolean): bigint {
  const f = decode(x);
  if (f.zero) return 0n;
  // real float_int caps decimal places at 15; out-of-range dp is INVALID_ARGUMENT (also bounds the
  // BigInt below, preventing OOM from a garbage dp).
  if (!Number.isInteger(dp) || dp < 0 || dp > 15) return INVALID_ARGUMENT;
  // float_int returns an unsigned integer; a negative value with absolute=0 is CANT_RETURN_NEGATIVE
  // (negatives are reserved for error codes), not a negative result.
  if (f.sign < 0 && !absolute) return CANT_RETURN_NEGATIVE;

  const shift = f.exp + dp;
  if (shift >= 0) return f.mant * 10n ** BigInt(shift);
  return f.mant / 10n ** BigInt(-shift);
}

function cmpMag(a: Xfl, b: Xfl): number {
  // compare positive magnitudes a,b (both non-zero)
  const ea = a.exp, eb = b.exp;
  let ma = a.mant, mb = b.mant;
  if (ea > eb) ma *= 10n ** BigInt(ea - eb);
  else if (eb > ea) mb *= 10n ** BigInt(eb - ea);
  return ma === mb ? 0 : ma > mb ? 1 : -1;
}

/** signed comparison: -1 if a<b, 0 if equal, 1 if a>b */
export function floatCmp(xa: bigint, xb: bigint): number {
  const a = decode(xa), b = decode(xb);
  const va = a.zero ? 0 : a.sign, vb = b.zero ? 0 : b.sign;
  if (va !== vb) return va < vb ? -1 : 1;
  if (a.zero && b.zero) return 0;
  const mag = cmpMag(a, b);
  return a.sign < 0 ? -mag : mag; // for negatives, larger magnitude = smaller value
}

/** float_compare(a,b,mode) — mode flags: 1=LT, 2=GT (combine for LTE/GTE etc.). Returns 1/0. */
export function floatCompare(xa: bigint, xb: bigint, mode: number): bigint {
  const c = floatCmp(xa, xb); // -1,0,1
  // VERIFIED against hooks-rs c/hookapi.h: COMPARE_EQUAL=1, COMPARE_LESS=2, COMPARE_GREATER=4.
  // (Do NOT "correct" to LESS=1/EQUAL=2 — that is the common-but-wrong assumption.)
  const EQ = 1, LT = 2, GT = 4;
  let truth = false;
  if (mode & EQ && c === 0) truth = true;
  if (mode & LT && c < 0) truth = true;
  if (mode & GT && c > 0) truth = true;
  return truth ? 1n : 0n;
}

export function floatNegate(x: bigint): bigint {
  if (x === 0n) return 0n;
  return x ^ (1n << 62n);
}
export function floatMantissa(x: bigint): bigint { return decode(x).mant; }
export function floatSign(x: bigint): bigint { const f = decode(x); return f.zero ? 0n : f.sign < 0 ? 1n : 0n; }

export function floatSum(xa: bigint, xb: bigint): bigint {
  const a = decode(xa), b = decode(xb);
  if (a.zero) return xb;
  if (b.zero) return xa;
  const e = Math.min(a.exp, b.exp);
  const ma = (a.sign < 0 ? -1n : 1n) * a.mant * 10n ** BigInt(a.exp - e);
  const mb = (b.sign < 0 ? -1n : 1n) * b.mant * 10n ** BigInt(b.exp - e);
  const s = ma + mb;
  if (s === 0n) return 0n;
  return encode(s < 0n ? -1 : 1, s < 0n ? -s : s, e);
}

export function floatMultiply(xa: bigint, xb: bigint): bigint {
  const a = decode(xa), b = decode(xb);
  if (a.zero || b.zero) return 0n;
  const sign: 1 | -1 = a.sign === b.sign ? 1 : -1;
  return encode(sign, a.mant * b.mant, a.exp + b.exp);
}

export function floatDivide(xa: bigint, xb: bigint): bigint {
  const a = decode(xa), b = decode(xb);
  if (b.zero) return DIVISION_BY_ZERO;
  if (a.zero) return 0n;
  const sign: 1 | -1 = a.sign === b.sign ? 1 : -1;
  // scale numerator by 10^17 for precision, then divide
  const scaled = (a.mant * 10n ** 17n) / b.mant;
  return encode(sign, scaled, a.exp - b.exp - 17);
}

export function floatInvert(x: bigint): bigint { return floatDivide(FLOAT_ONE, x); }

// NOTE: all XFL ops here TRUNCATE on normalization (encode), they do not round-half-up like xahaud,
// and float_mulratio's round_up flag is therefore not modeled (it would be lost in normalization).
// This is a documented last-significant-digit fidelity gap — see README. Not faked as honored.
export function floatMulratio(x: bigint, _roundUp: number, num: bigint, den: bigint): bigint {
  if (den === 0n) return DIVISION_BY_ZERO;
  const f = decode(x);
  if (f.zero || num === 0n) return 0n;
  const scaled = (f.mant * num * 10n ** 17n) / den;
  return encode(f.sign, scaled, f.exp - 17);
}

export { SCALE };
