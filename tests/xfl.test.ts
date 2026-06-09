import { describe, it, expect } from "vitest";
import * as xfl from "../src/xfl.js";

describe("XFL float", () => {
  it("float_one is the canonical constant", () => {
    expect(xfl.FLOAT_ONE).toBe(6089866696204910592n);
    expect(xfl.floatSet(0, 1n)).toBe(xfl.FLOAT_ONE);
  });

  it("round-trips integers via floatSet/floatInt", () => {
    for (const n of [1n, 2n, 10n, 1000000n, 999999999n]) {
      expect(xfl.floatInt(xfl.floatSet(0, n), 0, false)).toBe(n);
    }
  });

  it("multiply 2*5=10, sum 3+4=7, divide 10/4=2.5", () => {
    expect(xfl.floatInt(xfl.floatMultiply(xfl.floatSet(0, 2n), xfl.floatSet(0, 5n)), 0, false)).toBe(10n);
    expect(xfl.floatInt(xfl.floatSum(xfl.floatSet(0, 3n), xfl.floatSet(0, 4n)), 0, false)).toBe(7n);
    expect(xfl.floatInt(xfl.floatDivide(xfl.floatSet(0, 10n), xfl.floatSet(0, 4n)), 2, false)).toBe(250n);
  });

  it("handles fractional exponents: 1.5 + 1 = 2.5", () => {
    expect(xfl.floatInt(xfl.floatSum(xfl.floatSet(-2, 150n), xfl.floatSet(0, 1n)), 2, false)).toBe(250n);
  });

  it("compare flags match COMPARE_EQUAL=1 / LESS=2 / GREATER=4", () => {
    const two = xfl.floatSet(0, 2n), five = xfl.floatSet(0, 5n);
    expect(xfl.floatCmp(two, five)).toBe(-1);
    expect(xfl.floatCompare(two, five, 2)).toBe(1n); // LESS
    expect(xfl.floatCompare(five, two, 4)).toBe(1n); // GREATER
    expect(xfl.floatCompare(five, five, 1)).toBe(1n); // EQUAL
    expect(xfl.floatCompare(two, five, 4)).toBe(0n); // not greater
  });

  it("sign/negate and real error codes", () => {
    expect(xfl.floatSign(xfl.floatSet(0, -3n))).toBe(1n);
    expect(xfl.floatInt(xfl.floatNegate(xfl.floatSet(0, 9n)), 0, true)).toBe(9n);
    expect(xfl.floatDivide(xfl.floatSet(0, 1n), 0n)).toBe(-25n); // DIVISION_BY_ZERO
  });
});
