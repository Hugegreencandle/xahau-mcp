import { describe, it, expect } from "vitest";
import { validateAddress, xaddressEncode, xaddressDecode, currencyCode, rippleTime } from "../src/util.js";

const ACC = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

describe("address utilities", () => {
  it("validates a classic address + returns account id", () => {
    const v = validateAddress(ACC);
    expect(v.valid).toBe(true);
    expect(v.type).toBe("classic");
    expect((v as any).accountId).toMatch(/^[0-9A-F]{40}$/);
  });
  it("rejects garbage", () => {
    expect(validateAddress("not-an-address").valid).toBe(false);
  });
  it("X-address round-trips through encode/decode with the tag", () => {
    const x = xaddressEncode(ACC, 42).xAddress;
    expect(x.startsWith("X")).toBe(true);
    const d = xaddressDecode(x);
    expect(d.classicAddress).toBe(ACC);
    expect(d.tag).toBe(42);
    // validate_address also recognizes it
    const v = validateAddress(x);
    expect(v.type).toBe("x-address");
    expect((v as any).tag).toBe(42);
  });
});

describe("currency_code", () => {
  it("USD <-> 40-hex round-trips", () => {
    const hex = currencyCode("USD").hex;
    expect(hex).toBe("0000000000000000000000005553440000000000");
    const back = currencyCode(hex);
    expect(back.code).toBe("USD");
    expect(back.standard).toBe(true);
  });
  it("flags a non-standard 160-bit currency", () => {
    const c = currencyCode("01" + "23".repeat(19));
    expect(c.standard).toBe(false);
    expect(c.code).toBeNull();
  });
});

describe("ripple_time", () => {
  it("Ripple epoch (0) == 2000-01-01T00:00:00Z", () => {
    const t = rippleTime({ ripple: 0 });
    expect(t.unix).toBe(946684800);
    expect(t.iso).toBe("2000-01-01T00:00:00.000Z");
  });
  it("round-trips iso -> ripple -> iso", () => {
    const t = rippleTime({ iso: "2024-01-01T00:00:00.000Z" });
    expect(rippleTime({ ripple: t.rippleTime }).iso).toBe("2024-01-01T00:00:00.000Z");
  });
});
