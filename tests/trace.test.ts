import { describe, it, expect } from "vitest";
import { annotateHookTrace } from "../src/trace.js";
import * as xfl from "../src/xfl.js";

// helper: build the canonical 8-byte hex for an XFL value
const xflHex = (v: bigint) => v.toString(16).toUpperCase().padStart(16, "0");

describe("annotate_hook_trace", () => {
  it("(1) 8-byte canonical XFL FLOAT_ONE → definite XFL 1.0", () => {
    // NOTE: FLOAT_ONE === 6089866696204910592n === 0x54838D7EA4C68000 (the spec's
    // claimed 0x5460000000000000 was inconsistent with that decimal; verified here).
    expect(xfl.FLOAT_ONE).toBe(6089866696204910592n);
    const hex = xflHex(xfl.FLOAT_ONE);
    expect(hex).toBe("54838D7EA4C68000");
    const { decoded } = annotateHookTrace([`amount: ${hex}`]);
    expect(decoded[0].confidence).toBe("definite");
    expect(decoded[0].interpretation).toContain("XFL float");
    // FLOAT_ONE decodes to mantissa 1e15 * 10^-15 = 1.0 → "1000000000000000e-15"
    expect(decoded[0].interpretation).toContain("1000000000000000e-15");
    expect(decoded[0].raw).toBe("54838D7EA4C68000");
  });

  it("(2) 8-byte native drops 40420F0000000000 (little-endian) → 1000000 drops / 1.0 XAH", () => {
    const { decoded } = annotateHookTrace(["amount: 40420F0000000000"]);
    expect(decoded[0].confidence).toBe("heuristic");
    expect(decoded[0].interpretation).toContain("1000000 drops");
    expect(decoded[0].interpretation).toContain("1 XAH");
    expect(decoded[0].raw).toBe("40420F0000000000");
  });

  it("(3) 20-byte known account-id → possible address rHb9...", () => {
    // rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh account-id (verified via xrpl-accountlib)
    const accid = "B5F762798A53D543A014CAF8B297CFF8F2F937E8";
    const { decoded } = annotateHookTrace([`acct: ${accid}`]);
    expect(decoded[0].confidence).toBe("possible");
    expect(decoded[0].interpretation).toContain("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");
    expect(decoded[0].raw).toBe(accid);
  });

  it("(4) 4-byte 0001E240 → UInt32 123456 (big-endian)", () => {
    const { decoded } = annotateHookTrace(["count: 0001E240"]);
    expect(decoded[0].interpretation).toContain("123456 (big-endian)");
    expect(decoded[0].raw).toBe("0001E240");
  });

  it("(5) 32-byte all-zeros → possible hash", () => {
    const { decoded } = annotateHookTrace([`h: ${"00".repeat(32)}`]);
    expect(decoded[0].confidence).toBe("heuristic");
    expect(decoded[0].interpretation).toContain("possible tx hash or hook hash");
  });

  it("(6) unknown length (3 bytes) → raw blob", () => {
    const { decoded } = annotateHookTrace(["x: ABCDEF"]);
    expect(decoded[0].interpretation).toContain("raw blob (3 bytes)");
    expect(decoded[0].raw).toBe("ABCDEF");
  });

  it("(7) empty trace[] → empty arrays", () => {
    const r = annotateHookTrace([]);
    expect(r.annotated).toEqual([]);
    expect(r.decoded).toEqual([]);
  });

  it("(8) entry with no colon → raw pass-through", () => {
    const r = annotateHookTrace(["just a message no separator"]);
    expect(r.annotated[0]).toBe("just a message no separator");
    expect(r.decoded[0].interpretation).toContain("no ':' separator");
    expect(r.decoded[0].confidence).toBe("heuristic");
  });

  it("(9) 4-byte Ripple-epoch value in valid range → ISO date, confidence possible", () => {
    // 700000000 = 0x29B92700 (big-endian), in [4e8, 9e8]
    const v = 700_000_000;
    const hex = v.toString(16).toUpperCase().padStart(8, "0");
    expect(hex).toBe("29B92700");
    const { decoded } = annotateHookTrace([`when: ${hex}`]);
    expect(decoded[0].confidence).toBe("possible");
    expect(decoded[0].interpretation).toContain("Ripple time");
    // 700000000 ripple secs => unix 1646684800 => 2022-03-07T20:26:40Z
    expect(decoded[0].interpretation).toContain("2022-03-07T20:26:40.000Z");
  });

  it("(10) leading 0x is stripped and uppercased in raw", () => {
    const { decoded } = annotateHookTrace(["c: 0x0001e240"]);
    expect(decoded[0].raw).toBe("0001E240");
    expect(decoded[0].interpretation).toContain("123456");
  });

  it("(11) non-hex value → heuristic, raw preserved, not crashed", () => {
    const { decoded } = annotateHookTrace(["note: HELLOWORLD!!"]);
    expect(decoded[0].confidence).toBe("heuristic");
    expect(decoded[0].interpretation).toContain("not valid hex");
  });

  it("(12) empty hex value after colon → empty value", () => {
    const { decoded } = annotateHookTrace(["flag: "]);
    expect(decoded[0].interpretation).toContain("empty value");
    expect(decoded[0].raw).toBe("");
  });

  it("(13) 8-byte non-XFL, non-canonical → both endian int64 readings, heuristic", () => {
    const { decoded } = annotateHookTrace(["blob: 0102030405060708"]);
    expect(decoded[0].confidence).toBe("heuristic");
    expect(decoded[0].interpretation).toContain("big-endian");
    expect(decoded[0].interpretation).toContain("little-endian");
  });

  it("(14) 20-byte all-zeros encodes to the valid rrrr... address → possible", () => {
    const { decoded } = annotateHookTrace([`a: ${"00".repeat(20)}`]);
    // ACCOUNT_ZERO encodes to a valid classic address, so this is 'possible'
    expect(decoded[0].confidence).toBe("possible");
    expect(decoded[0].interpretation).toContain("→ address");
  });

  it("(15) annotated[] mirrors decoded[] with label/raw/interp/confidence formatting", () => {
    const { annotated, decoded } = annotateHookTrace(["count: 0001E240"]);
    expect(annotated.length).toBe(decoded.length);
    expect(annotated[0]).toContain("count:");
    expect(annotated[0]).toContain("0001E240");
    expect(annotated[0]).toContain("[heuristic]");
  });
});
