import { describe, it, expect } from "vitest";
import pkg from "xrpl-accountlib";
import { accountKeylet, hookKeylet, offerKeylet, lineKeylet, keyletToIndexHex } from "../src/keylet.js";

const accid = Uint8Array.from((pkg as any).libraries.rippleAddressCodec.decodeAccountID("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));

describe("keylet derivation", () => {
  it("account keylet index matches the live ledger index (verified vector)", () => {
    const kl = accountKeylet(accid);
    expect(kl.length).toBe(34);
    expect(kl[0]).toBe(0x00);
    expect(kl[1]).toBe(0x61); // 'a' = ltACCOUNT_ROOT
    expect(keyletToIndexHex(kl)).toBe("2B6AC232AA4C4BE41BF49D2459FA4A0347E1B543A4C92FCEE0821C0201E2E9A8");
  });

  it("hook keylet index matches the live genesis Hook object index (verified vector)", () => {
    const kl = hookKeylet(accid);
    expect(kl.length).toBe(34);
    expect(kl[1]).toBe(0x48); // 'H'
    expect(keyletToIndexHex(kl)).toBe("469372BEE8814EC52CA2AECB5374AB57A47B53627E3C0E2ACBE3FDC78DBFEC7B");
  });

  it("offer keylet is deterministic (derivation live-verified vs a real mainnet offer)", () => {
    const k1 = offerKeylet(accid, 764558504);
    expect(k1.length).toBe(34);
    expect(k1[1]).toBe(0x6f);
    expect(keyletToIndexHex(offerKeylet(accid, 764558504))).toBe(keyletToIndexHex(k1)); // stable
  });

  it("line keylet sorts the two accounts (order-independent; live-verified)", () => {
    const a = Uint8Array.from(Array(20).fill(1));
    const b = Uint8Array.from(Array(20).fill(2));
    const cur = Uint8Array.from(Array(20).fill(0));
    expect(keyletToIndexHex(lineKeylet(a, b, cur))).toBe(keyletToIndexHex(lineKeylet(b, a, cur)));
    expect(lineKeylet(a, b, cur)[1]).toBe(0x72);
  });

  it("keyletToIndexHex extracts from 34-byte and 32-byte keylets", () => {
    const idx = "AB".repeat(32);
    expect(keyletToIndexHex(Uint8Array.from(Buffer.from("0061" + idx, "hex")))).toBe(idx.toUpperCase());
    expect(keyletToIndexHex(Uint8Array.from(Buffer.from(idx, "hex")))).toBe(idx.toUpperCase());
    expect(keyletToIndexHex(new Uint8Array(10))).toBeNull();
  });
});
