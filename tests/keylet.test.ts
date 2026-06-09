import { describe, it, expect } from "vitest";
import pkg from "xrpl-accountlib";
import { accountKeylet, keyletToIndexHex } from "../src/keylet.js";

const accid = Uint8Array.from((pkg as any).libraries.rippleAddressCodec.decodeAccountID("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));

describe("keylet derivation", () => {
  it("account keylet index matches the live ledger index (verified vector)", () => {
    const kl = accountKeylet(accid);
    expect(kl.length).toBe(34);
    expect(kl[0]).toBe(0x00);
    expect(kl[1]).toBe(0x61); // 'a' = ltACCOUNT_ROOT
    expect(keyletToIndexHex(kl)).toBe("2B6AC232AA4C4BE41BF49D2459FA4A0347E1B543A4C92FCEE0821C0201E2E9A8");
  });

  it("keyletToIndexHex extracts from 34-byte and 32-byte keylets", () => {
    const idx = "AB".repeat(32);
    expect(keyletToIndexHex(Uint8Array.from(Buffer.from("0061" + idx, "hex")))).toBe(idx.toUpperCase());
    expect(keyletToIndexHex(Uint8Array.from(Buffer.from(idx, "hex")))).toBe(idx.toUpperCase());
    expect(keyletToIndexHex(new Uint8Array(10))).toBeNull();
  });
});
