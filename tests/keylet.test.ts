import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pkg from "xrpl-accountlib";
import { accountKeylet, hookKeylet, offerKeylet, lineKeylet, keyletToIndexHex,
  amendmentsKeylet, feesKeylet, negativeUnlKeylet } from "../src/keylet.js";
import { runHook } from "../src/sandbox.js";
import { reconstructContext } from "../src/fidelity.js";

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

  // Singleton derivations vs canonical/known indexes (the anchor for the whole
  // indexHash(uint16 ns || fields) approach copied from xahaud Indexes.cpp).
  it("amendments == known on-ledger singleton index", () => {
    expect(keyletToIndexHex(amendmentsKeylet())).toBe(
      "7DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4");
  });
  it("fees + negativeUNL == canonical XRPL singleton indexes", () => {
    expect(keyletToIndexHex(feesKeylet())).toBe(
      "4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651");
    expect(keyletToIndexHex(negativeUnlKeylet())).toBe(
      "2E8A59AA9D3B5B186B0B9E0F62E6C02587CA74A4D778938E957B6357D364B244");
  });
});

// Integration lock: the rshooks 13_keylets example computes ALL 26 keylet types.
// Before full util_keylet coverage it rolled back (rc 102) with unsupportedCalls:["util_keylet"],
// degraded. Now it must run to a clean accept with nothing unsupported and no degradation.
describe("util_keylet full coverage — rshooks keylets example runs clean", () => {
  it("accepts with no unsupported calls and no degradation", () => {
    const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
    const wasm = Uint8Array.from(Buffer.from(readFileSync(join(DIR, "keylets.hex"), "utf8").trim(), "hex"));
    const acc = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
    const ctx = reconstructContext({ TransactionType: "Payment", Account: acc, Destination: acc, Amount: "1000000" }, acc);
    const r = runHook(wasm, ctx);
    expect(r.exit).toBe("accept");
    expect(r.returnCode).toBe("0");
    expect(r.unsupportedCalls).toEqual([]);
    expect(r.degraded).toBe(false);
  });
});
