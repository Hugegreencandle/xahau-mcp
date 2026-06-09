import { describe, it, expect } from "vitest";
import { stoFieldRange } from "../src/sto.js";
import { encodeTxBlob } from "../src/codec.js";

const hexToBytes = (h: string) => new Uint8Array(Buffer.from(h, "hex"));

// sfield codes: (typeCode << 16) | fieldCode
const sfAmount = (6 << 16) | 1; // Amount, field 1
const sfAccount = (8 << 16) | 1; // AccountID, field 1
const sfTransactionType = (1 << 16) | 2; // UInt16, field 2

describe("STObject field walker", () => {
  const tx = { TransactionType: "Payment", Account: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", Destination: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", Amount: "1000000", Fee: "12", Sequence: 1 };
  const blob = hexToBytes(encodeTxBlob(tx).txBlobHex);

  it("locates the Amount field as exactly 8 bytes (native XAH) = 1,000,000 drops", () => {
    const r = stoFieldRange(blob, sfAmount);
    expect(r).not.toBeNull();
    expect(r!.len).toBe(8);
    // native amount: clear top bit, low 62 bits = drops
    const v = blob.slice(r!.start, r!.start + 8);
    let drops = 0n;
    for (const b of v) drops = (drops << 8n) | BigInt(b);
    drops &= (1n << 62n) - 1n;
    expect(drops).toBe(1000000n);
  });

  it("locates the AccountID field as 20 bytes", () => {
    const r = stoFieldRange(blob, sfAccount);
    expect(r).not.toBeNull();
    expect(r!.len).toBe(20);
  });

  it("reads the UInt16 TransactionType", () => {
    const r = stoFieldRange(blob, sfTransactionType);
    expect(r).not.toBeNull();
    expect(r!.len).toBe(2);
    expect((blob[r!.start] << 8) | blob[r!.start + 1]).toBe(0); // Payment = 0
  });

  it("returns null for an absent field", () => {
    expect(stoFieldRange(blob, (5 << 16) | 99)).toBeNull();
  });
});
