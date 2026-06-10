import { describe, it, expect } from "vitest";
import { decodeLeaseUri } from "../src/evernode.js";

// REAL mainnet lease URIs (captured from live URITokenMint txs during ecosystem recon, 2026-06-10).
const REAL_B64 = "ZXZybGVhc2VMVFYAAQACCAFnfryy9275fVMVSdiyfVQGCiQYHkAAL9eUlAAAAAAAAAAAAAAAAAAAAAAA";
const REAL_B64_2 = "ZXZybGVhc2VMVFYAAQAACAFnfryy9275fVMVSdiyfVPHGv1JjQAALSyHIwAAAAAAAAAAAAAAAAAAAAAA";

describe("decode_lease_uri (Evernode)", () => {
  it("decodes a real mainnet lease from base64 text", () => {
    const d = decodeLeaseUri(REAL_B64);
    expect(d.isEvernodeLease).toBe(true);
    expect(d.version).toBe(1);
    expect(d.leaseIndex).toBe(2);
    expect(d.leaseAmountEvr).toBe("0.017"); // XFL 6054537899185946624, verified by hand
    expect(d.identifier).toBe(802657428);
    expect(d.outboundIp).toBeNull(); // family byte 0 = none
    expect(d.totalBytes).toBe(60);
  });

  it("decodes the on-chain form (hex of the base64 ASCII)", () => {
    const onChainHex = Buffer.from(REAL_B64, "utf-8").toString("hex").toUpperCase();
    const d = decodeLeaseUri(onChainHex);
    expect(d.isEvernodeLease).toBe(true);
    expect(d.leaseAmountEvr).toBe("0.017");
  });

  it("decodes the raw buffer hex form", () => {
    const rawHex = Buffer.from(REAL_B64, "base64").toString("hex");
    const d = decodeLeaseUri(rawHex);
    expect(d.isEvernodeLease).toBe(true);
    expect(d.leaseIndex).toBe(2);
  });

  it("a second real lease parses with a different index/amount", () => {
    const d = decodeLeaseUri(REAL_B64_2);
    expect(d.isEvernodeLease).toBe(true);
    expect(d.leaseIndex).toBe(0);
    expect(Number(d.leaseAmountEvr)).toBeGreaterThan(0);
  });

  it("rejects non-lease URIs honestly", () => {
    expect(decodeLeaseUri("68747470733A2F2F6578616D706C652E636F6D").isEvernodeLease).toBe(false); // https://example.com
    expect(decodeLeaseUri("not even hex!").isEvernodeLease).toBe(false);
    expect(decodeLeaseUri(Buffer.from("evrlease-but-too-short").toString("hex")).isEvernodeLease).toBe(false);
  });
});
