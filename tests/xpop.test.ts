import { describe, it, expect } from "vitest";
import { decodeXpop } from "../src/xpop.js";

// Real inner burn-tx blob + meta from xahaud's canonical Import_test.cpp.
const BLOB =
  "12000322000000002400000002201B0000006C201D0000535968400000003B9ACA007321EDA8D46E11FD5D2082A4E6FF3039EB6259FBC2334983D015FC62ECAD0AE4A96C747440549A370E68DBB1947419D4CCDF90CAE0BCA9121593ECC21B3C79EF0F232EB4375F95F1EBCED78B94D09838B5E769D43F041019ADEF3EC206AD3C5177C519560F81148EA87CA747AF74EE03A7E36C0F8EB1C1568D588A";
const META =
  "201C00000000F8E51100612500000052553CEFE169D8DB251A7757C8A80214D7466E81FB2EF6A91E0970B428326B2134EB56A92E4B1340C656FE01A66D529BB7957EAD34D9E193D190EA62AAE4764B5B08C5E624000000026240000000773593F4E1E7220000000024000000032D0000000162400000003B9AC9F481148EA87CA747AF74EE03A7E36C0F8EB1C1568D588AE1E1F1031000";

const unlBlob = Buffer.from(JSON.stringify({ sequence: 1, validators: [{ validation_public_key: "ED1234" }, { validation_public_key: "ED5678" }] })).toString("base64");

const xpop = {
  ledger: { index: 108, acroot: "DCE3", txroot: "409C", coins: "100", close: 535969 },
  transaction: { blob: BLOB, meta: META, proof: { children: {} } },
  validation: { data: {}, unl: { blob: unlBlob } },
};

describe("decode_xpop", () => {
  it("decodes the inner burn transaction from an XPOP object", () => {
    const d = decodeXpop(xpop);
    expect(d.innerTransactionType).toBe("AccountSet");
    expect(d.targetNetworkId).toBe(21337);        // OperationLimit = Xahau network id
    expect(d.burnedDrops).toBe("1000000000");      // burn amount = inner tx Fee
    expect(d.ledgerIndex).toBe(108);
    expect(d.metaPresent).toBe(true);
    expect(d.proofPresent).toBe(true);
    expect(d.validators?.count).toBe(2);
    expect(d.summary).toMatch(/Burn2Mint/);
    expect(d.warnings).toEqual([]);
  });

  it("decodes the same XPOP from the on-chain Blob form (hex of JSON string)", () => {
    const hex = Buffer.from(JSON.stringify(xpop), "utf-8").toString("hex");
    const d = decodeXpop(hex);
    expect(d.innerTransactionType).toBe("AccountSet");
    expect(d.targetNetworkId).toBe(21337);
    expect(d.validators?.count).toBe(2);
  });

  it("warns (does not throw) on a malformed XPOP", () => {
    const d = decodeXpop({ ledger: { index: 1 } });
    expect(d.warnings.join(" ")).toMatch(/transaction/);
    expect(d.innerTransaction).toBeNull();
  });
});
