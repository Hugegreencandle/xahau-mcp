import { describe, it, expect } from "vitest";
import { buildRemitUnsigned } from "../src/builders.js";

// Well-known valid classic r-addresses.
const ACCT = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const DEST = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
const ISSUER = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW"; // valid r-address (issuer/3rd party)

describe("buildRemitUnsigned — shape", () => {
  it("sets TransactionType, Account, Destination, NetworkID per network", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: ["1000000"], network: "mainnet" });
    expect(r.unsignedTx.TransactionType).toBe("Remit");
    expect(r.unsignedTx.Account).toBe(ACCT);
    expect(r.unsignedTx.Destination).toBe(DEST);
    expect(r.unsignedTx.NetworkID).toBe(21337);
    expect(r.network).toBe("mainnet");
    // unsigned: the tx itself never carries signature/key material
    expect(JSON.stringify(r.unsignedTx)).not.toMatch(/TxnSignature|SigningPubKey|secret|seed/i);
  });

  it("defaults to testnet", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: ["1"] });
    expect(r.network).toBe("testnet");
    expect(r.unsignedTx.NetworkID).toBe(21338);
  });
});

describe("buildRemitUnsigned — Amounts nesting (canonical AmountEntry wrapper)", () => {
  it("wraps native drops as { AmountEntry: { Amount: '<drops>' } }", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: ["2500000"] });
    expect(r.unsignedTx.Amounts).toEqual([{ AmountEntry: { Amount: "2500000" } }]);
  });

  it("wraps issued currency as nested object and canonicalizes 3-char code", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: [{ currency: "USD", issuer: ISSUER, value: "10" }] });
    expect(r.unsignedTx.Amounts).toEqual([{ AmountEntry: { Amount: { currency: "USD", issuer: ISSUER, value: "10" } } }]);
  });

  it("supports mixed native + issued in one atomic Remit", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: ["1000000", { currency: "EUR", issuer: ISSUER, value: "1.5" }] });
    const a = r.unsignedTx.Amounts as any[];
    expect(a).toHaveLength(2);
    expect(a[0].AmountEntry.Amount).toBe("1000000");
    expect(a[1].AmountEntry.Amount.currency).toBe("EUR");
  });

  it("rejects a non-integer native amount", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: ["1.5"] })).toThrow(/integer string of drops/);
  });
  it("rejects an issued amount with a bad issuer", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: [{ currency: "USD", issuer: "notanaddr", value: "1" }] })).toThrow(/issuer/);
  });
  it("rejects an issued-amount object claiming native XAH (wrong-effect amount)", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: [{ currency: "XAH", issuer: ISSUER, value: "1" }] })).toThrow(/native/);
  });
});

describe("buildRemitUnsigned — URITokens", () => {
  const ID = "A".repeat(64);
  it("passes through 64-hex URITokenIDs uppercased", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, uriTokenIds: [ID.toLowerCase()] });
    expect(r.unsignedTx.URITokenIDs).toEqual([ID]);
  });
  it("rejects a wrong-length URIToken ID", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: DEST, uriTokenIds: ["ABC"] })).toThrow(/64-char hex/);
  });

  it("mints with hex URI passthrough + digest + flags", () => {
    const uri = "68747470733A2F2F78"; // hex
    const dg = "B".repeat(64);
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, mintURIToken: { uri, digest: dg, flags: 1 } });
    expect(r.unsignedTx.MintURIToken).toEqual({ URI: uri, Digest: dg, Flags: 1 });
  });

  it("UTF-8 encodes a non-hex URI and flags it LOW", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, mintURIToken: { uri: "ipfs://Qm…receipt" } });
    const mint = r.unsignedTx.MintURIToken as any;
    expect(mint.URI).toBe(Buffer.from("ipfs://Qm…receipt", "utf8").toString("hex").toUpperCase());
    expect(r.preflightFindings?.some((f) => f.ruleId === "REMIT-URI-ENCODED")).toBe(true);
  });

  it("rejects a bad mint digest", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: DEST, mintURIToken: { uri: "AB", digest: "xx" } })).toThrow(/digest/);
  });
});

describe("buildRemitUnsigned — extras + guards", () => {
  it("sets Inform / Blob / InvoiceID / DestinationTag", () => {
    const r = buildRemitUnsigned({
      account: ACCT, destination: DEST, amounts: ["1"],
      inform: ISSUER, blob: "0xDEAD", invoiceId: "C".repeat(64), destinationTag: 42,
    });
    expect(r.unsignedTx.Inform).toBe(ISSUER);
    expect(r.unsignedTx.Blob).toBe("DEAD");
    expect(r.unsignedTx.InvoiceID).toBe("C".repeat(64));
    expect(r.unsignedTx.DestinationTag).toBe(42);
  });

  it("rejects destination equal to account", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: ACCT, amounts: ["1"] })).toThrow(/differ/);
  });
  it("rejects odd-length blob", () => {
    expect(() => buildRemitUnsigned({ account: ACCT, destination: DEST, blob: "ABC" })).toThrow(/even-length hex/);
  });

  it("warns MEDIUM when the Remit carries no payload", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST });
    expect(r.unsignedTx.Amounts).toBeUndefined();
    const empty = r.preflightFindings?.find((f) => f.ruleId === "REMIT-EMPTY");
    expect(empty?.severity).toBe("MEDIUM");
  });

  it("always advises a LastLedgerSequence", () => {
    const r = buildRemitUnsigned({ account: ACCT, destination: DEST, amounts: ["1"] });
    expect(r.preflightFindings?.some((f) => f.ruleId === "TX-001-NO-LASTLEDGERSEQ")).toBe(true);
  });
});
