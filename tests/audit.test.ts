import { describe, it, expect } from "vitest";
import { extractStakeholders, auditThreading, decodeRemarksOnObjects } from "../src/audit.js";

const A = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const B = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
const C = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW";

describe("extractStakeholders", () => {
  const tx = {
    Account: A,
    hash: "F".repeat(64),
    meta: {
      AffectedNodes: [
        { ModifiedNode: { LedgerEntryType: "AccountRoot", LedgerIndex: "1", FinalFields: { Account: A }, PreviousFields: { Balance: "1" } } },
        { ModifiedNode: { LedgerEntryType: "AccountRoot", LedgerIndex: "2", FinalFields: { Account: B } } }, // touched, unchanged
        { CreatedNode: { LedgerEntryType: "RippleState", LedgerIndex: "3", NewFields: { HighLimit: { issuer: C }, LowLimit: { issuer: A } } } },
      ],
    },
  };
  it("collects all touched accounts from metadata with roles", () => {
    const r = extractStakeholders(tx);
    expect(r.originator).toBe(A);
    expect(r.metaPresent).toBe(true);
    const accts = r.stakeholders.map((s) => s.account).sort();
    expect(accts).toEqual([A, B, C].sort());
  });
  it("marks an unchanged-but-touched account (Touch amendment) as not materially changed", () => {
    const r = extractStakeholders(tx);
    const sB = r.stakeholders.find((s) => s.account === B)!;
    expect(sB.changed).toBe(false);
    expect(sB.roles).toContain("touched (unchanged)");
  });
  it("handles a tx with no metadata", () => {
    const r = extractStakeholders({ Account: A });
    expect(r.metaPresent).toBe(false);
    expect(r.stakeholderCount).toBe(1);
  });
});

describe("auditThreading", () => {
  it("flags a ledger object appearing in more than one node (double-thread symptom)", () => {
    const tx = {
      hash: "E".repeat(64),
      meta: {
        AffectedNodes: [
          { ModifiedNode: { LedgerEntryType: "AccountRoot", LedgerIndex: "DUP", PreviousTxnID: "A".repeat(64), PreviousTxnLgrSeq: 5 } },
          { ModifiedNode: { LedgerEntryType: "AccountRoot", LedgerIndex: "DUP", PreviousTxnID: "B".repeat(64), PreviousTxnLgrSeq: 6 } },
        ],
      },
    };
    const r = auditThreading(tx);
    expect(r.consistent).toBe(false);
    expect(r.anomalies.some((a) => a.level === "WARN" && /double-threading/.test(a.message))).toBe(true);
    expect(r.uniqueLedgerObjects).toBe(1);
    expect(r.affectedNodeCount).toBe(2);
  });
  it("is consistent for normal distinct nodes", () => {
    const tx = {
      hash: "D".repeat(64),
      meta: { AffectedNodes: [
        { ModifiedNode: { LedgerEntryType: "AccountRoot", LedgerIndex: "X", PreviousTxnID: "1".repeat(64), PreviousTxnLgrSeq: 5 } },
        { ModifiedNode: { LedgerEntryType: "Offer", LedgerIndex: "Y", PreviousTxnID: "2".repeat(64), PreviousTxnLgrSeq: 5 } },
      ] },
    };
    const r = auditThreading(tx);
    expect(r.consistent).toBe(true);
    expect(r.entries[0].previousTxnId).toBe("1".repeat(64));
  });
});

describe("decodeRemarksOnObjects", () => {
  it("decodes hex name/value and flags immutable", () => {
    const objs = [{
      LedgerEntryType: "URIToken", index: "OID",
      Remarks: [
        { Remark: { RemarkName: Buffer.from("color", "utf8").toString("hex").toUpperCase(), RemarkValue: Buffer.from("blue", "utf8").toString("hex").toUpperCase(), Flags: 1 } },
        { Remark: { RemarkName: "CAFE" } }, // no value
      ],
    }];
    const r = decodeRemarksOnObjects(objs);
    expect(r.objectsWithRemarks).toBe(1);
    expect(r.remarkCount).toBe(2);
    expect(r.immutableCount).toBe(1);
    const rem = r.objects[0].remarks;
    expect(rem[0].name).toBe("color");
    expect(rem[0].value).toBe("blue");
    expect(rem[0].immutable).toBe(true);
    expect(rem[1].value).toBeNull();
  });
  it("ignores objects without remarks", () => {
    const r = decodeRemarksOnObjects([{ LedgerEntryType: "AccountRoot" }]);
    expect(r.objectsWithRemarks).toBe(0);
    expect(r.remarkCount).toBe(0);
  });
});
