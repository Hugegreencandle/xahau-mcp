import { describe, it, expect } from "vitest";
import {
  amendmentId, nameFor, classify, computeStatus, computePrediction, computeDiff,
  MAJORITY_SECONDS, RIPPLE_EPOCH, KNOWN_NAME_COUNT, type AmendmentsNode,
} from "../src/amendments.js";

describe("amendmentId", () => {
  // Vectors confirmed against the live mainnet Amendments object (2026-06-15).
  it("computes SHA512-Half(name) uppercase hex", () => {
    expect(amendmentId("Hooks")).toBe("ECE6819DBA5DB528F1A241695F5A9811EF99467CDE22510954FD357780BBD078");
    expect(amendmentId("Remit")).toBe("0D8BF22FF7570D58598D1EF19EBB6E142AD46E59A223FD3816262FBB69345BEA");
    expect(amendmentId("XahauGenesis")).toBe("6E739F4F8B07BED29FC9FF440DA3C301CD14A180DF45819F658FEC2F7DE31427");
    expect(amendmentId("Cron")).toBe("DD6ABC68C1F37392E521EF6FF1475A11576D87C1BC36D9C9E4F0E6C09D18C120");
    expect(amendmentId("fixXahauV1")).toBe("4C499D17719BB365B69010A436B64FD1A82AAB199FC1CEB06962EBD01059FB09");
  });
});

describe("nameFor / known table", () => {
  it("resolves known ids both cases, null for unknown", () => {
    expect(nameFor(amendmentId("Remit"))).toBe("Remit");
    expect(nameFor(amendmentId("Remit").toLowerCase())).toBe("Remit");
    expect(nameFor("00".repeat(32))).toBeNull();
  });
  it("ships a populated name table", () => {
    expect(KNOWN_NAME_COUNT).toBeGreaterThan(50);
  });
});

describe("classify", () => {
  it("splits feature / fix / unknown", () => {
    expect(classify("Remit")).toBe("feature");
    expect(classify("Hooks")).toBe("feature");
    expect(classify("fixXahauV1")).toBe("fix");
    expect(classify(null)).toBe("unknown");
  });
});

const node: AmendmentsNode = {
  Amendments: [amendmentId("Hooks"), amendmentId("Remit"), "AB".repeat(32)],
  Majorities: [{ Majority: { Amendment: amendmentId("Cron"), CloseTime: 1_000_000 } }],
};

describe("computeStatus", () => {
  it("counts enabled/named/unnamed and voting", () => {
    const s = computeStatus(node, "mainnet");
    expect(s.enabledCount).toBe(3);
    expect(s.namedCount).toBe(2);
    expect(s.unnamedCount).toBe(1);
    expect(s.votingCount).toBe(1);
    expect(s.enabled.find((e) => e.id === "AB".repeat(32))!.name).toBeNull();
    expect(s.voting[0].name).toBe("Cron");
    expect(s.voting[0].gotMajorityAt).toBe(1_000_000);
  });
});

describe("computePrediction", () => {
  it("adds the 5-day window to the majority close time", () => {
    const gotMajorityUnix = 1_000_000 + RIPPLE_EPOCH;
    // now = exactly 1 day after majority → 4 days (in seconds) remaining, not eligible.
    const now = gotMajorityUnix + 86_400;
    const p = computePrediction(node, "mainnet", now);
    expect(p.pendingCount).toBe(1);
    expect(p.majorityWindowDays).toBe(5);
    const item = p.pending[0];
    expect(item.name).toBe("Cron");
    expect(item.secondsRemaining).toBe(MAJORITY_SECONDS - 86_400);
    expect(item.eligibleNow).toBe(false);
    expect(item.daysRemaining).toBe(4);
  });
  it("flags eligibleNow once the window elapses", () => {
    const now = 1_000_000 + RIPPLE_EPOCH + MAJORITY_SECONDS + 1;
    const p = computePrediction(node, "mainnet", now);
    expect(p.pending[0].eligibleNow).toBe(true);
    expect(p.pending[0].daysRemaining).toBe(0);
  });
  it("handles no pending majorities", () => {
    const p = computePrediction({ Amendments: [] }, "testnet", 0);
    expect(p.pendingCount).toBe(0);
    expect(p.summary).toMatch(/no amendments/);
  });
});

describe("computeDiff", () => {
  it("reports amendments enabled on one side only", () => {
    const a: AmendmentsNode = { Amendments: [amendmentId("Hooks"), amendmentId("Remit")] };
    const b: AmendmentsNode = { Amendments: [amendmentId("Hooks")] };
    const d = computeDiff(a, b, "mainnet", "testnet");
    expect(d.enabledA).toBe(2);
    expect(d.enabledB).toBe(1);
    expect(d.onlyOnA).toHaveLength(1);
    expect(d.onlyOnA[0].name).toBe("Remit");
    expect(d.onlyOnB).toHaveLength(0);
  });
});

// 2.2.0 — the name table must cover every amendment the live networks know. Literal fixture:
// read-only `feature` + Amendments-object captures from xahau.network / xahau-test.net, 2026-09-30.
import { readFileSync as readFixture } from "node:fs";
const LIVE = JSON.parse(readFixture(new URL("./fixtures-amendments/live-2026-09-30.json", import.meta.url), "utf8"));

describe("live coverage (fixture 2026-09-30)", () => {
  for (const net of ["mainnet", "testnet"] as const) {
    it(`every amendment the ${net} node reports via feature RPC resolves to its name`, () => {
      const feats = LIVE[net].feature.features as Record<string, { name: string }>;
      const missing = Object.entries(feats).filter(([id, f]) => nameFor(id) !== f.name).map(([, f]) => f.name);
      expect(missing).toEqual([]);
    });
    it(`every ENABLED amendment on ${net} (on-ledger Amendments object) is named`, () => {
      const s = computeStatus(LIVE[net].amendmentsObject.node, net);
      expect(s.enabledCount).toBeGreaterThan(70);
      expect(s.unnamedCount).toBe(0);
    });
  }

  it("feature-RPC IDs equal SHA512-Half(name) for the names added in 2.2.0", () => {
    const feats = LIVE.mainnet.feature.features as Record<string, { name: string }>;
    for (const n of ["NamedHooks", "HookOnV2", "HooksUpdate2", "fixHookMap", "fixHookAPI20251128", "XRPFees", "BalanceRewards"]) {
      const id = Object.keys(feats).find((k) => feats[k].name === n)!;
      expect(amendmentId(n)).toBe(id);
    }
    // literal vectors (from the mainnet feature RPC), so the check does not depend on the fixture parse
    expect(amendmentId("NamedHooks")).toBe("5A7EDF552D4015D082B1D4B179E6994C81BD20338EF263AA75E9B29CB702A48F");
    expect(amendmentId("fixHookMap")).toBe("99DEA90A03A9EDE1472561AD21781435AF53D6FFFC6C38DB419C61FB777D54AC");
  });

  it("source-only upstream names (not yet on any network) are known", () => {
    for (const n of ["HookOnV2_1", "fix20260929", "OnChainManifests"]) expect(nameFor(amendmentId(n))).toBe(n);
  });

  it("superseded pre-release names are NOT in the table (renamed/folded upstream, unknown to both networks)", () => {
    expect(nameFor(amendmentId("fix20261001"))).toBeNull();
    expect(nameFor(amendmentId("fixHookAPISType"))).toBeNull();
  });
});
