import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runHook, stAmountToXfl, xflToStAmountBytes, padStateKey } from "../src/sandbox.js";
import { hexToBytes } from "../src/wasm.js";
import { floatInt, floatSet, decode } from "../src/xfl.js";
import { reconstructContext } from "../src/fidelity.js";
import { validateAddress } from "../src/util.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
const loadFix = (n: string) => hexToBytes(readFileSync(join(DIR, n + ".hex"), "utf8").trim());

// Real Evernode heartbeat hook (1F7C84…, the dominant live hook on Xahau) + a real corpus case.
const corpus = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "data", "hook-corpus.json"), "utf8"));
const HEARTBEAT_HASH = Object.keys(corpus.hookCode).find((h: string) => h.startsWith("1F7C84"))!;
const heartbeatCase = corpus.cases.find((c: any) => c.hookExecutions.some((h: any) => h.HookHash === HEARTBEAT_HASH));
// Installed param (HookDefinition default, verified live 2026-06-11): governor address under key EVR\x01…01
const GOVERNOR_PARAM = { "4556520100000000000000000000000000000000000000000000000000000001": "77C6E707430AC26716121F50539634E4024FB457" };
const GOV_NS = "01EAF09326B4911554384121FF56FA8FECC215FDDE2EC35D9E59F2C53EC665A0";
const MOMENT_BASE_KEY = "4556523300000000000000000000000000000000000000000000000000000000";
const govComposite = (key: string) => `77C6E707430AC26716121F50539634E4024FB457|${GOV_NS}|${key}`;

describe("padStateKey", () => {
  it("left-zero-pads short keys (matches on-ledger genesis RR key layout)", () => {
    expect(padStateKey("5252")).toBe("0".repeat(60) + "5252");
    expect(padStateKey("F".repeat(64))).toBe("F".repeat(64));
    expect(padStateKey("F".repeat(66))).toBeNull();
  });
});

describe("STAmount <-> XFL (slot_float / float_sto)", () => {
  it("native fee round-trip: 8630 drops -> XFL -> float_int(x,6,1) == 8630 (reward.c usage)", () => {
    // serialized native amount: bit62 (positive) | drops, big-endian
    const raw = (1n << 62n) | 8630n;
    const bytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) bytes[i] = Number((raw >> BigInt((7 - i) * 8)) & 0xffn);
    const x = stAmountToXfl(bytes)!;
    expect(floatInt(x, 6, true)).toBe(8630n);
  });

  it("issued amount: layout below bit63 IS the XFL — clear top bit", () => {
    const xfl = floatSet(-2, 12345n); // 123.45
    const raw = (1n << 63n) | xfl;
    const bytes = new Uint8Array(48);
    for (let i = 7; i >= 0; i--) bytes[i] = Number((raw >> BigInt((7 - i) * 8)) & 0xffn);
    expect(stAmountToXfl(bytes)).toBe(xfl);
  });

  it("xflToStAmountBytes native: canonical zero is 0x4000000000000000", () => {
    const b = xflToStAmountBytes(0n)!;
    expect(Buffer.from(b).toString("hex").toUpperCase()).toBe("4000000000000000");
  });

  it("xflToStAmountBytes <-> stAmountToXfl round-trips an issued amount", () => {
    const xfl = floatSet(0, 7n);
    const cur = new Uint8Array(20).fill(1), iss = new Uint8Array(20).fill(2);
    const b = xflToStAmountBytes(xfl, cur, iss)!;
    expect(b.length).toBe(48);
    expect(stAmountToXfl(b)).toBe(xfl);
    expect(decode(stAmountToXfl(b)!).mant).toBe(7_000_000_000_000_000n);
  });
});

describe("state key padding — real genesis reward hook", () => {
  // reward.c calls state(&rr, 8, "RR", 2): a 2-byte key. On-ledger that key is 00…005252.
  // Before the padding fix the VM missed the entry and fell back to the compiled default;
  // with RR explicitly ZERO in state, the hook must now roll back "disabled by governance".
  it("reads a 32-byte-padded state entry through a 2-byte key (RR=0 -> rewards disabled)", () => {
    const r = runHook(loadFix("genesis-reward"), {
      txType: "ClaimReward", ledgerSeq: 23478900, hookAccountId: "00".repeat(20),
      otxnFields: { [String((8 << 16) | 1)]: "AB".repeat(20) }, // sfAccount (type 8, field 1) != hook account
      state: { ["0".repeat(60) + "5252"]: "0000000000000000" }, // RR = canonical XFL zero
    });
    expect(r.exit).toBe("rollback");
    expect(r.returnString).toMatch(/disabled by governance/);
  });
});

describe("state_foreign — real Evernode heartbeat hook (1F7C84…)", () => {
  const code = hexToBytes(corpus.hookCode[HEARTBEAT_HASH]);
  const v = validateAddress(heartbeatCase.hookAccount);
  const hookAccountId = (v as any).accountId as string;

  function run(foreignState?: Record<string, string | null>) {
    const ctx = reconstructContext(heartbeatCase.tx, hookAccountId, heartbeatCase.ledgerCloseTime, heartbeatCase.hookState, foreignState, undefined, GOVERNOR_PARAM);
    ctx.hookHash = HEARTBEAT_HASH;
    return runHook(code, ctx);
  }

  it("without install params the hook stops at hook_param; with them it reaches state_foreign and reports the EXACT wanted entry", () => {
    const ctx = reconstructContext(heartbeatCase.tx, hookAccountId, heartbeatCase.ledgerCloseTime, heartbeatCase.hookState);
    const bare = runHook(code, ctx);
    expect(bare.wantedForeignState).toHaveLength(0); // never got that far
    const withParams = run();
    expect(withParams.degraded).toBe(true);
    expect(withParams.wantedForeignState).toContain(govComposite(MOMENT_BASE_KEY));
  });

  it("feeding the wanted foreign-state entry advances execution (next dependent read surfaces)", () => {
    // real mainnet MOMENT_BASE_INFO value captured live 2026-06-11
    const r = run({ [govComposite(MOMENT_BASE_KEY)]: "16937A65000000000000000001" });
    // the moment-base read is satisfied — it must no longer be in the wanted list
    expect(r.wantedForeignState).not.toContain(govComposite(MOMENT_BASE_KEY));
    // and execution went further: either new wants or a decision
    expect(r.wantedForeignState.length + (r.exit !== "halted" ? 1 : 0)).toBeGreaterThan(0);
  });

  it("a CONFIRMED-ABSENT entry (null) is DOESNT_EXIST without degrading on that read", () => {
    const r = run({ [govComposite(MOMENT_BASE_KEY)]: null });
    expect(r.wantedForeignState).not.toContain(govComposite(MOMENT_BASE_KEY));
  });
});
