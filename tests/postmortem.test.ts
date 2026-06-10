import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  hookExecutionPostmortem,
  normalizeHookExecutions,
  decodeHexString,
  type PostmortemDeps,
  type Network,
} from "../src/postmortem.js";
import type { HookCorpus, CorpusCase } from "../src/fidelity.js";

// Drive the post-mortem offline from the COMMITTED real-mainnet corpus (data/hook-corpus.json).
// We reconstruct the LIVE `tx` document shape (inner tx + meta.HookExecutions + meta.TransactionResult
// + date + ledger_index) from each corpus case, exactly as rpc.getTx would return it, then synthesize
// a few variants (rollback / return-string / missing-code / indeterminate) the corpus doesn't contain.
const CORPUS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "data", "hook-corpus.json");
const CORPUS = JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as HookCorpus;

/** Build a live-shaped tx document from a corpus case (wrap HookExecutions like xahaud does). */
function liveTxFromCase(cs: CorpusCase): Record<string, unknown> {
  return {
    ...cs.tx,
    hash: cs.txHash,
    ledger_index: cs.ledgerIndex,
    date: cs.ledgerCloseTime,
    meta: {
      TransactionResult: cs.engineResult ?? "tesSUCCESS",
      HookExecutions: (cs.hookExecutions ?? []).map((he) => ({
        HookExecution: {
          HookAccount: cs.hookAccount,
          HookHash: he.HookHash,
          HookResult: he.HookResult,
          HookReturnCode: he.HookReturnCode,
          ...(he.HookReturnString ? { HookReturnString: he.HookReturnString } : {}),
        },
      })),
    },
  };
}

/** A deps object that serves a fixed tx doc + the corpus's real CreateCode (optionally suppressed). */
function depsFor(
  txByHash: Record<string, Record<string, unknown>>,
  opts: { suppressCode?: boolean; codeOverride?: Record<string, string | null> } = {},
): PostmortemDeps & { calls: { tx: number; def: number } } {
  const calls = { tx: 0, def: 0 };
  return {
    calls,
    sleep: async () => {}, // no real waiting in unit tests
    fetchTx: async (h: string) => { calls.tx++; const d = txByHash[h]; if (!d) throw new Error(`no tx ${h}`); return d; },
    fetchHookDefinition: async (hash: string) => {
      calls.def++;
      if (opts.codeOverride && hash in opts.codeOverride) return opts.codeOverride[hash];
      if (opts.suppressCode) return null;
      return CORPUS.hookCode[hash] ?? null;
    },
  };
}

const NET: Network = "mainnet";
const acceptCase = CORPUS.cases.find((c) => c.engineResult === "tesSUCCESS" && (c.hookExecutions ?? []).some((h) => Number(h.HookResult) === 3))!;
const claimReward = CORPUS.cases.find((c) => c.tx?.TransactionType === "ClaimReward");

describe("postmortem: decodeHexString", () => {
  it("decodes valid UTF-8 hex to a string", () => {
    const hex = Buffer.from("rejected: balance", "utf-8").toString("hex");
    expect(decodeHexString(hex)).toBe("rejected: balance");
  });
  it("falls back to raw uppercase hex for non-printable bytes ('deadbeef')", () => {
    const out = decodeHexString("deadbeef");
    // deadbeef is not valid printable UTF-8 -> surface raw hex (uppercased), never a lie.
    expect(out === "DEADBEEF" || (typeof out === "string" && /^[0-9A-F]+$/.test(out))).toBe(true);
  });
  it("returns null for empty/missing input", () => {
    expect(decodeHexString(null)).toBeNull();
    expect(decodeHexString("")).toBeNull();
    expect(decodeHexString(undefined)).toBeNull();
  });
});

describe("postmortem: normalizeHookExecutions", () => {
  it("flattens the live wrapped {HookExecution:{...}} shape and assigns positions", () => {
    const norm = normalizeHookExecutions([
      { HookExecution: { HookHash: "AA", HookResult: 3, HookReturnCode: "1", HookAccount: "rX" } },
      { HookExecution: { HookHash: "BB", HookResult: 4 } },
    ]);
    expect(norm).toHaveLength(2);
    expect(norm[0]).toMatchObject({ position: 0, HookHash: "AA", HookResult: 3, HookAccount: "rX" });
    expect(norm[1]).toMatchObject({ position: 1, HookHash: "BB", HookResult: 4 });
  });
  it("accepts the already-flat (corpus) shape too", () => {
    const norm = normalizeHookExecutions([{ HookHash: "CC", HookResult: 3 }]);
    expect(norm[0]).toMatchObject({ position: 0, HookHash: "CC", HookResult: 3 });
  });
  it("returns [] for non-array input", () => {
    expect(normalizeHookExecutions(undefined)).toEqual([]);
    expect(normalizeHookExecutions({})).toEqual([]);
  });
});

describe("postmortem: real-corpus accept transaction", () => {
  it("(2) a tesSUCCESS ClaimReward (or any accept tx) yields onChainDecision='accept'", async () => {
    const cs = claimReward ?? acceptCase;
    const tx = liveTxFromCase(cs);
    const deps = depsFor({ [cs.txHash]: tx });
    const res = await hookExecutionPostmortem(cs.txHash, NET, deps);
    expect(res.engineResult).toBe("tesSUCCESS");
    expect(res.hookPostmortems.length).toBeGreaterThan(0);
    expect(res.hookPostmortems.every((p) => p.onChainDecision === "accept")).toBe(true);
  });

  it("populates txHash, transactionType, ledger and a decoded ISO date", async () => {
    const cs = acceptCase;
    const tx = liveTxFromCase(cs);
    const res = await hookExecutionPostmortem(cs.txHash, NET, depsFor({ [cs.txHash]: tx }));
    expect(res.txHash).toBe(cs.txHash);
    expect(res.transactionType).toBe(cs.tx.TransactionType);
    expect(res.ledger).toBe(cs.ledgerIndex);
    expect(res.date.ripple).toBe(cs.ledgerCloseTime);
    expect(res.date.iso).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("every VM run is labeled fidelity=LOCAL_VM (never claims authority over the chain)", async () => {
    const cs = acceptCase;
    const res = await hookExecutionPostmortem(cs.txHash, NET, depsFor({ [cs.txHash]: liveTxFromCase(cs) }));
    expect(res.hookPostmortems.every((p) => p.vmResult.fidelity === "LOCAL_VM")).toBe(true);
  });

  it("agree is boolean|null only (degraded/indeterminate -> null, never false-by-default)", async () => {
    const cs = acceptCase;
    const res = await hookExecutionPostmortem(cs.txHash, NET, depsFor({ [cs.txHash]: liveTxFromCase(cs) }));
    for (const p of res.hookPostmortems) {
      expect(p.agree === true || p.agree === false || p.agree === null).toBe(true);
    }
  });
});

describe("postmortem: rollback / engine-result propagation (synthesized from real case)", () => {
  // The committed corpus is all tesSUCCESS; synthesize a tecHOOK_REJECTED variant by flipping the
  // engine result + HookResult on a REAL case's real bytecode. The on-chain mapping is what we test.
  function rejectedVariant(cs: CorpusCase): { hash: string; tx: Record<string, unknown> } {
    const hash = "REJ" + cs.txHash.slice(3);
    const base = liveTxFromCase(cs);
    const meta = base.meta as Record<string, unknown>;
    const hes = (meta.HookExecutions as { HookExecution: Record<string, unknown> }[]).map((w) => ({
      HookExecution: { ...w.HookExecution, HookResult: 4, HookReturnString: Buffer.from("rejected", "utf-8").toString("hex") },
    }));
    return { hash, tx: { ...base, hash, meta: { TransactionResult: "tecHOOK_REJECTED", HookExecutions: hes } } };
  }

  it("(1)+(5) a tecHOOK_REJECTED tx -> at least one onChainDecision='rollback' and the engine result is in the summary", async () => {
    const { hash, tx } = rejectedVariant(acceptCase);
    const res = await hookExecutionPostmortem(hash, NET, depsFor({ [hash]: tx }));
    expect(res.engineResult).toBe("tecHOOK_REJECTED");
    expect(res.hookPostmortems.some((p) => p.onChainDecision === "rollback")).toBe(true);
    expect(res.summary).toContain("tecHOOK_REJECTED");
    expect(res.summary).toMatch(/rolled back/);
  });

  it("(4) HookReturnString hex is decoded to UTF-8 when valid", async () => {
    const { hash, tx } = rejectedVariant(acceptCase);
    const res = await hookExecutionPostmortem(hash, NET, depsFor({ [hash]: tx }));
    expect(res.hookPostmortems[0].hookReturnString).toBe("rejected");
  });

  it("(4b) a 'deadbeef' HookReturnString falls back to raw hex, not a fabricated string", async () => {
    const hash = "DBF" + acceptCase.txHash.slice(3);
    const base = liveTxFromCase(acceptCase);
    const hes = ((base.meta as Record<string, unknown>).HookExecutions as { HookExecution: Record<string, unknown> }[])
      .map((w) => ({ HookExecution: { ...w.HookExecution, HookReturnString: "deadbeef" } }));
    const tx = { ...base, hash, meta: { TransactionResult: "tesSUCCESS", HookExecutions: hes } };
    const res = await hookExecutionPostmortem(hash, NET, depsFor({ [hash]: tx }));
    const rs = res.hookPostmortems[0].hookReturnString!;
    expect(/^[0-9A-F]+$/.test(rs)).toBe(true);
  });
});

describe("postmortem: honest degradation", () => {
  it("(3) missing CreateCode -> entry degraded:true, agree:null, no fabricated VM result", async () => {
    const cs = acceptCase;
    const tx = liveTxFromCase(cs);
    const res = await hookExecutionPostmortem(cs.txHash, NET, depsFor({ [cs.txHash]: tx }, { suppressCode: true }));
    expect(res.hookPostmortems.length).toBeGreaterThan(0);
    for (const p of res.hookPostmortems) {
      expect(p.vmResult.degraded).toBe(true);
      expect(p.agree).toBeNull();
      expect(p.vmResult.exit).toBeNull();
      expect(p.reason).toMatch(/no CreateCode|not found/i);
    }
    // on-chain decision still reported (chain is authoritative even when we can't reproduce it)
    expect(res.hookPostmortems[0].onChainDecision).toBe("accept");
  });

  it("(6) onChainDecision=null when HookResult absent AND no recognized engine result -> agree:null", async () => {
    const hash = "IND" + acceptCase.txHash.slice(3);
    const base = liveTxFromCase(acceptCase);
    const codeHash = (acceptCase.hookExecutions ?? [])[0]?.HookHash;
    const tx = {
      ...base, hash,
      meta: {
        TransactionResult: "tecKILLED", // not tesSUCCESS / tecHOOK_REJECTED -> no corroborating fallback
        HookExecutions: [{ HookExecution: { HookAccount: acceptCase.hookAccount, HookHash: codeHash /* no HookResult */ } }],
      },
    };
    const res = await hookExecutionPostmortem(hash, NET, depsFor({ [hash]: tx }));
    expect(res.hookPostmortems[0].onChainDecision).toBeNull();
    expect(res.hookPostmortems[0].agree).toBeNull();
  });

  it("a tx with zero HookExecutions yields an empty list and an honest 'No hooks fired' summary", async () => {
    const hash = "EMP" + acceptCase.txHash.slice(3);
    const base = liveTxFromCase(acceptCase);
    const tx = { ...base, hash, meta: { TransactionResult: "tesSUCCESS", HookExecutions: [] } };
    const res = await hookExecutionPostmortem(hash, NET, depsFor({ [hash]: tx }));
    expect(res.hookPostmortems).toEqual([]);
    expect(res.summary).toMatch(/No hooks fired/);
  });
});

describe("postmortem: serial RPC budget (dedup)", () => {
  it("fetches the tx once and the HookDefinition once per UNIQUE HookHash", async () => {
    // craft a tx with the SAME hook firing twice -> still only 1 def fetch.
    const cs = acceptCase;
    const codeHash = (cs.hookExecutions ?? [])[0].HookHash!;
    const base = liveTxFromCase(cs);
    const hash = "DUP" + cs.txHash.slice(3);
    const tx = {
      ...base, hash,
      meta: {
        TransactionResult: "tesSUCCESS",
        HookExecutions: [
          { HookExecution: { HookAccount: cs.hookAccount, HookHash: codeHash, HookResult: 3, HookReturnCode: "0" } },
          { HookExecution: { HookAccount: cs.hookAccount, HookHash: codeHash, HookResult: 3, HookReturnCode: "0" } },
        ],
      },
    };
    const deps = depsFor({ [hash]: tx });
    const res = await hookExecutionPostmortem(hash, NET, deps);
    expect(res.hookPostmortems).toHaveLength(2);
    expect(deps.calls.tx).toBe(1);
    expect(deps.calls.def).toBe(1); // deduplicated
  });
});
