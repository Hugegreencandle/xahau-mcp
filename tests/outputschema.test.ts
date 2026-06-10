import { describe, it, expect } from "vitest";
import { z, type ZodRawShape } from "zod";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as S from "../src/outputSchemas.js";
import { decodeCreateCode, runRules } from "../src/analyzer.js";
import { runHook } from "../src/sandbox.js";
import { readWasm } from "../src/wasm.js";
import { classifyHook } from "../src/classify.js";
import { diffHooks } from "../src/diff.js";
import { fidelityReport } from "../src/fidelity.js";
import { decodeHookOn, encodeHookOn } from "../src/hookon.js";
import { decodeAmount, validateAddress, describeTx } from "../src/util.js";
import { decodeXpop } from "../src/xpop.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures-wasm");
const reward = new Uint8Array(Buffer.from(readFileSync(join(dir, "genesis-reward.hex"), "utf8").trim(), "hex"));
const corpus = JSON.parse(readFileSync(join(dir, "..", "..", "data", "hook-corpus.json"), "utf8"));
const ACC = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

// validate that a REAL payload (the shape a tool actually returns) parses under the published schema,
// and that an error result also parses (so fail() responses never trip output validation).
const ok = (shape: ZodRawShape, payload: unknown) => {
  const r = z.object(shape).safeParse(payload);
  if (!r.success) throw new Error(JSON.stringify(r.error.issues));
  expect(r.success).toBe(true);
  expect(z.object(shape).safeParse({ error: "some error" }).success).toBe(true);
};

describe("output schemas accept real tool payloads", () => {
  it("execute_hook", () => { const r = runHook(reward, {}); ok(S.EXECUTE_HOOK_OUT, { ...r, resolvedKeylets: [] }); });
  it("analyze_hook", () => { const w = decodeCreateCode({ wasmHex: Buffer.from(reward).toString("hex") }); const { findings, summary } = runRules({ wasm: w }, { sethook: false }); ok(S.ANALYZE_HOOK_OUT, { findings, summary, decoded: { byteSize: w.byteSize } }); });
  it("classify_hook", () => ok(S.CLASSIFY_HOOK_OUT, classifyHook(readWasm(reward))));
  it("hook_diff", () => ok(S.HOOK_DIFF_OUT, diffHooks(readWasm(reward), readWasm(reward))));
  it("vm_fidelity_report", () => ok(S.FIDELITY_OUT, fidelityReport(corpus)));
  it("decode_hook_on", () => ok(S.DECODE_HOOKON_OUT, decodeHookOn("0".repeat(64))));
  it("encode_hook_on", () => ok(S.ENCODE_HOOKON_OUT, encodeHookOn(["Payment"])));
  it("decode_amount (native + issued)", () => { ok(S.DECODE_AMOUNT_OUT, decodeAmount("1000000")); ok(S.DECODE_AMOUNT_OUT, decodeAmount({ currency: "USD", issuer: ACC, value: "10" })); });
  it("validate_address (classic + x)", () => { ok(S.VALIDATE_ADDRESS_OUT, validateAddress(ACC)); ok(S.VALIDATE_ADDRESS_OUT, validateAddress("not-an-address")); });
  it("decode_sign_request", () => { const tx = { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "1000000", LastLedgerSequence: 1 }; const { summary, warnings } = describeTx(tx); ok(S.DECODE_SIGNREQ_OUT, { transactionType: tx.TransactionType, summary, warnings, amountDecoded: decodeAmount(tx.Amount), tx }); });
  it("decode_xpop", () => ok(S.DECODE_XPOP_OUT, decodeXpop({ ledger: { index: 1 } })));
});
