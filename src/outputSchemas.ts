// Output schemas for the high-value structured tools. Published in each tool's MCP definition so an
// agent knows the shape of `structuredContent` it gets back — without having to guess field names.
//
// SAFE BY DESIGN: the MCP SDK validates `structuredContent` against these (safeParseAsync) and throws
// on mismatch — BUT error results (fail()) set no fields beyond `error` and every field here is
// OPTIONAL, and the SDK skips validation for `isError` results anyway. With all fields optional, any
// success or error payload validates; undeclared fields pass through to the client unchanged (the SDK
// validates but does not rewrite the payload). Types are given where certain, `z.unknown()` where not,
// so a present field can never fail validation by type surprise.
import { z } from "zod";

const err = { error: z.string().optional() };
const arr = z.array(z.unknown()).optional();
const obj = z.record(z.string(), z.unknown()).optional();
const str = z.string().optional();
const num = z.number().optional();
const bool = z.boolean().optional();

export const EXECUTE_HOOK_OUT = {
  exit: str, returnCode: z.unknown().optional(), returnString: str, degraded: bool,
  unsupportedCalls: arr, syntheticCalls: arr, stateWrites: arr, foreignStateWrites: arr,
  emitted: arr, trace: arr, wantedKeylets: arr, wantedForeignState: arr,
  resolvedKeylets: arr, resolvedForeignState: arr, stateApplied: z.unknown().optional(), fidelity: str, caveat: str, ...err,
};

export const ANALYZE_HOOK_OUT = { findings: arr, summary: obj, decoded: obj, valid: bool, ...err };

export const CLASSIFY_HOOK_OUT = {
  archetype: str, confidence: str, capabilities: arr, firesOn: z.array(z.unknown()).nullable().optional(),
  behaviors: arr, summary: str, valid: bool, ...err,
};

export const HOOK_DIFF_OUT = {
  byteSizeBefore: num, byteSizeAfter: num, byteSizeDelta: num, imports: obj, exports: obj,
  firesOn: z.record(z.string(), z.unknown()).nullable().optional(), instructionDelta: num,
  loopDelta: num, guardDelta: num, newSensitiveCapabilities: arr, summary: str, ...err,
};

export const HOOK_REPORT_OUT = {
  verdict: str, structure: obj, classification: obj, analysis: obj,
  hookOnDecoded: z.array(z.unknown()).nullable().optional(), feeEstimate: obj, ...err,
};

export const FIDELITY_OUT = {
  total: num, comparable: num, agreements: num, agreementPct: z.number().nullable().optional(),
  degradedCount: num, composition: z.unknown().optional(), coverageWarning: z.string().nullable().optional(),
  perHook: arr, mismatches: arr, headline: str, insufficient: bool, ...err,
};

export const QUANTUM_OUT = {
  address: str, score: num, tier: str, masterDisabled: bool, regularKey: z.unknown().optional(),
  signerList: z.unknown().optional(), hooks: z.unknown().optional(), recommendations: arr, ...err,
};

export const DECODE_HOOKON_OUT = { firesOn: arr, count: num, hookOn: str, ...err };
export const ENCODE_HOOKON_OUT = { hookOn: str, firesOn: arr, ...err };

export const DECODE_AMOUNT_OUT = {
  type: str, drops: str, xah: str, value: z.unknown().optional(), currency: z.unknown().optional(),
  issuer: z.unknown().optional(), valueNote: str, ...err,
};

export const VALIDATE_ADDRESS_OUT = {
  valid: bool, type: str, classicAddress: str, accountId: str,
  tag: z.number().nullable().optional(), network: str, reason: str, ...err,
};

export const DECODE_SIGNREQ_OUT = {
  transactionType: z.string().nullable().optional(), summary: str, warnings: arr,
  amountDecoded: z.unknown().optional(), tx: obj, ...err,
};

export const DECODE_XPOP_OUT = {
  ledger: z.record(z.string(), z.unknown()).nullable().optional(), ledgerIndex: z.number().nullable().optional(),
  innerTransaction: z.record(z.string(), z.unknown()).nullable().optional(),
  innerTransactionType: z.string().nullable().optional(), burnedDrops: z.string().nullable().optional(),
  targetNetworkId: z.number().nullable().optional(), metaPresent: bool, proofPresent: bool,
  validators: z.record(z.string(), z.unknown()).nullable().optional(), warnings: arr, summary: str, ...err,
};

export const HOST_DIAGNOSTICS_OUT = {
  address: str, network: str, isRegisteredHost: bool, summary: str,
  checks: arr,
  registration: z.record(z.string(), z.unknown()).nullable().optional(),
  heartbeat: z.record(z.string(), z.unknown()).nullable().optional(),
  specs: z.record(z.string(), z.unknown()).nullable().optional(),
  balances: obj, leases: obj,
  warnings: arr, notes: arr, ...err,
};

export const REWARD_STATUS_OUT = {
  address: str, network: str, optedIn: bool, summary: str,
  balanceXah: z.number().nullable().optional(),
  fields: z.record(z.string(), z.unknown()).nullable().optional(),
  params: obj,
  eligibility: z.record(z.string(), z.unknown()).nullable().optional(),
  accrual: z.record(z.string(), z.unknown()).nullable().optional(),
  unsignedTx: z.record(z.string(), z.unknown()).nullable().optional(),
  unsignedTxPurpose: z.string().nullable().optional(),
  warnings: arr, notes: arr, ...err,
};

export const DIAGNOSE_TX_OUT = {
  txHash: str, network: str, found: bool, validated: z.boolean().nullable().optional(),
  engineResult: z.string().nullable().optional(), engineResultCode: z.number().nullable().optional(),
  resultClass: z.string().nullable().optional(), failed: z.boolean().nullable().optional(),
  summary: str, whatItTried: z.string().nullable().optional(),
  causes: arr, fixes: arr, hookRejections: arr,
  partialDelivery: z.record(z.string(), z.unknown()).nullable().optional(),
  notes: arr, ...err,
};

export const SIMULATE_OUT = {
  verdict: str, summary: str, ledgerIndex: num, historical: bool,
  hookRuns: arr, staticChecks: arr,
  transactor: z.record(z.string(), z.unknown()).nullable().optional(),
  scamScore: z.record(z.string(), z.unknown()).nullable().optional(),
  notes: arr, caveat: str,
  baseTxHash: str, overriddenFields: arr, ...err,
};
