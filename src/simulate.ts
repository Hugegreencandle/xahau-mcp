// simulate_transaction — the PRE-SIGN FLIGHT SIMULATOR. Take an UNSIGNED transaction and predict
// what Xahau's hooks will do with it BEFORE you sign: every hook it would trigger runs as REAL
// bytecode against LIVE (or historical) ledger state in the local VM — the same VM measured at
// 100% agreement on 30 real mainnet hook executions (accept-direction; rollback direction proven on
// real genesis bytecode in tests/regression.test.ts — see docs/FIDELITY.md for the composition).
//
// Execution semantics are CANONICAL, verified against xahaud Transactor.cpp + applyHook.cpp
// (fetched 2026-06-11):
//   1. The ORIGINATOR's hook chain runs first (HookOnOutgoing, falling back to legacy HookOn),
//      strong — it can roll the tx back. (Skipped for emitted txns.)
//   2. STRONG transactional stakeholders (TSH) run next, pre-application, in the insertion order of
//      applyHook.cpp getTransactionalStakeHolders — each can roll back (-> tecHOOK_REJECTED).
//   3. WEAK TSH execute post-application (collect-only, cannot reject) — we run + report them,
//      clearly labeled.
// The TSH table below mirrors applyHook.cpp per tx type. Tx types whose stakeholders require
// ledger-object lookups we don't perform (escrows/checks/NFT offers by id) are flagged honestly.
//
// HONESTY: this simulates the HOOK layer plus static engine preflights (sequence/fee/balance/
// destination). It is NOT full consensus — paths/offers/reserve interactions beyond the static
// checks are out of scope and labeled. Each hook run carries the VM's own degraded/synthetic flags.
import { runHook, type SandboxResult, type SandboxContext } from "./sandbox.js";
import { reconstructContext } from "./fidelity.js";
import { hexToBytes } from "./wasm.js";
import { decodeHookOn } from "./hookon.js";
import { inspectEmitted } from "./emitted.js";
import { scorePayload } from "./scam.js";
import { validateAddress } from "./util.js";
import { predictTransactor, TRANSACTOR_SUPPORTED, type TransactorPrediction } from "./transactorLite.js";

/** applyHook.cpp getTransactionalStakeHolders — the statically-derivable rows.
 *  field: top-level tx field holding an account; strong: can rollback. */
export const TSH_TABLE: Record<string, { field: string; strong: boolean }[]> = {
  Payment: [{ field: "Destination", strong: true }],
  Invoke: [{ field: "Destination", strong: true }],
  EscrowCreate: [{ field: "Destination", strong: true }],
  CheckCreate: [{ field: "Destination", strong: true }],
  AccountDelete: [{ field: "Destination", strong: true }],
  PaymentChannelCreate: [{ field: "Destination", strong: true }],
  ClaimReward: [{ field: "Issuer", strong: true }],
  NFTokenMint: [{ field: "Issuer", strong: true }],
  SetRegularKey: [{ field: "RegularKey", strong: true }],
  DepositPreauth: [{ field: "Authorize", strong: true }],
  URITokenMint: [{ field: "Destination", strong: true }],
  URITokenCreateSellOffer: [{ field: "Destination", strong: true }],
  Remit: [{ field: "Destination", strong: true }, { field: "Inform", strong: false }],
  Import: [{ field: "Issuer", strong: false }],
  // no extra stakeholders:
  AccountSet: [], OfferCancel: [], TicketCreate: [], SetHook: [], OfferCreate: [],
};
// stakeholders that would need ledger-object lookups we don't perform — flagged, not guessed
export const TSH_PARTIAL = new Set(["EscrowFinish", "EscrowCancel", "CheckCash", "CheckCancel", "PaymentChannelFund", "PaymentChannelClaim", "URITokenBuy", "URITokenBurn", "URITokenCancelSellOffer", "NFTokenAcceptOffer", "NFTokenCancelOffer", "NFTokenBurn", "NFTokenCreateOffer"]);

/** Static, no-RPC, no-bytecode prediction of which accounts' hooks a transaction WOULD invoke,
 *  with strong/weak (rollback-capable) roles. Derived from the statically-known TSH table; for tx
 *  types whose stakeholders need ledger-object lookups, returns a `partial` flag instead of guessing.
 *  (For a full prediction that runs the real hook bytecode, use simulate_transaction.) */
export function staticStakeholders(tx: Record<string, unknown>) {
  const txType = tx.TransactionType as string | undefined;
  const sender = tx.Account as string | undefined;
  const stakeholders: { account: string; role: string; strong: boolean }[] = [];
  if (sender) stakeholders.push({ account: sender, role: "originator", strong: true });
  let partial = false;
  const notes: string[] = [];
  if (!txType) {
    notes.push("tx has no TransactionType — only the originator could be determined");
  } else if (TSH_TABLE[txType]) {
    for (const r of TSH_TABLE[txType]) {
      const v = tx[r.field];
      if (typeof v === "string" && v !== sender) stakeholders.push({ account: v, role: `TSH:${r.field}`, strong: r.strong });
    }
  } else if (TSH_PARTIAL.has(txType)) {
    partial = true;
    notes.push(`${txType}: additional stakeholders come from ledger objects (escrow/check/offer owners) not derivable statically — incomplete without a ledger read`);
  } else {
    notes.push(`${txType}: no TSH-table entry — only the originator's hooks would fire`);
  }
  return {
    transactionType: txType ?? null,
    stakeholderCount: stakeholders.length,
    stakeholders,
    partial,
    strongCount: stakeholders.filter((s) => s.strong).length,
    weakCount: stakeholders.filter((s) => !s.strong).length,
    notes,
    summary: `${stakeholders.length} account(s) whose hooks would fire for ${txType ?? "(unknown)"}${partial ? " (partial — see notes)" : ""}`,
    caveat: "Static prediction from tx fields only — no bytecode run, no ledger read. strong = the hook can rollback the transaction; weak = it runs but cannot rollback. Use simulate_transaction to actually execute the hooks.",
  };
}

export interface SimDeps {
  /** account_objects(type:hook) -> the Hook ledger object's Hooks array (wrappers ok), or [] */
  getAccountHooks: (account: string) => Promise<Record<string, any>[]>;
  /** ledger_entry hook_definition -> { createCodeHex, hookOn, parameters } or null */
  getHookDefinition: (hash: string) => Promise<Record<string, any> | null>;
  getAccountInfo: (account: string) => Promise<Record<string, any> | null>;
  /** ledger_entry hook_state at the simulation ledger; null = entryNotFound (confirmed absent), undefined = unavailable */
  getHookState: (account: string, namespace: string, key: string) => Promise<string | null | undefined>;
  /** ledger_entry by index (binary) at the simulation ledger; null = entryNotFound (confirmed absent), undefined = unavailable */
  getLedgerObject: (index: string) => Promise<string | null | undefined>;
  getLedgerInfo: () => Promise<{ ledgerIndex: number; closeTime: number }>;
  getFee: () => Promise<number>; // base fee drops
  /** account_lines entries (for the approximate transactor: IOU Payment / TrustSet) */
  getAccountLines?: (account: string) => Promise<Record<string, any>[]>;
  /** network reserve params in drops (for the approximate transactor) */
  getReserves?: () => Promise<{ baseDrops: bigint; incDrops: bigint }>;
  sleep?: (ms: number) => Promise<void>;
  /** inter-read spacing in ms; simdeps sets this from XAHC_SIM_SPACING_MS (own-node -> 0, public ~300). Defaults to SPACING_MS. */
  spacingMs?: number;
  /** Overall wall-clock budget for the whole simulation, in ms. A crafted hook can chain
   *  MAX_RESOLVE_ROUNDS × live reads at spacingMs each, pinning the few inflight RPC slots.
   *  Once this deadline passes we STOP resolving further reads and mark the run degraded
   *  (INDETERMINATE) instead of holding a slot indefinitely. Defaults to XAHC_SIM_DEADLINE_MS
   *  (15000), or DEADLINE_MS when unset. 0/absent on a trusted in-process caller is fine. */
  deadlineMs?: number;
  /** Cumulative cap on resolved foreign-state/keylet reads across the whole request. Bounds the
   *  RPC amplification a hostile hook can drive. Defaults to XAHC_SIM_MAX_READS (64), or MAX_READS. */
  maxReads?: number;
}

export interface HookSimResult {
  role: string; // "originator" | "TSH:Destination (strong)" | ...
  account: string;
  position: number;
  hookHash: string | null;
  strong: boolean;
  fired: boolean;
  skippedReason?: string;
  exit?: SandboxResult["exit"];
  returnCode?: string | null;
  returnString?: string | null;
  degraded?: boolean;
  unsupportedCalls?: string[];
  syntheticCalls?: string[];
  stateWrites?: { key: string; value: string }[];
  foreignStateWrites?: { account: string; namespace: string; key: string; value: string }[];
  emitted?: { count: number; inspections: unknown[]; headline: string } | null;
  resolvedReads?: number;
}

export interface PreflightCheck { name: string; status: "PASS" | "WARN" | "FAIL" | "SKIP"; detail: string }

export interface Simulation {
  verdict: "WOULD_PASS_HOOKS" | "WOULD_FAIL_HOOKS" | "NO_HOOKS_FIRE" | "INDETERMINATE";
  summary: string;
  ledgerIndex: number;
  historical: boolean;
  hookRuns: HookSimResult[];
  staticChecks: PreflightCheck[];
  /** APPROXIMATE normal-transaction effects (the missing `simulate` RPC stand-in). null if not
   *  computed (deps unavailable). fidelity UNSUPPORTED for tx types not modeled. */
  transactor: TransactorPrediction | null;
  scamScore: { dangerScore: number; tier: string } | null;
  notes: string[];
  caveat: string;
}

const SPACING_MS = 1100;
const MAX_RESOLVE_ROUNDS = 8;
// Overall request budgets — defend the single rate-limited node against RPC amplification by a
// crafted hook (MAX_RESOLVE_ROUNDS × live reads at SPACING_MS each, pinning the few inflight slots).
// Read from env so deployments can tune; deps.deadlineMs / deps.maxReads override per-call.
// Guard with Number.isFinite (mirrors simdeps.ts spacingMs): `??` only catches undefined/null, so
// XAHC_SIM_DEADLINE_MS="" → 0 (deadline silently DISABLED) and ="abc" → NaN (NaN>0 false AND
// totalReads>=NaN false → BOTH deadline AND read-cap silently disabled). Empty/garbage must fall
// back to the safe default; a deliberate 0 (Number.isFinite(0) === true) still disables, as documented.
// NOTE: Number("") === 0 (finite), but an empty/unset var means "unconfigured" → safe default, not
// "disable". Treat "" like undefined (as simdeps.ts does for spacing); only a literal "0" disables.
const parseBudget = (raw: string | undefined, fallback: number): number => {
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
};
const DEADLINE_MS = parseBudget(process.env.XAHC_SIM_DEADLINE_MS, 15000);
const MAX_READS = parseBudget(process.env.XAHC_SIM_MAX_READS, 64);

function extractParams(arr: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const w of (arr as any[]) ?? []) {
    const p = w && w.HookParameter ? w.HookParameter : w;
    if (p && typeof p.HookParameterName === "string") out[p.HookParameterName.toUpperCase()] = String(p.HookParameterValue ?? "").toUpperCase();
  }
  return out;
}

function hookOnFires(hookObj: Record<string, any>, def: Record<string, any> | null, txType: string, outgoing: boolean): boolean {
  // getHookOn (applyHook.cpp): per-direction field on Hook obj, then legacy HookOn on obj,
  // then per-direction on definition, then legacy on definition, else zero-mask.
  const dirField = outgoing ? "HookOnOutgoing" : "HookOnIncoming";
  const mask = hookObj[dirField] ?? hookObj.HookOn ?? def?.[dirField] ?? def?.HookOn ?? def?.hookOn;
  if (typeof mask !== "string") return false; // zero/unknown mask: default HookOn fires nothing but Invoke-class? honest: don't guess
  try { return decodeHookOn(mask).firesOn.includes(txType); } catch { return false; }
}

export async function simulateTransaction(
  tx: Record<string, unknown>,
  deps: SimDeps,
  opts: {
    ledgerIndex?: number;
    closeTime?: number;
    /** Simulate NOT-YET-DEPLOYED code: account r-address -> candidate hook. When present
     *  for a stakeholder, its on-ledger hook chain is replaced by this single candidate so a
     *  freshly-compiled wasm runs against the full live-ledger TSH chain BEFORE SetHook. */
    candidateHooks?: Record<string, { createCodeHex: string; hookOn?: string; parameters?: unknown[]; namespace?: string }>;
    /** Override how hook bytecode is executed. The PUBLIC HTTP shim injects a
     *  worker-isolated, timeout+memory-capped runner so untrusted wasm can't hang
     *  or OOM the process. Defaults to the in-process synchronous runHook (used by
     *  the stdio MCP, the fidelity harness and tests — all trusted/bounded). */
    runHook?: (bytes: Uint8Array, ctx: SandboxContext) => SandboxResult | Promise<SandboxResult>;
  } = {},
): Promise<Simulation> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const runHookFn = opts.runHook ?? runHook;
  const spacing = deps.spacingMs ?? SPACING_MS;
  // Overall request budgets (see DEADLINE_MS / MAX_READS). deadlineMs <= 0 disables the deadline.
  const deadlineMs = deps.deadlineMs ?? DEADLINE_MS;
  const maxReads = deps.maxReads ?? MAX_READS;
  const startedAt = Date.now();
  const deadlinePassed = () => deadlineMs > 0 && Date.now() - startedAt > deadlineMs;
  let totalReads = 0; // cumulative resolved foreign-state/keylet reads across the whole request
  let budgetExhausted = false; // set once deadline OR read-cap stops further resolution
  const notes: string[] = [];
  const staticChecks: PreflightCheck[] = [];
  const hookRuns: HookSimResult[] = [];
  const txType = String(tx.TransactionType ?? "");
  const sender = String(tx.Account ?? "");

  const live = await deps.getLedgerInfo();
  tx = { ...tx }; // never mutate the caller's object
  const ledgerIndex = opts.ledgerIndex ?? live.ledgerIndex;
  const closeTime = opts.closeTime ?? live.closeTime;
  const historical = opts.ledgerIndex !== undefined && opts.ledgerIndex !== live.ledgerIndex;

  // ---------- static engine preflights (labeled STATIC — not consensus) ----------
  await sleep(spacing);
  const senderInfo = await deps.getAccountInfo(sender);
  const sa = (senderInfo?.account_data ?? senderInfo) as Record<string, any> | null;
  // Fetch real reserve params ONCE — single source for the static balance check AND the transactor
  // block below. Falls back to a STATIC 1 XAH base / 0 owner reserve only when getReserves is absent.
  let reserves: { baseDrops: bigint; incDrops: bigint } | null = null;
  if (sa && deps.getReserves) {
    await sleep(spacing);
    try { reserves = await deps.getReserves(); } catch { /* fall back to static approximation */ }
  }
  if (!sa) staticChecks.push({ name: "sender exists", status: "FAIL", detail: `${sender} not found on this network` });
  else {
    staticChecks.push({ name: "sender exists", status: "PASS", detail: sender });
    // the binary codec needs Sequence/Fee to serialize the otxn the hooks will read — autofill like
    // prepare_transaction does, and say so (the SIGNED tx must carry the same values to match)
    if (tx.Sequence === undefined) { tx.Sequence = Number(sa.Sequence ?? 0); notes.push(`Sequence autofilled to ${tx.Sequence} (account's current) so hooks can read the serialized tx`); }
    if (tx.Fee === undefined) { const f = await deps.getFee(); tx.Fee = String(f); notes.push(`Fee autofilled to ${tx.Fee} drops (network base) so hooks can read the serialized tx`); }
    if (tx.Sequence !== undefined && !historical) {
      const cur = Number(sa.Sequence);
      staticChecks.push(Number(tx.Sequence) === cur
        ? { name: "sequence", status: "PASS", detail: `Sequence ${tx.Sequence} matches the account` }
        : { name: "sequence", status: Number(tx.Sequence) < cur ? "FAIL" : "WARN", detail: `tx Sequence ${tx.Sequence} vs account ${cur} — ${Number(tx.Sequence) < cur ? "already used (tefPAST_SEQ)" : "future (would wait: terPRE_SEQ)"}` });
    }
    if (txType === "Payment" && typeof tx.Amount === "string" && typeof sa.Balance === "string") {
      const need = BigInt(tx.Amount as string) + BigInt(String(tx.Fee ?? "100000"));
      // Real reserve when available: base + ownerCount*inc (matches transactorLite). Falls back to
      // the static 1 XAH base / 0 owner reserve only when getReserves is unavailable.
      const ownerCount = BigInt(Math.max(0, Number(sa.OwnerCount ?? 0)));
      const reserve = reserves ? reserves.baseDrops + ownerCount * reserves.incDrops : 1_000_000n;
      const spendable = BigInt(sa.Balance) - reserve;
      const reserveNote = reserves
        ? `after ${reserve} drops reserve (base ${reserves.baseDrops} + ${ownerCount} owner × ${reserves.incDrops})`
        : `after 1 XAH base reserve; owner reserve NOT counted — STATIC fallback`;
      staticChecks.push(need <= spendable
        ? { name: "balance", status: "PASS", detail: `amount+fee within spendable balance (${reserveNote})` }
        : { name: "balance", status: "FAIL", detail: `amount+fee ${need} drops exceeds spendable ~${spendable} drops (${reserveNote})` });
    }
  }
  if (tx.LastLedgerSequence !== undefined && !historical && Number(tx.LastLedgerSequence) <= ledgerIndex) {
    staticChecks.push({ name: "LastLedgerSequence", status: "FAIL", detail: `already expired (tx ${tx.LastLedgerSequence} <= validated ${ledgerIndex}) — tefMAX_LEDGER` });
  }
  let destAcct: Record<string, any> | null = null;
  if (txType === "Payment" && typeof tx.Destination === "string") {
    await sleep(spacing);
    const di = await deps.getAccountInfo(tx.Destination as string);
    const da = (di?.account_data ?? di) as Record<string, any> | null;
    destAcct = da;
    if (!da) {
      // Account creation requires >= the live base reserve (transactorLite uses the same value);
      // fall back to the 1 XAH static literal only when reserves couldn't be fetched.
      const createThreshold = reserves ? reserves.baseDrops : 1_000_000n;
      const thresholdLabel = reserves ? `${createThreshold} drops (live base reserve)` : `1 XAH (STATIC fallback — reserves unavailable)`;
      staticChecks.push({ name: "destination exists", status: typeof tx.Amount === "string" && BigInt(tx.Amount as string) >= createThreshold ? "WARN" : "FAIL", detail: `${tx.Destination} does not exist — payment must carry >= ${thresholdLabel} to create it (else tecNO_DST)` });
    }
    else {
      const requireTag = ((da.Flags ?? 0) & 0x00020000) !== 0; // lsfRequireDestTag
      if (requireTag && tx.DestinationTag === undefined) staticChecks.push({ name: "destination tag", status: "FAIL", detail: "destination requires a DestinationTag (tecDST_TAG_NEEDED)" });
    }
  }

  // ---------- approximate transactor (stand-in for the missing `simulate` RPC) ----------
  let transactor: TransactorPrediction | null = null;
  if (sa && reserves) {
    try {
      let senderLines: Record<string, any>[] = [];
      const iouPayment = txType === "Payment" && tx.Amount !== null && typeof tx.Amount === "object";
      if ((iouPayment || txType === "TrustSet") && deps.getAccountLines) {
        await sleep(spacing);
        senderLines = await deps.getAccountLines(sender);
      }
      transactor = predictTransactor({
        tx, sender: sa, dest: destAcct, senderLines,
        reserveBaseDrops: reserves.baseDrops, reserveIncDrops: reserves.incDrops,
      });
      if (transactor.fidelity === "UNSUPPORTED") {
        notes.push(`transactor: normal-tx effects for ${txType || "this tx"} are not modeled (APPROXIMATE model covers: ${[...TRANSACTOR_SUPPORTED].join(", ")}); the hook layer above is faithful`);
      } else if (transactor.predictedResult && transactor.predictedResult !== "tesSUCCESS") {
        notes.push(`transactor (APPROXIMATE): would likely ${transactor.predictedResult} — ${transactor.reason}`);
      }
    } catch (e) {
      notes.push(`transactor: skipped (${(e as Error).message})`);
    }
  }

  // ---------- collect the hook chain: originator first, then TSH (canonical order) ----------
  const stakeholders: { account: string; role: string; strong: boolean; outgoing: boolean }[] = [];
  if (sender) stakeholders.push({ account: sender, role: "originator", strong: true, outgoing: true });
  const rows = TSH_TABLE[txType];
  if (rows) {
    for (const r of rows) {
      const v = (tx as Record<string, any>)[r.field];
      if (typeof v === "string" && v !== sender) stakeholders.push({ account: v, role: `TSH:${r.field} (${r.strong ? "strong" : "weak"})`, strong: r.strong, outgoing: false });
    }
  } else if (TSH_PARTIAL.has(txType)) {
    notes.push(`${txType}: additional stakeholders are derived from ledger objects (escrow/check/offer owners) which this simulator does not auto-collect — their hooks are NOT simulated (honest gap)`);
  } else if (txType) {
    notes.push(`${txType}: no TSH table entry — only the originator's hooks are simulated`);
  }

  // ---------- run each stakeholder's hook chain ----------
  let strongRejection: HookSimResult | null = null;
  for (const sh of stakeholders) {
    // overall budget blown — don't open any more stakeholder chains (each costs node reads)
    if (budgetExhausted || deadlinePassed()) {
      budgetExhausted = true;
      notes.push(`request budget exhausted before simulating ${sh.role} (${sh.account}) — its hook chain was NOT fetched/run (verdict INDETERMINATE)`);
      break;
    }
    const candidate = opts.candidateHooks?.[sh.account];
    let hooks: Record<string, any>[];
    if (candidate) {
      // not-yet-deployed code: a synthetic single-hook chain from the candidate
      hooks = [{ HookHash: "CANDIDATE", HookNamespace: candidate.namespace, HookParameters: candidate.parameters }];
      notes.push(`candidate code simulated for ${sh.account} (${candidate.createCodeHex.length / 2} bytes, NOT yet on ledger)`);
    } else {
      await sleep(spacing);
      const hooksArr = await deps.getAccountHooks(sh.account);
      hooks = hooksArr.map((w) => (w as any).Hook ?? w).filter((h) => h && typeof h === "object");
    }
    for (let pos = 0; pos < hooks.length; pos++) {
      const h = hooks[pos] as Record<string, any>;
      const hash = typeof h.HookHash === "string" ? h.HookHash : null;
      if (!hash) continue;
      let def: Record<string, any> | null;
      if (candidate) {
        def = { createCodeHex: candidate.createCodeHex, HookOn: candidate.hookOn, HookParameters: candidate.parameters };
      } else {
        await sleep(spacing);
        def = await deps.getHookDefinition(hash);
      }
      // a candidate with no declared HookOn is assumed to fire (you're testing the code);
      // a deployed hook (or a candidate WITH a HookOn) is gated by the real fire mask.
      const fires = candidate && !candidate.hookOn ? true : hookOnFires(h, def, txType, sh.outgoing);
      if (!fires) {
        hookRuns.push({ role: sh.role, account: sh.account, position: pos, hookHash: hash, strong: sh.strong, fired: false, skippedReason: `HookOn does not include ${txType}` });
        continue;
      }
      const code = def?.createCodeHex ?? def?.CreateCode;
      if (typeof code !== "string" || !code.length) {
        hookRuns.push({ role: sh.role, account: sh.account, position: pos, hookHash: hash, strong: sh.strong, fired: true, skippedReason: "CreateCode unavailable — cannot simulate", degraded: true });
        continue;
      }
      const v = validateAddress(sh.account);
      const accountId = v.valid && "accountId" in v && typeof v.accountId === "string" ? v.accountId : "00".repeat(20);
      const params = { ...extractParams(def?.HookParameters ?? def?.parameters), ...extractParams(h.HookParameters) };
      const namespace = typeof h.HookNamespace === "string" ? h.HookNamespace : typeof def?.HookNamespace === "string" ? def.HookNamespace : undefined;

      // iterative resolve: run, fetch exactly what it asks for at the simulation ledger, re-run
      const foreignState: Record<string, string | null> = {};
      const keyletBlobs: Record<string, string | null> = {};
      let r: SandboxResult | null = null;
      let resolved = 0;
      let runDegradedByBudget = false; // this hook stopped resolving due to deadline/read-cap
      for (let round = 0; round < MAX_RESOLVE_ROUNDS; round++) {
        const ctx = reconstructContext(tx, accountId, closeTime, undefined, foreignState, keyletBlobs, Object.keys(params).length ? params : undefined);
        ctx.hookHash = hash;
        ctx.ledgerSeq = ledgerIndex;
        if (namespace) ctx.hookNamespace = namespace;
        r = await runHookFn(hexToBytes(code), ctx);
        const wantsF = r.wantedForeignState.filter((k) => !(k in foreignState));
        const wantsK = r.wantedKeylets.filter((k) => !(k in keyletBlobs));
        if (!wantsF.length && !wantsK.length) break;
        // Stop resolving (leave the run degraded) once we'd blow the overall deadline or the
        // cumulative read cap — a hostile hook can't hold an inflight slot or hammer the node.
        if (deadlinePassed() || totalReads >= maxReads) { runDegradedByBudget = true; budgetExhausted = true; break; }
        let progressed = false;
        for (const composite of wantsF) {
          if (deadlinePassed() || totalReads >= maxReads) { runDegradedByBudget = true; budgetExhausted = true; break; }
          const [acc, ns, key] = composite.split("|");
          await sleep(spacing);
          const fv = await deps.getHookState(acc, ns, key);
          totalReads++;
          if (fv === undefined) continue; // unavailable — stays degraded
          foreignState[composite] = fv; resolved++; progressed = true;
        }
        for (const idx of wantsK) {
          if (deadlinePassed() || totalReads >= maxReads) { runDegradedByBudget = true; budgetExhausted = true; break; }
          await sleep(spacing);
          const blob = await deps.getLedgerObject(idx);
          totalReads++;
          if (blob === undefined) continue; // unavailable — stays degraded
          keyletBlobs[idx] = blob; resolved++; progressed = true; // string or confirmed-absent null
        }
        if (!progressed) break;
      }

      const run: HookSimResult = {
        role: sh.role, account: sh.account, position: pos, hookHash: hash, strong: sh.strong, fired: true,
        exit: r!.exit, returnCode: r!.returnCode, returnString: r!.returnString,
        degraded: r!.degraded || runDegradedByBudget, unsupportedCalls: r!.unsupportedCalls, syntheticCalls: r!.syntheticCalls,
        stateWrites: r!.stateWrites, foreignStateWrites: r!.foreignStateWrites,
        emitted: r!.emitted.length ? inspectEmitted(r!.emitted) : null,
        resolvedReads: resolved,
      };
      if (runDegradedByBudget) {
        notes.push(`request budget exhausted (${deadlinePassed() ? `>${deadlineMs}ms overall deadline` : `${maxReads}-read cumulative cap`}) while resolving ${sh.role} hook ${hash.slice(0, 12)}… — stopped fetching its reads; run forced degraded → verdict INDETERMINATE (not a pass)`);
      }
      hookRuns.push(run);
      if (sh.strong && r!.exit === "rollback" && !strongRejection) strongRejection = run;
      if (sh.strong && r!.exit === "rollback") break; // chain stops at first strong rollback
    }
    if (strongRejection) break;
  }

  // ---------- verdict ----------
  const fired = hookRuns.filter((x) => x.fired && !x.skippedReason);
  const anyDegraded = fired.some((x) => x.degraded);
  let verdict: Simulation["verdict"];
  // A real strong rollback we DID observe is authoritative even if the budget later ran out.
  if (strongRejection) verdict = "WOULD_FAIL_HOOKS";
  // Budget exhaustion means we couldn't finish — never report a pass; treat as unknown.
  else if (budgetExhausted) verdict = "INDETERMINATE";
  else if (!fired.length) verdict = "NO_HOOKS_FIRE";
  else if (anyDegraded) verdict = "INDETERMINATE";
  else verdict = "WOULD_PASS_HOOKS";

  let scam: Simulation["scamScore"] = null;
  try { const s = scorePayload(tx as Record<string, any>) as unknown as { dangerScore?: number; tier?: string }; if (typeof s.dangerScore === "number") scam = { dangerScore: s.dangerScore, tier: String(s.tier ?? "?") }; } catch { /* optional */ }

  const fails = staticChecks.filter((c) => c.status === "FAIL");
  const emitsTotal = fired.reduce((n, x) => n + (x.emitted?.count ?? 0), 0);
  const summary =
    (verdict === "WOULD_FAIL_HOOKS"
      ? `PREFLIGHT: WOULD FAIL — ${strongRejection!.role} hook ${strongRejection!.hookHash?.slice(0, 12)}… on ${strongRejection!.account} rolls back${strongRejection!.returnString ? ` ("${strongRejection!.returnString}")` : ""} → tecHOOK_REJECTED (fee would still burn).`
      : verdict === "WOULD_PASS_HOOKS"
        ? `PREFLIGHT: PASS — ${fired.length} hook(s) fire and all accept${emitsTotal ? `; ${emitsTotal} transaction(s) would be emitted` : ""}.`
        : verdict === "NO_HOOKS_FIRE"
          ? `PREFLIGHT: no hooks fire for this ${txType || "transaction"} — hook layer is clear.`
          : `PREFLIGHT: INDETERMINATE — a fired hook ran degraded (unresolved reads/unsupported calls); treat as unknown, not as pass.`) +
    (fails.length ? ` STATIC checks flag ${fails.length} engine-level problem(s): ${fails.map((f) => f.name).join(", ")}.` : "") +
    (historical ? ` (simulated at historical ledger ${ledgerIndex})` : ` (ledger ${ledgerIndex})`);

  return {
    verdict, summary, ledgerIndex, historical, hookRuns, staticChecks, transactor, scamScore: scam, notes,
    caveat: "Simulates the HOOK layer with real bytecode against real ledger state (VM measured 100% on 30 real mainnet executions — accept-direction; rollback direction proven on real genesis bytecode, see docs/FIDELITY.md) plus labeled STATIC engine preflights. NOT full consensus: paths/offers/owner-reserve interactions and ledger-object-derived stakeholders are out of scope and flagged in notes. Hook state writes/emits shown are simulated, never submitted.",
  };
}
