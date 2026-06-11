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
import { runHook, type SandboxResult } from "./sandbox.js";
import { reconstructContext } from "./fidelity.js";
import { hexToBytes } from "./wasm.js";
import { decodeHookOn } from "./hookon.js";
import { inspectEmitted } from "./emitted.js";
import { scorePayload } from "./scam.js";
import { validateAddress } from "./util.js";

/** applyHook.cpp getTransactionalStakeHolders — the statically-derivable rows.
 *  field: top-level tx field holding an account; strong: can rollback. */
const TSH_TABLE: Record<string, { field: string; strong: boolean }[]> = {
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
const TSH_PARTIAL = new Set(["EscrowFinish", "EscrowCancel", "CheckCash", "CheckCancel", "PaymentChannelFund", "PaymentChannelClaim", "URITokenBuy", "URITokenBurn", "URITokenCancelSellOffer", "NFTokenAcceptOffer", "NFTokenCancelOffer", "NFTokenBurn", "NFTokenCreateOffer"]);

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
  sleep?: (ms: number) => Promise<void>;
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
  scamScore: { dangerScore: number; tier: string } | null;
  notes: string[];
  caveat: string;
}

const SPACING_MS = 1100;
const MAX_RESOLVE_ROUNDS = 8;

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
  opts: { ledgerIndex?: number; closeTime?: number } = {},
): Promise<Simulation> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
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
  await sleep(SPACING_MS);
  const senderInfo = await deps.getAccountInfo(sender);
  const sa = (senderInfo?.account_data ?? senderInfo) as Record<string, any> | null;
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
      const spendable = BigInt(sa.Balance) - 1_000_000n; // base reserve, STATIC approximation
      staticChecks.push(need <= spendable
        ? { name: "balance", status: "PASS", detail: `amount+fee within spendable balance` }
        : { name: "balance", status: "FAIL", detail: `amount+fee ${need} drops exceeds spendable ~${spendable} drops (after 1 XAH base reserve; owner reserve NOT counted — STATIC check)` });
    }
  }
  if (tx.LastLedgerSequence !== undefined && !historical && Number(tx.LastLedgerSequence) <= ledgerIndex) {
    staticChecks.push({ name: "LastLedgerSequence", status: "FAIL", detail: `already expired (tx ${tx.LastLedgerSequence} <= validated ${ledgerIndex}) — tefMAX_LEDGER` });
  }
  if (txType === "Payment" && typeof tx.Destination === "string") {
    await sleep(SPACING_MS);
    const di = await deps.getAccountInfo(tx.Destination as string);
    const da = (di?.account_data ?? di) as Record<string, any> | null;
    if (!da) staticChecks.push({ name: "destination exists", status: typeof tx.Amount === "string" && BigInt(tx.Amount as string) >= 1_000_000n ? "WARN" : "FAIL", detail: `${tx.Destination} does not exist — payment must carry >= 1 XAH to create it (else tecNO_DST)` });
    else {
      const requireTag = ((da.Flags ?? 0) & 0x00020000) !== 0; // lsfRequireDestTag
      if (requireTag && tx.DestinationTag === undefined) staticChecks.push({ name: "destination tag", status: "FAIL", detail: "destination requires a DestinationTag (tecDST_TAG_NEEDED)" });
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
    await sleep(SPACING_MS);
    const hooksArr = await deps.getAccountHooks(sh.account);
    const hooks = hooksArr.map((w) => (w as any).Hook ?? w).filter((h) => h && typeof h === "object");
    for (let pos = 0; pos < hooks.length; pos++) {
      const h = hooks[pos] as Record<string, any>;
      const hash = typeof h.HookHash === "string" ? h.HookHash : null;
      if (!hash) continue;
      await sleep(SPACING_MS);
      const def = await deps.getHookDefinition(hash);
      if (!hookOnFires(h, def, txType, sh.outgoing)) {
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
      for (let round = 0; round < MAX_RESOLVE_ROUNDS; round++) {
        const ctx = reconstructContext(tx, accountId, closeTime, undefined, foreignState, keyletBlobs, Object.keys(params).length ? params : undefined);
        ctx.hookHash = hash;
        ctx.ledgerSeq = ledgerIndex;
        if (namespace) ctx.hookNamespace = namespace;
        r = runHook(hexToBytes(code), ctx);
        const wantsF = r.wantedForeignState.filter((k) => !(k in foreignState));
        const wantsK = r.wantedKeylets.filter((k) => !(k in keyletBlobs));
        if (!wantsF.length && !wantsK.length) break;
        let progressed = false;
        for (const composite of wantsF) {
          const [acc, ns, key] = composite.split("|");
          await sleep(SPACING_MS);
          const fv = await deps.getHookState(acc, ns, key);
          if (fv === undefined) continue; // unavailable — stays degraded
          foreignState[composite] = fv; resolved++; progressed = true;
        }
        for (const idx of wantsK) {
          await sleep(SPACING_MS);
          const blob = await deps.getLedgerObject(idx);
          if (blob === undefined) continue; // unavailable — stays degraded
          keyletBlobs[idx] = blob; resolved++; progressed = true; // string or confirmed-absent null
        }
        if (!progressed) break;
      }

      const run: HookSimResult = {
        role: sh.role, account: sh.account, position: pos, hookHash: hash, strong: sh.strong, fired: true,
        exit: r!.exit, returnCode: r!.returnCode, returnString: r!.returnString,
        degraded: r!.degraded, unsupportedCalls: r!.unsupportedCalls, syntheticCalls: r!.syntheticCalls,
        stateWrites: r!.stateWrites, foreignStateWrites: r!.foreignStateWrites,
        emitted: r!.emitted.length ? inspectEmitted(r!.emitted) : null,
        resolvedReads: resolved,
      };
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
  if (strongRejection) verdict = "WOULD_FAIL_HOOKS";
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
    verdict, summary, ledgerIndex, historical, hookRuns, staticChecks, scamScore: scam, notes,
    caveat: "Simulates the HOOK layer with real bytecode against real ledger state (VM measured 100% on 30 real mainnet executions — accept-direction; rollback direction proven on real genesis bytecode, see docs/FIDELITY.md) plus labeled STATIC engine preflights. NOT full consensus: paths/offers/owner-reserve interactions and ledger-object-derived stakeholders are out of scope and flagged in notes. Hook state writes/emits shown are simulated, never submitted.",
  };
}
