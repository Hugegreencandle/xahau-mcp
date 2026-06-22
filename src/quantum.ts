// Quantum-readiness (HNDL: Harvest-Now-Decrypt-Later) grading for Xahau accounts.
// Ports the xrpl-audit quantum_grade model to Xahau and adds a Hook/PQC dimension.
// ed25519 / secp256k1 keys are not quantum-safe; the near-term defense is minimizing exposed
// long-lived key material (disable the master key behind a rotatable regular key / signer list).
import { createHash } from "node:crypto";
import { getAccountInfo, getAccountObjects, getServerInfo, rpc, type Network } from "./rpc.js";
import { validateAddress } from "./util.js";

const LSF_DISABLE_MASTER = 0x00100000;

/** Derive a 20-byte AccountID (hex, upper) from a signing public key: RIPEMD160(SHA256(pubkey)). */
export function accountIdFromPubkey(pubkeyHex: string): string {
  const pub = Buffer.from(pubkeyHex, "hex");
  const sha = createHash("sha256").update(pub).digest();
  return createHash("ripemd160").update(sha).digest("hex").toUpperCase();
}

/** One self-originated transaction's signing evidence (newest/oldest-agnostic). */
export interface SignedTx { account: string; signingPubKey?: string; signers?: { signingPubKey?: string }[]; ledger?: number | null; }

export type HndlClass = "none" | "master" | "regular" | "multisig";

/**
 * PURE HNDL exposure classifier (no network). Given the account's r-address + AccountID and the
 * transactions it has ORIGINATED, decide which signing key material is now public on-ledger.
 *   - master   : a self-signed tx whose SigningPubKey hashes to THIS AccountID => the unrotatable
 *                master key's pubkey is exposed (IRREVERSIBLE under Shor — cannot be rotated).
 *   - regular  : a self-signed tx whose SigningPubKey hashes to a DIFFERENT AccountID => a regular
 *                key's pubkey is exposed (recoverable: rotate via SetRegularKey).
 *   - multisig : a self-signed multi-signed tx (empty SigningPubKey + Signers) => signer pubkeys
 *                exposed (recoverable: SignerListSet).
 *   - none     : the account has never originated a signed tx => only the hash is on-ledger.
 * `derive` is injected for testability. Priority master > regular > multisig.
 */
export function classifyHndl(rAddress: string, accountIdHex: string, txs: SignedTx[], derive = accountIdFromPubkey) {
  let masterExposed = false, regularExposed = false, multisigExposed = false;
  let signedTxCount = 0, firstExposureLedger: number | null = null;
  const acc = accountIdHex.toUpperCase();
  for (const t of txs) {
    if (t.account !== rAddress) continue;          // only txns this account ORIGINATED
    signedTxCount++;
    const spk = (t.signingPubKey ?? "").trim();
    let exposedHere = false;
    if (spk === "") {
      if ((t.signers ?? []).length > 0) { multisigExposed = true; exposedHere = true; }
    } else {
      if (derive(spk) === acc) masterExposed = true; else regularExposed = true;
      exposedHere = true;
    }
    if (exposedHere && t.ledger != null && (firstExposureLedger == null || t.ledger < firstExposureLedger))
      firstExposureLedger = t.ledger;
  }
  const exposureClass: HndlClass = masterExposed ? "master" : regularExposed ? "regular" : multisigExposed ? "multisig" : "none";
  return { exposed: exposureClass !== "none", exposureClass, masterExposed, regularExposed, multisigExposed, signedTxCount, firstExposureLedger };
}

export interface QuantumSignals {
  masterDisabled: boolean; hasRegularKey: boolean; hasMultiSig: boolean; signerCount: number;
  /** Account runs a Hook whose EXACT bytecode (by HookHash) is a registered, xahc-prover-PROVEN
   *  quantum-policy hook. Optional; absent => not credited (the honest default). */
  hasProvenQuantumHook?: boolean;
}

/**
 * Registry of quantum-policy Hooks whose bytecode has been PROVEN by xahc-prover.
 * Key = on-ledger HookHash (SHA-512Half of the hook wasm) — matching it proves the DEPLOYED
 * bytecode is byte-identical to the proven artifact (HookHash binds to wasm bytes). This is the
 * only honest way to credit a hook: not "a hook is installed", but "THIS proven hook is installed".
 */
export const PROVEN_QUANTUM_HOOKS: Record<string, { name: string; invariant: string; note: string }> = {
  // qkey_guard — forbids the master key from signing ordinary outgoing txns (master-disuse).
  // Proven 2026-06-21 (xahc-prover 39th invariant `master-disuse`), adversarially audited.
  "51285E956F1A611E911D035C3209F5E3B7DAF35BD5A78AF3C7B36F39F8C46596": {
    name: "qkey_guard",
    invariant: "master-disuse",
    note: "PROVEN: master key cannot sign ordinary outgoing txns (forces rotatable-key use). Master is admitted only for key/hook management (brick-safe). Caveat: master-key DISUSE, not compromise defense.",
  },
  // qday_vault — Q-Day recovery freeze: every outgoing tx requires the committed quantum-safe preimage.
  // Proven 2026-06-21 (xahc-prover 40th invariant `qday-freeze`), under SHA-512Half collision-resistance.
  "D1609B6E24EC3F29296FDB0071068273DBDA0428B6F13FDB6FEF71AC6FB9478F": {
    name: "qday_vault",
    invariant: "qday-freeze",
    note: "PROVEN: funds move ONLY for the holder of the committed quantum-safe secret — a Shor-broken classical key alone cannot spend. The strongest hardening; losing the secret loses access (no escape hatch by design).",
  },
};

/** Hardening-level label for a tier — framed as future-proofing, NOT a present-day safety alarm. */
const TIER_LABEL: Record<"LOW" | "MEDIUM" | "HIGH", string> = {
  LOW: "BASELINE", MEDIUM: "HARDENED", HIGH: "WELL HARDENED",
};

/**
 * Pure scorer (no network) — masterDisabled +40, multiSig +35, regularKey +25.
 * Score = FUTURE-hardening readiness against Harvest-Now-Decrypt-Later, NOT a safety alarm.
 * ed25519/secp256k1 are not broken today; a BASELINE account is not "unsafe", just un-hardened.
 */
export function gradeSignals(s: QuantumSignals): { score: number; tier: "LOW" | "MEDIUM" | "HIGH"; tierLabel: string; signals: string[]; recommendations: string[] } {
  const signals: string[] = [];
  let score = 0;
  if (s.masterDisabled) { score += 40; signals.push("master key disabled — long-lived key material minimized (+40)"); }
  else signals.push("master key active — normal default, not a flaw; disabling it behind a regular key / signer list is the single biggest future-hardening step");
  if (s.hasMultiSig) { score += 35; signals.push(`multi-sign active, ${s.signerCount} signer(s) (+35)`); }
  if (s.hasRegularKey) { score += 25; signals.push("regular key set — master key is rotatable (+25)"); }
  if (s.hasProvenQuantumHook) { score += 30; signals.push("PROVEN quantum-policy Hook enforced on-ledger — master key cannot sign ordinary txns (+30)"); }
  if (score > 100) score = 100;  // cap: the four signals can sum past 100; readiness tops out at 100
  const tier = score >= 70 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  const recommendations: string[] = [];
  if (!s.masterDisabled) recommendations.push("Optional hardening: after configuring a regular key or signer list, disable the master key (lsfDisableMaster) so the primary long-lived key can be retired.");
  if (!s.hasRegularKey && !s.hasMultiSig) recommendations.push("Optional hardening: set a regular key and/or a signer list so the master key can be rotated and then disabled.");
  if (!s.hasProvenQuantumHook) recommendations.push("Strongest Xahau-only hardening: install a PROVEN quantum-policy Hook (e.g. qkey_guard / master-disuse) that forbids the master key from signing ordinary transactions — enforcement XRPL accounts cannot make on-ledger.");
  return { score, tier, tierLabel: TIER_LABEL[tier], signals, recommendations };
}

export async function quantumGrade(address: string, network: Network) {
  const a = (await getAccountInfo(address, network)).account_data as Record<string, any>;
  const flags = Number(a.Flags ?? 0);
  const masterDisabled = (flags & LSF_DISABLE_MASTER) !== 0;
  const hasRegularKey = Boolean(a.RegularKey);

  let hasMultiSig = false, signerCount = 0;
  try {
    const objs = await getAccountObjects(address, network, "signer_list");
    const sl = objs.account_objects.find((o: any) => o.LedgerEntryType === "SignerList") as any;
    if (sl) { hasMultiSig = true; signerCount = (sl.SignerEntries ?? []).length; }
  } catch { /* tolerate */ }

  let hooksInstalled = 0;
  let provenHook: { name: string; invariant: string; note: string; hookHash: string } | null = null;
  try {
    const h = await getAccountObjects(address, network, "hook");
    const ho = h.account_objects.find((o: any) => o.LedgerEntryType === "Hook") as any;
    const hooks = (ho?.Hooks ?? []) as any[];
    hooksInstalled = hooks.length;
    // Step-4: credit a PROVEN quantum-policy hook by exact HookHash (binds to proven bytecode).
    // Each entry may be { Hook: {...} } or flat — mirror explain.ts's `w.Hook ?? w` unwrap.
    for (const e of hooks) {
      const hh = String((e?.Hook ?? e)?.HookHash ?? "").toUpperCase();
      const rec = hh && PROVEN_QUANTUM_HOOKS[hh];
      if (rec) { provenHook = { ...rec, hookHash: hh }; break; }
    }
  } catch { /* tolerate */ }

  const hasProvenQuantumHook = provenHook !== null;
  const { score, tier, tierLabel, signals, recommendations } =
    gradeSignals({ masterDisabled, hasRegularKey, hasMultiSig, signerCount, hasProvenQuantumHook });

  return {
    address, score, tier, tierLabel, signals,
    masterDisabled, hasRegularKey, hasMultiSig, signerCount, hooksInstalled,
    hasProvenQuantumHook, provenHook,
    // Honest hook dimension: a hook earns quantum credit ONLY when its exact bytecode (HookHash)
    // matches a registered, xahc-prover-PROVEN quantum-policy hook. Mere hook PRESENCE is never
    // scored — presence does not imply a key-rotation policy.
    hookPolicyNote: provenHook
      ? `PROVEN quantum-policy hook installed: ${provenHook.name} (invariant ${provenHook.invariant}, HookHash ${provenHook.hookHash.slice(0, 16)}…). Credited +30. ${provenHook.note}`
      : hooksInstalled > 0
        ? `${hooksInstalled} hook(s) installed — none match a registered PROVEN quantum-policy hook, so NOT scored. Presence alone earns no credit.`
        : "no hooks installed.",
    recommendations,
    framing: "FUTURE-hardening readiness, not a present-day safety alarm. ed25519/secp256k1 are not broken today; a BASELINE account is normal, not unsafe. Score reflects how hardened the account is against Harvest-Now-Decrypt-Later.",
    note: "HNDL (Harvest-Now-Decrypt-Later) readiness. Same key model as XRPL. Minimizing long-lived key material (rotate behind a regular key / signer list, then disable master) is the near-term defense.",
  };
}

/**
 * PURE coverage assessment — is a NEGATIVE ("none") HNDL verdict trustworthy? Only if the scan
 * provably covered the account's WHOLE history on BOTH ends:
 *   - early side: the node holds at least one ledger OLDER than the account's first seen tx, proving
 *     no earlier (e.g. master-signing setup) tx for this account was pruned away.
 *   - late side: the newest scanned tx reached the account's most-recent-tx ledger
 *     (account_info PreviousTxnLgrSeq) — this also subsumes pagination truncation and any early
 *     loop exit (both leave newestTxLedger short of the account's latest activity).
 * A POSITIVE finding (exposed) is always conclusive regardless of coverage.
 */
export function assessCoverage(o: {
  exposed: boolean; nodeEarliest: number | null; oldestTxLedger: number | null;
  newestTxLedger: number | null; accountLastLedger: number | null;
}) {
  const earlySideComplete = o.nodeEarliest != null && o.oldestTxLedger != null && o.oldestTxLedger > o.nodeEarliest;
  const lateSideComplete = o.accountLastLedger != null && o.newestTxLedger != null && o.newestTxLedger >= o.accountLastLedger;
  const coverageComplete = earlySideComplete && lateSideComplete;
  const conclusive = o.exposed || coverageComplete;
  return { earlySideComplete, lateSideComplete, coverageComplete, conclusive };
}

/**
 * HNDL EXPOSURE MEASUREMENT — does this account's signing public key sit on-ledger today, and
 * which key? An XRPL/Xahau address is RIPEMD160(SHA256(pubkey)); the pubkey is revealed only when
 * the account ORIGINATES a signed transaction. This walks the account's history (OLDEST-first,
 * because the master key is almost always used in an account's early setup txns before a regular
 * key exists) and classifies the exposure.
 *
 * Honesty: scanning is bounded (maxPages). If history is truncated and no master-signing was seen,
 * we CANNOT conclude the master key is unexposed — `truncated` says so explicitly. A POSITIVE
 * master/regular finding is always sound; only the NEGATIVE is coverage-bounded.
 */
export async function hndlExposure(address: string, network: Network, maxPages = 6, pageLimit = 400) {
  const v = validateAddress(address);
  if (!v.valid || !("accountId" in v)) throw new Error("not a valid r-address / X-address");
  const rAddress = ("classicAddress" in v ? v.classicAddress : address) as string;
  const accountId = (v as { accountId: string }).accountId;

  const a = (await getAccountInfo(rAddress, network)).account_data as Record<string, any>;
  const balanceDrops = String(a.Balance ?? "0");
  const masterDisabled = (Number(a.Flags ?? 0) & LSF_DISABLE_MASTER) !== 0;
  const accountLastLedger = Number.isFinite(Number(a.PreviousTxnLgrSeq)) ? Number(a.PreviousTxnLgrSeq) : null;

  // Node history range — needed to prove the scan reached the account's creation (early side).
  let nodeEarliest: number | null = null;
  try {
    const si = await getServerInfo(network);
    const cl = String((si.info as Record<string, any>)?.complete_ledgers ?? "");
    const starts = cl.split(",").map((seg) => parseInt(seg.split("-")[0], 10)).filter((n) => Number.isFinite(n));
    if (starts.length) nodeEarliest = Math.min(...starts);
  } catch { /* tolerate — absent node range => coverage cannot be proven => UNKNOWN below */ }

  // Paginate account_tx oldest-first, bounded.
  const txs: SignedTx[] = [];
  let marker: unknown = undefined;
  let pages = 0;
  let truncated = false;
  while (pages < maxPages) {
    const params: Record<string, unknown> = { account: rAddress, limit: pageLimit, ledger_index_min: -1, ledger_index_max: -1, forward: true };
    if (marker !== undefined) params.marker = marker;
    const r = await rpc<{ transactions?: Record<string, any>[]; marker?: unknown }>("account_tx", params, network);
    for (const t of r.transactions ?? []) {
      const tx = (t.tx ?? t.tx_json ?? t) as Record<string, any>;
      txs.push({
        account: String(tx.Account ?? ""),
        signingPubKey: typeof tx.SigningPubKey === "string" ? tx.SigningPubKey : "",
        signers: Array.isArray(tx.Signers) ? tx.Signers.map((s: any) => ({ signingPubKey: s?.Signer?.SigningPubKey })) : undefined,
        ledger: (tx.ledger_index ?? t.ledger_index ?? null) as number | null,
      });
    }
    pages++;
    marker = r.marker;
    if (marker === undefined || marker === null) break;
    if (pages >= maxPages) { truncated = true; break; }
  }

  const c = classifyHndl(rAddress, accountId, txs);

  const ledgers = txs.map((t) => t.ledger).filter((n): n is number => n != null);
  const oldestTxLedger = ledgers.length ? Math.min(...ledgers) : null;
  const newestTxLedger = ledgers.length ? Math.max(...ledgers) : null;
  const cov = assessCoverage({ exposed: c.exposed, nodeEarliest, oldestTxLedger, newestTxLedger, accountLastLedger });

  // Severity + balance-at-risk. Master exposure is IRREVERSIBLE (the master key cannot be rotated);
  // regular/multisig exposure is RECOVERABLE (rotate the key). A never-signed account is hash-only.
  // A POSITIVE finding is conclusive; a NEGATIVE is "NONE" only if coverage is PROVEN both ends,
  // else UNKNOWN — so a consumer never reads a coverage-bounded "none" as "safe".
  const conclusive = cov.conclusive;
  let severity: "NONE" | "RECOVERABLE" | "CRITICAL" | "UNKNOWN";
  let recoverable: boolean | null;
  if (c.masterExposed) { severity = "CRITICAL"; recoverable = false; }
  else if (c.regularExposed || c.multisigExposed) { severity = "RECOVERABLE"; recoverable = true; }
  else if (!conclusive) { severity = "UNKNOWN"; recoverable = null; }
  else { severity = "NONE"; recoverable = null; }
  const balanceAtRiskDrops = c.exposed ? balanceDrops : "0";

  const note =
    c.exposureClass === "master"
      ? "CRITICAL: the master key's public key is on-ledger. Under a future quantum computer (Shor) the private key is derivable, and the master key CANNOT be rotated — exposure is irreversible. Mitigation is limited: move funds to a fresh, never-signed account; a qkey_guard hook would have prevented this by barring master signing."
      : c.exposureClass === "regular"
        ? "RECOVERABLE: a regular key's public key is exposed, but the master key has not signed in the scanned history. Rotate the regular key (SetRegularKey) and keep routine signing off the master key (e.g. qkey_guard)."
        : c.exposureClass === "multisig"
          ? "RECOVERABLE: signer-list public keys are exposed; rotate them via SignerListSet. Master key not seen signing in the scanned history."
          : "NONE: this account has never originated a signed transaction in the scanned history, so only the hash of its public key is on-ledger — not Shor-actionable yet. It becomes exposed the moment it first signs.";

  return {
    address: rAddress, accountId, network,
    ...c, severity, recoverable, conclusive, balanceDrops, balanceAtRiskDrops, masterDisabled,
    scanned: {
      pages, txCount: txs.length, oldestFirst: true, truncated,
      nodeEarliestLedger: nodeEarliest, oldestTxLedger, newestTxLedger, accountLastLedger,
      earlySideComplete: cov.earlySideComplete, lateSideComplete: cov.lateSideComplete, coverageComplete: cov.coverageComplete,
    },
    note: severity === "UNKNOWN"
      ? "UNKNOWN: no key exposure was seen, but the scan did NOT provably cover the account's full history" +
        (!cov.earlySideComplete ? " (the queried node may not hold ledgers back to the account's creation — early master-signing could be pruned/unseen)" : "") +
        (!cov.lateSideComplete ? " (the scan did not reach the account's most recent transaction — raise maxPages or use a full-history node)" : "") +
        ". This is NOT a clean bill of health — re-run against a full-history node before trusting a negative."
      : note,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// QUANTUM READINESS SCORECARD — aggregate HNDL exposure + grade across a SAMPLE of
// accounts into a network-level readiness snapshot. Honesty: this is a SAMPLE of
// (by default) recently-active accounts, NOT the whole ledger — active accounts skew
// toward exposed, so figures are an upper-ish bound on exposure, not a census.
// ─────────────────────────────────────────────────────────────────────────────

export interface ScorecardRow {
  address: string;
  exposureClass: HndlClass;
  severity: "NONE" | "RECOVERABLE" | "CRITICAL" | "UNKNOWN";
  conclusive: boolean;
  balanceDrops: string;
  balanceAtRiskDrops: string;
  gradeScore: number;
  gradeTier: "LOW" | "MEDIUM" | "HIGH";
  hasProvenQuantumHook: boolean;
  masterDisabled: boolean;
}

const addDrops = (a: string, b: string): string => (BigInt(a || "0") + BigInt(b || "0")).toString();

/** PURE aggregation over per-account rows — no network. The scorecard's testable core. */
export function aggregateScorecard(rows: ScorecardRow[]) {
  // Bucket by the EFFECTIVE class: a non-conclusive "none" is reported as "unknown", never "none".
  const byClass = { master: 0, regular: 0, multisig: 0, none: 0, unknown: 0 };
  const byTier = { LOW: 0, MEDIUM: 0, HIGH: 0 };
  let totalBalance = "0", balanceAtRisk = "0", masterExposedBalance = "0";
  let masterExposed = 0, exposed = 0, conclusive = 0, provenHook = 0;
  for (const r of rows) {
    const eff: keyof typeof byClass = !r.conclusive && r.exposureClass === "none" ? "unknown" : r.exposureClass;
    byClass[eff]++;
    byTier[r.gradeTier]++;
    totalBalance = addDrops(totalBalance, r.balanceDrops);
    balanceAtRisk = addDrops(balanceAtRisk, r.balanceAtRiskDrops);
    if (r.exposureClass === "master") { masterExposed++; masterExposedBalance = addDrops(masterExposedBalance, r.balanceDrops); }
    if (r.exposureClass !== "none") exposed++;
    if (r.conclusive) conclusive++;
    if (r.hasProvenQuantumHook) provenHook++;
  }
  const n = rows.length || 1;
  const pct = (x: number) => Math.round((x / n) * 1000) / 10;
  const topExposedByBalance = [...rows]
    .filter((r) => r.exposureClass !== "none")
    .sort((a, b) => (BigInt(b.balanceAtRiskDrops) > BigInt(a.balanceAtRiskDrops) ? 1 : -1))
    .slice(0, 10);
  return {
    sampled: rows.length,
    byExposureClass: byClass,
    byGradeTier: byTier,
    exposedCount: exposed, exposedPct: pct(exposed),
    masterExposedCount: masterExposed, masterExposedPct: pct(masterExposed),
    conclusiveCount: conclusive, unknownCount: byClass.unknown,
    provenQuantumHookCount: provenHook,
    totalBalanceDrops: totalBalance, balanceAtRiskDrops: balanceAtRisk, masterExposedBalanceDrops: masterExposedBalance,
    topExposedByBalance,
  };
}

/** Sample distinct accounts seen in the last `ledgers` validated ledgers (active-account sample). */
export async function sampleRecentAccounts(network: Network, ledgers = 8, cap = 50): Promise<string[]> {
  const tip = Number(((await rpc<{ ledger: { ledger_index: number } }>("ledger", { ledger_index: "validated" }, network)).ledger ?? {}).ledger_index);
  const set = new Set<string>();
  for (let i = 0; i < ledgers && set.size < cap; i++) {
    try {
      const l = await rpc<{ ledger?: { transactions?: any[] } }>("ledger", { ledger_index: tip - i, transactions: true, expand: true }, network);
      for (const t of l.ledger?.transactions ?? []) {
        const tx = (t.tx_json ?? t) as Record<string, any>;
        if (tx.Account) set.add(tx.Account);
        if (set.size >= cap) break;
      }
    } catch { /* tolerate a bad ledger */ }
  }
  return [...set].slice(0, cap);
}

/** Build a scorecard over a list of accounts (or a fresh active-account sample). Bounded + honest. */
export async function quantumScorecard(network: Network, opts: { accounts?: string[]; sampleLedgers?: number; cap?: number; maxPages?: number } = {}) {
  const accounts = opts.accounts?.length ? opts.accounts : await sampleRecentAccounts(network, opts.sampleLedgers ?? 8, opts.cap ?? 40);
  const rows: ScorecardRow[] = [];
  for (const address of accounts) {
    try {
      const e = await hndlExposure(address, network, opts.maxPages ?? 6);
      const g = await quantumGrade(address, network);
      rows.push({
        address, exposureClass: e.exposureClass, severity: e.severity, conclusive: e.conclusive,
        balanceDrops: e.balanceDrops, balanceAtRiskDrops: e.balanceAtRiskDrops,
        gradeScore: g.score, gradeTier: g.tier, hasProvenQuantumHook: g.hasProvenQuantumHook, masterDisabled: e.masterDisabled,
      });
    } catch { /* skip an account that errors (deleted/anomalous) */ }
  }
  const originatorSample = !opts.accounts?.length;
  return {
    network,
    population: originatorSample ? `sample of recently-active accounts (last ${opts.sampleLedgers ?? 8} ledgers)` : "caller-supplied account list",
    originatorSample,
    attempted: accounts.length,
    skipped: accounts.length - rows.length,
    caveat: "SAMPLE, not a ledger census. Recently-active accounts skew toward exposed (they have signed)" +
      (originatorSample ? " — in fact this default sample is drawn from transaction ORIGINATORS, so 'exposed %' is ~100% BY CONSTRUCTION and is NOT a network statistic." : ".") +
      " Non-conclusive negatives are reported as 'unknown', never 'safe'.",
    ...aggregateScorecard(rows),
    rows,
  };
}

const dropsToXah = (d: string): string => {
  const n = BigInt(d || "0");
  const sign = n < 0n ? "-" : "";
  const abs = n < 0n ? -n : n;
  return `${sign}${abs / 1000000n}.${(abs % 1000000n).toString().padStart(6, "0")}`;
};

/** Render a scorecard result to public-facing markdown. */
export function renderScorecardMarkdown(s: Awaited<ReturnType<typeof quantumScorecard>>, asOf: string): string {
  const c = s.byExposureClass;
  const L: string[] = [];
  L.push(`# Quantum Readiness Scorecard${s.originatorSample ? " (active-account sample)" : ""} — ${s.network}`);
  L.push(`_As of ${asOf}. ${s.population}. n=${s.sampled}${s.skipped ? ` (of ${s.attempted} attempted; ${s.skipped} skipped — deleted/anomalous/errored)` : ""}._`);
  L.push("");
  L.push(`> ${s.caveat}`);
  L.push("");
  L.push("## Headline");
  L.push(`- **Exposed (signing pubkey on-ledger):** ${s.exposedCount}/${s.sampled}${s.originatorSample ? " — ~100% BY CONSTRUCTION of an originator sample; NOT a network statistic" : ` (${s.exposedPct}%)`}`);
  L.push(`- **Master-key exposed (IRREVERSIBLE):** ${s.masterExposedCount}/${s.sampled} (${s.masterExposedPct}%) — ${dropsToXah(s.masterExposedBalanceDrops)} XAH`);
  L.push(`- **Total balance at risk (sample):** ${dropsToXah(s.balanceAtRiskDrops)} XAH of ${dropsToXah(s.totalBalanceDrops)} XAH scanned`);
  L.push(`- **Conclusive verdicts:** ${s.conclusiveCount}/${s.sampled} (${s.unknownCount} coverage-bounded UNKNOWN)`);
  L.push(`- **Accounts running a PROVEN quantum-policy hook:** ${s.provenQuantumHookCount}`);
  L.push("");
  L.push("## HNDL exposure breakdown");
  L.push("| Class | Count | Meaning |");
  L.push("|---|---|---|");
  L.push(`| master | ${c.master} | CRITICAL — unrotatable master pubkey on-ledger (irreversible) |`);
  L.push(`| regular | ${c.regular} | RECOVERABLE — a regular key exposed; rotate it |`);
  L.push(`| multisig | ${c.multisig} | RECOVERABLE — signer pubkeys exposed; rotate the list |`);
  L.push(`| none | ${c.none} | hash-only; never signed (conclusive) |`);
  L.push(`| unknown | ${c.unknown} | coverage-bounded; not provably safe |`);
  L.push("");
  L.push("## Grade tiers (config readiness)");
  L.push(`- BASELINE (LOW): ${s.byGradeTier.LOW} · HARDENED (MEDIUM): ${s.byGradeTier.MEDIUM} · WELL HARDENED (HIGH): ${s.byGradeTier.HIGH}`);
  L.push("");
  if (s.topExposedByBalance.length) {
    L.push("## Top exposed by balance-at-risk");
    L.push("| Account | Class | XAH at risk | Grade |");
    L.push("|---|---|---|---|");
    for (const r of s.topExposedByBalance)
      L.push(`| ${r.address} | ${r.exposureClass} | ${dropsToXah(r.balanceAtRiskDrops)} | ${r.gradeScore}/100 |`);
    L.push("");
  }
  L.push("_Method: hndl_exposure (pubkey-on-ledger classification, two-sided coverage proof) + quantum_grade (config). Config ≠ reality: an account can have a regular key yet have master-signed (exposed). xahau-mcp._");
  return L.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG CENSUS — whole-ledger key-rotation posture via ledger_data (AccountRoot
// Flags/RegularKey/Balance), NO per-account tx scan. Cheap enough to cover the
// entire ledger, so its figures ARE network statistics (unlike the active-account
// scorecard sample). Measures CONFIG (can the master key be rotated?), not exposure
// (has it signed?) — an account with no regular key + master enabled has NO rotation
// path, so once it transacts its master key is unavoidably exposed.
// ─────────────────────────────────────────────────────────────────────────────

export interface AccountConfig { flags: number; hasRegularKey: boolean; balanceDrops: string; }

/** PURE per-account config classification. noRotation = master enabled AND no regular key. */
export function classifyAccountConfig(a: AccountConfig) {
  const masterDisabled = (a.flags & LSF_DISABLE_MASTER) !== 0;
  const noRotation = !masterDisabled && !a.hasRegularKey;   // can ONLY ever sign with the master key
  return { masterDisabled, hasRegularKey: a.hasRegularKey, noRotation };
}

/** PURE aggregation of config across all accounts. */
export function aggregateConfigCensus(accts: AccountConfig[]) {
  let masterDisabled = 0, hasRegularKey = 0, noRotation = 0;
  let totalDrops = "0", noRotationDrops = "0", masterDisabledDrops = "0";
  for (const a of accts) {
    const c = classifyAccountConfig(a);
    totalDrops = addDrops(totalDrops, a.balanceDrops);
    if (c.masterDisabled) { masterDisabled++; masterDisabledDrops = addDrops(masterDisabledDrops, a.balanceDrops); }
    if (c.hasRegularKey) hasRegularKey++;
    if (c.noRotation) { noRotation++; noRotationDrops = addDrops(noRotationDrops, a.balanceDrops); }
  }
  const n = accts.length || 1;
  const pct = (x: number) => Math.round((x / n) * 1000) / 10;
  const pctDrops = (x: string) => { const t = BigInt(totalDrops || "0"); return t === 0n ? 0 : Math.round((Number(BigInt(x) * 10000n / t)) / 100 * 10) / 10; };
  return {
    accounts: accts.length,
    masterDisabledCount: masterDisabled, masterDisabledPct: pct(masterDisabled),
    hasRegularKeyCount: hasRegularKey, hasRegularKeyPct: pct(hasRegularKey),
    noRotationCount: noRotation, noRotationPct: pct(noRotation),
    totalDrops, noRotationDrops, masterDisabledDrops,
    noRotationSupplyPct: pctDrops(noRotationDrops), masterDisabledSupplyPct: pctDrops(masterDisabledDrops),
  };
}

/** Whole-ledger config census via ledger_data pagination. Bounded by maxPages; reports completeness.
 *  `delayMs` paces requests to respect public-node rate limits; transient errors get bounded retries. */
export async function configCensus(network: Network, maxPages = 400, pageLimit = 2048, delayMs = 300) {
  const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));
  const accts: AccountConfig[] = [];
  let marker: unknown = undefined, pages = 0, complete = true;
  while (pages < maxPages) {
    const params: Record<string, unknown> = { ledger_index: "validated", type: "account", limit: pageLimit };
    if (marker !== undefined) params.marker = marker;
    let r: { state?: any[]; marker?: unknown } | null = null;
    for (let attempt = 0; attempt < 4; attempt++) {
      try { r = await rpc<{ state?: any[]; marker?: unknown }>("ledger_data", params, network); break; }
      catch (e) { if (attempt === 3) throw e; await sleep(delayMs * (attempt + 2)); }  // backoff on 429/transient
    }
    for (const o of r!.state ?? []) {
      if (o.LedgerEntryType !== "AccountRoot") continue;
      accts.push({ flags: Number(o.Flags ?? 0), hasRegularKey: Boolean(o.RegularKey), balanceDrops: String(o.Balance ?? "0") });
    }
    pages++; marker = r!.marker;
    if (marker === undefined || marker === null) break;
    if (pages >= maxPages) { complete = false; break; }
    await sleep(delayMs);
  }
  return {
    network, asOfComplete: complete, pagesScanned: pages,
    caveat: "CONFIG census (key-rotation posture) over the WHOLE account set via ledger_data — these ARE network figures. Measures whether an account CAN rotate off its master key (regular key / master-disabled), NOT whether it has already exposed a key (that is hndl_exposure). Signer-list multisig is not counted here (separate ledger object), so 'hardened' is a slight under-count." +
      (complete ? "" : " INCOMPLETE: hit the page bound — raise maxPages for a full census."),
    ...aggregateConfigCensus(accts),
  };
}

// ── Disable-master safety gate (brick prevention) ─────────────────────────────
/**
 * Can this account safely disable its master key? GOLD STANDARD, applied UNIFORMLY: an alternative
 * signer must be PROVEN to already work, not merely configured —
 *   - regular key: a self-originated tx whose SigningPubKey hashes to the RegularKey AccountID, OR
 *   - signer list: the list's quorum is REACHABLE (quorum ≤ Σ weights) AND a self-originated
 *     multi-signed tx (empty SigningPubKey + Signers) has been seen.
 * A bare/never-used/unreachable alternative is NOT safe — disabling master then bricks the account.
 * `safeToDisable` requires proof; a configured-but-unverified alternative is reported and BLOCKED.
 */
export async function disableMasterReadiness(address: string, network: Network, scanPages = 6, pageLimit = 200) {
  const a = (await getAccountInfo(address, network)).account_data as Record<string, any>;
  const alreadyDisabled = (Number(a.Flags ?? 0) & LSF_DISABLE_MASTER) !== 0;
  const regularKey: string | null = a.RegularKey ?? null;
  const rkv = regularKey ? validateAddress(regularKey) : null;
  const regularKeyAccountId = rkv && rkv.valid && "accountId" in rkv ? (rkv as { accountId: string }).accountId : null;

  // Signer list: existence is NOT enough — read its quorum + per-member weights. We need the CURRENT
  // member set (not just the total) so a historical multi-sign can be tied to the list that controls
  // the account NOW (a past list the account has since rotated away from is not proof — see below).
  let signerListSet = false, signerListReachable = false, signerQuorum = 0;
  const currentSigners = new Map<string, number>();   // current member AccountID -> SignerWeight
  try {
    const objs = await getAccountObjects(address, network, "signer_list");
    const sl = objs.account_objects.find((o: any) => o.LedgerEntryType === "SignerList") as any;
    if (sl) {
      signerListSet = true;
      signerQuorum = Number(sl.SignerQuorum ?? 0);
      for (const e of sl.SignerEntries ?? []) {
        const acc = e?.SignerEntry?.Account;
        if (typeof acc === "string") currentSigners.set(acc, Number(e?.SignerEntry?.SignerWeight ?? 0));
      }
      const totalWeight = [...currentSigners.values()].reduce((n, w) => n + w, 0);
      signerListReachable = signerQuorum > 0 && totalWeight >= signerQuorum;
    }
  } catch { /* tolerate — leaves signerListSet=false => conservative */ }

  // Scan history for PROOF a non-master signer has worked: a regular-key-signed tx, or a multi-signed tx.
  let regularKeyHasSigned = false, multisigHasSigned = false;
  {
    let marker: unknown = undefined, pages = 0;
    while (pages < scanPages && !(regularKeyHasSigned && multisigHasSigned)) {
      const params: Record<string, unknown> = { account: address, limit: pageLimit, ledger_index_min: -1, ledger_index_max: -1, forward: false };
      if (marker !== undefined) params.marker = marker;
      const r = await rpc<{ transactions?: any[]; marker?: unknown }>("account_tx", params, network);
      for (const t of r.transactions ?? []) {
        const tx = (t.tx ?? t.tx_json ?? t) as Record<string, any>;
        if (tx.Account !== address) continue;
        const spk = typeof tx.SigningPubKey === "string" ? tx.SigningPubKey : "";
        if (spk === "" && Array.isArray(tx.Signers) && tx.Signers.length > 0) {
          // H-1 fix: a past multi-sign is proof ONLY if it was signed by signers who are CURRENT
          // members of the live SignerList AND their summed CURRENT weights reach the CURRENT quorum.
          // Otherwise the account multi-signed with a list it has since rotated away from — disabling
          // master would brick it (the new, untested list is the only signer). Subset + quorum check:
          const accts = (tx.Signers as any[]).map((s) => s?.Signer?.Account).filter((x): x is string => typeof x === "string");
          if (accts.length > 0 && signerQuorum > 0 && accts.every((acc) => currentSigners.has(acc))) {
            const w = accts.reduce((n, acc) => n + (currentSigners.get(acc) ?? 0), 0);
            if (w >= signerQuorum) multisigHasSigned = true;
          }
        } else if (spk && regularKeyAccountId && accountIdFromPubkey(spk) === regularKeyAccountId) regularKeyHasSigned = true;
      }
      pages++; marker = r.marker; if (marker == null) break;
    }
  }

  // A signer-list alternative is only PROVEN when it has actually multi-signed AND is currently reachable.
  const signerListProven = multisigHasSigned && signerListReachable;
  const proven = regularKeyHasSigned || signerListProven;
  const safeToDisable = !alreadyDisabled && proven;

  const reasons: string[] = [];
  if (alreadyDisabled) reasons.push("master key is already disabled");
  if (!regularKey && !signerListSet) reasons.push("no regular key and no signer list — the master key is the ONLY signer; disabling it WILL brick the account");
  if (regularKey && !regularKeyHasSigned) reasons.push("a regular key is set but has NOT been seen signing — UNVERIFIED. Send a test tx signed by it first.");
  if (signerListSet && !signerListReachable) reasons.push("a signer list exists but its quorum is UNREACHABLE (quorum > total signer weight) — it cannot sign; disabling master would brick the account");
  if (signerListSet && signerListReachable && !multisigHasSigned) reasons.push("a signer list is reachable but no multi-signed tx FROM THE CURRENT SIGNERS (reaching quorum) was seen — UNVERIFIED. A past multi-sign with a now-replaced list does NOT count. Send a fresh multi-signed test tx with the current list first.");
  if (regularKeyHasSigned) reasons.push("the configured regular key has signed for this account (PROVEN alternative)");
  if (signerListProven) reasons.push("the signer list is reachable and has multi-signed (PROVEN alternative)");
  reasons.push("note: 'has signed' proves the key worked historically, not that you still hold it — confirm you control the alternative signer NOW.");

  return { address, alreadyDisabled, regularKey, regularKeyAccountId, signerListSet, signerListReachable, regularKeyHasSigned, multisigHasSigned, signerListProven, safeToDisable, proven, reasons };
}

/**
 * Derive an account's MASTER public key from the ledger: the SigningPubKey of any self-originated tx
 * whose pubkey hashes to the account's OWN AccountID. Scans OLDEST-first (master is used early). Returns
 * found=false if the master key has never signed — then the pubkey is not on-ledger and cannot be derived
 * here (the owner must supply it from their wallet). Read-only.
 */
export async function masterPubkey(address: string, network: Network, scanPages = 6, pageLimit = 200) {
  const v = validateAddress(address);
  if (!v.valid || !("accountId" in v)) throw new Error("not a valid r-address / X-address");
  const accountId = (v as { accountId: string }).accountId;
  let marker: unknown = undefined, pages = 0;
  while (pages < scanPages) {
    const params: Record<string, unknown> = { account: address, limit: pageLimit, ledger_index_min: -1, ledger_index_max: -1, forward: true };
    if (marker !== undefined) params.marker = marker;
    const r = await rpc<{ transactions?: any[]; marker?: unknown }>("account_tx", params, network);
    for (const t of r.transactions ?? []) {
      const tx = (t.tx ?? t.tx_json ?? t) as Record<string, any>;
      if (tx.Account !== address) continue;
      const spk = typeof tx.SigningPubKey === "string" ? tx.SigningPubKey : "";
      if (spk && accountIdFromPubkey(spk) === accountId)
        return { found: true, pubkey: spk.toUpperCase(), accountId };
    }
    pages++; marker = r.marker; if (marker == null) break;
  }
  return { found: false, pubkey: null as string | null, accountId };
}
