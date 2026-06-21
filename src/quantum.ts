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
