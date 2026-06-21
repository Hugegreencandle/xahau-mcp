// Quantum-readiness (HNDL: Harvest-Now-Decrypt-Later) grading for Xahau accounts.
// Ports the xrpl-audit quantum_grade model to Xahau and adds a Hook/PQC dimension.
// ed25519 / secp256k1 keys are not quantum-safe; the near-term defense is minimizing exposed
// long-lived key material (disable the master key behind a rotatable regular key / signer list).
import { getAccountInfo, getAccountObjects, type Network } from "./rpc.js";

const LSF_DISABLE_MASTER = 0x00100000;

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
