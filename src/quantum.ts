// Quantum-readiness (HNDL: Harvest-Now-Decrypt-Later) grading for Xahau accounts.
// Ports the xrpl-audit quantum_grade model to Xahau and adds a Hook/PQC dimension.
// ed25519 / secp256k1 keys are not quantum-safe; the near-term defense is minimizing exposed
// long-lived key material (disable the master key behind a rotatable regular key / signer list).
import { getAccountInfo, getAccountObjects, type Network } from "./rpc.js";

const LSF_DISABLE_MASTER = 0x00100000;

export interface QuantumSignals { masterDisabled: boolean; hasRegularKey: boolean; hasMultiSig: boolean; signerCount: number; }

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
  const tier = score >= 70 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  const recommendations: string[] = [];
  if (!s.masterDisabled) recommendations.push("Optional hardening: after configuring a regular key or signer list, disable the master key (lsfDisableMaster) so the primary long-lived key can be retired.");
  if (!s.hasRegularKey && !s.hasMultiSig) recommendations.push("Optional hardening: set a regular key and/or a signer list so the master key can be rotated and then disabled.");
  recommendations.push("Xahau is on Ripple's post-quantum roadmap; a proven quantum-policy Hook can enforce account-level key-rotation that XRPL accounts cannot — that enforcement is not scored here until the Hook's bytecode is proven.");
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
  try {
    const h = await getAccountObjects(address, network, "hook");
    const ho = h.account_objects.find((o: any) => o.LedgerEntryType === "Hook") as any;
    hooksInstalled = (ho?.Hooks ?? []).length;
  } catch { /* tolerate */ }

  const { score, tier, tierLabel, signals, recommendations } = gradeSignals({ masterDisabled, hasRegularKey, hasMultiSig, signerCount });

  return {
    address, score, tier, tierLabel, signals,
    masterDisabled, hasRegularKey, hasMultiSig, signerCount, hooksInstalled,
    // Honest hook dimension: we report that hooks are PRESENT, but presence does NOT imply a
    // quantum/key-rotation policy and is deliberately NOT scored. Confirming a Hook enforces such
    // a policy requires proving its bytecode (xahc-prover) — until then this stays informational.
    hookPolicyNote: hooksInstalled > 0
      ? `${hooksInstalled} hook(s) installed — presence only; not scored. A hook earns quantum credit only once its bytecode is proven to enforce key-rotation / master-disable policy.`
      : "no hooks installed.",
    recommendations,
    framing: "FUTURE-hardening readiness, not a present-day safety alarm. ed25519/secp256k1 are not broken today; a BASELINE account is normal, not unsafe. Score reflects how hardened the account is against Harvest-Now-Decrypt-Later.",
    note: "HNDL (Harvest-Now-Decrypt-Later) readiness. Same key model as XRPL. Minimizing long-lived key material (rotate behind a regular key / signer list, then disable master) is the near-term defense.",
  };
}
