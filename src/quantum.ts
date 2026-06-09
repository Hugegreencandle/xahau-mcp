// Quantum-readiness (HNDL: Harvest-Now-Decrypt-Later) grading for Xahau accounts.
// Ports the xrpl-audit quantum_grade model to Xahau and adds a Hook/PQC dimension.
// ed25519 / secp256k1 keys are not quantum-safe; the near-term defense is minimizing exposed
// long-lived key material (disable the master key behind a rotatable regular key / signer list).
import { getAccountInfo, getAccountObjects, type Network } from "./rpc.js";

const LSF_DISABLE_MASTER = 0x00100000;

export interface QuantumSignals { masterDisabled: boolean; hasRegularKey: boolean; hasMultiSig: boolean; signerCount: number; }

/** Pure scorer (no network) — masterDisabled +40, multiSig +35, regularKey +25. */
export function gradeSignals(s: QuantumSignals): { score: number; tier: "LOW" | "MEDIUM" | "HIGH"; signals: string[]; recommendations: string[] } {
  const signals: string[] = [];
  let score = 0;
  if (s.masterDisabled) { score += 40; signals.push("master key disabled (+40)"); }
  else signals.push("master key ENABLED — the long-lived HNDL target is exposed");
  if (s.hasMultiSig) { score += 35; signals.push(`multi-sign active, ${s.signerCount} signer(s) (+35)`); }
  if (s.hasRegularKey) { score += 25; signals.push("regular key set (+25)"); }
  const tier = score >= 70 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  const recommendations: string[] = [];
  if (!s.masterDisabled) recommendations.push("Disable the master key (lsfDisableMaster) after configuring a regular key or signer list — the master secret is the primary HNDL target.");
  if (!s.hasRegularKey && !s.hasMultiSig) recommendations.push("Set a regular key and/or a signer list so the master key can be rotated and then disabled.");
  recommendations.push("Xahau is on Ripple's post-quantum roadmap; a Hook can enforce account-level key-rotation / quantum policy that XRPL accounts cannot.");
  return { score, tier, signals, recommendations };
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

  const { score, tier, signals, recommendations } = gradeSignals({ masterDisabled, hasRegularKey, hasMultiSig, signerCount });

  return {
    address, score, tier, signals,
    masterDisabled, hasRegularKey, hasMultiSig, signerCount, hooksInstalled,
    recommendations,
    note: "HNDL (Harvest-Now-Decrypt-Later) readiness. Same key model as XRPL; ed25519/secp256k1 are not quantum-safe. Minimizing exposed long-lived key material is the near-term defense.",
  };
}
