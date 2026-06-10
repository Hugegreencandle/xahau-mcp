// Offline transaction-safety heuristic. Scores a decoded transaction for patterns that
// commonly appear in drainer / hijack / fat-finger sign requests, BEFORE a human signs it.
//
// HONESTY CONTRACT: every finding is a POTENTIAL risk, not a confirmed scam. This tool does
// NOT query any block list and NEVER verifies on-chain whether an address is actually malicious.
// It reads the SHAPE of the tx only. The DANGER tier is reserved for patterns that are almost
// universally malicious or irreversible (e.g. AccountDelete sending the remainder elsewhere).
import { describeTx } from "./util.js";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Tier = "SAFE" | "CAUTION" | "DANGER";

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  explanation: string;
  triggered: boolean;
}

export interface ScamResult {
  dangerScore: number;
  tier: Tier;
  verdict: string;
  findings: Finding[];
  summary: string;
  tx: Record<string, unknown>;
}

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  weight: number;
  explanation: string;
  check: (tx: Record<string, any>) => boolean;
}

const RULES: Rule[] = [
  {
    id: "SET_HOOK_NO_AUDIT",
    title: "Installs on-ledger Hook code",
    severity: "CRITICAL",
    weight: 35,
    explanation: "Installing on-ledger code that runs on every transaction; verify with analyze_hook before signing.",
    check: (tx) => tx.TransactionType === "SetHook",
  },
  {
    id: "ACCOUNT_DELETE_OTHER_DEST",
    title: "AccountDelete to a different address",
    severity: "CRITICAL",
    weight: 60,
    explanation: "AccountDelete to a different address — irreversible; verify the destination is your own.",
    check: (tx) => tx.TransactionType === "AccountDelete" && tx.Destination !== tx.Account,
  },
  {
    id: "SET_REGULAR_KEY",
    title: "Changes the regular key",
    severity: "HIGH",
    weight: 25,
    explanation: "Changes the key that can sign for this account; verify you own the new key.",
    check: (tx) => tx.TransactionType === "SetRegularKey",
  },
  {
    id: "REMOVE_REGULAR_KEY",
    title: "Removes the regular key",
    severity: "HIGH",
    weight: 35,
    explanation: "Removes the regular key, potentially locking the account if the master key is also disabled.",
    check: (tx) => tx.TransactionType === "SetRegularKey" && !tx.RegularKey,
  },
  {
    id: "SIGNER_LIST_SET",
    title: "Changes the signer list",
    severity: "MEDIUM",
    weight: 20,
    explanation: "Changes the signer list; verify all new signers.",
    check: (tx) => tx.TransactionType === "SignerListSet",
  },
  {
    id: "LARGE_PAYMENT",
    title: "Very large native payment",
    severity: "MEDIUM",
    weight: 25, // alone reaches the CAUTION floor — a >10k-XAH send should never read as plain SAFE
    explanation: "Very large native payment (>10,000 XAH).",
    check: (tx) => {
      if (tx.TransactionType !== "Payment" || typeof tx.Amount !== "string") return false;
      try { return BigInt(tx.Amount) > 10_000_000_000n; } catch { return false; }
    },
  },
  {
    id: "NO_LAST_LEDGER",
    title: "No LastLedgerSequence",
    severity: "LOW",
    weight: 10,
    explanation: "No LastLedgerSequence — the signed tx never expires (replay risk).",
    check: (tx) => tx.LastLedgerSequence === undefined,
  },
  {
    id: "ALREADY_SIGNED",
    title: "Pre-signed blob",
    severity: "LOW",
    weight: 5,
    explanation: "Pre-signed blob — inspect carefully before re-broadcasting.",
    check: (tx) => Boolean(tx.TxnSignature || tx.SigningPubKey),
  },
];

const HONESTY_TAG = " (Potential risk, not a confirmed scam — this tool never verifies on-chain whether an address is malicious.)";

export function scorePayload(tx: Record<string, any>): ScamResult {
  const findings: Finding[] = RULES.map((r) => {
    let triggered = false;
    try { triggered = r.check(tx); } catch { triggered = false; }
    return { ruleId: r.id, severity: r.severity, title: r.title, explanation: r.explanation + HONESTY_TAG, triggered };
  });

  let score = RULES.reduce((acc, r, i) => acc + (findings[i].triggered ? r.weight : 0), 0);

  // Fold describeTx() warnings in as LOW-severity advisories (each weight 5), de-duplicated against
  // rules that already flagged the same concern (no-expiry / already-signed) so we don't double-count.
  const { warnings } = describeTx(tx);
  const noLastLedgerHit = findings.find((f) => f.ruleId === "NO_LAST_LEDGER")?.triggered;
  const alreadySignedHit = findings.find((f) => f.ruleId === "ALREADY_SIGNED")?.triggered;
  let warnIdx = 0;
  for (const w of warnings) {
    const isExpiry = /LastLedgerSequence|never expires/i.test(w);
    const isSigned = /already carries a signature|SIGNED blob/i.test(w);
    if (isExpiry && noLastLedgerHit) continue; // already covered by RULE-7
    if (isSigned && alreadySignedHit) continue; // already covered by RULE-8
    findings.push({
      ruleId: `DESCRIBE_WARN_${warnIdx++}`,
      severity: "LOW",
      title: "Advisory from plain-English decode",
      explanation: w + HONESTY_TAG,
      triggered: true,
    });
    score += 5;
  }

  if (score > 100) score = 100;

  const tier: Tier = score >= 60 ? "DANGER" : score >= 25 ? "CAUTION" : "SAFE";

  const topTriggered = findings
    .filter((f) => f.triggered && !f.ruleId.startsWith("DESCRIBE_WARN_"))
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity))
    .slice(0, 3)
    .map((f) => f.title);

  const verdict = topTriggered.length
    ? `${tier}: ${topTriggered.join("; ")}. Treat as a potential risk and verify before signing.`
    : `${tier}: no risky patterns detected in the transaction shape. Always verify the destination and amount yourself.`;

  const triggeredCount = findings.filter((f) => f.triggered).length;
  const summary = `dangerScore ${score}/100 → ${tier}. ${triggeredCount} finding(s) triggered. Heuristic on tx shape only; not a block-list check.`;

  return { dangerScore: score, tier, verdict, findings, summary, tx };
}

function sevRank(s: Severity): number {
  return s === "CRITICAL" ? 4 : s === "HIGH" ? 3 : s === "MEDIUM" ? 2 : 1;
}
