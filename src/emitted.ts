// inspect_emitted_tx — decode what a hook's emit() actually built.
// execute_hook returns `emitted[]` = the raw serialized tx blobs the hook passed to emit().
// This decodes each one (codec), explains it in plain English (describeTx), and danger-scores it
// (scam rules) — closing the loop on emitter hooks: "my hook fired, but WHAT did it try to send?"
// Fully offline. Decode failures are reported per-blob, never silently dropped.
import { decodeTxBlob } from "./codec.js";
import { describeTx } from "./util.js";
import { scorePayload } from "./scam.js";

export interface EmittedInspection {
  index: number;
  decoded: Record<string, unknown> | null;
  decodeError?: string;
  transactionType?: string;
  summary?: string;
  warnings?: string[];
  dangerScore?: number;
  dangerTier?: string;
  note?: string;
}

export function inspectEmitted(blobs: string[]): { count: number; inspections: EmittedInspection[]; headline: string } {
  const inspections: EmittedInspection[] = blobs.map((blob, index) => {
    let tx: Record<string, unknown>;
    try {
      tx = decodeTxBlob(blob) as Record<string, unknown>;
    } catch (e) {
      // Emitted blobs are built inside hook memory; a partial/garbled buffer is a real finding, not noise.
      return { index, decoded: null, decodeError: `could not decode emitted blob: ${(e as Error).message}` };
    }
    const { summary, warnings } = describeTx(tx);
    const danger = scorePayload(tx as Record<string, any>);
    return {
      index,
      decoded: tx,
      transactionType: (tx.TransactionType as string) ?? undefined,
      summary,
      warnings,
      dangerScore: danger.dangerScore,
      dangerTier: danger.tier,
      note: "emitted txns carry hook-supplied fields; the network adds/validates EmitDetails on-chain — treat amounts/destinations here as exactly what the hook ASKED to send",
    };
  });

  const okCount = inspections.filter((i) => i.decoded).length;
  const worst = inspections.reduce<string>((w, i) => (i.dangerTier === "DANGER" ? "DANGER" : i.dangerTier === "CAUTION" && w !== "DANGER" ? "CAUTION" : w), "SAFE");
  const headline = blobs.length === 0
    ? "no emitted transactions"
    : `${okCount}/${blobs.length} emitted blob(s) decoded · ${inspections.map((i) => i.transactionType ?? "undecodable").join(", ")} · worst tier ${worst}`;
  return { count: blobs.length, inspections, headline };
}
