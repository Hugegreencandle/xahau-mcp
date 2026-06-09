// Xahau Genesis "Governance Game" + Burn2Mint (B2M) helpers.
// Full Genesis-hook-state decode (seats/members/topics) is intricate and partly undocumented,
// so governance_state returns the verified constants + a live genesis-account read and is honest
// that per-seat/topic decoding is not yet implemented.
import { GOVERNANCE } from "./defs.js";
import { getAccountInfo, type Network } from "./rpc.js";

export async function governanceState(network: Network) {
  if (!GOVERNANCE) return { available: false, note: "governance.json not built" };
  let genesisLive: Record<string, unknown> | null = null;
  try {
    const info = await getAccountInfo(GOVERNANCE.genesisAccount, network);
    genesisLive = info.account_data;
  } catch { /* offline-tolerant */ }
  return {
    genesisAccount: GOVERNANCE.genesisAccount,
    governanceSeats: GOVERNANCE.governanceSeats,
    rewardDelayLedgers: GOVERNANCE.rewardDelayLedgers,
    rewardRateMonthly_doc: GOVERNANCE.rewardRateMonthly_doc,
    genesisAccountLive: genesisLive
      ? { balanceDrops: genesisLive.Balance, sequence: genesisLive.Sequence, ownerCount: genesisLive.OwnerCount }
      : null,
    seatsDecoded: null,
    topicsDecoded: null,
    caveat: "Per-seat / per-topic decode of the Genesis hook state is not yet implemented; values above are documented constants plus a live genesis-account read. " + GOVERNANCE.caveat,
  };
}

/** Heuristic inspection of a Burn2Mint-related transaction (XRPL<->Xahau bridge). */
export function decodeB2M(tx: Record<string, unknown>) {
  const tt = tx.TransactionType as string | undefined;
  if (tt === "Import") {
    return { transactionType: tt, direction: "XRPL->Xahau (mint via Import)", hasBlob: Boolean(tx.Blob), note: "Import carries a Burn2Mint proof (a validated XRPL burn) in its Blob; mint amount is derived from the proof." };
  }
  if (tt === "Payment" || tt === "AccountDelete") {
    return { transactionType: tt, direction: "Xahau->XRPL (burn side, if to genesis/bridge)", hasBlob: false, note: "Burn side is a standard tx whose outcome is later proven on the other chain; B2M direction can't be confirmed from this tx alone." };
  }
  return { transactionType: tt ?? "(unknown)", direction: "unknown", hasBlob: Boolean(tx.Blob), note: "Not a recognized B2M transaction shape." };
}
