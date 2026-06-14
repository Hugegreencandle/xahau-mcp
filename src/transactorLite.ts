// transactorLite — an APPROXIMATE model of the normal-transaction effects xahaud's transactor
// would apply, to partially fill the gap left by Xahau lacking the `simulate` RPC.
//
// HONESTY: this is NOT consensus. It models common-case preconditions + balance/reserve/trustline
// deltas for the tx types below, against LIVE ledger state. Pathfinding, offer/AMM crossing,
// transfer fees, and the long tail of tec codes are OUT OF SCOPE and labeled UNSUPPORTED. The HOOK
// layer simulated alongside this (in simulate.ts) IS faithful; this is the approximate companion.
//
// A faithful Xahau `simulate` requires the node-side Simulate amendment in xahaud; this is the
// practical stand-in until then.

export interface TxDelta {
  account: string;
  asset: string; // "XAH" | "owner reserve" | "<CUR>.<ISSUER>"
  change: string; // signed, human-readable
}

export interface TransactorPrediction {
  fidelity: "APPROXIMATE" | "UNSUPPORTED";
  /** predicted engine_result, or null if unsupported */
  predictedResult: string | null;
  reason: string;
  deltas: TxDelta[];
  caveat: string;
}

const CAVEAT =
  "APPROXIMATE transactor model — common-case preconditions + balance/reserve/trustline deltas only. " +
  "NOT consensus: pathfinding, offer/AMM crossing, transfer fees, and many tec edge codes are out of scope. " +
  "The HOOK layer is the faithful part; a fully faithful result needs the Simulate amendment in xahaud.";

const UNSUPPORTED_CAVEAT =
  "Transactor effects are not modeled for this tx type. The HOOK layer above is faithful; the normal-tx " +
  "outcome here is unknown without the node-side Simulate amendment.";

const lsfRequireDestTag = 0x00020000;

export interface TransactorInputs {
  tx: Record<string, any>;
  /** sender account_data (Balance, OwnerCount, Sequence, Flags) or null if absent */
  sender: Record<string, any> | null;
  /** destination account_data or null if it does not exist (Payment only) */
  dest?: Record<string, any> | null;
  /** sender's account_lines entries (for IOU Payment / TrustSet) */
  senderLines?: Record<string, any>[];
  /** network reserve params, in drops */
  reserveBaseDrops: bigint;
  reserveIncDrops: bigint;
}

export function predictTransactor(i: TransactorInputs): TransactorPrediction {
  const { tx, sender, dest } = i;
  const type = String(tx.TransactionType ?? "");
  if (!sender) return unsupported(`sender ${tx.Account} not found`);

  const fee = BigInt(String(tx.Fee ?? "100000"));
  const ownerCount = BigInt(Math.max(0, Number(sender.OwnerCount ?? 0)));
  const reserve = i.reserveBaseDrops + ownerCount * i.reserveIncDrops;
  const balance = BigInt(String(sender.Balance ?? "0"));
  const spendableXAH = balance - reserve; // XAH usable without breaking reserve

  if (type === "Payment") return payment();
  if (type === "TrustSet") return trustSet();
  return unsupported(`transactor effects for ${type} are not modeled`);

  function payment(): TransactorPrediction {
    const amt = tx.Amount;

    // ---- native XAH payment ----
    if (typeof amt === "string") {
      const amount = BigInt(amt);
      const need = amount + fee;
      if (!dest) {
        if (amount < i.reserveBaseDrops) {
          return res("tecNO_DST_INSUF_XRP", `destination doesn't exist and amount ${amount} < base reserve ${i.reserveBaseDrops} drops — can't fund it`);
        }
      } else if ((Number(dest.Flags ?? 0) & lsfRequireDestTag) !== 0 && tx.DestinationTag === undefined) {
        return res("tecDST_TAG_NEEDED", "destination requires a DestinationTag");
      }
      if (need > balance) return res("tecUNFUNDED_PAYMENT", `amount+fee ${need} drops exceeds balance ${balance}`);
      if (balance - need < reserve) return res("tecUNFUNDED_PAYMENT", `resulting balance ${balance - need} would fall below reserve ${reserve} drops`);
      return ok("native payment within spendable balance + reserve", [
        { account: String(tx.Account), asset: "XAH", change: `-${need} drops (amount+fee)` },
        { account: String(tx.Destination), asset: "XAH", change: `+${amount} drops` },
      ]);
    }

    // ---- issued (IOU) payment ----
    if (amt && typeof amt === "object") {
      const cur = String(amt.currency ?? "");
      const iss = String(amt.issuer ?? "");
      const val = String(amt.value ?? "0");
      // cross-currency (SendMax with a different asset) needs pathfinding → unsupported
      if (tx.SendMax !== undefined && JSON.stringify(tx.SendMax) !== JSON.stringify(amt)) {
        return unsupported("cross-currency / SendMax payment requires pathfinding");
      }
      if (fee > spendableXAH) return res("tecUNFUNDED_FEE", `not enough spendable XAH for the fee (${fee} > ${spendableXAH})`);
      if (String(tx.Account) !== iss) {
        const line = (i.senderLines ?? []).find((l) => l.currency === cur && l.account === iss);
        if (!line) return res("tecPATH_DRY", `sender holds no ${cur}.${iss} trustline`);
        if (parseFloat(String(line.balance ?? "0")) < parseFloat(val)) {
          return res("tecPATH_DRY", `sender ${cur} balance ${line.balance} < ${val} (no pathfinding modeled)`);
        }
        if (line.freeze === true || line.freeze_peer === true) return res("tecFROZEN", "trustline is frozen");
      }
      return {
        fidelity: "APPROXIMATE",
        predictedResult: "tesSUCCESS",
        reason: "direct IOU transfer (issuer transfer fee + dest-line rippling not modeled)",
        deltas: [
          { account: String(tx.Account), asset: `${cur}.${iss}`, change: `-${val}` },
          { account: String(tx.Destination), asset: `${cur}.${iss}`, change: `+${val} (less any transfer fee)` },
          { account: String(tx.Account), asset: "XAH", change: `-${fee} drops (fee)` },
        ],
        caveat: CAVEAT,
      };
    }

    return unsupported("unrecognized Amount shape");
  }

  function trustSet(): TransactorPrediction {
    const limit = tx.LimitAmount as Record<string, any> | undefined;
    const cur = String(limit?.currency ?? "");
    const iss = String(limit?.issuer ?? "");
    if (fee > spendableXAH) return res("tecINSUF_RESERVE_LINE", `fee ${fee} exceeds spendable XAH ${spendableXAH}`);
    const existing = (i.senderLines ?? []).find((l) => l.currency === cur && l.account === iss);
    if (!existing) {
      const newReserve = reserve + i.reserveIncDrops;
      if (balance - fee < newReserve) {
        return res("tecINSUF_RESERVE_LINE", `a new trustline needs +${i.reserveIncDrops} owner reserve; balance ${balance} insufficient`);
      }
      return ok("creates a new trustline (+1 owner reserve)", [
        { account: String(tx.Account), asset: "XAH", change: `-${fee} drops (fee)` },
        { account: String(tx.Account), asset: "owner reserve", change: `+${i.reserveIncDrops} drops` },
      ]);
    }
    return ok("modifies an existing trustline (no new reserve)", [
      { account: String(tx.Account), asset: "XAH", change: `-${fee} drops (fee)` },
    ]);
  }

  function ok(reason: string, deltas: TxDelta[]): TransactorPrediction {
    return { fidelity: "APPROXIMATE", predictedResult: "tesSUCCESS", reason, deltas, caveat: CAVEAT };
  }
  function res(code: string, reason: string): TransactorPrediction {
    return { fidelity: "APPROXIMATE", predictedResult: code, reason, deltas: [], caveat: CAVEAT };
  }
  function unsupported(reason: string): TransactorPrediction {
    return { fidelity: "UNSUPPORTED", predictedResult: null, reason, deltas: [], caveat: UNSUPPORTED_CAVEAT };
  }
}

/** Which tx types this model covers. */
export const TRANSACTOR_SUPPORTED = new Set(["Payment", "TrustSet"]);
