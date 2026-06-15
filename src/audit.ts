// Audit / forensics tooling that leans on Xahau-specific metadata richness.
//
//  - trace_transaction_stakeholders : every account a transaction touched, from its metadata.
//      The Touch amendment forces ALL transactional stakeholders to appear in metadata (a touch
//      counter increments even when nothing else on the account changed), so the AffectedNodes set
//      is the authoritative participant list — no guessing from tx fields.
//  - verify_double_threading : structural audit of a tx's metadata threading (PreviousTxnID /
//      PreviousTxnLgrSeq), flagging the duplicate-node symptom that fixProvisionalDoubleThreading addressed.
//  - audit_account_remarks : read the Remarks (Remarks amendment) attached to an account's objects,
//      decode names/values, flag immutable ones.
//
// All read-only.
import { getTx, type Network, rpc } from "./rpc.js";

const TF_IMMUTABLE = 1;

function hexToText(hex?: string): string | null {
  if (typeof hex !== "string" || hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/.test(hex)) return null;
  const buf = Buffer.from(hex, "hex");
  // reject if any control byte (other than tab/newline/cr) is present → keep the hex instead
  for (const b of buf) if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) return null;
  return buf.toString("utf8");
}

const META = (tx: Record<string, unknown>): Record<string, unknown> | null =>
  (tx.meta as Record<string, unknown>) ?? (tx.metaData as Record<string, unknown>) ?? null;

interface NodeWrap { ModifiedNode?: any; CreatedNode?: any; DeletedNode?: any }
function unwrapNode(n: NodeWrap): { op: "Modified" | "Created" | "Deleted"; node: any } | null {
  if (n.ModifiedNode) return { op: "Modified", node: n.ModifiedNode };
  if (n.CreatedNode) return { op: "Created", node: n.CreatedNode };
  if (n.DeletedNode) return { op: "Deleted", node: n.DeletedNode };
  return null;
}

const fieldsOf = (node: any) => ({ ...(node.NewFields ?? {}), ...(node.FinalFields ?? {}) });

// ---- stakeholders ----

export interface Stakeholder {
  account: string;
  roles: string[];      // e.g. "originator", "AccountRoot", "RippleState:high", "Offer owner"
  entryTypes: string[]; // ledger entry types this account appeared in
  changed: boolean;     // true if anything beyond a Touch changed (heuristic: PreviousFields present)
}

export function extractStakeholders(tx: Record<string, unknown>) {
  const meta = META(tx);
  const originator = (tx.Account as string) ?? (tx.tx?.["Account" as keyof typeof tx.tx] as any) ?? null;
  const map = new Map<string, Stakeholder>();
  const add = (acct: unknown, role: string, entryType: string, changed: boolean) => {
    if (typeof acct !== "string" || !acct.startsWith("r")) return;
    const s = map.get(acct) ?? { account: acct, roles: [], entryTypes: [], changed: false };
    if (!s.roles.includes(role)) s.roles.push(role);
    if (entryType && !s.entryTypes.includes(entryType)) s.entryTypes.push(entryType);
    s.changed = s.changed || changed;
    map.set(acct, s);
  };
  if (originator) add(originator, "originator", "", true);

  const nodes = (meta?.AffectedNodes as NodeWrap[]) ?? [];
  for (const wrap of nodes) {
    const u = unwrapNode(wrap);
    if (!u) continue;
    const { op, node } = u;
    const et = node.LedgerEntryType as string;
    const f = fieldsOf(node);
    const changed = op !== "Modified" || node.PreviousFields !== undefined;
    if (et === "AccountRoot") {
      add(f.Account, op === "Modified" && !changed ? "touched (unchanged)" : "AccountRoot", et, changed);
    } else if (et === "RippleState") {
      add(f.HighLimit?.issuer, "RippleState:high", et, changed);
      add(f.LowLimit?.issuer, "RippleState:low", et, changed);
    } else {
      // Offer/Escrow/Check/URIToken/PayChannel/etc.
      add(f.Account, `${et} owner`, et, changed);
      add(f.Destination, `${et} destination`, et, changed);
      add(f.Owner, `${et} owner`, et, changed);
      add(f.Issuer, `${et} issuer`, et, changed);
    }
  }
  const stakeholders = [...map.values()];
  return {
    originator,
    stakeholderCount: stakeholders.length,
    stakeholders,
    summary: `${stakeholders.length} stakeholder(s)${meta ? "" : " (no metadata — originator only)"}`,
    metaPresent: Boolean(meta),
    note: meta
      ? "Participant set is from transaction metadata (AffectedNodes). With the Touch amendment, even otherwise-unchanged stakeholders appear here."
      : "No metadata on this transaction — only the originator could be determined. Provide a validated tx hash.",
  };
}

// ---- threading audit ----

export function auditThreading(tx: Record<string, unknown>) {
  const meta = META(tx);
  const txHash = (tx.hash as string) ?? null;
  const nodes = (meta?.AffectedNodes as NodeWrap[]) ?? [];
  const byIndex = new Map<string, number>();
  const entries = nodes.map((wrap) => {
    const u = unwrapNode(wrap);
    if (!u) return null;
    const { op, node } = u;
    const idx = node.LedgerIndex as string;
    byIndex.set(idx, (byIndex.get(idx) ?? 0) + 1);
    return {
      op,
      entryType: node.LedgerEntryType,
      ledgerIndex: idx,
      previousTxnId: node.PreviousTxnID ?? node.FinalFields?.PreviousTxnID ?? null,
      previousTxnLgrSeq: node.PreviousTxnLgrSeq ?? node.FinalFields?.PreviousTxnLgrSeq ?? null,
    };
  }).filter(Boolean) as Array<{ op: string; entryType: string; ledgerIndex: string; previousTxnId: string | null; previousTxnLgrSeq: number | null }>;

  const anomalies: { level: "WARN" | "INFO"; message: string }[] = [];
  // Double-threading symptom: a single ledger object touched by more than one node op.
  for (const [idx, count] of byIndex) {
    if (count > 1) anomalies.push({ level: "WARN", message: `ledger object ${idx} appears in ${count} AffectedNodes — possible double-threading; the kind of inconsistency fixProvisionalDoubleThreading addressed.` });
  }
  // Modified AccountRoot should carry a prior thread pointer.
  for (const e of entries) {
    if (e.op === "Modified" && e.entryType === "AccountRoot" && !e.previousTxnId) {
      anomalies.push({ level: "INFO", message: `modified AccountRoot ${e.ledgerIndex} has no PreviousTxnID in metadata (may be normal depending on node fields shown).` });
    }
  }
  return {
    txHash,
    affectedNodeCount: entries.length,
    uniqueLedgerObjects: byIndex.size,
    entries,
    anomalies,
    consistent: anomalies.filter((a) => a.level === "WARN").length === 0,
    summary: anomalies.length
      ? `${anomalies.length} threading note(s); ${anomalies.filter((a) => a.level === "WARN").length} warning(s)`
      : `${entries.length} affected node(s), no threading anomalies`,
    caveat: "Structural metadata check only — it does not walk the full transaction thread across ledgers.",
  };
}

// ---- remarks ----

export function decodeRemarksOnObjects(objects: Record<string, unknown>[]) {
  const out: { objectType: string; objectId: unknown; remarks: { name: string | null; nameHex: string; value: string | null; valueHex: string | null; immutable: boolean }[] }[] = [];
  let total = 0, immutable = 0;
  for (const obj of objects) {
    const remarks = (obj.Remarks as { Remark?: any }[]) ?? null;
    if (!remarks?.length) continue;
    const decoded = remarks.map((w) => {
      const r = w.Remark ?? {};
      const nameHex = (r.RemarkName as string) ?? "";
      const valueHex = (r.RemarkValue as string) ?? null;
      const flags = (r.Flags as number) ?? 0;
      const isImm = (flags & TF_IMMUTABLE) === TF_IMMUTABLE;
      total++; if (isImm) immutable++;
      return { name: hexToText(nameHex), nameHex, value: valueHex ? hexToText(valueHex) : null, valueHex, immutable: isImm };
    });
    out.push({ objectType: (obj.LedgerEntryType as string) ?? "?", objectId: obj.index ?? obj.LedgerIndex ?? null, remarks: decoded });
  }
  return { objectsWithRemarks: out.length, remarkCount: total, immutableCount: immutable, objects: out };
}

// ---- network wrappers ----

export async function traceTransactionStakeholders(txHash: string, network: Network) {
  const tx = await getTx(txHash, network);
  return { network, txHash, ...extractStakeholders(tx as Record<string, unknown>) };
}

export async function verifyDoubleThreading(txHash: string, network: Network) {
  const tx = await getTx(txHash, network);
  return { network, ...auditThreading(tx as Record<string, unknown>) };
}

// Accounts can own more than one page of objects; account_objects returns a `marker` to continue.
// We follow the marker so remarks on later pages aren't silently dropped. Bounded by MAX_PAGES so a
// pathological account can't drive unbounded RPC; if hit, `truncated` is surfaced honestly.
const REMARKS_MAX_PAGES = 20;

type ObjectsPage = { account_objects?: Record<string, unknown>[]; marker?: unknown };
/** Fetches one account_objects page (overridable in tests). */
export type AccountObjectsPager = (account: string, network: Network, marker: unknown) => Promise<ObjectsPage>;

const defaultPager: AccountObjectsPager = (account, network, marker) =>
  rpc<ObjectsPage>(
    "account_objects",
    { account, ledger_index: "validated", limit: 400, ...(marker !== undefined ? { marker } : {}) },
    network,
  );

/** Collect every owned object across all account_objects pages, following `marker`. Bounded by
 *  REMARKS_MAX_PAGES so a pathological account can't drive unbounded RPC. */
export async function collectAllAccountObjects(account: string, network: Network, pager: AccountObjectsPager = defaultPager) {
  const objs: Record<string, unknown>[] = [];
  let marker: unknown = undefined;
  let pages = 0;
  let truncated = false;
  do {
    const r = await pager(account, network, marker);
    objs.push(...((r.account_objects ?? []) as Record<string, unknown>[]));
    marker = r.marker;
    pages++;
    if (marker !== undefined && pages >= REMARKS_MAX_PAGES) { truncated = true; break; }
  } while (marker !== undefined);
  return { objs, pages, truncated };
}

export async function auditAccountRemarks(account: string, network: Network, pager: AccountObjectsPager = defaultPager) {
  const { objs, pages, truncated } = await collectAllAccountObjects(account, network, pager);

  const decoded = decodeRemarksOnObjects(objs);
  return {
    account, network,
    objectsScanned: objs.length,
    pagesFetched: pages,
    truncated,
    ...decoded,
    summary: `${decoded.remarkCount} remark(s) across ${decoded.objectsWithRemarks} object(s) on ${account}; ${decoded.immutableCount} immutable${truncated ? ` (TRUNCATED at ${REMARKS_MAX_PAGES} pages — more objects exist)` : ""}`,
    note: `Remarks are read from each owned ledger object's Remarks field (Remarks amendment). All object pages are followed via account_objects marker${truncated ? `, capped at ${REMARKS_MAX_PAGES} pages` : ""}.`,
  };
}
