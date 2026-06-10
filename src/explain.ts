// explain_account — one call that turns an account into a plain-English snapshot:
// balance/keys, installed hooks (+what they fire on), trustlines, URITokens (Evernode leases
// decoded), and recent activity. Pure composition of existing read tools.
// Network access is injected (postmortem.ts pattern) so unit tests run offline; the live wiring in
// index.ts is STRICTLY SERIAL with >=1100ms spacing — exactly 5 RPC reads per invocation.
import { decodeHookOn } from "./hookon.js";
import { decodeLeaseUri } from "./evernode.js";

export interface ExplainDeps {
  getAccountInfo: (a: string) => Promise<Record<string, any>>;
  getHookObjects: (a: string) => Promise<Record<string, any>[]>;
  getLines: (a: string) => Promise<Record<string, any>[]>;
  getUriTokens: (a: string) => Promise<Record<string, any>[]>;
  getRecentTx: (a: string) => Promise<Record<string, any>[]>;
  sleep?: (ms: number) => Promise<void>;
}

export interface AccountExplained {
  address: string;
  summary: string;
  balanceXah: string | null;
  keySafety: { masterDisabled: boolean; regularKey: string | null; note: string };
  hooks: { count: number; details: { hookHash: string | null; firesOn: string[] | null }[] };
  trustlines: { count: number; currencies: string[] };
  uriTokens: { count: number; evernodeLeases: number; sample: Record<string, unknown>[] };
  recentActivity: { count: number; byType: Record<string, number>; lastTxIso: string | null };
  warnings: string[];
  notes: string[];
}

const RIPPLE_EPOCH = 946684800;
const SPACING_MS = 1100;

export async function explainAccount(address: string, deps: ExplainDeps): Promise<AccountExplained> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const warnings: string[] = [];
  const notes: string[] = [];

  const info = await deps.getAccountInfo(address);
  const a = (info.account_data ?? info) as Record<string, any>;
  const balanceXah = typeof a.Balance === "string" ? (() => { const d = BigInt(a.Balance); return `${d / 1_000_000n}.${(d % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "") || "0"}`; })() : null;
  const masterDisabled = ((a.Flags ?? 0) & 0x00100000) !== 0; // lsfDisableMaster
  const regularKey = (a.RegularKey as string) ?? null;
  const keyNote = masterDisabled
    ? "master key disabled — good practice (signing happens via the regular key / signer list)"
    : regularKey
      ? "master key still ENABLED alongside a regular key — consider disabling the master key"
      : "single master key only — consider a regular key or multi-sign for safety";
  if (!masterDisabled && regularKey) warnings.push("master key enabled while a regular key exists");

  await sleep(SPACING_MS);
  const hookObjs = await deps.getHookObjects(address);
  const hookEntry = hookObjs.find((o) => o.LedgerEntryType === "Hook");
  const hookArr: Record<string, any>[] = (hookEntry?.Hooks ?? []).map((w: any) => w.Hook ?? w);
  const hookDetails = hookArr.map((h) => ({
    hookHash: (h.HookHash as string) ?? null,
    firesOn: h.HookOn ? (() => { try { return decodeHookOn(h.HookOn).firesOn; } catch { return null; } })() : null,
  }));
  if (hookDetails.length) notes.push(`this account runs ${hookDetails.length} on-ledger Hook(s) — its transactions are subject to their rules (audit with audit_account_hooks)`);

  await sleep(SPACING_MS);
  const lines = await deps.getLines(address);
  const currencies = [...new Set(lines.map((l) => String(l.currency ?? "?")))];

  await sleep(SPACING_MS);
  const uris = await deps.getUriTokens(address);
  let evernodeLeases = 0;
  const sample: Record<string, unknown>[] = [];
  for (const u of uris) {
    const lease = typeof u.URI === "string" ? decodeLeaseUri(u.URI) : { isEvernodeLease: false };
    if (lease.isEvernodeLease) evernodeLeases++;
    if (sample.length < 5) sample.push({ uriTokenId: u.index, lease: lease.isEvernodeLease ? lease : undefined, uri: !lease.isEvernodeLease && typeof u.URI === "string" ? Buffer.from(u.URI, "hex").toString("utf-8").slice(0, 80) : undefined });
  }
  if (evernodeLeases > 0) notes.push(`${evernodeLeases} of its URITokens are Evernode hosting leases — this account is likely an Evernode host or tenant`);

  await sleep(SPACING_MS);
  const txs = await deps.getRecentTx(address);
  const byType: Record<string, number> = {};
  let lastClose: number | null = null;
  for (const t of txs) {
    const tx = (t.tx ?? t.tx_json ?? t) as Record<string, any>;
    const ty = String(tx.TransactionType ?? "?");
    byType[ty] = (byType[ty] ?? 0) + 1;
    const dt = (tx.date ?? (t as any).close_time) as number | undefined;
    if (typeof dt === "number" && (lastClose === null || dt > lastClose)) lastClose = dt;
  }
  const lastTxIso = lastClose !== null ? new Date((lastClose + RIPPLE_EPOCH) * 1000).toISOString() : null;

  const summary =
    `${address} holds ${balanceXah ?? "?"} XAH. ` +
    `${keyNote}. ` +
    `${hookDetails.length ? `${hookDetails.length} Hook(s) installed.` : "No Hooks installed."} ` +
    `${currencies.length ? `${lines.length} trustline(s) (${currencies.slice(0, 5).join(", ")}).` : "No trustlines."} ` +
    `${uris.length ? `${uris.length} URIToken(s)${evernodeLeases ? ` (${evernodeLeases} Evernode lease(s))` : ""}.` : "No URITokens."} ` +
    `${txs.length ? `Recent activity: ${Object.entries(byType).map(([k, v]) => `${v} ${k}`).join(", ")}${lastTxIso ? ` (latest ${lastTxIso.slice(0, 10)})` : ""}.` : "No recent transactions found."}`;

  return {
    address, summary, balanceXah,
    keySafety: { masterDisabled, regularKey, note: keyNote },
    hooks: { count: hookDetails.length, details: hookDetails },
    trustlines: { count: lines.length, currencies },
    uriTokens: { count: uris.length, evernodeLeases, sample },
    recentActivity: { count: txs.length, byType, lastTxIso },
    warnings, notes,
  };
}
