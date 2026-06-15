// Network amendment intelligence for Xahau.
//
// Reads the on-ledger Amendments singleton (enabled set + Majorities voting set) over the
// repo's fixed read-only RPC endpoints — NO admin node required. Amendment IDs are
// SHA512-Half(ASCII name); we ship a known-name table (data/amendments.json) and resolve IDs
// to names, leaving unknown IDs as their raw hash (forward-compatible — new amendments just
// show as a hash until their name is added to the data file).
//
// PUBLIC-RPC LIMITS (documented, not bugs):
//  - The on-ledger Majorities array lists only amendments that ALREADY hold >80% support and
//    are counting toward enablement. Sub-80% candidates and per-validator vote breakdowns
//    require an admin `feature` call or a validation-stream subscription — out of scope for a
//    read-only, no-admin server.
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { getLedgerEntry, getServerInfo, type Network } from "./rpc.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const NAMES_FILE = join(__dirname, "..", "data", "amendments.json");

/** Canonical keylet of the Amendments singleton ledger object. */
export const AMENDMENTS_INDEX = "7DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4";

/** Xahau enables an amendment after it holds >80% validator support for this long (5 days). */
export const MAJORITY_SECONDS = 5 * 24 * 60 * 60;
/** Ripple epoch (2000-01-01 UTC) in unix seconds; ledger CloseTime is offset from here. */
export const RIPPLE_EPOCH = 946684800;

/** Amendment ID = first 32 bytes of SHA512(ASCII name), uppercase hex. */
export function amendmentId(name: string): string {
  return createHash("sha512").update(name, "ascii").digest("hex").slice(0, 64).toUpperCase();
}

interface AmendmentsFile { names?: string[]; categories?: Record<string, string> }
let NAMES: string[] = [];
let CATS: Record<string, string> = {};
if (existsSync(NAMES_FILE)) {
  const f = JSON.parse(readFileSync(NAMES_FILE, "utf-8")) as AmendmentsFile;
  NAMES = f.names ?? [];
  CATS = f.categories ?? {};
}
const ID_TO_NAME = new Map<string, string>(NAMES.map((n) => [amendmentId(n), n]));

/** Resolve an amendment ID hash to its known name, or null if not in the table. */
export function nameFor(id: string): string | null {
  return ID_TO_NAME.get(id.toUpperCase()) ?? null;
}
export const KNOWN_NAME_COUNT = NAMES.length;

/** feature vs fix vs unknown, from name shape (or explicit category override). */
export function classify(name: string | null): "feature" | "fix" | "unknown" {
  if (!name) return "unknown";
  if (CATS[name]) return CATS[name] as "feature" | "fix";
  return name.startsWith("fix") ? "fix" : "feature";
}

export interface AmendmentsNode {
  Amendments?: string[];
  Majorities?: { Majority: { Amendment: string; CloseTime: number } }[];
}

function named(id: string) {
  const name = nameFor(id);
  return { id, name, category: classify(name) };
}

// ---- pure compute (unit-testable, no network) ----

export function computeStatus(node: AmendmentsNode, network: Network) {
  const enabled = (node.Amendments ?? []).map(named);
  const voting = (node.Majorities ?? []).map((m) => ({
    ...named(m.Majority.Amendment),
    gotMajorityAt: m.Majority.CloseTime,
  }));
  const namedCount = enabled.filter((e) => e.name).length;
  return {
    network,
    enabledCount: enabled.length,
    votingCount: voting.length,
    namedCount,
    unnamedCount: enabled.length - namedCount,
    knownNameTableSize: KNOWN_NAME_COUNT,
    enabled,
    voting,
    summary: `${enabled.length} enabled (${namedCount} named, ${enabled.length - namedCount} unnamed), ${voting.length} in voting on ${network}`,
    caveat:
      "voting[] reflects only amendments already at >80% (the on-ledger Majorities set). Sub-80% candidates and per-validator votes need an admin `feature` call or the validation stream.",
  };
}

export function computePrediction(node: AmendmentsNode, network: Network, nowUnix: number) {
  const pending = (node.Majorities ?? []).map((m) => {
    const gotMajorityUnix = m.Majority.CloseTime + RIPPLE_EPOCH;
    const eta = gotMajorityUnix + MAJORITY_SECONDS;
    const secondsRemaining = eta - nowUnix;
    return {
      ...named(m.Majority.Amendment),
      gotMajorityAt: new Date(gotMajorityUnix * 1000).toISOString(),
      estimatedEnableAt: new Date(eta * 1000).toISOString(),
      secondsRemaining,
      daysRemaining: Math.max(0, Math.round((secondsRemaining / 86400) * 10) / 10),
      eligibleNow: secondsRemaining <= 0,
    };
  });
  return {
    network,
    majorityWindowDays: MAJORITY_SECONDS / 86400,
    pendingCount: pending.length,
    pending,
    summary: pending.length
      ? `${pending.length} amendment(s) hold majority and are counting toward enablement on ${network}`
      : `no amendments currently hold majority on ${network}`,
    caveat:
      "ETA is APPROXIMATE: it models the >80%-for-5-days majority window only and does NOT include the protocol's flag-ledger +2 step — enablement actually lands at the next flag ledger plus 2, so the true activation is at or slightly after estimatedEnableAt, not before. ETA also assumes support is sustained; if support drops below 80% (tfLostMajority) the window resets. Per-validator votes require an admin `feature` call.",
  };
}

export function computeDiff(nodeA: AmendmentsNode, nodeB: AmendmentsNode, a: Network, b: Network) {
  const ea = new Set(nodeA.Amendments ?? []);
  const eb = new Set(nodeB.Amendments ?? []);
  const onlyOnA = [...ea].filter((x) => !eb.has(x)).map(named);
  const onlyOnB = [...eb].filter((x) => !ea.has(x)).map(named);
  return {
    a,
    b,
    enabledA: ea.size,
    enabledB: eb.size,
    onlyOnA,
    onlyOnB,
    summary: `${onlyOnA.length} enabled only on ${a}, ${onlyOnB.length} only on ${b} (${ea.size} vs ${eb.size} total)`,
  };
}

// ---- network wrappers ----

async function readNode(network: Network): Promise<AmendmentsNode> {
  const r = await getLedgerEntry({ index: AMENDMENTS_INDEX }, network);
  return ((r as { node?: AmendmentsNode }).node ?? {}) as AmendmentsNode;
}

export async function getAmendmentStatus(network: Network) {
  return computeStatus(await readNode(network), network);
}

export async function predictAmendmentActivation(network: Network) {
  return computePrediction(await readNode(network), network, Math.floor(Date.now() / 1000));
}

export async function diffNodeAmendments(a: Network, b: Network) {
  const [na, nb] = await Promise.all([readNode(a), readNode(b)]);
  return computeDiff(na, nb, a, b);
}

export async function checkAmendmentBlocked(network: Network) {
  const info = (await getServerInfo(network)).info as Record<string, unknown>;
  const blocked = Boolean(info.amendment_blocked);
  const build = (info.build_version as string) ?? null;
  return {
    network,
    amendmentBlocked: blocked,
    buildVersion: build,
    networkId: info.network_id ?? null,
    validatedLedger: (info.validated_ledger as { seq?: number } | undefined)?.seq ?? null,
    summary: blocked
      ? `⚠ configured ${network} node is AMENDMENT BLOCKED (build ${build}) — it can't validate ledgers, submit txns, or vote until upgraded`
      : `configured ${network} node is not amendment blocked (build ${build})`,
    remedy: blocked
      ? "Upgrade xahaud to the latest release that includes the newly-enabled amendment's code, then restart."
      : null,
    note: "Checks the server's fixed RPC endpoint for this network (no arbitrary-URL input, by design).",
  };
}
