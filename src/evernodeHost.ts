// evernode_host_diagnostics — one-call health check for Evernode hosts (the largest operator
// group on Xahau; the official docs make hosts walk this checklist by hand).
//
// Layout verified against the canonical EvernodeXRPL/evernode-js-client (state-helpers.js,
// evernode-common.js, base-evernode-client.js, fetched 2026-06-11) and against a live mainnet
// host state entry. All Evernode hook state lives on the GOVERNOR account in HOOK_NAMESPACE:
//  - config singletons: "EVR" + 0x01 + index (addresses are 20-byte accountIDs; sizes are u16 LE)
//  - host registration: key "EVR" + 0x03 + 8 zero bytes + 20-byte host accountID
//  - host specs (token id): key "EVR" + 0x02 + bytes [4..32) of the registration URIToken ID
// Host "active" rule (base-evernode-client.js): lastHeartbeatIndex >= current-moment-start
// minus hostHeartbeatFreq * momentSize (timestamps are UNIX seconds on mainnet, momentType=1).
// Read-only; network access injected (explain.ts pattern) so unit tests run offline.
import pkg from "xrpl-accountlib";
import * as xfl from "./xfl.js";
import { decodeLeaseUri } from "./evernode.js";
import { validateAddress } from "./util.js";

const AC = (pkg as unknown as { libraries: { rippleAddressCodec: { encodeAccountID: (b: Uint8Array) => string } } }).libraries.rippleAddressCodec;

export const EVERNODE_GOVERNOR = {
  mainnet: "rBvKgF3jSZWdJcwSsmoJspoXLLDVLDp6jg",
  testnet: "rUZXZuqhjRP2ouHTmBncp2pmntt2WmNo9c",
} as const;
export const EVERNODE_HOOK_NAMESPACE = "01EAF09326B4911554384121FF56FA8FECC215FDDE2EC35D9E59F2C53EC665A0";

// Governor-namespace config keys (evernode-common.js HookStateKeys)
export const EVK = {
  EVR_ISSUER_ADDR: "4556520100000000000000000000000000000000000000000000000000000001",
  MOMENT_SIZE: "4556520100000000000000000000000000000000000000000000000000000003",
  HOST_HEARTBEAT_FREQ: "4556520100000000000000000000000000000000000000000000000000000006",
  HEARTBEAT_ADDR: "455652010000000000000000000000000000000000000000000000000000000C",
  MOMENT_BASE_INFO: "4556523300000000000000000000000000000000000000000000000000000000",
  PREFIX_HOST_TOKENID: "45565202",
  PREFIX_HOST_ADDR: "45565203",
} as const;

const RIPPLE_EPOCH = 946684800;

export interface HostDeps {
  getAccountInfo: (a: string) => Promise<Record<string, any>>;
  /** ledger_entry hook_state on the governor account; null when the entry doesn't exist. */
  getHookState: (key: string) => Promise<string | null>;
  getLines: (a: string) => Promise<Record<string, any>[]>;
  getUriTokens: (a: string) => Promise<Record<string, any>[]>;
  /** current validated ledger close time (Ripple time, seconds) — used as "now". */
  getCloseTime: () => Promise<number>;
  sleep?: (ms: number) => Promise<void>;
}

export interface HostCheck {
  name: string;
  status: "PASS" | "WARN" | "FAIL" | "INFO";
  detail: string;
}

export interface HostDiagnostics {
  address: string;
  network: string;
  isRegisteredHost: boolean;
  summary: string;
  checks: HostCheck[];
  registration: {
    uriTokenId: string;
    countryCode: string;
    description: string;
    registrationLedger: number;
    version: string;
    maxInstances: number;
    activeInstances: number;
    reputation: number | null;
    reputedOnHeartbeat: boolean | null;
    transferPending: boolean;
    leaseAmountEvr: string | null;
  } | null;
  heartbeat: {
    lastHeartbeatUnix: number;
    lastHeartbeatIso: string | null;
    active: boolean;
    secondsSinceLast: number;
    momentSizeSeconds: number;
    heartbeatFreqMoments: number;
    momentsMissed: number;
  } | null;
  specs: {
    cpuModelName: string;
    cpuCount: number;
    cpuMHz: number;
    ramMb: number;
    diskMb: number;
    email: string;
    accumulatedRewardEvr: string;
  } | null;
  balances: { xah: number | null; evr: string | null; evrIssuer: string | null };
  leases: { totalLeaseTokens: number; offered: number; leasedOut: number };
  warnings: string[];
  notes: string[];
}

const SPACING_MS = 1100;

/* ---------- buffer decode helpers (offsets from state-helpers.js, verified live) ---------- */
const u16 = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8);
const u32 = (b: Uint8Array, o: number) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u64 = (b: Uint8Array, o: number) => { let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; };
const i64 = (b: Uint8Array, o: number) => BigInt.asIntN(64, u64(b, o));
const ascii = (b: Uint8Array, s: number, e: number) => Buffer.from(b.slice(s, e)).toString("utf-8").replace(/\0/g, "");
const hexOf = (b: Uint8Array, s: number, e: number) => Buffer.from(b.slice(s, e)).toString("hex").toUpperCase();
const fromHexStr = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

function xflToString(x: bigint): string {
  if (x <= 0n) return "0";
  const f = xfl.decode(x);
  if (f.zero) return "0";
  const m = f.mant.toString();
  const point = m.length + f.exp;
  let s: string;
  if (point <= 0) s = "0." + "0".repeat(-point) + m;
  else if (point >= m.length) s = m + "0".repeat(point - m.length);
  else s = m.slice(0, point) + "." + m.slice(point);
  if (s.includes(".")) s = s.replace(/0+$/, "").replace(/\.$/, "");
  return (f.sign < 0 ? "-" : "") + s;
}

/** HOST_ADDR registration state (state-helpers.js decodeHostAddressState; min 135 bytes seen live as 143). */
export function decodeHostAddrState(data: Uint8Array) {
  return {
    uriTokenId: hexOf(data, 0, 32),
    countryCode: ascii(data, 32, 34),
    description: ascii(data, 42, 68),
    registrationLedger: Number(u64(data, 68)),
    registrationFee: Number(u64(data, 76)),
    maxInstances: u32(data, 84),
    activeInstances: u32(data, 88),
    lastHeartbeatIndex: Number(u64(data, 92)),
    version: `${data[100]}.${data[101]}.${data[102]}`,
    transferPending: data.length > 111 ? data[111] === 1 : false,
    reputation: data.length > 125 ? data[125] : null,
    reputedOnHeartbeat: data.length > 126 ? (data[126] & 1) !== 0 : null,
    leaseAmountEvr: data.length >= 143 ? xflToString(i64(data, 135)) : null,
  };
}

/** HOST_TOKENID specs state (state-helpers.js decodeTokenIdState). */
export function decodeTokenIdState(data: Uint8Array) {
  return {
    cpuModelName: ascii(data, 20, 60).trim(),
    cpuCount: u16(data, 60),
    cpuMHz: u16(data, 62),
    ramMb: u32(data, 68),
    diskMb: u32(data, 72),
    email: ascii(data, 76, 116),
    accumulatedRewardEvr: data.length >= 124 ? xflToString(i64(data, 116)) : "0",
  };
}

export function hostAddrKey(accountIdHex: string): string {
  return EVK.PREFIX_HOST_ADDR + "00".repeat(8) + accountIdHex.toUpperCase();
}
export function tokenIdKey(uriTokenIdHex: string): string {
  return EVK.PREFIX_HOST_TOKENID + uriTokenIdHex.slice(8, 64).toUpperCase();
}

export async function evernodeHostDiagnostics(address: string, network: string, deps: HostDeps): Promise<HostDiagnostics> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const warnings: string[] = [];
  const notes: string[] = [];
  const checks: HostCheck[] = [];

  const v = validateAddress(address);
  const accountId = v.valid && "accountId" in v && typeof v.accountId === "string" ? v.accountId : null;
  if (!accountId) throw new Error(`not a valid r-address: ${address}`);

  // 1. host account exists + XAH balance
  const info = await deps.getAccountInfo(address);
  const a = (info.account_data ?? info) as Record<string, any>;
  const xahBalance = typeof a.Balance === "string" ? Number(BigInt(a.Balance)) / 1e6 : null;
  if (xahBalance !== null && xahBalance < 1) {
    checks.push({ name: "XAH balance", status: "WARN", detail: `${xahBalance} XAH — very low; heartbeats and lease handling need tx fees (heuristic threshold 1 XAH; see docs.evernode.org for the authoritative minimums)` });
    warnings.push("XAH balance very low — host may fail to send heartbeats");
  } else {
    checks.push({ name: "XAH balance", status: "PASS", detail: `${xahBalance ?? "?"} XAH` });
  }

  // 2. registration entry on the governor namespace
  await sleep(SPACING_MS);
  const regHex = await deps.getHookState(hostAddrKey(accountId));
  if (!regHex) {
    checks.push({ name: "registration", status: "FAIL", detail: "no host registration entry on the Evernode governor namespace — this account is not a registered Evernode host" });
    return {
      address, network, isRegisteredHost: false,
      summary: `${address} is NOT a registered Evernode host (no registration entry in the governor's hook state). If this should be a host, run the Evernode installer / 'evernode register'; see docs.evernode.org.`,
      checks, registration: null, heartbeat: null, specs: null,
      balances: { xah: xahBalance, evr: null, evrIssuer: null },
      leases: { totalLeaseTokens: 0, offered: 0, leasedOut: 0 },
      warnings, notes,
    };
  }
  const reg = decodeHostAddrState(fromHexStr(regHex));
  checks.push({ name: "registration", status: "PASS", detail: `registered (ledger ${reg.registrationLedger}, country ${reg.countryCode}, version ${reg.version})` });
  if (reg.transferPending) {
    checks.push({ name: "transfer", status: "WARN", detail: "a host transfer is PENDING on this registration" });
    warnings.push("host transfer pending");
  }

  // 3. heartbeat liveness vs the on-chain active rule
  await sleep(SPACING_MS);
  const momentSizeHex = await deps.getHookState(EVK.MOMENT_SIZE);
  await sleep(SPACING_MS);
  const freqHex = await deps.getHookState(EVK.HOST_HEARTBEAT_FREQ);
  await sleep(SPACING_MS);
  const baseHex = await deps.getHookState(EVK.MOMENT_BASE_INFO);
  await sleep(SPACING_MS);
  const closeTime = await deps.getCloseTime();
  const nowUnix = closeTime + RIPPLE_EPOCH;

  let heartbeat: HostDiagnostics["heartbeat"] = null;
  if (momentSizeHex && freqHex && baseHex) {
    const momentSize = u16(fromHexStr(momentSizeHex), 0);
    const freq = u16(fromHexStr(freqHex), 0);
    const base = fromHexStr(baseHex);
    const baseIdx = Number(u64(base, 0));
    // current moment start (timestamp moment type; base-evernode-client.js active rule)
    const curMomentStart = baseIdx + Math.floor((nowUnix - baseIdx) / momentSize) * momentSize;
    const active = reg.lastHeartbeatIndex > freq * momentSize
      ? reg.lastHeartbeatIndex >= curMomentStart - freq * momentSize
      : reg.lastHeartbeatIndex > 0;
    const secondsSince = reg.lastHeartbeatIndex > 0 ? Math.max(0, nowUnix - reg.lastHeartbeatIndex) : -1;
    const momentsMissed = reg.lastHeartbeatIndex > 0 ? Math.max(0, Math.floor((curMomentStart - reg.lastHeartbeatIndex) / momentSize)) : -1;
    heartbeat = {
      lastHeartbeatUnix: reg.lastHeartbeatIndex,
      lastHeartbeatIso: reg.lastHeartbeatIndex > 0 ? new Date(reg.lastHeartbeatIndex * 1000).toISOString() : null,
      active, secondsSinceLast: secondsSince,
      momentSizeSeconds: momentSize, heartbeatFreqMoments: freq, momentsMissed,
    };
    if (active) {
      checks.push({ name: "heartbeat", status: "PASS", detail: `ACTIVE — last heartbeat ${heartbeat.lastHeartbeatIso} (${Math.floor(secondsSince / 60)} min ago; rule: within ${freq} moment(s) of ${momentSize}s)` });
    } else {
      checks.push({ name: "heartbeat", status: "FAIL", detail: `INACTIVE — last heartbeat ${heartbeat.lastHeartbeatIso ?? "never"}; ${momentsMissed >= 0 ? `${momentsMissed} moment(s) missed` : "no heartbeat recorded"}. Check the Sashimono/evernode services on the machine (evernode status).` });
      warnings.push("host is INACTIVE by the on-chain heartbeat rule — it will not win leases and risks deregistration/reputation loss");
    }
  } else {
    notes.push("could not read Evernode moment/heartbeat config from the governor namespace — heartbeat liveness not evaluated");
  }

  // 4. instance load
  checks.push({
    name: "instances",
    status: reg.maxInstances > 0 && reg.activeInstances >= reg.maxInstances ? "INFO" : "PASS",
    detail: `${reg.activeInstances}/${reg.maxInstances} instances in use${reg.leaseAmountEvr ? ` · lease price ${reg.leaseAmountEvr} EVR/moment` : ""}`,
  });

  // 5. reputation
  if (reg.reputation !== null) {
    const repOk = reg.reputation >= 200; // hosts start at 200 in reputationD scoring (0-255 scale)
    checks.push({ name: "reputation", status: repOk ? "PASS" : "WARN", detail: `on-chain reputation byte ${reg.reputation}/255${reg.reputedOnHeartbeat !== null ? ` · reputed-on-heartbeat ${reg.reputedOnHeartbeat}` : ""} (threshold heuristic 200 — reputationD docs are authoritative)` });
    if (!repOk) warnings.push(`reputation ${reg.reputation}/255 below the common reward threshold — check reputationD service`);
  }

  // 6. EVR trustline + balance
  await sleep(SPACING_MS);
  const issuerHex = await deps.getHookState(EVK.EVR_ISSUER_ADDR);
  let evrIssuer: string | null = null;
  let evrBalance: string | null = null;
  await sleep(SPACING_MS);
  const lines = await deps.getLines(address);
  if (issuerHex && issuerHex.length === 40) {
    const enc = validAccountIdToR(issuerHex);
    evrIssuer = enc;
    const evrLine = lines.find((l) => String(l.currency) === "EVR" && (!enc || String(l.account) === enc));
    evrBalance = evrLine ? String(evrLine.balance) : null;
    if (!evrLine) {
      checks.push({ name: "EVR trustline", status: "FAIL", detail: `no EVR trustline to the issuer (${enc ?? issuerHex}) — hosts need one to receive lease payments and rewards` });
      warnings.push("missing EVR trustline");
    } else {
      checks.push({ name: "EVR trustline", status: "PASS", detail: `${evrBalance} EVR` });
    }
  } else {
    const evrLine = lines.find((l) => String(l.currency) === "EVR");
    evrBalance = evrLine ? String(evrLine.balance) : null;
    notes.push("EVR issuer config unreadable — trustline matched by currency code only");
  }

  // 7. registration URIToken held + lease tokens
  await sleep(SPACING_MS);
  const uris = await deps.getUriTokens(address);
  const holdsRegToken = uris.some((u) => String(u.index ?? "").toUpperCase() === reg.uriTokenId);
  checks.push(holdsRegToken
    ? { name: "registration URIToken", status: "PASS", detail: `held (${reg.uriTokenId.slice(0, 16)}…)` }
    : { name: "registration URIToken", status: "WARN", detail: `registration URIToken ${reg.uriTokenId.slice(0, 16)}… NOT found on the host account — expected unless a transfer is in flight` });
  if (!holdsRegToken && !reg.transferPending) warnings.push("registration URIToken missing from the host account");

  let totalLease = 0, offered = 0, leasedOut = 0;
  for (const u of uris) {
    const lease = typeof u.URI === "string" ? decodeLeaseUri(u.URI) : { isEvernodeLease: false };
    if (!lease.isEvernodeLease) continue;
    totalLease++;
    if (u.Amount !== undefined) offered++; // URIToken with a sell offer = lease on the market
  }
  leasedOut = Math.max(0, reg.activeInstances); // instances in use per the registry
  checks.push({ name: "lease offers", status: totalLease > 0 || reg.maxInstances === 0 ? "PASS" : "WARN", detail: `${totalLease} lease URIToken(s) on the account, ${offered} with an open sell offer; registry says ${reg.activeInstances}/${reg.maxInstances} instances in use` });

  // 8. specs + accumulated reward (token-id state)
  await sleep(SPACING_MS);
  const specsHex = await deps.getHookState(tokenIdKey(reg.uriTokenId));
  let specs: HostDiagnostics["specs"] = null;
  if (specsHex) {
    const t = decodeTokenIdState(fromHexStr(specsHex));
    specs = { cpuModelName: t.cpuModelName, cpuCount: t.cpuCount, cpuMHz: t.cpuMHz, ramMb: t.ramMb, diskMb: t.diskMb, email: t.email, accumulatedRewardEvr: t.accumulatedRewardEvr };
    checks.push({ name: "accumulated reward", status: "INFO", detail: `${t.accumulatedRewardEvr} EVR accumulated (paid out per the reward configuration)` });
  }

  const fails = checks.filter((c) => c.status === "FAIL").length;
  const warns = checks.filter((c) => c.status === "WARN").length;
  const headline = fails > 0 ? `${fails} FAILING check(s)` : warns > 0 ? `healthy with ${warns} warning(s)` : "healthy";
  const summary = `${address} — Evernode host (${reg.countryCode}, v${reg.version}): ${headline}. ` +
    `${heartbeat ? (heartbeat.active ? "ACTIVE" : "INACTIVE") : "liveness unknown"} · ${reg.activeInstances}/${reg.maxInstances} instances · ` +
    `${xahBalance ?? "?"} XAH · ${evrBalance ?? "no"} EVR${specs ? ` · ${specs.accumulatedRewardEvr} EVR reward accumulated` : ""}.`;

  return {
    address, network, isRegisteredHost: true, summary, checks,
    registration: {
      uriTokenId: reg.uriTokenId, countryCode: reg.countryCode, description: reg.description,
      registrationLedger: reg.registrationLedger, version: reg.version,
      maxInstances: reg.maxInstances, activeInstances: reg.activeInstances,
      reputation: reg.reputation, reputedOnHeartbeat: reg.reputedOnHeartbeat,
      transferPending: reg.transferPending, leaseAmountEvr: reg.leaseAmountEvr,
    },
    heartbeat, specs,
    balances: { xah: xahBalance, evr: evrBalance, evrIssuer },
    leases: { totalLeaseTokens: totalLease, offered, leasedOut },
    warnings, notes,
  };
}

function validAccountIdToR(accountIdHex: string): string | null {
  try {
    return AC.encodeAccountID(Uint8Array.from(Buffer.from(accountIdHex, "hex")));
  } catch {
    return null;
  }
}
