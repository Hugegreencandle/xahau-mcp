// Genesis Governance Game — full per-seat / per-topic / per-vote decode of the L1 table's hook
// state. Layout is CANONICAL, from the header comment of Xahau/xahaud hook/genesis/govern.c
// (fetched + verified against the live genesis namespace 2026-06-11):
//
//   {0..0,'M','C'}                       -> member count <1B>
//   {0..0,'R','R'} / {0..0,'R','D'}      -> reward rate / delay <8B LE XFL>
//   {0..0, seat-id}                      -> seat occupant <20B accid> (key 31 zero bytes + seat byte)
//   {0..0, <20B accid>}                  -> seat number this member occupies <1B> (12 zero bytes + accid)
//   {'V', 'H|R|S', topic-id, layer, 0.., <member accid>} -> that member's vote (topic data)
//   {'C', 'H|R|S', topic-id, layer, 0.., <front-truncated topic data>} -> votes for that exact data <1B>
//
// Thresholds (same source): membership (seat) topics need 80% of filled seats; everything else 100%.
// 20-seat round table. A vote of all-zero topic data on a seat = vote to VACATE it.
import { decode as xflDecode } from "./xfl.js";
import { accountIdToR } from "./util.js";

export const SEAT_COUNT = 20;

export interface GovernanceVote {
  topic: string; // "seat 7" | "hook position 3" | "reward rate" | "reward delay"
  layer: number;
  voter: string | null; // r-address
  votedFor: string; // decoded target: r-address | "(vacate)" | hook hash | XFL number
}

export interface GovernanceTally {
  topic: string;
  layer: number;
  votedFor: string; // decoded from the front-truncated topic data
  votes: number;
  needed: number;
  reached: boolean;
}

export interface GovernanceDecoded {
  memberCount: number | null;
  seats: { seat: number; address: string | null }[]; // all 20 seats, null = unoccupied
  rewardRate: number | null;
  rewardDelaySeconds: number | null;
  openVotes: GovernanceVote[];
  tallies: GovernanceTally[];
  unparsedEntries: number;
  summary: string;
}

const leU64 = (hex: string): bigint => { let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(parseInt(hex.slice(i * 2, i * 2 + 2), 16)); return v; };
const xflNum = (hex: string): number | null => {
  if (!/^[0-9a-fA-F]{16}$/.test(hex)) return null;
  const f = xflDecode(leU64(hex));
  return f.zero ? 0 : f.sign * Number(f.mant) * Math.pow(10, f.exp);
};

function topicName(typeByte: number, idByte: number): string {
  const t = String.fromCharCode(typeByte);
  if (t === "S") return `seat ${idByte}`;
  if (t === "H") return `hook position ${idByte}`;
  if (t === "R") { const d = String.fromCharCode(idByte); return d === "R" ? "reward rate" : d === "D" ? "reward delay" : `reward ${d}`; }
  return `topic ${t}${idByte}`;
}

function decodeTopicData(typeByte: number, dataHex: string): string {
  const t = String.fromCharCode(typeByte);
  if (t === "S") {
    const accid = dataHex.slice(-40);
    if (/^0{40}$/.test(accid)) return "(vacate)";
    return accountIdToR(accid) ?? accid;
  }
  if (t === "H") return dataHex.replace(/^0+/, "").padStart(64, "0").toUpperCase();
  if (t === "R") { const x = xflNum(dataHex.slice(-16)); return x !== null ? String(x) : dataHex; }
  return dataHex;
}

/** Decode the genesis governance namespace entries (HookStateKey/HookStateData pairs). */
export function decodeGovernance(entries: { HookStateKey?: string; HookStateData?: string }[]): GovernanceDecoded {
  let memberCount: number | null = null;
  let rewardRate: number | null = null;
  let rewardDelaySeconds: number | null = null;
  const seatMap = new Map<number, string>();
  const openVotes: GovernanceVote[] = [];
  const rawTallies: GovernanceTally[] = [];
  let unparsed = 0;

  for (const e of entries) {
    const key = String(e.HookStateKey ?? "").toUpperCase();
    const data = String(e.HookStateData ?? "").toUpperCase();
    if (key.length !== 64) { unparsed++; continue; }
    const k0 = parseInt(key.slice(0, 2), 16);

    if (key.endsWith("4D43") && /^0{60}$/.test(key.slice(0, 60))) { memberCount = parseInt(data.slice(0, 2), 16); continue; }
    if (key.endsWith("5252") && /^0{60}$/.test(key.slice(0, 60))) { rewardRate = xflNum(data); continue; }
    if (key.endsWith("5244") && /^0{60}$/.test(key.slice(0, 60))) { const x = xflNum(data); rewardDelaySeconds = x !== null ? Math.round(x) : null; continue; }

    // seat -> member (31 zero bytes + seat byte; data 20B accid). Seat 0 key is all zeros.
    if (/^0{62}/.test(key.slice(0, 62)) && data.length === 40) {
      const seat = parseInt(key.slice(62), 16);
      if (seat < SEAT_COUNT) { seatMap.set(seat, accountIdToR(data) ?? data); continue; }
    }
    // member -> seat reverse (12 zero bytes + accid; data 1B) — redundant with the above, skip silently
    if (/^0{24}/.test(key.slice(0, 24)) && !/^0{40}$/.test(key.slice(24)) && data.length === 2) continue;

    if (k0 === 0x56 /* 'V' vote */) {
      const typeByte = parseInt(key.slice(2, 4), 16);
      const idByte = parseInt(key.slice(4, 6), 16);
      const layer = parseInt(key.slice(6, 8), 16);
      const voterHex = key.slice(24);
      openVotes.push({
        topic: topicName(typeByte, idByte), layer,
        voter: accountIdToR(voterHex),
        votedFor: decodeTopicData(typeByte, data),
      });
      continue;
    }
    if (k0 === 0x43 /* 'C' count */) {
      const typeByte = parseInt(key.slice(2, 4), 16);
      const idByte = parseInt(key.slice(4, 6), 16);
      const layer = parseInt(key.slice(6, 8), 16);
      rawTallies.push({
        topic: topicName(typeByte, idByte), layer,
        votedFor: decodeTopicData(typeByte, key.slice(8)),
        votes: parseInt(data.slice(0, 2), 16) || 0,
        needed: 0, reached: false, // filled below once memberCount is known
      });
      continue;
    }
    unparsed++;
  }

  // thresholds (govern.c): seat/membership topics 80% of filled seats, everything else 100%
  const mc = memberCount ?? seatMap.size;
  for (const t of rawTallies) {
    t.needed = t.topic.startsWith("seat") ? Math.ceil(mc * 0.8) : mc;
    t.reached = mc > 0 && t.votes >= t.needed;
  }

  const seats = Array.from({ length: SEAT_COUNT }, (_, i) => ({ seat: i, address: seatMap.get(i) ?? null }));
  const occupied = seats.filter((s) => s.address !== null).length;
  const activeTallies = rawTallies.filter((t) => t.votes > 0);
  const summary =
    `Governance table: ${occupied}/${SEAT_COUNT} seats filled (member count ${mc}). ` +
    `Reward rate ${rewardRate ?? "?"} per period, delay ${rewardDelaySeconds ?? "?"}s. ` +
    (activeTallies.length
      ? `${activeTallies.length} open tally(ies): ${activeTallies.slice(0, 3).map((t) => `${t.topic} -> ${t.votedFor} (${t.votes}/${t.needed}${t.reached ? " REACHED" : ""})`).join("; ")}${activeTallies.length > 3 ? "; …" : ""}.`
      : "No open vote tallies.");

  return { memberCount, seats, rewardRate, rewardDelaySeconds, openVotes, tallies: rawTallies, unparsedEntries: unparsed, summary };
}
