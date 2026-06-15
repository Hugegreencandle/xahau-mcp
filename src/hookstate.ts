// ExtendedHookState reserve-cost calculator (ExtendedHookState amendment).
//
// Hook State is a key-value store per Hook. The HookStateScale (1..16) sets, per state entry:
//   - capacity:  up to 256 * scale bytes of value
//   - reserve:   `scale` owner-reserve UNITS — charged at that rate even if the entry holds 1 byte
// You can raise the scale after state exists, but not lower it without first deleting all state.
//
// This calculator is deterministic (reserve UNITS + byte capacity). To get an XAH figure, multiply
// totalReserveUnits by your network's owner-reserve increment (fetch via server_info/server_state) —
// we don't hardcode that constant so the math can't go stale.
export const MAX_SCALE = 16;
export const BYTES_PER_UNIT = 256;

export interface HookStateEntryInput { label?: string; valueBytes: number }

export function computeHookStateCost(input: { entries: HookStateEntryInput[]; scale?: number; ownerReserveIncrementXah?: number }) {
  const scale = input.scale ?? 1;
  if (!Number.isInteger(scale) || scale < 1 || scale > MAX_SCALE) throw new Error(`scale must be an integer 1–${MAX_SCALE}`);
  if (!input.entries?.length) throw new Error("provide at least one entry (with valueBytes)");

  const perEntryCapacityBytes = BYTES_PER_UNIT * scale;
  const perEntryReserveUnits = scale;

  const entries = input.entries.map((e, i) => {
    if (!Number.isInteger(e.valueBytes) || e.valueBytes < 0) throw new Error(`entries[${i}].valueBytes must be a non-negative integer`);
    const fits = e.valueBytes <= perEntryCapacityBytes;
    return {
      label: e.label ?? `entry[${i}]`,
      valueBytes: e.valueBytes,
      fits,
      overBy: fits ? 0 : e.valueBytes - perEntryCapacityBytes,
      reserveUnits: perEntryReserveUnits,
    };
  });

  const overflows = entries.filter((e) => !e.fits);
  const totalReserveUnits = entries.length * perEntryReserveUnits;
  const minScaleNeeded = Math.max(scale, ...input.entries.map((e) => Math.ceil((e.valueBytes || 1) / BYTES_PER_UNIT)));

  const result: Record<string, unknown> = {
    scale,
    perEntryCapacityBytes,
    perEntryReserveUnits,
    entryCount: entries.length,
    totalReserveUnits,
    entries,
    overflowCount: overflows.length,
    minScaleNeeded,
    summary: `${entries.length} entr(y/ies) at scale ${scale} → ${totalReserveUnits} owner-reserve unit(s); each holds up to ${perEntryCapacityBytes} bytes`,
    caveat: "Reserve UNITS are exact. For XAH, multiply totalReserveUnits by your network's owner-reserve increment (server_info/server_state). Scale can be raised later but not lowered without deleting all hook state first.",
  };
  if (overflows.length) {
    result.warning = `${overflows.length} entr(y/ies) exceed ${perEntryCapacityBytes} bytes at scale ${scale}; raise scale to at least ${minScaleNeeded}.`;
  }
  if (typeof input.ownerReserveIncrementXah === "number") {
    result.estimatedReserveXah = totalReserveUnits * input.ownerReserveIncrementXah;
  }
  return result;
}
