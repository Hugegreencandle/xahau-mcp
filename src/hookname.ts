// Named-hook firing rule (NamedHooks).
//
// Ground truth: xahaud Transactor.cpp, executeHookChain (lines 1357-1369 at 20ec473be) and the
// identical fee-side check in calculateHookChainFee (lines 286-298). Introduced upstream by
// 663ed4edb "Named Hook (#718)" (2026-05-19):
//
//   requiredHookName = hookObj.sfHookName   iff present AND non-empty
//   if (requiredHookName) {
//       if (!tx.isFieldPresent(sfHookName)) continue;           // skip this hook
//       if (*requiredHookName != tx.getFieldVL(sfHookName)) continue;
//   }
//
// Notes that follow directly from that code:
//  - The check reads ONLY the Hook object's sfHookName (the per-account installation), never the
//    HookDefinition.
//  - It runs BEFORE the HookOn check, in the same loop, for every chain executeHookChain runs:
//    the originator (outgoing), strong TSH and weak TSH alike. There is no strong/weak/owner
//    distinction.
//  - Comparison is byte-exact on the VL blob. In JSON the blob is hex, so hex case is irrelevant
//    but the underlying bytes must match exactly (UTF-8 "Accept" != "accept").
//  - A hook with an ABSENT or EMPTY HookName has no requirement: it fires whether or not the tx
//    carries a HookName.
//  - The execution-side check is NOT itself amendment-gated. What is gated is how a name can
//    exist at all: SetHook rejects sfHookName without featureNamedHooks (SetHook.cpp:815-817,
//    temDISABLED) and preflight1 rejects a tx carrying sfHookName without featureNamedHooks
//    (Transactor.cpp:152-156, temMALFORMED). So on a network without NamedHooks the rule is
//    vacuous, and applying it unconditionally is exact.
//  - preflight1 also validates the tx's HookName with SetHook::validateHookName
//    (SetHook.cpp:625-638): length 0 or 4..16 bytes, valid UTF-8, else temMALFORMED.

const HEX_RE = /^([0-9a-fA-F]{2})*$/;

/** Normalise a JSON Blob value to uppercase hex. null when absent; `invalid` when present but
 *  not an even-length hex string (a JSON tx with such a value cannot be serialized). */
export function normalizeBlobHex(v: unknown): { present: boolean; hex: string | null; invalid: boolean } {
  if (v === undefined || v === null) return { present: false, hex: null, invalid: false };
  if (typeof v !== "string" || !HEX_RE.test(v)) return { present: true, hex: null, invalid: true };
  return { present: true, hex: v.toUpperCase(), invalid: false };
}

/** Best-effort UTF-8 rendering of a hex name for human-readable reasons. */
export function hookNameText(hex: string | null): string | null {
  if (!hex) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(hex, "hex"));
  } catch {
    return null;
  }
}

function label(hex: string): string {
  const t = hookNameText(hex);
  return t !== null && /^[\x20-\x7e]*$/.test(t) ? `${hex} ("${t}")` : hex;
}

/** The HookName a Hook object requires, as uppercase hex, or null if it has no requirement
 *  (field absent or empty). A present-but-non-hex value is reported as `invalid`. */
export function requiredHookName(hookObj: Record<string, unknown> | null | undefined): { hex: string | null; invalid: boolean } {
  const n = normalizeBlobHex(hookObj?.HookName);
  if (n.invalid) return { hex: null, invalid: true };
  return { hex: n.hex && n.hex.length > 0 ? n.hex : null, invalid: false };
}

export interface HookNameGate {
  /** false = xahaud skips this hook for this tx (Transactor.cpp:1362-1369) */
  passes: boolean;
  /** uppercase hex of the hook's required name, or null */
  required: string | null;
  reason?: string;
}

/** Apply the named-hook rule to one installed Hook object against one transaction. */
export function hookNameGate(hookObj: Record<string, unknown> | null | undefined, tx: Record<string, unknown>): HookNameGate {
  const req = requiredHookName(hookObj);
  if (req.invalid) {
    // Ledger JSON always renders blobs as hex; this only happens for hand-built candidates.
    return { passes: false, required: null, reason: "not fired: the hook's HookName is not valid hex, so it cannot be compared (fix the input)" };
  }
  if (!req.hex) return { passes: true, required: null };
  const t = normalizeBlobHex(tx.HookName);
  if (!t.present) {
    return { passes: false, required: req.hex, reason: `not fired: hook requires HookName ${label(req.hex)}; the transaction carries no HookName` };
  }
  if (t.invalid) {
    return { passes: false, required: req.hex, reason: `not fired: hook requires HookName ${label(req.hex)}; the transaction's HookName is not valid hex (it must be the hex of the name bytes)` };
  }
  if (t.hex !== req.hex) {
    return { passes: false, required: req.hex, reason: `not fired: hook requires HookName ${label(req.hex)}; the transaction carries ${t.hex ? label(t.hex) : "an empty HookName"}` };
  }
  return { passes: true, required: req.hex };
}

/** preflight1 checks on the tx's own HookName (Transactor.cpp:152-160). Returns null when the tx
 *  carries no HookName. Validity mirrors SetHook::validateHookName (SetHook.cpp:625-638). */
export function txHookNamePreflight(tx: Record<string, unknown>): { status: "PASS" | "WARN" | "FAIL"; detail: string } | null {
  const t = normalizeBlobHex(tx.HookName);
  if (!t.present) return null;
  const gate = "requires the NamedHooks amendment (Transactor.cpp:152-156: temMALFORMED without it) — check get_amendment_status for this network";
  if (t.invalid) {
    const hint = typeof tx.HookName === "string" ? ` (e.g. "${tx.HookName}" → ${Buffer.from(tx.HookName, "utf-8").toString("hex").toUpperCase()})` : "";
    return { status: "FAIL", detail: `HookName must be hex-encoded bytes (Blob)${hint}; not serializable as given` };
  }
  const bytes = t.hex!.length / 2;
  if (bytes !== 0 && (bytes < 4 || bytes > 16)) {
    return { status: "FAIL", detail: `HookName is ${bytes} bytes; must be 0 or 4-16 bytes (SetHook::validateHookName) → temMALFORMED` };
  }
  if (bytes > 0 && hookNameText(t.hex) === null) {
    return { status: "FAIL", detail: "HookName is not valid UTF-8 (SetHook::validateHookName) → temMALFORMED" };
  }
  return { status: "WARN", detail: `tx carries HookName ${bytes ? label(t.hex!) : "(empty)"}: ${gate}. Named hooks fire only when it matches their HookName byte-for-byte` };
}
