// Xahau binary codec helpers, backed by xrpl-accountlib's Xahau-aware binary codec.
// Encode/decode are used for INSPECTION only — nothing here signs or submits.
import pkg from "xrpl-accountlib";
import { decodeHookOn } from "./hookon.js";
const { binary } = pkg as unknown as { binary: { encode: (tx: object) => string; decode: (hex: string) => Record<string, unknown> } };

const DROPS_PER_XAH = 1_000_000n;

export function xahAmount(value: string | number, from: "xah" | "drops"): { xah: string; drops: string } {
  if (from === "drops") {
    const d = BigInt(String(value).trim());
    const xah = (Number(d) / Number(DROPS_PER_XAH)).toString();
    return { xah, drops: d.toString() };
  }
  const [whole, frac = ""] = String(value).trim().split(".");
  const fracPadded = (frac + "000000").slice(0, 6);
  const drops = BigInt(whole || "0") * DROPS_PER_XAH + BigInt(fracPadded || "0");
  return { xah: String(value), drops: drops.toString() };
}

export function decodeTxBlob(txBlobHex: string): Record<string, unknown> {
  return binary.decode(txBlobHex.trim().replace(/^0x/i, ""));
}

export function encodeTxBlob(tx: object): { txBlobHex: string } {
  return { txBlobHex: binary.encode(tx) };
}

export interface DecodedHook {
  position: number;
  createCodeHex?: string;
  createCodeBytes?: number;
  hookHash?: string;
  hookOn?: string;
  hookOnDecoded?: { firesOn: string[]; count: number };
  hookApiVersion?: number;
  namespace?: string;
  parameters: { name?: string; value?: string }[];
  grants: { authorize?: string; hookHash?: string }[];
  flags?: number;
}

export function decodeSetHook(input: { tx?: Record<string, unknown>; txBlobHex?: string }): { transactionType: string; account?: string; hooks: DecodedHook[] } {
  const tx = input.tx ?? (input.txBlobHex ? decodeTxBlob(input.txBlobHex) : undefined);
  if (!tx) throw new Error("provide tx or txBlobHex");
  const hooksArr = (tx.Hooks as { Hook?: Record<string, unknown> }[] | undefined) ?? [];
  const hooks: DecodedHook[] = hooksArr.map((entry, i) => {
    const h = entry.Hook ?? {};
    const createCodeHex = h.CreateCode as string | undefined;
    const hookOn = h.HookOn as string | undefined;
    const params = ((h.HookParameters as { HookParameter?: { HookParameterName?: string; HookParameterValue?: string } }[] | undefined) ?? [])
      .map((p) => ({ name: p.HookParameter?.HookParameterName, value: p.HookParameter?.HookParameterValue }));
    const grants = ((h.HookGrants as { HookGrant?: { Authorize?: string; HookHash?: string } }[] | undefined) ?? [])
      .map((g) => ({ authorize: g.HookGrant?.Authorize, hookHash: g.HookGrant?.HookHash }));
    return {
      position: i,
      createCodeHex,
      createCodeBytes: createCodeHex ? createCodeHex.length / 2 : undefined,
      hookHash: h.HookHash as string | undefined,
      hookOn,
      hookOnDecoded: hookOn ? (({ firesOn, count }) => ({ firesOn, count }))(decodeHookOn(hookOn)) : undefined,
      hookApiVersion: h.HookApiVersion as number | undefined,
      namespace: h.HookNamespace as string | undefined,
      parameters: params,
      grants,
      flags: h.Flags as number | undefined,
    };
  });
  return { transactionType: tx.TransactionType as string, account: tx.Account as string | undefined, hooks };
}

export function decodeUriTokenId(id: string): { uriTokenId: string; valid: boolean; note: string } {
  const clean = id.trim().replace(/^0x/i, "").toUpperCase();
  const valid = /^[0-9A-F]{64}$/.test(clean);
  return {
    uriTokenId: clean,
    valid,
    note: valid
      ? "Valid 256-bit URIToken ID. The ID is SHA512-Half(issuer || URI) and is not reversible to its URI offline; fetch the URIToken ledger object to read the issuer/URI/digest."
      : "Not a valid 256-bit (64 hex char) URIToken ID.",
  };
}
