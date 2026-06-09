// Generate a starter Xahau Hook (C, the canonical Hooks language) for a stated intent.
// Every template is structurally valid (hook() entry, _g guards, an accept/rollback exit path) and
// is meant as a STARTING POINT: compile it with the Hooks Builder, then verify with this MCP's
// analyze_hook + execute_hook before you ever SetHook it on mainnet.

export type Archetype = "accept_all" | "firewall" | "payment_limit" | "require_dest_tag" | "state_counter" | "notary";

export interface ScaffoldOpts {
  archetype: Archetype;
  blockTxType?: string; // for firewall, e.g. "Payment"
  maxDrops?: string;    // for payment_limit
}

const HEADER = `#include <stdint.h>\n#include "hookapi.h"\n\n// cbak() handles the result of any transactions this hook emit()s. Safe no-op if you don't emit.\nint64_t cbak(uint32_t reserved) { _g(1,1); return 0; }\n`;

const TT: Record<string, string> = {
  Payment: "ttPAYMENT", SetHook: "ttHOOK_SET", TrustSet: "ttTRUST_SET", OfferCreate: "ttOFFER_CREATE",
  AccountSet: "ttACCOUNT_SET", URITokenMint: "ttURITOKEN_MINT", Import: "ttIMPORT", Invoke: "ttINVOKE",
};

function body(opts: ScaffoldOpts): string {
  switch (opts.archetype) {
    case "accept_all":
      return `// Accept every transaction this hook fires on (a passthrough / observer skeleton).\nint64_t hook(uint32_t reserved) {\n    _g(1,1);\n    accept(SBUF("accept_all: ok"), __LINE__);\n    _g(1,1);\n    return 0;\n}`;
    case "firewall": {
      const tt = TT[opts.blockTxType ?? "Payment"] ?? "ttPAYMENT";
      return `// Firewall: reject one transaction type, accept the rest.\nint64_t hook(uint32_t reserved) {\n    _g(1,1);\n    if (otxn_type() == ${tt})\n        rollback(SBUF("firewall: ${opts.blockTxType ?? "Payment"} blocked"), __LINE__);\n    accept(SBUF("firewall: ok"), __LINE__);\n    _g(1,1);\n    return 0;\n}`;
    }
    case "payment_limit": {
      const max = opts.maxDrops ?? "1000000";
      return `// Payment limit: reject native (XAH) Payments above ${max} drops.\nint64_t hook(uint32_t reserved) {\n    _g(1,1);\n    if (otxn_type() != ttPAYMENT) { accept(SBUF("not a payment"), __LINE__); }\n    uint8_t amount[48];\n    int64_t len = otxn_field(SBUF(amount), sfAmount);\n    // native XAH amount is 8 bytes; issued currency is 48 bytes (allow those through here)\n    if (len == 8) {\n        uint64_t drops = AMOUNT_TO_DROPS(amount); // low 62 bits\n        if (drops > ${max}ULL)\n            rollback(SBUF("payment_limit: amount exceeds cap"), __LINE__);\n    }\n    accept(SBUF("payment_limit: ok"), __LINE__);\n    _g(1,1);\n    return 0;\n}`;
    }
    case "require_dest_tag":
      return `// Require a DestinationTag on incoming Payments (exchange-style).\nint64_t hook(uint32_t reserved) {\n    _g(1,1);\n    if (otxn_type() == ttPAYMENT) {\n        uint8_t tag[4];\n        if (otxn_field(SBUF(tag), sfDestinationTag) != 4)\n            rollback(SBUF("a destination tag is required"), __LINE__);\n    }\n    accept(SBUF("ok"), __LINE__);\n    _g(1,1);\n    return 0;\n}`;
    case "state_counter":
      return `// Count how many matching transactions this account has seen (own hook state).\nint64_t hook(uint32_t reserved) {\n    _g(1,1);\n    uint8_t key[32] = {0}; // single counter slot\n    uint8_t buf[8] = {0};\n    int64_t n = 0;\n    if (state(SBUF(buf), SBUF(key)) == 8) n = INT64_FROM_BUF(buf);\n    n += 1;\n    INT64_TO_BUF(buf, n);\n    state_set(SBUF(buf), SBUF(key));\n    accept(SBUF("counted"), n);\n    _g(1,1);\n    return 0;\n}`;
    case "notary":
      return `// Notary: emit a record / co-signed action in response (emit + cbak required).\n// NOTE: you must etxn_reserve() and build the emitted txn; this is a skeleton — fill in the emit.\nint64_t hook(uint32_t reserved) {\n    _g(1,1);\n    // etxn_reserve(1); ... build txn ... emit(...);\n    accept(SBUF("notary: ok"), __LINE__);\n    _g(1,1);\n    return 0;\n}`;
  }
}

export function scaffoldHook(opts: ScaffoldOpts): { archetype: string; language: "c"; source: string; buildInstructions: string; notes: string[] } {
  const source = `${HEADER}\n${body(opts)}\n`;
  return {
    archetype: opts.archetype,
    language: "c",
    source,
    buildInstructions:
      "Compile to WebAssembly with the Xahau Hooks Builder (builder.xahau.network) or the hooks C toolchain (wasmcc + the cleaner), producing CreateCode for a SetHook. The required HookOn (which tx types it fires on) can be built with this MCP's encode_hook_on.",
    notes: [
      "STARTING POINT — not production-ready. Audit + simulate before mainnet: run analyze_hook on the compiled WASM, then execute_hook / fuzz_hook against representative transactions.",
      "Set the HookOn to the minimum tx types you need (encode_hook_on); a too-broad HookOn wastes fees and triggers HOOK-006.",
      "Macros like SBUF/AMOUNT_TO_DROPS/INT64_*_BUF and tt*/sf* constants come from the Hooks C headers (hookapi.h, macro.h, sfcodes.h). Confirm exact names against your toolchain.",
    ],
  };
}
