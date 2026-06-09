# xahau-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the **[Xahau](https://xahau.network) network** with two firsts: it **runs a Hook's real WebAssembly bytecode in a local VM** (no `xahaud` node required), and it runs a **Hooks-specific static-analysis / security rule engine** over it — both fully offline. Around that core it adds read-only ledger access, a Xahau-aware binary codec, an instruction-count fee estimate, network-reward math, governance helpers, and unsigned-transaction builders.

> Xahau is the XRPL fork whose flagship feature is **Hooks** — small on-ledger WebAssembly smart contracts. There was no MCP for Xahau and no static analyzer for Hooks; this is both.

## Why it's useful

Point any MCP-capable agent (Claude, etc.) at this server and it can:

- **Run a Hook without deploying it** — `execute_hook` instantiates the real CreateCode WASM in a local VM, supplies the Hook API over a *simulated* transaction + ledger state, and reports the actual `accept`/`rollback` decision, return code/string, state writes, emitted transactions and a call trace. The first dev-accessible Hook simulator that needs no `xahaud` node.
- **Audit a Hook before it's installed** — paste the CreateCode WASM (or an on-ledger hook hash) and get SARIF-lite findings: missing `accept`/`rollback` exit, unguarded loops (`_g`), unknown `env` imports, dangerous `HookGrant`s, over-broad `HookOn`, and more.
- **Decode the cryptic `HookOn` bitmap** in both directions — the 256-bit, inverted, active-low mask (with the active-high SetHook bit) is easy to get wrong; here it's verified and round-trip-tested.
- **Read Xahau ledger state** — accounts, installed hooks, hook definitions, hook state, transactions (with `HookExecutions` metadata), ledgers.
- **Build unsigned transactions** (SetHook, ClaimReward, Payment) with an automatic security preflight — returned **unsigned**, to be signed offline.

## Safety posture

- **Read-only** toward the network. There is no `submit` and no `sign` anywhere in this server.
- **No key custody.** Builder tools never accept a secret/seed and always return an **unsigned** transaction plus instructions to sign offline (e.g. with [xaman](https://xaman.app) or `xrpl-accountlib`). They default to **testnet**.
- **Honest fidelity.** `execute_hook` runs the **real bytecode** but against a **simulated environment** with an implemented **subset** of the 78-function Hook API; any unsupported call (the heavy `slot_*`/`sto_*`/full XFL machinery) returns a sentinel and is listed in `unsupportedCalls`, marking the run `degraded` — never faked. It is **not** a consensus-faithful `xahaud` replica; always confirm on testnet. `hook_dry_run` is `STATIC_ONLY`, `compute_reward` is `DOCUMENTED_MODEL`, `estimate_hook_fee` is `ESTIMATE`. The server never pretends to more certainty than it has.

## Tools

**Hook intelligence (offline — the core)**
| Tool | Purpose |
|---|---|
| `execute_hook` | **Run the real Hook bytecode in a local VM** against a simulated tx/state → actual accept/rollback, return code, state writes, emits, trace (`LOCAL_VM`). |
| `analyze_hook` | Run the static-analysis rule engine over a hook → SARIF-lite findings. |
| `audit_account_hooks` | Pull every hook on an account and analyze all of them. |
| `inspect_hook_wasm` | Parse CreateCode WASM: imports, exports (`hook`/`cbak`), memory, custom sections, loop, `_g` guard & instruction counts. |
| `estimate_hook_fee` | Byte size (SetHook fee) + static instruction count (complexity proxy), `ESTIMATE`. |
| `hook_dry_run` | `STATIC_ONLY` quick check — fires-on-tx + exit calls present (use `execute_hook` for real runs). |
| `list_rules` · `hook_api_lookup` | Enumerate analyzer rules · look up a Hook API function's role & hazards. |

**Codec / decode (offline)**
| Tool | Purpose |
|---|---|
| `decode_hook_on` / `encode_hook_on` | HookOn bitmap ⇄ transaction-type list. |
| `decode_sethook` | A SetHook tx → its hook definitions, HookOn decoded. |
| `decode_tx_blob` / `encode_tx_blob` | Xahau tx blob ⇄ JSON (unsigned). |
| `decode_uritoken_id` · `xah_amount` | URIToken ID validation · XAH⇄drops. |

**Ledger (read-only RPC)**
| Tool | Purpose |
|---|---|
| `xahau_server_info` · `get_account_info` · `get_account_objects` | Node/account reads. |
| `get_account_hooks` · `get_hook_definition` · `get_hook_state` | Hook reads. |
| `get_transaction` · `get_ledger` | Tx (with `HookExecutions`) · ledger reads. |

**Economics / governance**
| Tool | Purpose |
|---|---|
| `compute_reward` | Project claimable XAH network reward (`DOCUMENTED_MODEL`). |
| `governance_state` · `decode_b2m` | Genesis governance constants + live read · Burn2Mint classification. |

**Unsigned builders (no keys, testnet-default)**
| Tool | Purpose |
|---|---|
| `build_sethook_unsigned` | UNSIGNED SetHook with automatic `analyze_hook` preflight. |
| `build_claimreward_unsigned` · `build_payment_unsigned` | UNSIGNED ClaimReward · Payment. |

## Install

```bash
npm install && npm run fetch:all && npm run build
npm run smoke    # health check + a live mainnet read
npm test         # 24 tests (offline)
```

Add to an MCP client (e.g. Claude Code / Desktop):
```json
{ "mcpServers": { "xahau": { "command": "node", "args": ["/path/to/xahau-mcp/dist/index.js"] } } }
```

## How it works

- **No heavy deps.** Three runtime deps: `@modelcontextprotocol/sdk`, `zod`, and `xrpl-accountlib` (used only for the Xahau-aware binary codec; its signing surface is never called). RPC is plain `fetch`; the **WASM reader is hand-rolled and zero-dep**; the VM uses **Node's built-in `WebAssembly` engine** to run the bytecode with a JS Hook API shim — no WASM toolchain or native deps.
- **Real data, regenerable.** `data/` is built from a live Xahau node's `server_definitions` and the canonical Hook API list (`Xahau/hooks-rs` `c/extern.h`) via `npm run fetch:all`. The 78-function Hook API catalog carries per-function hazard metadata that drives the analyzer.
- **HookOn** semantics are verified against the [Xahau docs](http://xahau.network/docs/hooks/concepts/hookon-field/): 256-bit, bit *n* = tx type *n*, **inverted/active-low** (set = does *not* fire), with bit 22 (SetHook) **active-high**.

## License

MIT © 2026 Dane Brown. Not affiliated with XRPL Labs or the Xahau project. Analyzer findings are heuristic guidance, not a security guarantee — always test on testnet and review hooks independently before mainnet use.
