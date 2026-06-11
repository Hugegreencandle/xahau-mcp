# xahau-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the **[Xahau](https://xahau.network) network** with two firsts: it **runs a Hook's real WebAssembly bytecode in a local VM** (no `xahaud` node required), and it runs a **Hooks-specific static-analysis / security rule engine** over it — both fully offline. Around that core it adds read-only ledger access, a Xahau-aware binary codec, an instruction-count fee estimate, network-reward math, governance helpers, and unsigned-transaction builders.

> Xahau is the XRPL fork whose flagship feature is **Hooks** — small on-ledger WebAssembly smart contracts. There was no MCP for Xahau and no static analyzer for Hooks; this is both.

## Why it's useful

Point any MCP-capable agent (Claude, etc.) at this server and it can:

- **See the future before signing** — `simulate_transaction` is a pre-sign **flight simulator**: every hook an unsigned transaction would trigger runs as real bytecode against live ledger state, with per-hook accept/rollback, decoded emitted transactions, simulated state writes and labeled static engine preflights. Its sibling `what_if` is a **time machine**: replay any real historical transaction — with your modifications — at its original ledger. Verified to reproduce a real claim's emitted `GenesisMint` payout **to the drop** (72,251,963 drops), test-locked.

- **Run a Hook without deploying it** — `execute_hook` instantiates the real CreateCode WASM in a local VM, supplies the Hook API over a *simulated* transaction + ledger state, and reports the actual `accept`/`rollback` decision, return code/string, state writes, emitted transactions and a call trace. The first dev-accessible Hook simulator that needs no `xahaud` node.
- **Audit a Hook before it's installed** — paste the CreateCode WASM (or an on-ledger hook hash) and get SARIF-lite findings: missing `accept`/`rollback` exit, unguarded loops (`_g`), unknown `env` imports, dangerous `HookGrant`s, over-broad `HookOn`, and more.
- **Decode the cryptic `HookOn` bitmap** in both directions — the 256-bit, inverted, active-low mask (with the active-high SetHook bit) is easy to get wrong; here it's verified and round-trip-tested.
- **Read Xahau ledger state** — accounts, installed hooks, hook definitions, hook state, transactions (with `HookExecutions` metadata), ledgers.
- **Answer the #1 retail question** — `reward_status` tells any account whether it's opted in to Xahau network rewards (Balance Adjustments), the exact XAH accrued — computed with the genesis reward hook's own formula and live parameters, verified to reproduce a real on-chain payout **to the drop** — when it can next claim, and whether the claim is overdue (late claiming forfeits yield).
- **Diagnose an Evernode host** — `evernode_host_diagnostics` automates the official troubleshooting checklist for Xahau's largest operator group: registration, heartbeat liveness (the actual on-chain active rule), reputation, EVR trustline, lease offers, specs and accumulated rewards, in one read-only call.
- **Explain a failed transaction** — `diagnose_failed_tx` turns an engine result + hook return strings into a plain-English cause and a concrete fix.
- **Watch governance live** — `governance_state` decodes the Genesis Governance Game's full hook state: who holds the 20 seats, every open vote and tally, and whether a change (member swap, reward-rate change) is about to be actioned. No explorer shows this.
- **Build unsigned transactions** (SetHook, ClaimReward, Payment) with an automatic security preflight — returned **unsigned**, to be signed offline.

## Why this is the most advanced blockchain MCP we know of

Strong claim, so here is the checkable evidence (2026-06-11). To our knowledge no MCP for ANY
chain — Ethereum, Solana, Bitcoin, XRPL or otherwise — combines even two of these; the closest
comparators are cloud-simulation MCPs (e.g. Tenderly's, which simulates on their hosted
infrastructure) and standalone analyzers (e.g. Slither, which is EVM-only and not an MCP):

1. **Executes real on-chain contract bytecode in a LOCAL VM** — `execute_hook` runs the actual
   CreateCode WASM with no node, no cloud, no account. Not an ABI wrapper, not a hosted simulator.
2. **Publishes a measured, regression-locked fidelity score against chain ground truth** —
   `vm_fidelity_report` replays 30 real mainnet hook executions: **30/30 agree (100%), 0 degraded**,
   including the foreign-state-reading hook that dominates live traffic. The corpus, the method and
   the honest history (25% → 0% → 100%) are in [docs/FIDELITY.md](docs/FIDELITY.md). We know of no
   other blockchain MCP that even attempts this measurement.
3. **In-protocol static security analysis** — a Hooks-specific rule engine (SARIF-lite findings),
   calibrated against the network's own genesis hooks.
4. **In-protocol differential fuzzing** — `fuzz_hook` maps a contract's accept/reject decision
   boundary in the local VM.
5. **Post-mortems real transactions with real bytecode** — `hook_execution_postmortem` replays what
   actually fired on chain and compares.
6. **Reproduces on-chain economics exactly** — `reward_status` re-implements the genesis reward
   hook's formula and reproduces a real emitted payout **to the drop** (verified, test-locked).
7. **Decodes live governance end-to-end** — `governance_state` shows every seat, vote, tally and
   threshold of the Governance Game, live.
8. **Operational doctors** for the ecosystem's real pain: failed-tx diagnosis with cause+fix,
   Evernode host health, claim-overdue detection.

Every claim above is reproducible from this repo: the corpus is committed, the tests assert the
numbers, and the canonical sources (xahaud genesis hooks, evernode-js-client) are cited in code.

## Safety posture

- **Read-only** toward the network. There is no `submit` and no `sign` anywhere in this server.
- **No key custody.** Builder tools never accept a secret/seed and always return an **unsigned** transaction plus instructions to sign offline (e.g. with [xaman](https://xaman.app) or `xrpl-accountlib`). They default to **testnet**.
- **Honest fidelity.** `execute_hook` runs the **real bytecode** against a **simulated environment**. The VM implements a large slice of the 78-function Hook API — the full **XFL float** API (verified against `float_one`), the **slot** table + **STObject subfield extraction** (`slot_subfield`/`sto_subfield`, byte-exact against real txns), state, `otxn_*`/`hook_*`, `util_accid`/`util_raddr`/`util_verify`/`util_sha512h`, and more. STObject mutation (`sto_emplace`/`erase`/`validate`), `util_keylet` (account + hook verified against live ledger indexes; offer/escrow/check/ticket/signers canonical + fail-safe), **`slot_set` + foreign hook state (`state_foreign`/`state_foreign_set`) with async pre-resolve** (`execute_hook resolveKeylets:true` fetches the ledger objects AND foreign-state entries the hook reads — iteratively, since one resolved read can expose the next — and re-runs), `slot_float`/`float_sto` (STAmount ⇄ XFL, the issued layout below bit 63 *is* the XFL layout), and 32-byte state-key padding (short keys are left-zero-padded exactly as on-ledger) are now supported. `state_foreign_set` records the write but does NOT model the on-chain HookGrant requirement; `etxn_details` serves a disclosed SYNTHETIC placeholder (listed in `syntheticCalls`, cannot change the accept/rollback decision). What still can't be faithful is honestly recorded: unverified keylet subtypes, `meta_slot`, and other un-modelled calls return the real `NOT_IMPLEMENTED` code, are listed in `unsupportedCalls`, and mark the run `degraded` — **never faked**. The VM models the guard budget (`_g` enforces each guard's declared `maxiter` → `GUARD_VIOLATION`), and reports `stateApplied` (state writes commit only on `accept`, discarded on `rollback`). It is **not** a consensus-faithful `xahaud` replica — it has no fee/fuel metering beyond guards, XFL math truncates rather than round-half-up (so `float_mulratio`'s round-up flag and last-significant-digit results can differ), value-level math is verified only where tested. Hooks with a loop but no `_g` guard are **refused before execution** (invalid on-chain), and *guarded* runs are bounded by a **VM budget** (1M cumulative guard calls / 2s wall clock — labeled as a local VM cap, not a consensus limit); always confirm financial/resource hooks on testnet. `hook_dry_run` is `STATIC_ONLY`, `compute_reward` is `DOCUMENTED_MODEL` (legacy — prefer `reward_status`, whose `REWARD_HOOK_FORMULA` re-implements `reward.c` exactly and reproduces a real on-chain `GenesisMint` payout to the drop), `estimate_hook_fee` is `ESTIMATE`.

- **Resources & prompts.** Beyond tools, the server exposes MCP **resources** (`xahau://rules`, `xahau://hook-api`, `xahau://tx-types`) and guided **prompts** (`audit_hook`, `simulate_hook`, `explain_hook`) so agents can pull reference data and run the common workflows directly.

## Tools

**Hook intelligence (offline — the core)**
| Tool | Purpose |
|---|---|
| `execute_hook` | **Run the real Hook bytecode in a local VM** against a simulated tx/state → actual accept/rollback, return code, state writes, emits, trace (`LOCAL_VM`). |
| `simulate_transaction` | **PRE-SIGN FLIGHT SIMULATOR** — predict an unsigned tx's fate: originator + stakeholder hook chains (order canonical from xahaud `Transactor.cpp`/`applyHook.cpp`) run as real bytecode against live state; per-hook verdicts, decoded emits, state writes, static engine preflights, scam score. |
| `what_if` | **TIME MACHINE** — fetch a real historical tx, apply your overrides, re-simulate at its original ledger. Reproduces the real reward claim's `GenesisMint` to the drop (test-locked). |
| `fuzz_hook` | **Differential fuzzing**: sweep many generated transactions through the VM to map the hook's accept/rollback **decision boundary** (which tx types / amounts it accepts vs rejects). |
| `annotate_hook_trace` | **Decode an `execute_hook` `trace[]`** into human-readable values by byte-width: canonical XFL float (`definite`), int64/native-drops (both endians), UInt32 + Ripple-epoch date, candidate account-id → r-address (`possible`), 32-byte hash. Raw hex always preserved; offline. |
| `hook_report` | **One-call full report**: structure + plain-English classification + security findings + fee. |
| `hook_execution_postmortem` | **Post-mortem a real on-chain tx's hooks**: fetch the tx + its `meta.HookExecutions` + engine result, then run each fired hook's **real bytecode** through the VM and compare the VM's accept/rollback to what the chain recorded. On-chain decision is authoritative; VM run is `LOCAL_VM`; `agree` is `null` (not false) when degraded/indeterminate. Serial RPC: 1 `tx` + 1 `ledger_entry` per unique HookHash. |
| `vm_fidelity_report` | **Honest fidelity metric**: replays a committed corpus of real mainnet HookExecutions through the VM and reports agreement % over **comparable (non-degraded)** runs only; offline. |
| `classify_hook` | Infer in plain English what a hook does (firewall/emitter/stateful/financial/…). |
| `hook_diff` | Compare two hook versions — API/HookOn/size deltas + newly-gained sensitive capabilities. |
| `scaffold_hook` | **Generate a starter Hook in C** for an intent (firewall/payment-limit/state-counter/…) — then verify with analyze/execute. |
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
| `decode_xpop` | Decode an Import/Burn2Mint XPOP → source ledger, inner burn tx, burned drops, UNL validators. |
| `decode_result` | Engine result code ⇄ name (e.g. 153 ⇄ tecHOOK_REJECTED). |
| `diagnose_failed_tx` | **"Why did my transaction fail?"** — plain-English diagnosis from on-chain facts: engine result → cause + concrete fix (~30-code catalog), hook rollback return-strings decoded and *interpreted* (the reward hook's "You must wait N seconds" becomes a claimable-at date), the partial-payment trap on "successful" Payments, and not-found triage (expired `LastLedgerSequence` / wrong network). 1 read. |
| `validate_address` · `xaddress` | Validate classic/X-address (type, account-id, tag) · encode/decode X-addresses. |
| `currency_code` · `ripple_time` | 3-char ISO ⇄ 160-bit currency · Ripple-time ⇄ Unix/ISO. |
| `decode_amount` | Decode native drops / 8-byte / 48-byte issued STAmount / amount object → value+currency+issuer. |
| `decode_sign_request` | Decode a Xaman txjson or tx_blob → plain-English "what you authorize" + safety warnings. |
| `scam_check` | Danger-score any sign request 0–100 → SAFE/CAUTION/DANGER + per-rule findings. |
| `decode_lease_uri` | Decode an Evernode lease URIToken (`evrlease`/LTV) → lease index, EVR amount (XFL), ToS hash, IP. |
| `evernode_host_diagnostics` | **One-call Evernode host health check** (the official troubleshooting checklist, automated): registration entry, heartbeat liveness vs the on-chain active rule, instance load, reputation, EVR trustline/balance, registration URIToken, lease offers, machine specs + accumulated EVR reward. Layout verified against the canonical `evernode-js-client` + a live mainnet host (~9 serial reads). |
| `inspect_emitted_tx` | Decode a hook's `emit()` blobs → tx JSON + plain-English summary + danger score. |
| `scam_check` | Score a sign request (txjson or tx_blob) for risky patterns → `dangerScore` 0-100 + SAFE/CAUTION/DANGER tier + per-rule findings (SetHook, AccountDelete-to-other, regular-key/signer-list changes, large native payment, no-expiry, pre-signed). Offline heuristic on tx **shape only** — every finding is a **potential** risk, never a confirmed scam; no block-list lookup, no on-chain malice check. |

**Ledger (read-only RPC)**
| Tool | Purpose |
|---|---|
| `xahau_server_info` · `get_account_info` · `get_account_objects` | Node/account reads. |
| `get_account_hooks` · `get_hook_definition` · `get_hook_state` | Hook reads. |
| `get_transaction` · `get_ledger` · `get_fee` | Tx (with `HookExecutions`) · ledger · current network fee. |
| `get_account_lines` · `get_account_offers` · `get_account_uritokens` | Trustlines · DEX offers · URITokens (NFTs, URI decoded). |
| `explain_account` | **One-call plain-English account snapshot** — balance, key safety, hooks, trustlines, Evernode leases, recent activity (5 serial reads). |

**Economics / governance**
| Tool | Purpose |
|---|---|
| `reward_status` | **Balance Adjustment doctor** — opted in? exact accrued XAH (the genesis reward hook's own formula from `reward.c`, with live `RR`/`RD` read from genesis hook state; reproduces a real on-chain `GenesisMint` payout **to the drop**), next-claim countdown, overdue-claim warning (late claiming forfeits yield), plus an unsigned opt-in/claim `ClaimReward` when applicable (3 serial reads). |
| `compute_reward` | Project claimable XAH network reward (`DOCUMENTED_MODEL`; legacy — prefer `reward_status`). |
| `quantum_grade` | Grade an account for quantum (HNDL) readiness — master-key/regular-key/multisig + hooks → score, tier, recommendations (with a Hook/PQC angle). |
| `governance_state` | **Full live decode of the Governance Game**: all 20 seats + members, member count, live reward rate/delay, every open vote (who voted what) and every tally with its threshold (80% membership / 100% else) and reached-flag. Layout canonical from `xahaud hook/genesis/govern.c`. |
| `decode_b2m` | Burn2Mint classification. |

**Unsigned builders (no keys, testnet-default)**
| Tool | Purpose |
|---|---|
| `build_sethook_unsigned` | UNSIGNED SetHook with automatic `analyze_hook` preflight. |
| `build_claimreward_unsigned` · `build_import_unsigned` · `build_payment_unsigned` | UNSIGNED ClaimReward · Import/B2M · Payment. |
| `prepare_transaction` | Autofill Sequence/Fee/LastLedgerSequence/NetworkID from the live network → ready to sign offline (never signs). |

## Install

> New here or non-technical? Start with the **[plain-English tutorial](docs/TUTORIAL.md)** — what it does + cool things to just *ask*.

Install straight from GitHub — no npm-registry account needed; it builds on install:

```bash
npm install -g github:Hugegreencandle/xahau-mcp
```

Or clone and build:
```bash
git clone https://github.com/Hugegreencandle/xahau-mcp && cd xahau-mcp
npm install        # the `prepare` script compiles dist/ automatically
npm run smoke      # health check + a live mainnet read
npm test           # ~115 tests (offline)
```

Also published to **GitHub Packages** as `@hugegreencandle/xahau-mcp`. GitHub Packages requires auth even for public installs, so add to your `.npmrc`:
```
@hugegreencandle:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN   # token with read:packages
```
then `npm install -g @hugegreencandle/xahau-mcp`. (The `github:` install above needs no auth and is simpler.)

Add to an MCP client (e.g. Claude Code / Desktop):
```json
{ "mcpServers": { "xahau": { "command": "xahau-mcp" } } }
```

## Security

Designed defensively and reviewed (`npm audit` + a danger-surface pass):

- **Read-only & no key custody** — no `sign`/`submit` anywhere; builder tools never accept a secret and only emit *unsigned* transactions to sign offline.
- **No code-exec surface** — no `eval`/`Function`, no `child_process`/shell, no filesystem writes, no dynamic `require`. RPC `fetch` only ever hits the fixed endpoints in `data/endpoints.json` (or your `XAHAU_RPC_URLS` override) — never a URL built from tool input, so no SSRF.
- **Untrusted Hook WASM is sandboxed** — `execute_hook`/`fuzz_hook` run hook bytecode in Node's WebAssembly engine, which has no syscall/fs/network access; a hook can only call the in-memory JS Hook-API shims, with bounds-checked memory reads/writes.
- **Known limits (DoS-of-self, not RCE/exfil):** the VM has no fuel metering beyond guards, so a pathological *unguarded* infinite-loop hook can hang a single run — just cancel it. Tool output is data, not instructions (treat it as such, as with any MCP).
- **Dependencies:** `npm audit` reports only low-severity advisories transitively under `xrpl-accountlib`'s signing libraries (elliptic/bip32/tiny-secp256k1) — code paths this server never calls (it uses only the binary codec).

## How it works

- **No heavy deps.** Three runtime deps: `@modelcontextprotocol/sdk`, `zod`, and `xrpl-accountlib` (used only for the Xahau-aware binary codec; its signing surface is never called). RPC is plain `fetch`; the **WASM reader is hand-rolled and zero-dep**; the VM uses **Node's built-in `WebAssembly` engine** to run the bytecode with a JS Hook API shim — no WASM toolchain or native deps.
- **Real data, regenerable.** `data/` is built from a live Xahau node's `server_definitions` and the canonical Hook API list (`Xahau/hooks-rs` `c/extern.h`) via `npm run fetch:all`. The 78-function Hook API catalog carries per-function hazard metadata that drives the analyzer.
- **HookOn** semantics are verified against the [Xahau docs](http://xahau.network/docs/hooks/concepts/hookon-field/): 256-bit, bit *n* = tx type *n*, **inverted/active-low** (set = does *not* fire), with bit 22 (SetHook) **active-high**.

## License

MIT © 2026 Dane Brown. Not affiliated with XRPL Labs or the Xahau project. Analyzer findings are heuristic guidance, not a security guarantee — always test on testnet and review hooks independently before mainnet use.
