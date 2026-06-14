# xahau-mcp — agent guide

TypeScript MCP server that **simulates** Xahau transactions before they're signed — runs the
real hook bytecode against live (or historical) ledger state in a local VM. Second leg of the
trifecta: **xahc (write) → xahau-mcp (simulate one) → xahc-prover (prove all)**.

## Reference docs (read before Xahau protocol questions — don't guess from training)
- `~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md` — host fns, return codes, sfcodes, SetHook,
  **TSH weak/strong table** (maps directly onto `simulate.ts` TSH logic), amendments.
- `~/Desktop/xahc-prover/docs/XAHAU-RESOURCES.md` — repos/tools/libs.
- Ground truth for VM/transactor behaviour: `Xahau/xahaud` (`Transactor.cpp`, `applyHook.cpp`).
  `docs/FIDELITY.md` records the VM's measured agreement.

## What it does
The flagship tool is `simulate_transaction` — a pre-sign flight simulator: takes an UNSIGNED tx,
runs every hook it would trigger (originator + TSH chain) as real WASM against live state, and
predicts accept/rollback + emitted txns + static preflight, honestly labeling what's out of scope
(it's the hook layer + static engine checks, NOT full consensus).

## Layout (`src/`)
- `index.ts` (stdio MCP) / `http.ts` (HTTP) — entry points. `simulate.ts` — the simulator +
  TSH table + transactor-lite composition. `sandbox.ts` / `runhook-worker.ts` / `isolated.ts` —
  the hook VM. `codec.ts` / `defs.ts` / `hookapi.ts` / `keylet.ts` — serialization + hook API.
  `rpc.ts` — Xahau RPC. `fidelity.ts` — context reconstruction. `emitted.ts`, `analyzer.ts`,
  `transactorLite.ts`, `scam.ts`, plus feature modules (evernode, governance, rewards, quantum).

## Build / test / run
```sh
npm run build         # tsc -> dist/
npm test              # vitest run  (run after any change; tests/regression.test.ts is the fidelity gate)
npm run start         # stdio MCP (dist/index.js)
npm run http          # HTTP server (dist/http.js)
npm run fetch:all     # refresh server_definitions + hook-api from a live node (run when protocol moves)
```
- Deployed via **Railway**, integrated into Kairo Vault (live — the deploy is real).
- `validate_termination.cjs` is a one-off testnet script (uses `xrpl-accountlib` + `xrpl-client`,
  holds a throwaway faucet secret — keep it untracked).

## Honesty rules (the product's credibility)
- Every simulation output must label degraded/synthetic/INDETERMINATE state — never imply full
  consensus. Out-of-scope paths (offers/reserve beyond static checks) are flagged, not guessed.
- The TSH table mirrors `applyHook.cpp`; tx types needing ledger-object lookups we don't do are
  flagged honestly, not assumed.
- Keep `fetch:all`-pulled defs current; a stale codec = wrong serialization = wrong verdict.

## Conventions
- Stage commits BY NAME (never `git add -A` — hook-blocked); Conventional-commit; end with the
  Co-Authored-By Claude line. Caveman mode on this session: terse chat, code/docs normal.
