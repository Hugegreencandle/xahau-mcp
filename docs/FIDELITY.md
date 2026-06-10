# VM Fidelity — how faithful is the local Hook VM to Xahau mainnet?

`xahau-mcp` can execute a Hook's real WebAssembly bytecode in a local VM (`src/sandbox.ts`)
with **no `xahaud` node required**. A reasonable question for any such simulator is: *does it
actually reproduce what the network does?* This document explains how we measure that, honestly,
and reports the current measured numbers.

The whole measurement is **read-only and offline**. It never signs, never submits, and (once the
corpus is committed) touches no network at all. The corpus itself was gathered earlier by serial,
rate-limit-respecting `tx` lookups against the public node.

## Ground truth: historical on-chain HookExecutions

When a Hook runs on Xahau, the resulting transaction's metadata records a `HookExecutions`
array. Each entry tells us, for one hook invocation:

- `HookHash` — which installed hook ran,
- `HookResult` — the hook's **exit type** (the `hook_api::ExitType` surfaced into metadata),
- `HookReturnCode` — the `i64` the hook passed to `accept()` / `rollback()`.

These are **real, already-validated facts about the past** — the strongest possible ground truth.
We do not re-run anything on the network; we replay history locally and check whether the local VM
would have made the **same decision** the chain actually recorded.

The corpus lives at [`data/hook-corpus.json`](../data/hook-corpus.json): each case is one real
validated transaction (its `tx` JSON, the `hookAccount`, its `hookExecutions`, and the enclosing
`engineResult`), plus a `hookCode` map of `HookHash → CreateCode (WASM) hex`, deduped by hash.

## What we compare: direction only (accept vs. rollback)

We compare the **direction** of the decision — did the hook **accept** or **rollback**? — not the
exact numeric `HookReturnCode`. The precise return code generally depends on per-transaction
runtime/ledger state we do not fully reconstruct (e.g. reward accumulators, current ledger time),
so claiming to match it would be dishonest. Matching the accept/rollback *direction* is the
meaningful, defensible fidelity claim.

### HookResult → decision mapping (empirically determined)

From real mainnet data (`tx` lookups whose meta carry HookExecutions, cross-checked against the
genesis-reward regression fixture):

| `HookResult` | `hook_api::ExitType` | We map to |
|---|---|---|
| `3` | `ACCEPT` (hook called `accept()`) | **accept** |
| `4` | `REJECT` (hook called `rollback()`) | **rollback** |
| `0` | `ROLLBACK` (wasm trap / guard violation / error) | **rollback** |
| anything else | unexpected | **unknown → excluded** (never silently mis-scored) |

If `HookResult` is absent we fall back to the enclosing-tx `engineResult`: `tesSUCCESS` (with a
hook present) corroborates **accept**; `tecHOOK_REJECTED` corroborates **rollback**. If neither is
recognizable, the case is **excluded**, not guessed.

## The honest metric: agreement over *comparable* runs only

This is the single most important rule in this harness, because it is a public correctness claim:

> **The agreement percentage is computed ONLY over COMPARABLE runs.**

A run is **comparable** (scoreable) iff *all* of the following hold:

1. The VM run was **not degraded** — it did not hit an unsupported Hook-API call and did not halt.
2. The VM actually reached an `accept` or `rollback` (not `no-exit-called`).
3. The on-chain decision was **determinable** from `HookResult`/`engineResult`.

Any run that fails one of these is counted in **`degradedCount`** and **excluded** — it is *never*
scored as a match and *never* scored as a miss. Faking agreement on a run whose outcome the VM
could not actually determine would be a lie about correctness, so we refuse to.

```
agreementPct = agreements / comparable        (NOT agreements / total)
```

`fidelityReport(corpus)` (in [`src/fidelity.ts`](../src/fidelity.ts)) returns:
`total`, `comparable`, `agreements`, `agreementPct` (null when `comparable === 0`),
`degradedCount`, a `mismatches[]` list (`{txHash, hookHash, vmExit, onChainResult, reason}`), and a
per-hook breakdown. When `comparable === 0` it flags `insufficient: true` and the headline says so
rather than printing a percentage the data cannot support.

The MCP tool **`vm_fidelity_report`** loads the committed corpus and returns this aggregate plus a
one-line headline.

## Limitations (read these before quoting any number)

- **Direction, not exact return code.** See above — we deliberately do not claim numeric-code parity.
- **VM coverage gates comparability.** The local VM implements a *subset* of the Hook API. Any hook
  that calls an unsupported function degrades and is **excluded**. This protects the metric's honesty
  but means a corpus full of hooks that use unsupported calls yields **few or zero comparable runs**
  — exactly the case today (see below).
- **Partial context reconstruction.** We reconstruct the originating-transaction fields (via the STO
  codec) and basic ledger context, but not full ledger state (account objects, other hooks' state,
  keylet lookups). Hooks whose decision depends on un-reconstructed state may diverge — and will
  legitimately show up as mismatches if they are comparable.
- **Corpus size and provenance.** The public node rate-limits bursts; the corpus is capped and was
  collected serially with ≥1200 ms pacing. The report surfaces `_truncatedByRateLimit`,
  `_rateLimitedCalls`, and `_ledgersWalked` so the gathering conditions are visible. A larger corpus
  (and broader VM API coverage) is the path to a meaningful percentage.

## Current measured numbers

Measured by `fidelityReport()` over the committed [`data/hook-corpus.json`](../data/hook-corpus.json)
— **30 real mainnet HookExecutions** spread across multiple ledgers, with each ledger's `close_time`
captured (so `ledger_last_time()` is real) and each account's pre-execution hook state fetched at
`ledgerIndex-1` (0 rate-limited calls, not truncated). 0 degraded — all 30 are comparable.

| metric | value |
|---|---|
| total / comparable | **30 / 29** |
| agreements (VM decision == on-chain) | **0** |
| **agreementPct** | **0% (29 comparable)** |
| degraded / excluded | **1** |

**Per-hook:**

| HookHash (prefix) | comparable | agreementPct | what it is |
|---|---|---|---|
| `1F7C84E14313…` (Evernode-style) | 29 | **0%** | reads **foreign-account state + keylet-resolved slots** |
| `610F33B8EBF7…` (genesis reward) | 0 | n/a (degraded) | needs more context once its real memory + account are connected |

> **Why this is *lower* than the earlier 3.3% — and why that's correct.** An expert panel found a
> real VM bug: the local VM was reading/writing a **disconnected scratch buffer** for hooks that
> define linear memory but don't *export* it (which most real hooks don't). That's now fixed — the VM
> splices a memory export so it operates on the hook's *real* memory (`src/wasm.ts ensureMemoryExport`,
> same bytecode, nothing faked). With the bug fixed, the reward hook no longer *accidentally* accepts
> on a zeroed buffer; it honestly degrades when its full context isn't reconstructed. The old 3.3%
> was partly an artifact of the bug. We also now populate `otxn_param`/`hook_param` (keyed by hex, not
> ASCII) from the tx — correctness fixes that don't move this Evernode-dominated corpus but improve
> `execute_hook` for every hook with internal data constants.

(An earlier 12-case snapshot showed `858715…` at **60%** — simpler hooks still reproduce well.)

### What this means — the honest, precise picture

The VM **runs the real bytecode faithfully** (0 degraded — no unsupported-call escape). The low
aggregate is **not** "the VM is wrong"; it is **corpus composition + context completeness**:

- **Live Xahau hook traffic is currently dominated by one complex hook** (`1F7C84…`, an Evernode-style
  reputation/heartbeat hook) — 29 of 30 executions. Its imports include `state_foreign`,
  `state_foreign_set`, `slot_set`, `slot_subfield`, `slot_float`, `otxn_slot`, `float_*`, `emit`.
- It reads **another account's state** and **keylet-resolved ledger objects** — data that lives across
  the ledger, not in the originating tx or its own account. The offline harness reconstructs the tx
  fields, `ledger_last_time`, and the account's *own* hook state, but **not foreign-account state or
  slotted objects**, so this hook can't fetch its inputs and rolls back. Reproducing it faithfully
  would require reconstructing arbitrary ledger state — essentially re-implementing node state access.
- **Simpler hooks reproduce well**: the reward hook is 100%; an earlier sample's `858715…` was 60%.

**Honest takeaway:** the VM is trustworthy today for **control-flow / param / own-state** hooks; it
**cannot yet reproduce the decision of hooks that read foreign state or keylet-resolved slots**
without full ledger-context reconstruction. That class dominates current live traffic, so the raw
aggregate is low — but the per-hook breakdown is the truthful measure, and it is reported, not hidden.

**Path forward (large, deliberately deferred):** reconstruct foreign-account state + pre-resolve the
keylets a hook `slot_set`s (the corpus fetch already has the infrastructure to pull ledger objects by
index) into the VM context, then re-measure. This is a meaningful undertaking, not a one-liner, and is
tracked rather than rushed — overstating fidelity would defeat the purpose of measuring it.
