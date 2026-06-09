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

Measured by running `fidelityReport()` over the committed
[`data/hook-corpus.json`](../data/hook-corpus.json) — 12 real mainnet HookExecutions spread across
6 ledgers, with each ledger's `close_time` captured so `ledger_last_time()` returns a real value
(0 rate-limited calls, not truncated):

| metric | value |
|---|---|
| total HookExecution comparisons | **12** |
| comparable (non-degraded, scoreable) | **12** |
| agreements (VM decision == on-chain) | **3** |
| **agreementPct** | **25%** |
| degraded / excluded | **0** |

Per-hook breakdown:

| HookHash (prefix) | total | comparable | agreements | agreementPct |
|---|---|---|---|---|
| `858715147E39…` | 5 | 5 | 3 | **60%** |
| `1F7C84E14313…` | 7 | 7 | 0 | **0%** |

**Headline:** *the local VM agrees with on-chain on 3 of 12 comparable real hook executions (25%); 0 degraded.*

### What this number means — and why it is honestly low

This is a **real, un-massaged** measurement, not a flattering one. After implementing
`ledger_last_time` (so the runs stop degrading), all 12 are now comparable — and the VM **disagrees
on 9 of them** (it rolls back where the network accepted). The runs are *not* degraded — no
unsupported-API escape hatch — so this is a genuine decision divergence.

**Root cause: missing hook-state reconstruction.** The harness reconstructs the originating
transaction's fields, but it does **not** load the account's real on-chain **hook state** (or slotted
ledger objects) at that ledger. State-reading hooks therefore see empty state and take a different
branch. Hook `1F7C84E1…` is clearly state-dependent (0/7); the less state-dependent `858715…` already
reaches 60%.

**This is exactly the limitation the harness exists to expose.** The honest takeaway: the VM is
trustworthy today for **control-flow / param-gated** hooks, and **state-dependent** hooks need their
on-chain state reconstructed before the VM reproduces them. The fidelity number is a measured floor
that will rise as state reconstruction lands.

**Path to a higher (still honest) percentage:** reconstruct hook state (and keylet-resolved slots)
at the case's ledger into the VM context, then re-run `vm_fidelity_report` and update this table. A
larger, rollback-inclusive corpus will also sharpen the figure.
