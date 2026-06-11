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
— **30 real mainnet HookExecutions** spread across multiple ledgers (0 rate-limited calls, not
truncated). Each case carries the FULL pre-execution context, captured at `ledgerIndex-1`:

- the ledger's `close_time` (so `ledger_last_time()` is real),
- the hook account's own hook state,
- the **installed hook parameters** (Hook ledger object, falling back to the HookDefinition's
  defaults — e.g. Evernode hooks read their governor address from these),
- every **foreign-state entry the hook actually reads** (`state_foreign`), discovered by running the
  bytecode and iteratively fetching exactly what it asks for (`entryNotFound` stored as
  confirmed-absent so `DOESNT_EXIST` is faithful, never a guess),
- any **keylet-resolved ledger objects** it `slot_set`s, and the real originating tx hash (`otxn_id`).

| metric | value |
|---|---|
| total / comparable | **30 / 30** |
| agreements (VM decision == on-chain) | **30** |
| **agreementPct** | **100%** |
| degraded / excluded | **0** |
| direction composition | **30 accept / 0 rollback** (single-direction → `coverageWarning` set) |

**Per-hook:**

| HookHash (prefix) | comparable | agreementPct | what it is |
|---|---|---|---|
| `1F7C84E14313…` (Evernode heartbeat) | 29 | **100%** | reads foreign-account state, config chain, keylet slots, `slot_float`, emits |
| `B352CB99C3F0…` (Evernode registry) | 1 | **100%** | foreign state + `otxn_id` |

### How it got here (the honest history)

- An early 12-case snapshot measured **25%**; a memory-export bug fix (the VM had been operating on a
  disconnected scratch buffer) dropped an Evernode-dominated corpus to an honest **0%** — the hook
  could not fetch its foreign-state inputs and rolled back where the chain accepted.
- The fix was **foreign-state reconstruction** (v1.7.0): `state_foreign`/`state_foreign_set` in the VM,
  32-byte state-key padding (short keys are left-zero-padded exactly as on-ledger), `slot_float` /
  `float_sto` (STAmount ⇄ XFL), installed-hook-param capture, and an **iterative pre-resolve** loop —
  run the bytecode, fetch exactly the entries it asks for at the pre-execution ledger, re-run, repeat
  (a resolved read can expose the next dependent read; the Evernode heartbeat hook's chain is
  6+ reads deep).
- With the real inputs supplied, the dominant live hook reproduces **29/29**, and the corpus measures
  **30/30 (100%), 0 degraded**.

### What this means — kept honest

- 100% here means: on this 30-execution corpus, with full pre-execution context, the VM's
  accept/rollback **direction** matched the chain on every comparable run. It does **not** mean the
  VM is a consensus-faithful xahaud replica — `etxn_details` is served as a disclosed synthetic
  placeholder (cannot change the decision), `state_foreign_set` does not model the HookGrant
  requirement, XFL math truncates rather than round-half-up, and the exact `HookReturnCode` is not
  asserted (it can encode source line numbers and runtime values).
- **Direction coverage (the load-bearing caveat).** All 30 comparable executions are
  **accept-direction** (`HookResult=3`) — live Xahau traffic is heartbeat-dominated, so the corpus is
  too. That means *an unconditional-accept VM would also score 100% on this corpus*. The metric does
  not hide this: `fidelityReport` returns `composition` (`{accept, rollback, distinctHooks}`) and a
  `coverageWarning`, and the headline carries the note whenever the comparable set is single-direction.
  The **rollback** direction is exercised on real mainnet genesis bytecode — governance `Invoke` →
  rollback (and reward `ClaimReward` → accept) — in [`tests/regression.test.ts`](../tests/regression.test.ts),
  reproducing the on-chain decision direction non-degraded. Folding real on-chain rollbacks
  (`tecHOOK_REJECTED`, `HookResult=4`) into the scored corpus is the next coverage step.
- The per-hook breakdown is always reported so composition can't hide anything.
- The measurement stays **offline and reproducible**: the resolved context is committed inside the
  corpus; `vm_fidelity_report` replays it with no network access.
