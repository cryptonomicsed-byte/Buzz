# Crucible wire format

Crucible objects are ordinary [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
Nostr events. Nothing here changes how a relay stores, indexes or serves an
event; a stock [Buzz](https://github.com/block/buzz) relay handles Crucible
traffic today without knowing what any of it means.

## Kind allocation

Buzz dispatches on the `kind` integer and reserves `40000–49999` for its own
custom events, currently using `40002`, `40003`, `40100`, `43001`, `45001`,
`45003` and `46001–46012`. Crucible claims the contiguous, unused **`47000`
block** so the two can share a database without either reinterpreting the
other's events.

| Kind | Name | Purpose |
| --- | --- | --- |
| 47001 | `claim` | A falsifiable proposition entering the belief space |
| 47002 | `attestation` | One agent's signed record of running the falsifier |
| 47003 | `challenge` | A staked bet that a claim is false |
| 47004 | `verdict` | The kernel's derived status for a claim |
| 47005 | `calibration` | A scoring-rule update to an agent's reliability |
| 47006 | `belief-snapshot` | Digest of current belief, for fast bootstrap |
| 47007 | `falsifier-manifest` | Announcement of a reusable falsifier |

`crates/crucible-core/src/kinds.rs` carries a test that fails if any of these
ever collides with a known Buzz kind.

## Common conventions

- All digests are SHA-256, lower-case hex, 64 characters.
- Public keys are 32-byte x-only secp256k1 keys — the same identity the agent
  uses everywhere else in Buzz.
- Single-valued tags take the **first** occurrence. Taking the last would let an
  appended duplicate override a signed value's intent.
- Timestamps are Unix seconds.
- Confidence is in the **open** interval `(0, 1)`. Zero and one are refused:
  they are immune to evidence, and a scoring rule cannot finitely punish an
  agent that was certain and wrong.

---

## 47001 — claim

The proposition, and the executable that would refute it.

### Tags

| Tag | Cardinality | Value |
| --- | --- | --- |
| `c` | 1 | Buzz community/channel. Belief is scoped to a room |
| `domain` | 1 | Calibration bucket: `ci`, `security`, `perf`, … |
| `conf` | 1 | Author's probability, `0 < p < 1` |
| `halflife` | 1 | Seconds after which evidence is worth half as much |
| `expiry` | 0–1 | Unix time after which the claim is `Decayed` regardless |
| `falsifier` | 1 | `["falsifier", <module-sha256>, "wasm", <manifest-sha256>, <purity>]` |
| `lineage` | 0–1 | Author's model lineage; defaults to `key:<pubkey>` |
| `env` | 0–1 | Author's environment fingerprint; defaults to `key:<pubkey>` |

`<purity>` is `pure` or `observational`. **Absent means observational** — the
conservative reading. Defaulting to `pure` would condemn an untagged
world-reading probe as broken the first time two agents saw different worlds.

Purity is not a free assertion: it is derived from the capability manifest,
whose digest the author signed. A manifest granting no observations is pure.

### Content

```json
{
  "statement": "block/buzz is green at deadbeef",
  "rationale": "the pipeline went green on my machine",
  "inputs": { "repo": "block/buzz", "sha": "deadbeef" }
}
```

`inputs` is hashed as canonical JSON — `serde_json`'s object representation is
a sorted map — so two agents writing the same inputs in a different key order
produce the same digest. Arrays stay order-sensitive: they are sequences, not
sets.

### Experiment id

```
experiment = SHA256(module ‖ manifest ‖ inputs_digest ‖ [pure])
```

Two attestations are only comparable when all four match. An attestation
against a different experiment is evidence about a different question, and the
kernel excludes it with a stated reason rather than pooling it.

---

## 47002 — attestation

Somebody ran the falsifier and signed what happened.

| Tag | Value |
| --- | --- |
| `e` | `[<claim-id>, "", "claim"]` |
| `experiment` | Must equal the claim's experiment id |
| `outcome` | `holds` \| `fails` \| `indeterminate` |
| `digest` | SHA-256 of the falsifier's verdict and explanation |
| `fuel` | Fuel consumed |
| `lineage` | Model/implementation lineage |
| `env` | Execution environment fingerprint |
| `blind` | `true` if run **before** reading any prior attestation or verdict |

Content is the falsifier's explanation.

`indeterminate` is not a quiet vote for the claim. A falsifier that trapped,
starved or was denied an observation has said something about *itself*, and
reading that as refutation would let anyone refute anything by shipping a
module that divides by zero.

`lineage`, `env` and `blind` are **self-reported and unverified**. They are the
substrate's soft underbelly, and the README says so plainly.

---

## 47003 — challenge

| Tag | Value |
| --- | --- |
| `e` | `[<claim-id>, "", "claim"]` |
| `stake` | Fraction of the challenger's standing, `0 < s ≤ 1` |
| `counter` | Optional alternative falsifier digest |

A challenge moves **no belief on its own**. Doubt is not a measurement, and
letting it count as evidence would make suppressing a true claim free. What it
does is settle against the ledger when the claim resolves: right challengers
gain, wrong ones lose, in proportion to what they staked. A stake of `s` reads
as a forecast of `(1 − s) / 2` that the claim is true, so a bold wrong
challenge costs exactly what a bold wrong claim does.

---

## 47004 — verdict

| Tag | Value |
| --- | --- |
| `e` | `[<claim-id>, "", "claim"]` |
| `status` | `supported` \| `refuted` \| `contested` \| `insufficient` \| `decayed` \| `nondeterministic` |
| `mass` | Posterior probability the claim is true |
| `neff` | Effective independent witnesses |
| `support` / `opposition` | Decayed, discounted log-odds each way |
| `n` | Attestations considered |

A verdict is **not authoritative**. It is a computation over events the relay
already holds, published so anyone can recompute it and publish a different one
if they disagree. Two replicas replaying the same log at the same `now` derive
byte-identical verdicts.

### How status is decided

In order, first match wins:

1. **`nondeterministic`** — the falsifier declared itself pure and two probes
   produced different output. Nothing computed from a broken experiment means
   anything, so this outranks everything.
2. **`decayed`** — past `expiry`, or evidence once existed and has aged below
   the floor.
3. **`insufficient`** — fewer than `min_n_eff` independent probes.
4. **`contested`** — both sides carry real, comparable weight *among probes*.
   The author's own forecast is excluded here: letting it count as one side
   would let a claimant manufacture a controversy by asserting against the
   evidence. A relative ratio is required as well as an absolute floor, so a
   lone dissenter cannot freeze an overwhelming claim forever.
5. **`supported`** / **`refuted`** — mass past the threshold.
6. **`insufficient`** — otherwise.

## Falsifier ABI

A falsifier exports `memory` and `crucible_falsify()`, and may import only from
the `crucible` module:

```
input_len()                      -> i32   bytes of declared input JSON
input_read(ptr)                          copy that JSON into memory
observe_len(key_ptr, key_len)    -> i32   size of an observation, -1 if ungathered
observe_read(key_ptr, key_len, out)      copy the observation in
emit(verdict, ptr, len)                  1 = holds, 2 = fails, 3 = indeterminate
```

There is no clock, no randomness, no allocator and no I/O. The world reaches a
falsifier only through observation keys its manifest named in advance, gathered
by the runner *outside* the sandbox — so the impurity is explicit and signed
rather than hidden inside a module.

Refusals are traps, not sentinel returns. A guest that could mistake "denied"
for "empty" would go on to judge a world it never saw.

### Manifest

```json
{ "observations": ["ci:status"], "fuel": 50000000,
  "memory_pages": 64, "max_output": 8192 }
```

All fields default; `{}` is a pure manifest. Limits are clamped on
canonicalization, because the manifest is written by whoever wrote the claim —
not necessarily by somebody acting in the prober's interest.
