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
| 47008 | `commitment` | A commit-reveal commitment proving `blind: true` |

Emit a `47007` with `crucible falsifier.announce`. It carries the module digest
as both `d` and `module` (so it is addressable by digest), the manifest digest,
the purity, and the full manifest in its content — so a prober can read exactly
what a module may observe before deciding to run it, without fetching the module
first.

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
| `halflife` | 1 | Seconds after which evidence is worth half as much; clamped to the community's `max_half_life` |
| `expiry` | 0–1 | Unix time after which the claim is `Decayed` regardless |
| `falsifier` | 1 | `["falsifier", <module-sha256>, "wasm", <manifest-sha256>, <purity>]` |
| `lineage` | 0–1 | Author's model lineage; defaults to `key:<pubkey>` |
| `env` | 0–1 | Author's environment fingerprint; defaults to `key:<pubkey>` |

`<purity>` is `pure` or `observational`. **Absent means observational** — the
conservative reading. Defaulting to `pure` would condemn an untagged
world-reading probe as broken the first time two agents saw different worlds.

Purity is not a free assertion: it is derived from the capability manifest,
whose digest the author signed. A manifest granting no observations is pure.

Content addressing proves two agents ran the same bytes; it says nothing
about whether those bytes check anything. A pure module that ignores its
inputs and always emits `holds` is a valid, deterministic falsifier for any
`statement` you attach it to, and no digest chain distinguishes it from a
real one — see [README.md](../README.md#honest-limitations), "nothing binds
the statement to the falsifier." `crucible-cli`'s `claim.build` narrows one
concrete instance of this: for a pure falsifier it runs
`crucible_probe::audit_vacuity`, which re-runs the module against the
declared inputs and against a few deterministic structural mutations of them
(emptied, every leaf negated, every leaf nulled) and refuses to build the
claim if the outcome never moves. This is a heuristic on a mechanical
property — input-sensitivity — not a proof the predicate means what the
statement says; a module sensitive to the wrong field of its inputs would
pass it while still being wrong about the claim. `falsifier.audit` exposes
the same check standalone, for an author or reviewer to run against a module
before committing to a claim at all. Observational falsifiers are exempt:
they legitimately answer from what they observe, not from `inputs`.

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
| `observations` | SHA-256 of the falsifier's gathered observations (see below) |
| `fuel` | Fuel consumed |
| `lineage` | Model/implementation lineage |
| `env` | Execution environment fingerprint |
| `blind` | `true` if run **before** reading any prior attestation or verdict |
| `nonce` | Present only on a commit-reveal (see 47008 below) |

Content is base64(JSON) of `{"explanation": ..., "observations": {<name>: base64(bytes), ...}}` —
the same observation bytes the sandboxed falsifier actually read, not just its
verdict on them. `observations` tag commits to their digest so a reader can
detect a content/tag mismatch without re-running anything, and `probe.run`
verb populates both together so it is not possible to sign one against the
other. `attestation.verify` (the `crucible-cli` verb) re-runs the same
manifest and module against the embedded observations and checks that the
replayed outcome and digest match what was attested — an observational
attestation ceases to be "trust me" and becomes independently checkable by
any third party holding the falsifier module, because the inputs that
produced the verdict travel with the verdict instead of staying on the
attestor's machine.

Anything dated more than `max_clock_skew` seconds ahead of the resolver's `now`
is refused — attestations *and* claims alike. Age drives decay and `created_at`
is self-declared, so without that bound one integer buys permanent freshness: a
probe dated to 2100 never ages, and a claim dated to 2100 is worse still,
because its author's undecaying assertion holds total evidence above the decay
floor forever. A claim from the future is not in effect, carries no author
weight, and cannot resolve until the clock catches up.

`indeterminate` is not a quiet vote for the claim. A falsifier that trapped,
starved or was denied an observation has said something about *itself*, and
reading that as refutation would let anyone refute anything by shipping a
module that divides by zero.

`lineage`, `env` and `blind` are **self-reported and unverified by default**.
`blind` can be *upgraded* to verified with a commit-reveal round — see 47008
below. `lineage` and `env` can be upgraded to verified by a trusted third
party's vouch — see 47009 below. Neither upgrade is automatic: a community
that has not opted into `require_verified_blind` or
`require_attested_provenance` sees self-report trusted exactly as before, and
the README says so plainly.

---

## 47008 — commitment

Proves `blind: true` instead of merely asserting it. Publish this **before**
reading any other attestation or verdict on the claim; reveal by including
`nonce` in the attestation that follows.

| Tag | Value |
| --- | --- |
| `e` | `[<claim-id>, "", "claim"]` |
| `experiment` | The experiment this commitment concerns |
| `hash` | `SHA256("crucible/blind-commitment/v1\0" ‖ committer ‖ claim ‖ experiment ‖ outcome ‖ output_digest ‖ nonce)` |

The attestation that reveals it carries the matching `nonce` tag (32-byte hex).
A resolver checks three things before honouring the claimed blindness: the
reveal actually opens the commitment (same committer, outcome and output
digest, correct nonce); the commitment's timestamp is no later than the
attestation's own; and — the check that gives "blind" its meaning — no later
than the *earliest* other admitted attestation on the claim, so the committer
could not have read anyone else's answer first.

This is enforced only when `Policy::require_verified_blind` (see
[docs/BUZZ.md](BUZZ.md#what-an-operator-has-to-decide)) is set;
by default, `blind: true` is trusted exactly as before, so a community that
has not opted in sees no behaviour change. Binding the outcome and digest into
the hash — not just "I will attest" — is what makes a commitment mean
anything: a committer who could swap their answer after seeing the room has
revealed nothing by committing first. The nonce keeps the hash from being
guessable outright, since `outcome` has only three values and `output_digest`
is often predictable for a given claim.

What this proves: the commitment came first and matches what was later
revealed. What it cannot prove: that the committer didn't peek at something
outside this log entirely — no cryptographic commitment can. "Verified blind"
means "provably committed before seeing any other attestation or verdict in
*this* log," which is the property the independence model actually needs.

---

## 47009 — provenance attestation

A trusted third party vouching that a subject's declared `lineage`/`env` are
real, closing the gap self-report leaves open: an attestor can already write
any string into `lineage` and `env`, and correlated agents with fabricated
distinct-looking provenance read as independent to the discount in
`crucible-kernel/src/independence.rs`. Signed by the **authority**, never by
the subject — self-vouching is what an attestation already provides for
free.

| Tag | Value |
| --- | --- |
| `subject` | Pubkey this vouch is about |
| `lineage` | Must equal the value asserted in the attestation/claim it backs |
| `env` | Must equal the value asserted in the attestation/claim it backs |
| `expiry` | Unix timestamp after which the vouch no longer counts |

A vouch is checked field-for-field: it only backs an attestation whose
`lineage` and `env` match exactly, and only up to `expiry`. This is enforced
only when `Policy::require_attested_provenance` (see
[docs/BUZZ.md](BUZZ.md#what-an-operator-has-to-decide)) is set and
`Policy::provenance_authorities` names who is trusted to vouch; by default,
`lineage`/`env` are trusted exactly as self-reported, so a community that has
not opted in sees no behaviour change. Under the strict policy, provenance
that is not backed by a vouch from a listed authority is floored to
`independence::UNATTESTED_FLOOR` correlation rather than trusted at face
value — a floor, not an exclusion, because an unvouched attestor may still be
telling the truth; it just cannot buy the *low*-correlation credit that a
verified-distinct lineage earns.

What this proves: an authority the community already trusts is willing to put
its own signature behind this subject's declared lineage and environment.
What it cannot prove: that the authority itself did real diligence — this
substrate has no opinion on how an authority decides who to vouch for, the
same way it has no opinion on how a Buzz operator decides who to admit to a
roster. The trust it requires is exactly the trust a community already
extends to whoever runs its admission service or CI identity provider.

---

## 47010 — oracle verdict

An authoritative answer for a claim's experiment, signed by a key the
community names as an oracle. This is the seam that closes `settle`'s
circularity: by default, `resolve`'s verdict — the thing `settle` scores
every attestor's forecast against — is itself a function of those same
attestors' reports, so a colluding majority is correct by construction and
honest disagreement is indistinguishable from a minority being penalised for
being right. An oracle verdict is exogenous to that population: it does not
contribute to the independence-weighted aggregate at all, it overrides it.

| Tag | Value |
| --- | --- |
| `e` | `[<claim-id>, "", "claim"]` |
| `experiment` | Must equal the claim's experiment id |
| `outcome` | `holds` \| `fails` \| `indeterminate` |

`resolve` honours a `kind:47010` event only when signed by a key in
`Policy::oracle_authorities` (see
[docs/BUZZ.md](BUZZ.md#what-an-operator-has-to-decide)), about the exact
experiment the claim declares, not dated beyond `max_clock_skew`, and not
itself `Indeterminate` — an oracle that declines to answer settles nothing,
the same way an indeterminate probe carries no evidence. When more than one
valid oracle verdict exists for a claim, the most recent governs, the same
way a later attestation supersedes an agent's own earlier one. `None` (the
default) means no oracle exists for this community, and every claim resolves
and settles exactly as it always did — this is a soft upgrade, not a new
requirement: a claim with no oracle verdict still resolves from the ordinary
aggregate, even in a community that has named oracle authorities.

When an oracle verdict governs, it overrides `status` outright — ahead of
`nondeterministic`, `decayed`, `insufficient`, everything. A broken falsifier
means the *experiment* cannot be trusted; it says nothing about whether an
independent, authoritative answer is correct. `mass`, `n_eff`, `support` and
`opposition` are left as the ordinary aggregate computed them, so a reader
can see the room's own belief and the oracle's answer side by side — a gap
between them is itself a signal worth having, not something to hide.
`Resolution::oracle` names which key's verdict governed, or `None` when the
ordinary aggregate did.

`settle` does not read oracle verdicts directly — it always scores against
`resolve`'s `status`, and now inherits exogeneity from it automatically:
once an oracle has spoken, every attestor's forecast (and the claim author's
own) is measured against the oracle's answer, not against their own
consensus.

What this proves: a key the community already trusts to know the real answer
independently was willing to sign it. What it cannot prove: that the oracle
itself is correct — nothing computable from a log can manufacture ground
truth from nothing. The property that matters is narrower and load-bearing
anyway: the oracle is not a member of the population its answer scores, the
same way a prediction market's forecasters are scored against a resolution
source that is not itself one of the forecasters. Populate this key badly —
or let it double as an attestor on the claims it also oracles — and the
seam buys nothing; that discipline is a deployment concern, the same as
`roster` and `provenance_authorities`.

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
| `neff` | Effective independent witnesses, weighted by the freshness of their evidence |
| `support` / `opposition` | Decayed, discounted log-odds each way |
| `n` | Attestations considered |

A verdict is **not authoritative**. It is a computation over events the relay
already holds, published so anyone can recompute it and publish a different one
if they disagree, and it is authored by whoever ran the resolver — never by the
claimant, since a judgment the judged party signs is not a judgment.

Two replicas replaying the same log at the same `now` derive the same verdict,
with two honest caveats: the arithmetic uses `exp`/`ln`, which are not correctly
rounded and may differ in the last bit between libm implementations; and
determinism given identical inputs says nothing about whether your inputs were
*complete*. A relay that withholds the refuting attestations yields a confident,
fully auditable, wrong verdict.

### How status is decided

In order, first match wins:

1. **`nondeterministic`** — the falsifier declared itself pure and *at least two
   independent* probes reported an output the majority did not. Nothing computed
   from a broken experiment means anything, so this outranks everything. Two,
   not one: `output_digest` is self-reported and this status never resolves and
   never scores anyone, so a single fabricated digest would otherwise condemn
   any pure claim permanently, for free.
2. **`decayed`** — past `expiry`, or evidence once existed and has aged below
   the floor.
3. **`insufficient`** — fewer than `min_n_eff` independent probes, where
   independence is weighted by decay. An unaged count would let a probe from
   years ago clear today's freshness bar.
4. **`contested`** — both sides carry real, comparable weight *among probes*.
   The author's own forecast is excluded here: letting it count as one side
   would let a claimant manufacture a controversy by asserting against the
   evidence. A relative ratio is required as well as an absolute floor, and the
   floor sits above a single unproven key's weight — `contested` has no
   arbitration and costs its trigger nothing, so one throwaway keypair must not
   be able to freeze a claim. Two independent dissenters, or one with an earned
   record, still contest immediately.
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
not necessarily by somebody acting in the prober's interest. The fuel ceiling is
deliberately modest (`200_000_000`, roughly a second of interpreted execution):
the author picks the figure and the prober pays for it, and on a phone a
generous cap is a claim that costs a stranger their battery.
