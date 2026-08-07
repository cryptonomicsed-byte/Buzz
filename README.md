# Crucible

**Buzz proves who said what. Crucible asks whether any of it was true.**

[Buzz](https://github.com/block/buzz) gave humans and agents the same rooms and
the same cryptographic footing. Every message, patch, workflow step and review
is a signed Nostr event in one community log, and every agent holds a keypair
that belongs to it rather than to a vendor. Provenance, in that world, is
solved: you can always tell who said a thing and prove they said it.

What Buzz deliberately does not do — because it is a workspace, not an oracle —
is tell you whether the thing was *correct*. And in a room with forty agents,
that is the load-bearing question. An agent says "the migration is safe." Four
others agree within seconds. They are the same model, on the same runner,
having read each other's messages. The audit log records five confident
statements, cryptographically attributed, unanimously wrong.

Crucible is the missing half. It is a **falsification substrate**: a set of
Nostr event kinds and a resolution kernel that live on an ordinary Buzz relay
and answer one question — *what is this room actually entitled to believe?*

```
$ python3 examples/demo.py

SCENE 1  Three agents agree. They are the same model, on the same
         runner, and each read the channel before answering.

  unanimous, and worth almost nothing:
    status        INSUFFICIENT
    belief mass   0.780
    attestations  3
    n_eff         1.13   <- independent witnesses
    -> three voices, barely one witness. A vote would have said 3/3.

SCENE 2  Three agents that could genuinely have disagreed:
         different models, different hosts, none of them looked
         at the channel first.

  checked, and believed:
    status        SUPPORTED
    belief mass   0.918
    n_eff         3.00   <- independent witnesses
```

Nothing above is mocked. Those events are signed with real secp256k1 keys,
verified with real BIP-340, and the verdicts come out of the real kernel.

---

## The one rule

**You may not assert into the shared belief space without saying how you could
be proven wrong.**

A Crucible claim carries a *falsifier*: a content-addressed WebAssembly
predicate that returns false if the claim is false. No falsifier, no claim —
it is rejected at parse time, not by convention. Everything else follows from
that rule:

| Because a claim ships a falsifier… | …the substrate can |
| --- | --- |
| anyone can run it | gather evidence instead of opinions |
| it is content-addressed | be sure two agents ran the same thing |
| it declares its capabilities | let you read the blast radius before running it |
| it is deterministic | treat divergent output as a defect, not noise |

An agent that will not say what would change its mind is not making a claim in
this system. It is just talking — which Buzz already supports perfectly well.

## Four ideas, each because a simpler one fails

**1. Agreement is discounted for redundancy.**
Ten agents agreeing is ten pieces of evidence only if the ten could have failed
independently. Every attestation declares its model lineage, its execution
environment, and whether it ran the falsifier *before* reading the channel.
Evidence is walked in the order the room learned it, and each piece counts only
for what the record does not already explain. The headline number is `n_eff` —
effective independent witnesses — and the gap between it and the raw count is
the herding, made visible.

**2. Reliability is earned per domain, under a proper scoring rule.**
An agent joins with no track record and a deliberately small voice. Being wrong
at 0.99 costs far more than being wrong at 0.55, so the winning strategy is
calibration rather than volume. Scores are per domain, because an agent that
reads build logs beautifully may be hopeless at schema migrations, and one
global trust score would let competence in the easy domain buy authority in the
hard one. An agent that falls below chance is *silenced*, never inverted —
rewarding predictable wrongness would invite an adversary to be wrong on purpose.

**3. Beliefs perish.**
Every claim has a half-life. "`main` is green" is worth half as much fifteen
minutes later; "the licence is Apache-2.0" decays over months. A claim nobody
re-checks becomes `Decayed`, not `Supported`. Silence is not corroboration.

**4. Not knowing and disagreeing are different things.**
Both sit near probability one-half, and collapsing them is how a room mistakes
a live controversy for an unexamined guess. `Insufficient` means nobody checked.
`Contested` means independent agents checked and got different answers, and
somebody needs to look. Only `Supported` is safe to act on.

## Layout

```
crates/crucible-core     Nostr event types, NIP-01 ids, BIP-340 verification
crates/crucible-kernel   independence discounting, calibration, resolution
crates/crucible-probe    the wasm sandbox falsifiers run in
crates/crucible-cli      `crucible` — JSON in, JSON out, one verb per call
mcp/crucible-mcp.mjs     MCP server, zero dependencies
examples/falsifiers      readable .wat falsifiers
examples/demo.py         the five scenes above, end to end
docs/SPEC.md             wire format: kinds 47001–47007
docs/BUZZ.md             how this attaches to a Buzz deployment
```

## Try it

```bash
cargo test                      # 141 tests
cargo build -p crucible-cli
python3 examples/demo.py        # the walkthrough above

crucible tools                  # every verb, machine-readable
echo '{"observations":["ci:status"]}' | crucible manifest.digest
```

Wire it into an agent over MCP:

```bash
node mcp/crucible-mcp.mjs       # tool list is generated from `crucible tools`
```

## How it attaches to Buzz

Crucible needs **no relay fork**. Its events are ordinary NIP-01 events in the
unused `47000` kind block, which a stock Buzz relay stores and serves without
having any opinion about them. Agents sign with the keypair their community
already admitted. See [docs/BUZZ.md](docs/BUZZ.md).

The dependency runs the other way, and deliberately. Crucible's independence
model defends against correlated *error*; it does not defend against an
adversary minting keypairs, and twenty sock puppets with distinct declared
lineages will read as twenty witnesses. That defence is Buzz's: agents are
members admitted by an operator, and a key nobody admitted has no standing.
Crucible is built on Buzz rather than beside it because it inherits exactly the
admission control its threat model requires.

## What this is not

It is not a consensus protocol, a blockchain, or a truth oracle. It computes
one number and one status from evidence anybody can recheck, and it is wrong
whenever the falsifiers are wrong. Its bet is narrower than that: **a room
where assertions must be falsifiable, and agreement is counted by independence
rather than by volume, makes better decisions than one where confidence is
free.**

## Honest limitations

- `lineage`, `env` and `blind` are **self-reported**. An agent that lies about
  them looks more independent than it is. Claiming to be blind only ever raises
  how much your agreement counts, so it is a claim about yourself that others
  can dispute — but nothing here verifies it. Attesting environments that sign
  their own fingerprint would close this; that work is not done.
- Sybil resistance is inherited from Buzz membership, not provided here.
- Not every useful assertion is a WASM predicate over declared inputs. Crucible
  covers the checkable ones. For the rest, Buzz's ordinary channels remain
  exactly as good as they were.
- The correlation weights and thresholds are defensible defaults, not measured
  constants. They are per-community policy for that reason.

## Licence

Apache-2.0, matching Buzz.
