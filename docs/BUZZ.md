# Attaching Crucible to a Buzz deployment

Crucible is designed to be additive. There is no relay fork, no schema
migration, no change to how Buzz authenticates anyone, and nothing an operator
has to turn on before agents can start using it.

## What Buzz already provides, and Crucible relies on

| Buzz gives | Crucible uses it for |
| --- | --- |
| Portable secp256k1 keypairs for humans *and* agents | Signing every claim, probe and challenge as the same identity the agent already has in the room |
| NIP-01 relay semantics | Storage and retrieval of kinds `47001–47007`, untouched |
| NIP-42 / NIP-98 authentication | Access control; Crucible adds none of its own |
| Community membership via `buzz-admin` | **Sybil resistance** — see below |
| `buzz-audit`'s hash chain | Tamper-evidence for the evidence trail itself |
| `buzz-acp`, `buzz-dev-mcp` | The agents that will actually do the probing |
| Per-community semantic boundary | Belief is scoped to a room; two communities may legitimately believe different things |

Every one of those is load-bearing. Crucible would be a substantially worse
system standing alone, which is the point.

## Sybil resistance is Buzz's, not ours

Independence discounting defends against *correlated error*: agents that share
a model, a machine, or a transcript. It does not defend against one operator
running twenty processes under twenty keys with twenty distinct declared
lineages. Those would read as twenty witnesses.

The defence for that is admission control, and Buzz already has it — agents are
community members an operator admitted with `buzz-admin`, and a key nobody
admitted has no standing in the room. A Crucible-aware resolver should refuse
attestations from keys outside the community's membership set for exactly this
reason.

This is the clearest single argument for building Crucible *on* Buzz rather
than as a standalone service: the threat model requires an identity layer with
real admission control, and inventing one would have meant rebuilding the part
of Buzz that is already good.

## Three ways to run it

### 1. As a tool an agent already in the room can call

The lightest integration, and the one to start with. Any agent reachable over
MCP — Goose, Codex, Claude Code via `buzz-acp` — gains the Crucible verbs:

```jsonc
// alongside buzz-dev-mcp in the agent's MCP configuration
{
  "crucible": {
    "command": "node",
    "args": ["/path/to/crucible/mcp/crucible-mcp.mjs"],
    "env": { "CRUCIBLE_BIN": "/path/to/crucible/target/release/crucible" }
  }
}
```

The agent asserts with `crucible_claim_build`, signs the returned event with
its own Buzz key, and publishes it to the relay like any other event. Nothing
else in the deployment changes.

### 2. As a workflow step

Buzz workflows (`46001–46012`) are the natural place for the probe loop. A
workflow triggered by a new `47001` can gather the observations the manifest
names, shell out to `crucible probe.run`, and publish the signed attestation —
turning "somebody should check that" into something the room does automatically.

Because every verb is `JSON → JSON` on stdin/stdout, a workflow step is a pipe:

```bash
crucible probe.run < probe-request.json | jq .attestation | buzz-cli publish
```

### 3. As a resolver service

`crucible ledger.replay` over a community's `47000`-block events produces every
verdict and the calibration ledger that falls out. Run it on a timer, publish
the `47004` verdicts back to the relay, and the room gets a live view of what
it believes.

Resolution is a pure function of `(events, ledger, policy, now)`, so this
service holds no authority: anyone who disagrees can rerun it and publish a
competing verdict, and the two can be compared line by line because both ship
the full derivation.

## What an operator has to decide

One thing: the community's [`Policy`](../crates/crucible-kernel/src/policy.rs).

```jsonc
{
  "min_n_eff": 2.0,           // independent probes before anything resolves
  "support_threshold": 0.90,
  "refute_threshold": 0.10,
  "conflict_floor": 0.5,      // weight each side needs to count as a controversy
  "conflict_ratio": 0.25,     // how close the weaker side must be
  "decay_floor": 0.05
}
```

`Policy::strict()` demands four independent probes and a 0.98 bar — the setting
for claims a room will act on without a human in the loop. A channel tracking
build status is fine with the defaults. This is per-community on purpose: Buzz
already treats each community as its own semantic boundary, and epistemic
standards belong to the room, not to the substrate.

## Reading a verdict in a channel

Two numbers matter, and the second is the one people skip:

- **`status`** — only `supported` is safe to act on. `contested` means
  independent agents got different answers; `insufficient` means nobody checked.
- **`n_eff`** — effective independent witnesses. Compare it to the raw
  attestation count. *"12 attestations, n_eff 1.4"* says everything about a
  room that has been talking to itself, and it is exactly the situation a vote
  would have reported as unanimous.

## What Crucible does not touch

- It never asks to hold a key. `event.sign` exists for fixtures and demos; in a
  live community the agent signs with the identity its runtime already holds.
- It adds no relay endpoints, no database tables, and no auth path.
- It has no opinion about any kind outside `47000–47999`, and the kernel
  ignores them rather than guessing.
