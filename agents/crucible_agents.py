#!/usr/bin/env python3
"""Three autonomous agents sharing a Crucible log.

They never call each other. There is no message bus, no scheduler and no
coordinator — because in a Buzz world there already is one, and it is the relay.
Every agent here reads the same append-only event log, decides on its own what
to do next, and writes signed events back. That is what agent-to-agent
communication looks like when the substrate is a shared audit log: coordination
is a side effect of reading, and any agent can be stopped, restarted, or
replaced without telling the others.

Each agent carries a persistent **profile** — its goals, its declared
provenance, its keypair, and an isolated memory namespace on disk — so its
behaviour depends on what it has personally seen, not on what it was handed
this run.

    Prover    proposes falsifiable claims and stands behind them
    Skeptic   probes what the room believes but has not checked, adversarially
    Auditor   resolves, settles the ledger, publishes verdicts

Run:  python3 agents/crucible_agents.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRUCIBLE = ROOT / "target" / "debug" / "crucible"
FALSIFIER = ROOT / "examples" / "falsifiers" / "ci-green.wat"
WORKSPACE = ROOT / ".crucible-workspace"

MANIFEST = {"observations": ["ci:status"]}
HALF_LIFE = 900
T0 = 1_700_000_000


# The falsifier store bounds what `module_path` may read, and the demo key
# verbs are refused without a deliberate opt-in. Both are set here rather than
# assumed, so running this script never widens anything beyond this process.
ENV = {
    **os.environ,
    "CRUCIBLE_FALSIFIER_DIR": str(ROOT / "examples" / "falsifiers"),
    "CRUCIBLE_ALLOW_DEMO_KEYS": "1",
}

# Resolving with no roster is refused unless a policy says so out loud. These
# scripts are demonstrations, not deployments, so they say so.
OPEN = {"allow_unrostered": True}


def crucible(verb: str, payload: dict | None = None) -> dict:
    proc = subprocess.run(
        [str(CRUCIBLE), verb], input=json.dumps(payload or {}),
        capture_output=True, text=True, env=ENV,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"crucible {verb}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


class Relay:
    """Stands in for a Buzz relay: an append-only log of signed events.

    Deliberately dumb. It stores and serves; it has no opinion about what any
    event means, which is exactly the property that lets Crucible ride on a
    stock Buzz deployment without a fork.
    """

    def __init__(self, path: Path):
        self.path = path
        self.events: list[dict] = json.loads(path.read_text()) if path.exists() else []

    def publish(self, event: dict) -> dict:
        if not any(e["id"] == event["id"] for e in self.events):
            self.events.append(event)
            self.path.write_text(json.dumps(self.events, indent=2))
        return event


@dataclass
class Profile:
    """Who an agent is, what it wants, and what it remembers.

    `lineage` and `env` are the agent's own account of itself. The kernel treats
    them as exactly that — a self-report that raises how independent the agent
    looks — which is why an honest agent states them accurately even though
    lying would pay better. That gap is real and documented in the README.
    """

    name: str
    goal: str
    lineage: str
    env: str
    secret: str = field(default="", repr=False)
    pubkey: str = ""

    def __post_init__(self):
        keys = crucible("keygen", {"seed": f"agent/{self.name}"})
        self.secret, self.pubkey = keys["secret_key"], keys["pubkey"]
        self.memory_path = WORKSPACE / f"memory-{self.name}.json"
        self.memory: dict = (
            json.loads(self.memory_path.read_text())
            if self.memory_path.exists()
            else {"seen": [], "notes": {}}
        )

    def remember(self, key: str, note=None) -> None:
        if key not in self.memory["seen"]:
            self.memory["seen"].append(key)
        if note is not None:
            self.memory["notes"][key] = note
        self.memory_path.write_text(json.dumps(self.memory, indent=2))

    def recalls(self, key: str) -> bool:
        return key in self.memory["seen"]

    def sign(self, unsigned: dict) -> dict:
        return crucible("event.sign", {"event": unsigned, "secret_key": self.secret})

    def say(self, message: str) -> None:
        print(f"  {self.name:<8} {message}")


class Prover:
    """Proposes claims. Will not assert anything it cannot ship a falsifier for."""

    def __init__(self, profile: Profile, relay: Relay):
        self.p, self.relay = profile, relay

    def propose(self, statement: str, inputs: dict, confidence: float, at: int) -> dict:
        built = crucible("claim.build", {
            "pubkey": self.p.pubkey, "created_at": at,
            "community": "eng", "domain": "ci",
            "statement": statement, "confidence": confidence,
            "half_life": HALF_LIFE, "inputs": inputs,
            "manifest": MANIFEST, "module_path": FALSIFIER.name,
            "lineage": self.p.lineage, "env": self.p.env,
        })
        event = self.relay.publish(self.p.sign(built["event"]))
        self.p.remember(event["id"], {"statement": statement, "confidence": confidence})
        self.p.say(f'claims "{statement}" at {confidence:g}, falsifier attached')
        return {"event": event, "experiment": built["experiment"], "inputs": inputs}


class Skeptic:
    """Probes what the room has not checked, and reports what it actually saw.

    It refuses to probe the same claim twice — that is what its memory is for,
    and re-attesting would be worth nothing anyway: the kernel counts one
    position per key.
    """

    def __init__(self, profile: Profile, relay: Relay, world: dict):
        self.p, self.relay = profile, relay
        # The Skeptic's private view of the world. In a deployment this is a CI
        # query; here it is a dict, and it is deliberately allowed to disagree
        # with what the Prover believed.
        self.world = world

    def probe(self, claim: dict, at: int) -> dict | None:
        cid = claim["event"]["id"]
        if self.p.recalls(cid):
            self.p.say("already probed this claim; a second attestation is worth nothing")
            return None

        result = crucible("probe.run", {
            "manifest": MANIFEST, "module_path": FALSIFIER.name,
            "inputs": claim["inputs"], "observations": self.world,
            "claim": cid, "experiment": claim["experiment"],
            "pubkey": self.p.pubkey, "created_at": at,
            "lineage": self.p.lineage, "env": self.p.env,
            # It ran the falsifier before reading any verdict on this claim.
            "blind": True,
        })
        event = self.relay.publish(self.p.sign(result["attestation"]))
        self.p.remember(cid, {"outcome": result["outcome"]})
        self.p.say(f'probed -> {result["outcome"]}: "{result["explanation"]}"')
        return event


class Auditor:
    """Resolves claims, publishes verdicts, and keeps the calibration ledger.

    It holds no authority. Every verdict it publishes is a pure function of
    events already on the log, so any agent that disagrees can recompute it and
    publish a competing one.
    """

    def __init__(self, profile: Profile, relay: Relay):
        self.p, self.relay = profile, relay
        self.ledger = self.p.memory["notes"].get("ledger", {})

    def audit(self, now: int) -> list[dict]:
        replay = crucible("ledger.replay", {
            "events": self.relay.events, "now": now, "ledger": self.ledger,
            "policy": OPEN,
        })
        self.ledger = replay["ledger"]
        self.p.remember("ledger", replay["ledger"])

        for v in replay["verdicts"]:
            resolved = crucible("resolve", {
                "events": self.relay.events, "claim": v["claim"], "now": now,
                "resolver": self.p.pubkey, "policy": OPEN,
            })
            if resolved["verdict_event"]:
                self.relay.publish(self.p.sign(resolved["verdict_event"]))
            self.p.say(
                f'"{v["statement"][:34]}" -> {v["status"].upper()}'
                f'  n_eff {v["n_eff"]:.2f} of {v["attestations"]}'
            )
        return replay["calibration"]


def main() -> None:
    if not CRUCIBLE.exists():
        sys.exit("build first:  cargo build -p crucible-cli")
    WORKSPACE.mkdir(exist_ok=True)
    for stale in WORKSPACE.glob("*.json"):
        stale.unlink()  # a fresh run, so the story reads the same every time

    relay = Relay(WORKSPACE / "relay.json")

    prover = Prover(Profile("prover", "assert what I can defend",
                            "release-bot", "runner-a"), relay)
    # Two skeptics that could genuinely fail differently — and one of them is
    # looking at a world where the build is red.
    optimist = Skeptic(Profile("goose", "check what the room assumes",
                               "goose-gpt", "host-goose"),
                       relay, {"ci:status": "green"})
    pessimist = Skeptic(Profile("codex", "look for the case that breaks it",
                                "codex", "host-codex"),
                        relay, {"ci:status": "red"})
    third = Skeptic(Profile("opus", "independent second opinion",
                            "claude-opus-5", "host-opus"),
                    relay, {"ci:status": "green"})
    fourth = Skeptic(Profile("gemma", "independent third opinion",
                             "gemma", "host-gemma"),
                     relay, {"ci:status": "green"})
    # A human is a member on exactly the same terms — same keypair, same
    # attestation, same scoring. That is Buzz's premise, and Crucible keeps it.
    human = Skeptic(Profile("dana", "look with my own eyes",
                            "human", "laptop-dana"),
                    relay, {"ci:status": "green"})
    auditor = Auditor(Profile("auditor", "keep the room honest",
                              "auditor", "host-auditor"), relay)

    print("=" * 72)
    print("Three roles, one log, no coordinator.")
    print("=" * 72)

    print("\nROUND 1  the claim goes up, one agent checks it")
    claim = prover.propose("block/buzz is green at deadbeef",
                           {"repo": "block/buzz", "sha": "deadbeef"}, 0.85, T0)
    optimist.probe(claim, T0 + 10)
    auditor.audit(T0 + 20)

    print("\nROUND 2  a second agent looks, and sees something else")
    pessimist.probe(claim, T0 + 30)
    auditor.audit(T0 + 40)

    print("\nROUND 3  the dissent raised the bar, so three more look —")
    print("         one of them a human, on the same terms as the agents")
    third.probe(claim, T0 + 50)
    fourth.probe(claim, T0 + 55)
    human.probe(claim, T0 + 58)
    optimist.probe(claim, T0 + 60)
    calibration = auditor.audit(T0 + 70)

    print("\nWHAT THE ROOM LEARNED ABOUT ITS MEMBERS")
    known = {p.pubkey: p.name for p in
             (prover.p, optimist.p, pessimist.p, third.p, fourth.p,
              human.p, auditor.p)}
    for row in calibration:
        name = known.get(row["agent"], row["agent"][:8])
        brier = f"{row['brier']:.3f}" if row["brier"] is not None else "  -  "
        print(f"  {name:<8} reliability {row['reliability']:.3f}"
              f"  weight {row['weight']:.2f}  brier {brier}")

    print("\n  codex was outvoted, and it is the only one that lost standing —")
    print("  not for disagreeing, but for being wrong about what CI said.")
    print(f"\n  relay: {len(relay.events)} signed events at {relay.path}")
    print("  each agent's memory is its own file; none of them called another.")
    print("=" * 72)


if __name__ == "__main__":
    main()
