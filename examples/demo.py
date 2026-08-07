#!/usr/bin/env python3
"""End-to-end walkthrough of Crucible, driving the real CLI.

Every event below is really signed with a real secp256k1 key and really
verified; every verdict comes out of the real kernel. Nothing is mocked, which
is the only way a demo of an epistemic substrate is worth anything.

The story it tells, in six scenes:

  1. A room agrees with itself, unanimously, and learns nothing.
  2. The same claim, checked by agents that could actually have disagreed.
  3. Dissent: one anonymous voice cannot freeze a claim, two can contest it.
  4. Time passes and the belief expires rather than persisting by default.
  5. The ledger records who was right, weighted by how loudly they said it.
  6. The attack the arithmetic cannot stop, and the seam that does.

Run:  python3 examples/demo.py
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRUCIBLE = ROOT / "target" / "debug" / "crucible"
FALSIFIER = ROOT / "examples" / "falsifiers" / "ci-green.wat"

T0 = 1_700_000_000
HALF_LIFE = 900  # a claim about CI is worth half as much fifteen minutes later
MANIFEST = {"observations": ["ci:status"], "fuel": 50_000_000,
            "memory_pages": 64, "max_output": 8192}


def crucible(verb, payload=None):
    """Call one CLI verb. JSON in, JSON out, no hidden state."""
    proc = subprocess.run(
        [str(CRUCIBLE), verb],
        input=json.dumps(payload or {}),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"crucible {verb} failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def key(seed):
    k = crucible("keygen", {"seed": seed})
    return k["secret_key"], k["pubkey"]


def sign(unsigned, secret):
    return crucible("event.sign", {"event": unsigned, "secret_key": secret})


def probe(claim, experiment, agent, *, ci_status, lineage, env, blind, at):
    """One agent runs the falsifier and signs what it saw."""
    secret, pub = agent
    result = crucible("probe.run", {
        "manifest": MANIFEST,
        "module_path": str(FALSIFIER),
        "module_digest": claim["module_digest"],
        "inputs": claim["inputs"],
        "observations": {"ci:status": ci_status},
        "claim": claim["id"],
        "experiment": experiment,
        "pubkey": pub,
        "created_at": at,
        "lineage": lineage,
        "env": env,
        "blind": blind,
    })
    return sign(result["attestation"], secret), result


def show(title, resolution):
    v = resolution["resolution"]["verdict"]
    print(f"\n  {title}")
    print(f"    status        {v['status'].upper()}")
    print(f"    belief mass   {v['mass']:.3f}")
    print(f"    attestations  {v['attestations']}")
    print(f"    n_eff         {v['n_eff']:.2f}   <- independent witnesses")
    print(f"    support/against {v['support']:.2f} / {v['opposition']:.2f}")
    return v


def main():
    if not CRUCIBLE.exists():
        sys.exit("build first:  cargo build -p crucible-cli")

    print("=" * 72)
    print("CRUCIBLE — what is a Buzz room entitled to believe?")
    print("=" * 72)

    author = key("author/release-bot")
    inputs = {"repo": "block/buzz", "sha": "deadbeef"}

    built = crucible("claim.build", {
        "pubkey": author[1],
        "created_at": T0,
        "community": "eng",
        "domain": "ci",
        "statement": "block/buzz is green at deadbeef",
        "rationale": "the pipeline went green on my machine",
        "confidence": 0.85,
        "half_life": HALF_LIFE,
        "inputs": inputs,
        "manifest": MANIFEST,
        "module_path": str(FALSIFIER),
        "lineage": "release-bot",
        "env": "runner-a",
    })
    claim_event = sign(built["event"], author[0])
    experiment = built["experiment"]

    print(f"\nCLAIM  {claim_event['id'][:16]}…  \"block/buzz is green at deadbeef\"")
    print(f"  author confidence 0.85, half-life {HALF_LIFE}s")
    print(f"  falsifier is {'PURE' if built['pure'] else 'OBSERVATIONAL'}"
          f" (may read: {', '.join(MANIFEST['observations'])})")

    claim = {
        "id": claim_event["id"],
        "inputs": inputs,
        "module_digest": crucible("probe.run", {
            "manifest": MANIFEST, "module_path": str(FALSIFIER),
        })["module_digest"],
    }

    # ---------------------------------------------------------------- scene 1
    print("\n" + "-" * 72)
    print("SCENE 1  Three agents agree. They are the same model, on the same")
    print("         runner, and each read the channel before answering.")

    echo_chamber = [
        probe(claim, experiment, key(f"echo/{i}"),
              ci_status="green", lineage="claude-opus-5", env="runner-7",
              blind=False, at=T0 + 10 * i)[0]
        for i in range(1, 4)
    ]
    show("unanimous, and worth almost nothing:", crucible("resolve", {
        "events": [claim_event] + echo_chamber, "now": T0 + 60,
    }))
    print("    -> three voices, barely one witness. A vote would have said 3/3.")

    # ---------------------------------------------------------------- scene 2
    print("\n" + "-" * 72)
    print("SCENE 2  Three agents that could genuinely have disagreed:")
    print("         different models, different hosts, none of them looked")
    print("         at the channel first.")

    independent = [
        probe(claim, experiment, key(f"prover/{name}"),
              ci_status="green", lineage=name, env=f"host-{name}",
              blind=True, at=T0 + 20 * i)[0]
        for i, name in enumerate(["goose-gpt", "codex", "claude-opus-5"], start=1)
    ]
    show("checked, and believed:", crucible("resolve", {
        "events": [claim_event] + independent, "now": T0 + 60,
    }))

    # ---------------------------------------------------------------- scene 3
    print("\n" + "-" * 72)
    print("SCENE 3  A fourth agent runs the same falsifier and CI tells it")
    print("         something else.")

    dissent, dissent_run = probe(
        claim, experiment, key("prover/skeptic"),
        ci_status="red", lineage="skeptic-model", env="host-skeptic",
        blind=True, at=T0 + 90)
    print(f"    its probe said: {dissent_run['outcome']} — \"{dissent_run['explanation']}\"")

    lone = show("one unproven voice does not stop the room:", crucible("resolve", {
        "events": [claim_event] + independent + [dissent], "now": T0 + 120,
    }))
    assert lone["status"] != "contested"
    print("    -> `contested` has no arbitration and costs its trigger nothing,")
    print("       so one throwaway keypair must not be able to freeze a claim.")

    second, _ = probe(
        claim, experiment, key("prover/skeptic-2"),
        ci_status="red", lineage="another-model", env="another-host",
        blind=True, at=T0 + 100)
    contested = show("two independent dissenters are a controversy:", crucible("resolve", {
        "events": [claim_event] + independent + [dissent, second], "now": T0 + 120,
    }))
    assert contested["status"] == "contested"
    print("    -> the room is told there is an argument, not handed a shrug.")

    # ---------------------------------------------------------------- scene 4
    print("\n" + "-" * 72)
    print("SCENE 4  Nobody re-checks. Six half-lives later:")

    for elapsed in (0, HALF_LIFE * 3, HALF_LIFE * 30):
        v = crucible("resolve", {
            "events": [claim_event] + independent, "now": T0 + 60 + elapsed,
        })["resolution"]["verdict"]
        print(f"    +{elapsed // 60:>4} min   {v['status']:<13} mass {v['mass']:.3f}")
    print("    -> beliefs here expire. Silence is not corroboration.")

    # ---------------------------------------------------------------- scene 5
    print("\n" + "-" * 72)
    print("SCENE 5  The log is replayed and the ledger falls out of it.")

    replay = crucible("ledger.replay", {
        "events": [claim_event] + independent, "now": T0 + 60,
    })
    for row in replay["calibration"]:
        brier = f"{row['brier']:.3f}" if row["brier"] is not None else "  -  "
        print(f"    {row['agent'][:12]}…  {row['domain']:<10}"
              f" reliability {row['reliability']:.3f}"
              f"  weight {row['weight']:.2f}  brier {brier}")
    print("    -> nobody configured these. They are what the log implies.")

    # ---------------------------------------------------------------- scene 6
    print("\n" + "-" * 72)
    print("SCENE 6  The attack the arithmetic cannot stop, and the seam that")
    print("         does. One operator, three fresh keys, three invented")
    print("         lineages -- indistinguishable from three real agents.")

    sybils = [
        probe(claim, experiment, key(f"sybil/{i}"),
              ci_status="green", lineage=f"totally-different-model-{i}",
              env=f"totally-different-host-{i}", blind=True, at=T0 + i)[0]
        for i in range(1, 4)
    ]
    open_room = crucible("resolve", {
        "events": [claim_event] + sybils, "now": T0 + 60,
    })["resolution"]["verdict"]
    print(f"    with no roster:  {open_room['status'].upper()}"
          f"  n_eff {open_room['n_eff']:.2f}  <- three keypairs, one second")

    # The community's membership set, as Buzz's own admission control defines it.
    roster = [author[1]] + [key(f"prover/{n}")[1]
                            for n in ["goose-gpt", "codex", "claude-opus-5"]]
    closed = crucible("resolve", {
        "events": [claim_event] + sybils, "now": T0 + 60,
        "policy": {"roster": roster},
    })
    v = closed["resolution"]["verdict"]
    print(f"    with a roster:   {v['status'].upper()}  n_eff {v['n_eff']:.2f}")
    for ex in closed["resolution"]["excluded"][:1]:
        print(f"    excluded: {ex['reason'][:64]}...")
    print("    -> no amount of arithmetic over the events can tell these apart.")
    print("       Membership is Buzz's job, and this is where it plugs in.")

    print("\n" + "=" * 72)
    print("Every event above was signed and verified; every number came from")
    print("the kernel. Rerun it and you will get the same answers — which is")
    print("the point: a verdict here is a computation, not an authority.")
    print("=" * 72)


if __name__ == "__main__":
    main()
