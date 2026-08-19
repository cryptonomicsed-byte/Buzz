//! Scenario tests for the resolution kernel.
//!
//! These are written as situations a Buzz room actually gets into, because the
//! interesting failures of a belief substrate are situational, not unit-level:
//! it is easy to write an aggregator that is arithmetically correct and still
//! declares a false thing true the moment eight copies of one agent agree.

use crate::calibration::Ledger;
use crate::policy::Policy;
use crate::resolve::{resolve, settle, Role};
use crucible_core::attestation::Provenance;
use crucible_core::claim::{ClaimBody, FalsifierRef};
use crucible_core::{Attestation, Challenge, Claim, EventId, Outcome, PubKey, Status};

const T0: u64 = 1_700_000_000;
const HALF_LIFE: u64 = 900;

fn key(n: u8) -> PubKey {
    PubKey::from_bytes([n; 32])
}

fn id(n: u8) -> EventId {
    EventId::from_bytes([n; 32])
}

fn claim_with(confidence: f64) -> Claim {
    Claim {
        id: id(200),
        author: key(200),
        created_at: T0,
        community: "eng".into(),
        domain: "ci".into(),
        confidence,
        half_life: HALF_LIFE,
        expiry: None,
        falsifier: FalsifierRef {
            module: [1; 32],
            manifest: [2; 32],
            inputs: [3; 32],
            // The realistic default: a probe that reads CI, and therefore may
            // legitimately see a different world than another probe did.
            pure: false,
        },
        body: ClaimBody {
            statement: "main is green at deadbeef".into(),
            rationale: None,
            inputs: serde_json::json!({"sha": "deadbeef"}),
        },
        provenance: Provenance {
            lineage: "key:author".into(),
            env: "key:author".into(),
            blind: true,
        },
    }
}

fn a_claim() -> Claim {
    claim_with(0.8)
}

/// A claim whose falsifier takes no capabilities, so it must produce identical
/// output everywhere.
fn a_pure_claim() -> Claim {
    let mut c = claim_with(0.8);
    c.falsifier.pure = true;
    c
}

struct ProbeSpec {
    n: u8,
    outcome: Outcome,
    lineage: &'static str,
    env: &'static str,
    blind: bool,
    at: u64,
    digest: Option<u8>,
}

impl ProbeSpec {
    fn new(n: u8, outcome: Outcome) -> Self {
        Self {
            n,
            outcome,
            lineage: "lineage-default",
            env: "env-default",
            blind: true,
            at: T0,
            digest: None,
        }
    }
    fn independent(n: u8, outcome: Outcome) -> Self {
        // Distinct model and distinct machine: genuinely separate witnesses.
        Self {
            lineage: Box::leak(format!("model-{n}").into_boxed_str()),
            env: Box::leak(format!("host-{n}").into_boxed_str()),
            ..Self::new(n, outcome)
        }
    }
    fn build(self, claim: &Claim) -> Attestation {
        Attestation {
            id: id(self.n),
            attestor: key(self.n),
            created_at: self.at,
            claim: claim.id,
            experiment: claim.falsifier.experiment_id(),
            outcome: self.outcome,
            // A real falsifier's outcome is read off its output, so probes that
            // disagree necessarily hashed different things. Test data that
            // ignored this would exercise a state the sandbox cannot produce.
            output_digest: [self.digest.unwrap_or(match self.outcome {
                Outcome::Holds => 1,
                Outcome::Fails => 2,
                Outcome::Indeterminate => 3,
            }); 32],
            fuel: 1000,
            provenance: Provenance {
                lineage: self.lineage.into(),
                env: self.env.into(),
                blind: self.blind,
            },
        }
    }
}

/// An agent with a strong, earned track record in `domain`.
fn proven(ledger: &mut Ledger, agent: u8, domain: &str) {
    for _ in 0..200 {
        ledger.record(&key(agent), domain, 0.95, true, T0);
    }
}

/// The defaults, with the roster requirement waived. Scenario tests are about
/// the kernel's arithmetic, not about admission control, which has its own.
fn open_policy() -> Policy {
    Policy {
        allow_unrostered: true,
        ..Policy::default()
    }
}

fn resolve_at(
    claim: &Claim,
    probes: &[Attestation],
    ledger: &Ledger,
    now: u64,
) -> crate::resolve::Resolution {
    resolve(claim, probes, &[], ledger, &open_policy(), now)
}

// ---------------------------------------------------------------- independence

/// The headline result. Ten agents agree, unanimously, immediately — and the
/// room is still not entitled to believe them, because they are the same model
/// on the same host reading each other's messages. A conventional vote would
/// report 10/10 and call it settled.
#[test]
fn ten_agreeing_clones_do_not_establish_truth() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=10)
        .map(|n| {
            let mut p = ProbeSpec::new(n, Outcome::Holds);
            p.blind = false; // they read the channel before answering
            p.build(&claim)
        })
        .collect();

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(r.verdict.attestations, 10);
    assert!(
        r.verdict.n_eff < 2.0,
        "ten clones must not look independent, n_eff was {}",
        r.verdict.n_eff
    );
    assert_eq!(r.verdict.status, Status::Insufficient);
}

/// The same ten messages, but from ten genuinely different agents, settle it.
#[test]
fn ten_independent_agents_do_establish_truth() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=10)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert!((r.verdict.n_eff - 10.0).abs() < 1e-9);
    assert_eq!(r.verdict.status, Status::Supported);
    assert!(r.verdict.mass > 0.99);
}

/// One agent, however trusted, is one machine and one blind spot.
#[test]
fn a_single_probe_never_resolves_a_claim() {
    let claim = a_claim();
    let mut ledger = Ledger::new();
    proven(&mut ledger, 1, "ci");
    proven(&mut ledger, 200, "ci");

    let probes = [ProbeSpec::independent(1, Outcome::Holds).build(&claim)];
    let r = resolve_at(&claim, &probes, &ledger, T0);

    assert_eq!(r.verdict.n_eff, 1.0);
    assert_eq!(r.verdict.status, Status::Insufficient);
    assert!(
        r.verdict.mass > 0.9,
        "belief may be high — but high belief from one witness is not a verdict"
    );
}

/// An agent cannot manufacture consensus by attesting repeatedly.
#[test]
fn one_agent_attesting_many_times_counts_once() {
    let claim = a_claim();
    let probes: Vec<_> = (0..20)
        .map(|i| {
            let mut a = ProbeSpec::independent(1, Outcome::Holds).build(&claim);
            a.id = id(i + 1);
            a.created_at = T0 + i as u64;
            a
        })
        .collect();

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0 + 100);
    assert_eq!(r.verdict.attestations, 1, "only the latest position counts");
    assert!(
        (r.verdict.n_eff - 0.94).abs() < 0.01,
        "one witness, slightly aged: {}",
        r.verdict.n_eff
    );
    assert_eq!(r.verdict.status, Status::Insufficient);
}

/// An agent is allowed to change its mind; the latest word is the one that
/// counts, and it must be able to overturn its own earlier support.
#[test]
fn an_agent_can_revise_its_own_attestation() {
    let claim = a_claim();
    let mut early = ProbeSpec::independent(1, Outcome::Holds).build(&claim);
    early.id = id(1);
    let mut late = ProbeSpec::independent(1, Outcome::Fails).build(&claim);
    late.id = id(2);
    late.created_at = T0 + 60;

    let r = resolve_at(&claim, &[early, late], &Ledger::new(), T0 + 60);
    assert_eq!(r.verdict.attestations, 1);
    let probe = r
        .contributions
        .iter()
        .find(|c| c.role == Role::Probe)
        .unwrap();
    assert_eq!(probe.outcome, Outcome::Fails);
}

// -------------------------------------------------------------------- conflict

/// Real disagreement between independent witnesses is not something to average
/// into a shrug. Somebody has to look.
#[test]
fn independent_disagreement_is_contested_not_averaged() {
    let claim = a_claim();
    let probes = [
        ProbeSpec::independent(1, Outcome::Holds).build(&claim),
        ProbeSpec::independent(2, Outcome::Holds).build(&claim),
        ProbeSpec::independent(3, Outcome::Fails).build(&claim),
        ProbeSpec::independent(4, Outcome::Fails).build(&claim),
    ];
    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);

    assert_eq!(r.verdict.status, Status::Contested);
    assert!(r.verdict.support > 0.0 && r.verdict.opposition > 0.0);
}

/// One credible dissenter is still a controversy — an earned record buys the
/// right to stop the room on your own.
#[test]
fn a_single_proven_dissenter_contests() {
    let claim = a_claim();
    let mut ledger = Ledger::new();
    proven(&mut ledger, 3, "ci");
    let probes = [
        ProbeSpec::independent(1, Outcome::Holds).build(&claim),
        ProbeSpec::independent(2, Outcome::Holds).build(&claim),
        ProbeSpec::independent(3, Outcome::Fails).build(&claim),
    ];
    assert_eq!(
        resolve_at(&claim, &probes, &ledger, T0).verdict.status,
        Status::Contested
    );
}

/// …but one anonymous key must not be able to freeze a claim.
///
/// `Contested` has no arbitration, no expiry and no cost to whoever triggered
/// it: `settle` never runs, so nobody is ever scored for it. If a single fresh
/// keypair could reach it, suppressing any true claim in the room would be free
/// and permanent.
#[test]
fn one_unproven_dissenter_cannot_freeze_a_claim() {
    let claim = a_claim();
    let supported: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    assert_eq!(
        resolve_at(&claim, &supported, &Ledger::new(), T0)
            .verdict
            .status,
        Status::Supported
    );

    let mut with_dissent = supported;
    with_dissent.push(ProbeSpec::independent(9, Outcome::Fails).build(&claim));
    let r = resolve_at(&claim, &with_dissent, &Ledger::new(), T0);
    assert_eq!(r.verdict.status, Status::Supported);
    assert!(
        r.verdict.opposition > 0.0,
        "the dissent must still be visible in the record"
    );
}

/// …but one straggler must not be able to freeze a well-established claim
/// forever, or challenging becomes a denial-of-service on truth.
#[test]
fn a_lone_dissenter_does_not_freeze_an_overwhelming_claim() {
    let claim = a_claim();
    let mut ledger = Ledger::new();
    for a in [1, 2, 3, 4, 5, 200] {
        proven(&mut ledger, a, "ci");
    }

    let mut probes: Vec<_> = (1..=5)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    probes.push(ProbeSpec::independent(9, Outcome::Fails).build(&claim)); // unproven

    let r = resolve_at(&claim, &probes, &ledger, T0);
    assert_eq!(r.verdict.status, Status::Supported);
    assert!(
        r.verdict.opposition > 0.0,
        "the dissent must remain visible in the record even when outweighed"
    );
}

/// "Nobody checked" and "the checks fight each other" both sit near a half.
/// Reporting them as the same thing is how a room mistakes a live controversy
/// for an unexamined guess.
#[test]
fn ignorance_and_controversy_are_different_statuses() {
    let claim = a_claim();
    let ignorance = resolve_at(&claim, &[], &Ledger::new(), T0);
    assert_eq!(ignorance.verdict.status, Status::Insufficient);
    assert_eq!(ignorance.verdict.n_eff, 0.0);

    let probes = [
        ProbeSpec::independent(1, Outcome::Holds).build(&claim),
        ProbeSpec::independent(2, Outcome::Holds).build(&claim),
        ProbeSpec::independent(3, Outcome::Fails).build(&claim),
        ProbeSpec::independent(4, Outcome::Fails).build(&claim),
    ];
    let controversy = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(controversy.verdict.status, Status::Contested);

    assert!(
        (controversy.verdict.mass - 0.5).abs() < 0.35
            && (ignorance.verdict.mass - 0.5).abs() < 0.35,
        "both sit near a half — which is exactly why the status must distinguish them"
    );
}

// --------------------------------------------------------------- determinism

/// If two agents ran the same module on the same inputs and saw different
/// output, the experiment is broken. No amount of further agreement means
/// anything until the author fixes it, so this outranks every other status.
#[test]
fn divergent_output_digests_poison_a_pure_claim() {
    let claim = a_pure_claim();
    let mut probes: Vec<_> = (1..=6)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    // Same module, same inputs, same verdict — but a different output hash.
    // The falsifier hashed something it did not declare: a clock, a path, a
    // random seed. Everything downstream of it is now unreliable.
    probes[4].output_digest = [99; 32];
    probes[5].output_digest = [99; 32];

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(r.verdict.status, Status::Nondeterministic);
    assert_eq!(r.output_digests.len(), 2);
}

/// `output_digest` is self-reported, and `Nondeterministic` is an absorbing
/// status that never resolves and never scores anyone — so a single fabricated
/// digest must not be able to condemn a claim permanently. One odd voice is far
/// likelier to be a broken or lying prober than a broken claim; two independent
/// ones are worth believing.
#[test]
fn one_fabricated_digest_cannot_condemn_a_pure_claim() {
    let claim = a_pure_claim();
    let mut probes: Vec<_> = (1..=6)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    probes[5].output_digest = [0x5a; 32];

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(r.verdict.status, Status::Supported);
    assert_eq!(
        r.output_digests.len(),
        2,
        "the divergence is still on the record for a reader to weigh"
    );
}

/// The other half of the distinction, and the reason it exists. An
/// observational falsifier is *supposed* to return different things when the
/// world differs — that is what makes it worth running. Two agents seeing
/// different CI results is a disagreement to resolve, not a broken probe, and a
/// substrate that could not tell these apart would condemn every useful check
/// it ran.
#[test]
fn divergent_output_does_not_poison_an_observational_claim() {
    let claim = a_claim();
    assert!(!claim.falsifier.pure);
    let probes = [
        ProbeSpec::independent(1, Outcome::Holds).build(&claim),
        ProbeSpec::independent(2, Outcome::Holds).build(&claim),
        ProbeSpec::independent(3, Outcome::Fails).build(&claim),
        ProbeSpec::independent(4, Outcome::Fails).build(&claim),
    ];

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(
        r.output_digests.len(),
        2,
        "the divergence is still recorded"
    );
    assert_eq!(r.verdict.status, Status::Contested, "…but as disagreement");
}

/// An indeterminate probe often *cannot* produce a comparable digest — a denied
/// capability, an exhausted fuel budget. Reading that as non-determinism would
/// poison every claim whose falsifier ever hit a sandbox limit.
#[test]
fn indeterminate_probes_do_not_trigger_nondeterminism() {
    let claim = a_pure_claim();
    let mut probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    let mut odd = ProbeSpec::independent(5, Outcome::Indeterminate).build(&claim);
    odd.output_digest = [0; 32];
    probes.push(odd);

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(r.verdict.status, Status::Supported);
}

/// An indeterminate probe is not a quiet vote for the claim.
#[test]
fn indeterminate_probes_carry_no_evidence() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=8)
        .map(|n| ProbeSpec::independent(n, Outcome::Indeterminate).build(&claim))
        .collect();

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    assert_eq!(r.verdict.n_eff, 0.0);
    assert_eq!(r.verdict.status, Status::Insufficient);
}

/// Two replicas replaying the same relay log must agree, whatever order the
/// relay happened to hand them the events in.
#[test]
fn resolution_is_independent_of_event_order() {
    let claim = a_claim();
    let mut probes: Vec<_> = (1..=6)
        .map(|n| {
            ProbeSpec::independent(
                n,
                if n % 3 == 0 {
                    Outcome::Fails
                } else {
                    Outcome::Holds
                },
            )
            .build(&claim)
        })
        .collect();

    let forward = resolve_at(&claim, &probes, &Ledger::new(), T0);
    probes.reverse();
    let backward = resolve_at(&claim, &probes, &Ledger::new(), T0);

    assert_eq!(forward.verdict, backward.verdict);
}

// -------------------------------------------------------------------- decay

/// Beliefs here are perishable. A claim about a build being green is not still
/// true a day later just because nobody said otherwise.
#[test]
fn evidence_goes_stale_after_enough_half_lives() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=6)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    assert_eq!(
        resolve_at(&claim, &probes, &Ledger::new(), T0)
            .verdict
            .status,
        Status::Supported
    );

    let much_later = T0 + HALF_LIFE * 40;
    let stale = resolve_at(&claim, &probes, &Ledger::new(), much_later);
    assert_eq!(stale.verdict.status, Status::Decayed);
    assert!(stale.verdict.mass < 0.51 && stale.verdict.mass > 0.49);
}

/// Decay is gradual, not a cliff: belief must fall monotonically as evidence
/// ages, so an agent can see a claim weakening before it expires.
#[test]
fn belief_decays_monotonically() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=6)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    let mut previous = 1.0;
    for k in 0..12 {
        let mass = resolve_at(&claim, &probes, &Ledger::new(), T0 + HALF_LIFE * k)
            .verdict
            .mass;
        assert!(mass <= previous + 1e-12, "belief rose with age: {mass}");
        previous = mass;
    }
    assert!(previous < 0.6);
}

#[test]
fn an_expired_claim_is_decayed_however_strong_the_evidence() {
    let mut claim = a_claim();
    claim.expiry = Some(T0 + 60);
    let probes: Vec<_> = (1..=8)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    let r = resolve_at(&claim, &probes, &Ledger::new(), T0 + 61);
    assert_eq!(r.verdict.status, Status::Decayed);
}

/// A claim nobody ever probed is unexamined, not stale — and an agent needs
/// that difference to know whether to re-probe or to start from scratch.
#[test]
fn an_unprobed_claim_is_insufficient_not_decayed() {
    let claim = a_claim();
    let r = resolve_at(&claim, &[], &Ledger::new(), T0 + HALF_LIFE * 50);
    assert_eq!(r.verdict.status, Status::Insufficient);
}

// -------------------------------------------------------------- author weight

/// Confidence is not authority. An agent with no track record cannot talk its
/// own claim into being believed, however certain it says it is.
#[test]
fn an_unproven_author_cannot_self_certify() {
    let claim = claim_with(0.999);
    let r = resolve_at(&claim, &[], &Ledger::new(), T0);
    assert_eq!(r.verdict.status, Status::Insufficient);
    assert!(r.verdict.mass < 0.7, "mass was {}", r.verdict.mass);
}

/// Nor can a proven one: a track record buys weight, not the right to skip
/// being checked.
#[test]
fn even_a_proven_author_cannot_self_certify() {
    let claim = claim_with(0.99);
    let mut ledger = Ledger::new();
    proven(&mut ledger, 200, "ci");

    let r = resolve_at(&claim, &[], &ledger, T0);
    assert!(r.verdict.mass > 0.9, "belief is high…");
    assert_eq!(r.verdict.status, Status::Insufficient, "…but unverified");
}

/// The author's forecast is bounded by the confidence they were willing to
/// state, so hedging cannot be a free option that still swings the room.
#[test]
fn a_hedged_claim_moves_belief_less_than_a_committed_one() {
    let mut ledger = Ledger::new();
    proven(&mut ledger, 200, "ci");

    let hedged = resolve_at(&claim_with(0.55), &[], &ledger, T0).verdict.mass;
    let committed = resolve_at(&claim_with(0.97), &[], &ledger, T0).verdict.mass;
    assert!(hedged < committed);
    assert!(hedged < 0.6);
}

/// An author who attests to their own claim is still one agent.
#[test]
fn an_author_cannot_double_count_by_probing_its_own_claim() {
    let claim = a_claim();
    let mut own = ProbeSpec::independent(1, Outcome::Holds).build(&claim);
    own.attestor = claim.author;

    let r = resolve_at(&claim, &[own], &Ledger::new(), T0);
    let probe = r
        .contributions
        .iter()
        .find(|c| c.role == Role::Probe)
        .unwrap();
    assert_eq!(probe.novelty, 0.0, "self-agreement is not a second witness");
    assert_eq!(r.verdict.n_eff, 0.0);
}

/// A disproven author is silenced, not inverted: a substrate that reads a liar
/// backwards can be steered by lying deliberately.
#[test]
fn a_discredited_author_contributes_nothing() {
    let claim = claim_with(0.99);
    let mut ledger = Ledger::new();
    for _ in 0..200 {
        ledger.record(&key(200), "ci", 0.95, false, T0);
    }

    let r = resolve_at(&claim, &[], &ledger, T0);
    assert_eq!(r.verdict.mass, 0.5);
    assert_eq!(r.verdict.support, 0.0);
    assert_eq!(r.verdict.opposition, 0.0);
}

// ------------------------------------------------------------------ hygiene

/// Evidence about a different experiment is not evidence about this claim —
/// and the reason it was dropped has to be visible, or the kernel is asking to
/// be trusted rather than audited.
#[test]
fn attestations_about_a_different_experiment_are_excluded_with_a_reason() {
    let claim = a_claim();
    let mut wrong = ProbeSpec::independent(1, Outcome::Fails).build(&claim);
    wrong.experiment = [7; 32];
    let right = ProbeSpec::independent(2, Outcome::Holds).build(&claim);

    let r = resolve_at(&claim, &[wrong, right], &Ledger::new(), T0);
    assert_eq!(r.verdict.attestations, 1);
    assert_eq!(r.excluded.len(), 1);
    assert!(
        r.excluded[0].reason.contains("different module"),
        "unhelpful reason: {}",
        r.excluded[0].reason
    );
}

#[test]
fn attestations_about_a_different_claim_are_excluded() {
    let claim = a_claim();
    let mut stray = ProbeSpec::independent(1, Outcome::Holds).build(&claim);
    stray.claim = id(250);

    let r = resolve_at(&claim, &[stray], &Ledger::new(), T0);
    assert_eq!(r.excluded.len(), 1);
    assert_eq!(r.verdict.attestations, 0);
}

/// Every contribution must be explainable: the room can ask why, and get
/// arithmetic rather than an assurance.
#[test]
fn every_contribution_is_fully_traced() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=3)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    let r = resolve_at(&claim, &probes, &Ledger::new(), T0 + 450);

    assert_eq!(r.contributions.len(), 4, "three probes plus the assertion");
    for c in &r.contributions {
        assert!(c.decay > 0.0 && c.decay <= 1.0);
        assert!((0.0..=1.0).contains(&c.novelty));
        let expected = c.raw_weight * c.decay * c.novelty * c.outcome.sign();
        assert!(
            (c.effective - expected).abs() < 1e-12,
            "effective weight is not reproducible from its parts"
        );
    }
    assert_eq!(
        r.contributions
            .iter()
            .filter(|c| c.role == Role::Assertion)
            .count(),
        1
    );
}

/// `created_at` is self-declared and drives decay, so an event dated into the
/// future would never age: a claim with a fifteen-minute half-life, permanently
/// fresh, from one integer. Beyond the skew bound the evidence is refused.
#[test]
fn future_dated_evidence_is_refused_rather_than_never_ageing() {
    let claim = a_claim();
    let mut ahead: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    for a in &mut ahead {
        a.created_at = T0 + 100 * HALF_LIFE;
    }

    let r = resolve_at(&claim, &ahead, &Ledger::new(), T0 + HALF_LIFE * 50);
    assert_eq!(r.verdict.attestations, 0);
    assert_eq!(r.excluded.len(), 4);
    assert!(
        r.excluded[0].reason.contains("clock-skew"),
        "got {}",
        r.excluded[0].reason
    );
    assert_ne!(r.verdict.status, Status::Supported);
}

/// Ordinary clock jitter is not an attack, and must not cost an honest agent
/// its probe.
#[test]
fn evidence_within_the_skew_bound_is_accepted() {
    let claim = a_claim();
    let mut jittery = ProbeSpec::independent(1, Outcome::Holds).build(&claim);
    jittery.created_at = T0 + 30;

    let r = resolve_at(&claim, &[jittery], &Ledger::new(), T0);
    assert_eq!(r.verdict.attestations, 1);
    let probe = r
        .contributions
        .iter()
        .find(|c| c.role == Role::Probe)
        .unwrap();
    assert_eq!(
        probe.decay, 1.0,
        "a slightly-ahead clock does not gain weight"
    );
}

#[test]
fn a_stricter_policy_demands_more_witnesses() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=3)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    assert_eq!(
        resolve_at(&claim, &probes, &Ledger::new(), T0)
            .verdict
            .status,
        Status::Supported
    );
    let strict = resolve(
        &claim,
        &probes,
        &[],
        &Ledger::new(),
        &Policy {
            allow_unrostered: true,
            ..Policy::strict()
        },
        T0,
    );
    assert_eq!(strict.verdict.status, Status::Insufficient);
}

#[test]
fn resolution_round_trips_through_json() {
    let claim = a_claim();
    let probes = [ProbeSpec::independent(1, Outcome::Holds).build(&claim)];
    let r = resolve_at(&claim, &probes, &Ledger::new(), T0);
    let back: crate::resolve::Resolution =
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

// ---------------------------------------------------------------- settlement

/// Getting it right must pay, and getting it loudly wrong must cost — otherwise
/// nothing in the ledger means anything.
#[test]
fn settling_rewards_the_correct_and_penalises_the_wrong() {
    let claim = a_claim();
    let mut probes: Vec<_> = (1..=5)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    probes.push(ProbeSpec::independent(6, Outcome::Fails).build(&claim));

    let mut ledger = Ledger::new();
    let r = resolve_at(&claim, &probes, &ledger, T0);
    assert_eq!(r.verdict.status, Status::Supported);

    assert!(settle(
        &mut ledger,
        &claim,
        &probes,
        &[],
        &r.verdict,
        &open_policy()
    ));

    assert!(ledger.get(&key(1), "ci").r() > crate::calibration::BOOTSTRAP);
    assert!(ledger.get(&key(6), "ci").r() < crate::calibration::BOOTSTRAP);
    assert!(
        ledger.get(&key(200), "ci").r() > crate::calibration::BOOTSTRAP,
        "the author was right and should gain"
    );
}

/// An unresolved claim scores nobody. Docking agents for a room's inattention
/// would teach them to claim less, which is the opposite of the point.
#[test]
fn an_unresolved_claim_settles_nothing() {
    let claim = a_claim();
    let probes = [ProbeSpec::independent(1, Outcome::Holds).build(&claim)];
    let mut ledger = Ledger::new();
    let r = resolve_at(&claim, &probes, &ledger, T0);
    assert_eq!(r.verdict.status, Status::Insufficient);

    assert!(!settle(
        &mut ledger,
        &claim,
        &probes,
        &[],
        &r.verdict,
        &open_policy()
    ));
    assert!(ledger.is_empty());
}

/// Honest uncertainty must be free. If "I could not tell" were scored, agents
/// would learn to guess instead of reporting that the probe was inconclusive.
#[test]
fn an_indeterminate_probe_is_not_scored() {
    let claim = a_claim();
    let mut probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    probes.push(ProbeSpec::independent(5, Outcome::Indeterminate).build(&claim));

    let mut ledger = Ledger::new();
    let r = resolve_at(&claim, &probes, &ledger, T0);
    settle(
        &mut ledger,
        &claim,
        &probes,
        &[],
        &r.verdict,
        &open_policy(),
    );

    assert!(
        (ledger.get(&key(5), "ci").r() - crate::calibration::BOOTSTRAP).abs() < 1e-3,
        "an honest abstention must neither gain nor lose standing, got {}",
        ledger.get(&key(5), "ci").r()
    );
}

#[test]
fn a_correct_challenger_gains_and_a_wrong_one_loses() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    let challenge = Challenge {
        id: id(90),
        challenger: key(90),
        created_at: T0,
        claim: claim.id,
        stake: 0.8,
        counter_falsifier: None,
        reason: "the probe never touched the database".into(),
    };

    let mut ledger = Ledger::new();
    let r = resolve_at(&claim, &probes, &ledger, T0);
    assert_eq!(r.verdict.status, Status::Supported);
    assert_eq!(r.open_challenges, 0, "challenge was not passed to resolve");

    settle(
        &mut ledger,
        &claim,
        &probes,
        std::slice::from_ref(&challenge),
        &r.verdict,
        &open_policy(),
    );
    assert!(
        ledger.get(&key(90), "ci").r() < crate::calibration::BOOTSTRAP,
        "a bold, wrong challenge must cost standing"
    );

    // The same challenge against a claim that really was false.
    let refuting: Vec<_> = (1..=6)
        .map(|n| ProbeSpec::independent(n, Outcome::Fails).build(&claim))
        .collect();
    let mut ledger2 = Ledger::new();
    let r2 = resolve_at(&claim, &refuting, &ledger2, T0);
    assert_eq!(r2.verdict.status, Status::Refuted);
    settle(
        &mut ledger2,
        &claim,
        &refuting,
        &[challenge],
        &r2.verdict,
        &open_policy(),
    );
    assert!(ledger2.get(&key(90), "ci").r() > crate::calibration::BOOTSTRAP);
}

/// Challenges are visible in the resolution but move no belief on their own:
/// doubt is not a measurement, or suppressing a true claim would be free.
#[test]
fn a_challenge_does_not_move_belief_by_itself() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    let challenges: Vec<_> = (1..=20)
        .map(|n| Challenge {
            id: id(n + 100),
            challenger: key(n + 100),
            created_at: T0,
            claim: claim.id,
            stake: 1.0,
            counter_falsifier: None,
            reason: "no".into(),
        })
        .collect();

    let quiet = resolve_at(&claim, &probes, &Ledger::new(), T0);
    let noisy = resolve(
        &claim,
        &probes,
        &challenges,
        &Ledger::new(),
        &open_policy(),
        T0,
    );

    assert_eq!(noisy.verdict.mass, quiet.verdict.mass);
    assert_eq!(noisy.verdict.status, Status::Supported);
    assert_eq!(noisy.open_challenges, 20, "but the room can see them");
}

/// The loop closes: an agent that keeps being right earns weight, and its later
/// probes carry further than its earlier ones did.
#[test]
fn reliability_earned_in_one_round_carries_into_the_next() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    let mut ledger = Ledger::new();
    let before = resolve_at(&claim, &probes[..1], &ledger, T0).verdict.mass;

    for _ in 0..30 {
        let r = resolve_at(&claim, &probes, &ledger, T0);
        settle(
            &mut ledger,
            &claim,
            &probes,
            &[],
            &r.verdict,
            &open_policy(),
        );
    }

    let after = resolve_at(&claim, &probes[..1], &ledger, T0).verdict.mass;
    assert!(
        after > before + 0.1,
        "a proven agent's word must carry further: {before} -> {after}"
    );
}

// ------------------------------------------------------- adversarial hardening

/// Settlement must be idempotent. A resolver runs on a timer over the same log;
/// without this, every tick pays every agent again for the same claim and
/// reputation measures how often somebody pressed the button.
#[test]
fn a_claim_settles_exactly_once_however_often_it_is_replayed() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    let mut ledger = Ledger::new();
    let r = resolve_at(&claim, &probes, &ledger, T0);

    assert!(settle(
        &mut ledger,
        &claim,
        &probes,
        &[],
        &r.verdict,
        &open_policy()
    ));
    let once = ledger.get(&key(1), "ci").r();

    for _ in 0..50 {
        assert!(
            !settle(
                &mut ledger,
                &claim,
                &probes,
                &[],
                &r.verdict,
                &open_policy()
            ),
            "a replayed settlement must be refused"
        );
    }
    assert_eq!(ledger.get(&key(1), "ci").r(), once);
    assert_eq!(ledger.settled_count(), 1);
}

/// The roster is the seam for the one attack the kernel cannot compute its way
/// out of: an operator minting keys. Nothing in the events distinguishes twenty
/// sock puppets from twenty agents, so the answer has to come from outside —
/// from the community's own membership set.
#[test]
fn attestors_outside_the_roster_are_excluded_with_a_reason() {
    let claim = a_claim();
    let sybils: Vec<_> = (1..=5)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    // With no roster, five fresh keys look like five witnesses.
    let open = resolve_at(&claim, &sybils, &Ledger::new(), T0);
    assert_eq!(open.verdict.status, Status::Supported);

    // With one, only the admitted members are heard.
    let policy = Policy {
        roster: Some([key(200), key(1), key(2)].into_iter().collect()),
        ..open_policy()
    };
    let closed = resolve(&claim, &sybils, &[], &Ledger::new(), &policy, T0);
    assert_eq!(closed.verdict.attestations, 2);
    assert_eq!(closed.excluded.len(), 3);
    assert!(closed.excluded[0].reason.contains("roster"));
    assert_eq!(closed.verdict.status, Status::Insufficient);
}

/// An author off the roster may still make a claim — anyone may — but it lends
/// itself no credibility while doing so.
#[test]
fn an_unadmitted_author_carries_no_weight_of_its_own() {
    let claim = claim_with(0.99);
    let mut ledger = Ledger::new();
    proven(&mut ledger, 200, "ci");

    let policy = Policy {
        roster: Some([key(1)].into_iter().collect()),
        ..open_policy()
    };
    let r = resolve(&claim, &[], &[], &ledger, &policy, T0);
    assert_eq!(r.verdict.mass, 0.5);
    assert_eq!(r.verdict.support, 0.0);
}

/// The domain is chosen by the claim's author and reliability is keyed on it,
/// so an unconstrained domain is a reset button an adversary can press per
/// claim — putting every hard-won attestor back beside the newcomers.
#[test]
fn a_domain_the_community_does_not_recognise_earns_the_author_nothing() {
    let mut claim = claim_with(0.99);
    claim.domain = "migration-safety-q3".into();
    let mut ledger = Ledger::new();
    proven(&mut ledger, 200, "migration-safety-q3");

    let policy = Policy {
        domains: Some(
            ["ci".to_string(), "security".to_string()]
                .into_iter()
                .collect(),
        ),
        ..open_policy()
    };
    let r = resolve(&claim, &[], &[], &ledger, &policy, T0);
    assert_eq!(r.verdict.support, 0.0);
}

/// Resolution is quadratic in the attestation count and the input arrives from
/// a relay, so the ceiling cannot be "however many turned up".
#[test]
fn attestations_beyond_the_cap_are_dropped_oldest_first() {
    let claim = a_claim();
    let flood: Vec<_> = (1..=200)
        .map(|n| {
            let mut a = ProbeSpec::independent((n % 250) as u8, Outcome::Holds).build(&claim);
            a.attestor = PubKey::from_bytes([(n % 256) as u8; 32]);
            a.id = EventId::from_bytes([(n % 256) as u8; 32]);
            a.created_at = T0 + n as u64;
            a
        })
        .collect();

    let policy = Policy {
        max_attestations: 10,
        ..open_policy()
    };
    let r = resolve(&claim, &flood, &[], &Ledger::new(), &policy, T0 + 500);
    assert!(r.verdict.attestations <= 10);
    assert!(r.excluded.iter().any(|e| e.reason.contains("cap")));
}

/// An indeterminate probe is free to publish and is never scored. If it could
/// also soak the novelty of agents that share its declared provenance, it would
/// be the cheapest attack in the system — and it would target true claims.
#[test]
fn a_free_abstention_cannot_suppress_an_honest_fleet() {
    let claim = a_claim();
    let fleet: Vec<_> = (1..=5)
        .map(|n| {
            let mut p = ProbeSpec::new(n, Outcome::Holds);
            p.lineage = "ci-runner-v3";
            p.env = "gha-ubuntu";
            p.build(&claim)
        })
        .collect();
    let clean = resolve_at(&claim, &fleet, &Ledger::new(), T0).verdict.n_eff;

    let mut poisoned = vec![{
        let mut p = ProbeSpec::new(99, Outcome::Indeterminate);
        p.lineage = "ci-runner-v3";
        p.env = "gha-ubuntu";
        p.build(&claim)
    }];
    poisoned.extend(fleet);
    let after = resolve_at(&claim, &poisoned, &Ledger::new(), T0)
        .verdict
        .n_eff;

    assert!(
        (after - clean).abs() < 1e-12,
        "an abstention wearing the fleet's provenance changed n_eff {clean} -> {after}"
    );
}

// ------------------------------------------------ third-pass audit regressions

/// A claim dated into the future computes its own age as zero, so its author's
/// assertion never decays — and that assertion alone keeps total evidence above
/// the decay floor, so the claim can never go stale either. One integer used to
/// buy a belief that outlived every piece of evidence in it: the identical
/// honestly-dated claim read `Decayed` at 0.5 while the future-dated one read
/// `Supported` at 0.99.
#[test]
fn a_future_dated_claim_is_not_in_effect() {
    let mut ledger = Ledger::new();
    proven(&mut ledger, 200, "ci");
    let now = T0 + HALF_LIFE * 3000;

    let mut zombie = claim_with(0.99);
    zombie.created_at = now + 10 * HALF_LIFE;
    let probes: Vec<_> = (1..=2)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&zombie))
        .collect();

    let r = resolve_at(&zombie, &probes, &ledger, now);
    assert_eq!(r.verdict.status, Status::Insufficient);
    assert_eq!(
        r.verdict.support, 0.0,
        "a claim from the future carries no weight"
    );
    assert!(r
        .excluded
        .iter()
        .any(|e| e.source == zombie.id && e.reason.contains("clock-skew")));

    // The honestly-dated twin, for contrast: this is what staleness looks like.
    let honest = claim_with(0.99);
    let hp: Vec<_> = (1..=2)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&honest))
        .collect();
    assert_eq!(
        resolve_at(&honest, &hp, &ledger, now).verdict.status,
        Status::Decayed
    );
}

/// Independence has to age with the evidence carrying it, or a probe from years
/// ago still clears `min_n_eff` today and the room keeps passing its own
/// freshness bar on witnesses that no longer say anything about the present.
#[test]
fn independence_ages_with_its_evidence() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=6)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    assert!(
        (resolve_at(&claim, &probes, &Ledger::new(), T0)
            .verdict
            .n_eff
            - 6.0)
            .abs()
            < 1e-9
    );

    let mut previous = 6.0;
    for k in 1..8 {
        let n = resolve_at(&claim, &probes, &Ledger::new(), T0 + HALF_LIFE * k)
            .verdict
            .n_eff;
        assert!(n < previous, "n_eff must fall with age: {previous} -> {n}");
        previous = n;
    }
    assert!(
        previous < 0.1,
        "stale witnesses stop counting, got {previous}"
    );
}

/// A half-life of a century decays imperceptibly, so the claim never reaches
/// the decay floor and never has to be re-checked — immortality without needing
/// to lie about the date.
#[test]
fn an_absurd_half_life_is_clamped_and_reported() {
    let mut forever = claim_with(0.99);
    forever.half_life = u64::MAX / 2;
    let mut ledger = Ledger::new();
    proven(&mut ledger, 200, "ci");
    let probes: Vec<_> = (1..=3)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&forever))
        .collect();

    let policy = open_policy();
    let far = T0 + policy.max_half_life * 60;
    let r = resolve(&forever, &probes, &[], &ledger, &policy, far);

    assert_eq!(r.verdict.status, Status::Decayed);
    assert!(
        r.excluded.iter().any(|e| e.reason.contains("clamped")),
        "the clamp must be visible"
    );
}

/// The verdict and the ledger have to be computed over the same evidence.
/// They were not: the roster and clock-skew filters lived inside `resolve`, so
/// an unadmitted key farmed reputation for attestations the room had explicitly
/// refused — and cashed it in the moment it was admitted.
#[test]
fn settlement_scores_only_what_the_verdict_counted() {
    let claim = a_claim();
    let mut probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();

    // An outsider, and a future-dated self-attestation by the claimant.
    probes.push(ProbeSpec::independent(9, Outcome::Holds).build(&claim));
    let mut ahead = ProbeSpec::independent(10, Outcome::Holds).build(&claim);
    ahead.attestor = claim.author;
    ahead.created_at = T0 + 100 * HALF_LIFE;
    probes.push(ahead);

    let policy = Policy {
        roster: (1..=4)
            .map(key)
            .chain([key(200)])
            .collect::<std::collections::BTreeSet<_>>()
            .into(),
        ..Policy::default()
    };
    let mut ledger = Ledger::new();
    let r = resolve(&claim, &probes, &[], &ledger, &policy, T0 + 60);
    assert_eq!(r.verdict.status, Status::Supported);
    assert_eq!(r.verdict.attestations, 4);
    assert_eq!(r.excluded.len(), 2);

    assert!(settle(
        &mut ledger,
        &claim,
        &probes,
        &[],
        &r.verdict,
        &policy
    ));

    assert_eq!(
        ledger.get(&key(9), "ci").evidence(),
        0.0,
        "an unadmitted key must not build a record on evidence the room refused"
    );
    // The author is scored for its claim, and for nothing else.
    let author = ledger.get(&key(200), "ci");
    // ln(0.8/0.5): the log-score of a truthful, correct p=0.8 forecast (the
    // claim's own declared confidence) against the coin-flip baseline. If the
    // future-dated self-attestation had *also* been scored, this would include
    // a second such term and be roughly double.
    let one_truthful_call = (0.8f64 / 0.5).ln();
    assert!(
        (author.evidence() - one_truthful_call).abs() < 1e-9,
        "the claimant inflated its own record with a future-dated self-attestation: \
         evidence was {}, expected exactly one scored call ({one_truthful_call})",
        author.evidence()
    );
    for n in 1..=4 {
        assert!(ledger.get(&key(n), "ci").evidence() > 0.0);
    }
}

/// A challenge from a key nobody admitted settles against nobody.
#[test]
fn an_unadmitted_challenger_is_not_scored() {
    let claim = a_claim();
    let probes: Vec<_> = (1..=4)
        .map(|n| ProbeSpec::independent(n, Outcome::Holds).build(&claim))
        .collect();
    let challenge = Challenge {
        id: id(90),
        challenger: key(90),
        created_at: T0,
        claim: claim.id,
        stake: 0.8,
        counter_falsifier: None,
        reason: "no".into(),
    };
    let policy = Policy {
        roster: (1..=4)
            .map(key)
            .chain([key(200)])
            .collect::<std::collections::BTreeSet<_>>()
            .into(),
        ..Policy::default()
    };

    let mut ledger = Ledger::new();
    let r = resolve(&claim, &probes, &[], &ledger, &policy, T0);
    settle(
        &mut ledger,
        &claim,
        &probes,
        std::slice::from_ref(&challenge),
        &r.verdict,
        &policy,
    );
    assert_eq!(ledger.get(&key(90), "ci").evidence(), 0.0);
}
