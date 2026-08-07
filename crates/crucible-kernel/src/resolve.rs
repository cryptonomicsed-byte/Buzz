//! The resolution kernel: evidence in, epistemic status out.
//!
//! Everything here is a pure function of the events the relay already holds
//! plus a clock reading. Two agents replaying the same Buzz log at the same
//! `now` derive byte-identical verdicts, which is what lets a verdict be
//! published as a signed event that anyone can recompute and dispute rather
//! than an authority's opinion that must be taken on trust.

use crate::calibration::Ledger;
use crate::independence::{discount, Contributor};
use crate::policy::Policy;
use crucible_core::attestation::Provenance;
use crucible_core::{
    Attestation, Challenge, Claim, EventId, Outcome, PubKey, Status, Timestamp, Verdict,
};
use serde::{Deserialize, Serialize};

/// Why a piece of evidence carried the weight it did. The room can ask "why do
/// you believe that?" and get an arithmetic answer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Contribution {
    pub source: EventId,
    pub author: PubKey,
    pub role: Role,
    pub outcome: Outcome,
    /// Reliability weight in log-odds, before decay and discounting.
    pub raw_weight: f64,
    /// Age multiplier from the claim's half-life.
    pub decay: f64,
    /// Fraction that was not already explained by evidence already on record.
    pub novelty: f64,
    /// Signed log-odds actually applied to belief.
    pub effective: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The author's own forecast, carried by the claim itself.
    Assertion,
    /// Somebody ran the falsifier.
    Probe,
}

/// Evidence the kernel refused, and why. Silent exclusion is how a substrate
/// loses the room's trust.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Exclusion {
    pub source: EventId,
    pub reason: String,
}

/// A verdict plus the full derivation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resolution {
    pub verdict: Verdict,
    pub contributions: Vec<Contribution>,
    pub excluded: Vec<Exclusion>,
    /// Distinct output digests seen for this claim's experiment. For a pure
    /// falsifier, more than one proves it is not a function of its inputs; for
    /// an observational one it simply records that the world looked different
    /// to different observers.
    pub output_digests: Vec<String>,
    /// Challenges outstanding against this claim. Visible, but not evidence.
    pub open_challenges: usize,
}

fn sigmoid(x: f64) -> f64 {
    // Branch on sign so neither `exp` overflows; both branches are exact at 0.
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

/// Keep one attestation per attestor — the most recent — so an agent expresses
/// a current position rather than a voting bloc, and return them in the order
/// the room learned them.
fn latest_per_attestor(attestations: &[Attestation]) -> Vec<&Attestation> {
    let mut best: Vec<&Attestation> = Vec::new();
    for a in attestations {
        match best.iter_mut().find(|b| b.attestor == a.attestor) {
            Some(slot) => {
                let newer = (a.created_at, a.id.as_bytes()) > (slot.created_at, slot.id.as_bytes());
                if newer {
                    *slot = a;
                }
            }
            None => best.push(a),
        }
    }
    // Chronological, with the event id breaking ties, so every replica walks the
    // evidence in the same order regardless of the order the relay served it.
    best.sort_by_key(|a| (a.created_at, *a.id.as_bytes()));
    best
}

/// Resolve a claim against everything known about it.
///
/// `now` is supplied rather than read so that replaying history reproduces the
/// verdicts history actually saw.
pub fn resolve(
    claim: &Claim,
    attestations: &[Attestation],
    challenges: &[Challenge],
    ledger: &Ledger,
    policy: &Policy,
    now: Timestamp,
) -> Resolution {
    let mut excluded = Vec::new();

    // 1. Discard evidence that is about a different question. An attestation
    //    against a different module, manifest or inputs answers a different
    //    experiment, and pooling it would be the substrate lying to itself.
    let mut relevant: Vec<Attestation> = Vec::with_capacity(attestations.len());
    let horizon = now.saturating_add(policy.max_clock_skew);
    for a in attestations {
        let refusal = if let Err(e) = a.check_matches(claim) {
            Some(e.to_string())
        } else if !policy.admits(&a.attestor) {
            // Not a member of this community. The one defence against an
            // operator minting keys is that somebody had to admit them.
            Some(format!(
                "attestor {} is not on this community's roster",
                a.attestor
            ))
        } else if a.created_at > horizon {
            // Age drives decay, and `created_at` is self-declared. An event
            // dated past the horizon would otherwise never age at all.
            Some(format!(
                "dated {}s beyond now, past the {}s clock-skew bound",
                a.created_at - now,
                policy.max_clock_skew
            ))
        } else {
            None
        };

        match refusal {
            None => relevant.push(a.clone()),
            Some(reason) => excluded.push(Exclusion {
                source: a.id,
                reason,
            }),
        }
    }
    // Bound the quadratic stage. Oldest-first, so the cap drops the newest
    // arrivals rather than letting a flood evict the record.
    relevant.sort_by_key(|a| (a.created_at, *a.id.as_bytes()));
    if relevant.len() > policy.max_attestations {
        for a in &relevant[policy.max_attestations..] {
            excluded.push(Exclusion {
                source: a.id,
                reason: format!("beyond this community's cap of {}", policy.max_attestations),
            });
        }
        relevant.truncate(policy.max_attestations);
    }
    let deduped: Vec<Attestation> = latest_per_attestor(&relevant)
        .into_iter()
        .cloned()
        .collect();

    // 2. Collect the distinct outputs the room saw. What this means depends on
    //    whether the falsifier claimed purity; see `decide`.
    let mut tally: std::collections::BTreeMap<String, usize> = Default::default();
    for a in deduped
        .iter()
        .filter(|a| a.outcome != Outcome::Indeterminate)
    {
        *tally.entry(hex::encode(a.output_digest)).or_default() += 1;
    }
    let digests: Vec<String> = tally.keys().cloned().collect();
    // How many attestors backed the *second* most popular output. One agent
    // reporting an odd digest is far more likely to be broken or lying than the
    // claim is to be broken, and a self-reported digest is free to fabricate —
    // so a single voice must not be able to condemn a claim to a status that
    // never resolves and never scores anyone.
    let mut backing: Vec<usize> = tally.values().copied().collect();
    backing.sort_unstable_by(|a, b| b.cmp(a));
    let minority_digest_backing = backing.get(1).copied().unwrap_or(0);

    let age_of = |t: Timestamp| now.saturating_sub(t);

    // 3. The author's own forecast is evidence, bounded by both their track
    //    record and the confidence they were willing to state. An unproven agent
    //    shouting 0.99 moves belief no further than its record allows; a proven
    //    one hedging at 0.6 moves it no further than its hedge allows.
    let odds = (claim.confidence / (1.0 - claim.confidence)).ln();
    // An author off the roster, or writing in a domain the community does not
    // recognise, gets no evidentiary weight of its own. The claim still stands
    // and can still be probed — what it cannot do is lend itself credibility.
    let author_admitted = policy.admits(&claim.author) && policy.recognises(&claim.domain);
    let author_weight = if author_admitted {
        odds.abs().min(ledger.weight(&claim.author, &claim.domain))
    } else {
        0.0
    };
    let author_decay = claim.decay(age_of(claim.created_at));

    struct Row<'a> {
        source: EventId,
        author: PubKey,
        role: Role,
        outcome: Outcome,
        raw: f64,
        decay: f64,
        sign: f64,
        provenance: &'a Provenance,
    }

    let mut rows = vec![Row {
        source: claim.id,
        author: claim.author,
        role: Role::Assertion,
        outcome: if odds >= 0.0 {
            Outcome::Holds
        } else {
            Outcome::Fails
        },
        raw: author_weight,
        decay: author_decay,
        sign: if odds >= 0.0 { 1.0 } else { -1.0 },
        provenance: &claim.provenance,
    }];

    for a in &deduped {
        rows.push(Row {
            source: a.id,
            author: a.attestor,
            role: Role::Probe,
            outcome: a.outcome,
            raw: ledger.weight(&a.attestor, &claim.domain),
            decay: claim.decay(age_of(a.created_at)),
            sign: a.outcome.sign(),
            provenance: &a.provenance,
        });
    }

    let contributors: Vec<Contributor> = rows
        .iter()
        .map(|r| Contributor {
            key: r.author,
            provenance: r.provenance,
            weight: r.raw * r.decay,
            sign: r.sign,
        })
        .collect();

    let discounted = discount(&contributors);

    let contributions: Vec<Contribution> = rows
        .iter()
        .zip(&discounted)
        .map(|(r, d)| Contribution {
            source: r.source,
            author: r.author,
            role: r.role,
            outcome: r.outcome,
            raw_weight: r.raw,
            decay: r.decay,
            novelty: d.novelty,
            effective: d.effective,
        })
        .collect();

    let support: f64 = contributions
        .iter()
        .filter(|c| c.effective > 0.0)
        .map(|c| c.effective)
        .sum();
    let opposition: f64 = -contributions
        .iter()
        .filter(|c| c.effective < 0.0)
        .map(|c| c.effective)
        .sum::<f64>();

    // Conflict is measured over probes alone. The author's own forecast is not
    // a witness, and letting it count as one side of a controversy would mean a
    // confident claimant could manufacture "Contested" simply by asserting
    // against the evidence.
    let probe_support: f64 = contributions
        .iter()
        .filter(|c| c.role == Role::Probe && c.effective > 0.0)
        .map(|c| c.effective)
        .sum();
    let probe_opposition: f64 = -contributions
        .iter()
        .filter(|c| c.role == Role::Probe && c.effective < 0.0)
        .map(|c| c.effective)
        .sum::<f64>();

    // Only probes count toward independence. The author asserting is not
    // somebody checking, however trusted the author is.
    let n_eff: f64 = contributions
        .iter()
        .filter(|c| c.role == Role::Probe && c.outcome != Outcome::Indeterminate)
        .map(|c| c.novelty)
        .sum();

    // Adding zero normalises a negative zero, which is arithmetically fine and
    // reads as a bug in a report.
    let n_eff = n_eff + 0.0;
    let log_odds = support - opposition;
    let mass = sigmoid(log_odds);

    let status = decide(
        claim,
        policy,
        now,
        &digests,
        minority_digest_backing,
        deduped.len(),
        support + opposition,
        probe_support,
        probe_opposition,
        n_eff,
        mass,
    );

    // 4. Challenges are recorded but deliberately move no belief on their own.
    //    A challenge is a bet, not a measurement; it earns its influence by
    //    provoking probes, and it settles against the ledger once the claim
    //    resolves. Letting doubt move belief directly would make scepticism a
    //    free way to suppress true claims.
    let open_challenges = challenges.iter().filter(|c| c.claim == claim.id).count();

    Resolution {
        open_challenges,
        verdict: Verdict {
            claim: claim.id,
            status,
            mass,
            n_eff,
            support,
            opposition,
            attestations: deduped.len(),
            computed_at: now,
        },
        contributions,
        excluded,
        output_digests: digests,
    }
}

#[allow(clippy::too_many_arguments)]
fn decide(
    claim: &Claim,
    policy: &Policy,
    now: Timestamp,
    digests: &[String],
    minority_digest_backing: usize,
    probe_count: usize,
    total_evidence: f64,
    probe_support: f64,
    probe_opposition: f64,
    n_eff: f64,
    mass: f64,
) -> Status {
    // A broken experiment outranks everything: until the falsifier is a
    // function of its inputs, every other number computed from it is
    // meaningless. This applies only to *pure* falsifiers — one that reads the
    // world is supposed to return different things when the world differs, and
    // flagging that as a defect would condemn every probe worth running.
    if claim.falsifier.pure && digests.len() > 1 && minority_digest_backing >= 2 {
        return Status::Nondeterministic;
    }
    if claim.is_expired(now) {
        return Status::Decayed;
    }
    // Evidence that once existed and has since aged out is stale, not absent —
    // and the difference tells an agent whether to re-probe or to start fresh.
    if probe_count > 0 && total_evidence < policy.decay_floor {
        return Status::Decayed;
    }
    if n_eff < policy.min_n_eff {
        return Status::Insufficient;
    }

    let (weak, strong) = if probe_support < probe_opposition {
        (probe_support, probe_opposition)
    } else {
        (probe_opposition, probe_support)
    };
    if weak >= policy.conflict_floor && weak >= strong * policy.conflict_ratio {
        return Status::Contested;
    }

    if mass >= policy.support_threshold {
        Status::Supported
    } else if mass <= policy.refute_threshold {
        Status::Refuted
    } else {
        Status::Insufficient
    }
}

/// Fold a resolved claim into the calibration ledger.
///
/// Only `Supported` and `Refuted` score anyone. Docking an agent because the
/// room never got round to probing its claim would teach it to claim less,
/// which is the opposite of what the substrate wants.
pub fn settle(
    ledger: &mut Ledger,
    claim: &Claim,
    attestations: &[Attestation],
    challenges: &[Challenge],
    verdict: &Verdict,
) -> bool {
    if !verdict.status.is_resolved() {
        return false;
    }
    // Exactly once, ever. A resolver runs on a timer over the same log, so
    // without this every tick pays every agent again for the same claim and
    // reputation becomes a measure of how often somebody pressed the button.
    if !ledger.mark_settled(&claim.id) {
        return false;
    }
    let truth = verdict.status == Status::Supported;
    let at = verdict.computed_at;

    ledger.record(&claim.author, &claim.domain, claim.confidence, truth, at);

    for a in latest_per_attestor(attestations) {
        // A probe is a categorical call, scored at the confidence a categorical
        // call implies. Indeterminate results are not forecasts and are not
        // scored — punishing an honest "I could not tell" would train agents to
        // guess instead.
        let forecast = match a.outcome {
            Outcome::Holds => 0.9,
            Outcome::Fails => 0.1,
            Outcome::Indeterminate => continue,
        };
        ledger.record(&a.attestor, &claim.domain, forecast, truth, at);
    }

    for c in challenges {
        if c.claim == claim.id {
            ledger.settle_challenge(&c.challenger, &claim.domain, c.stake, truth, at);
        }
    }
    true
}
