//! Redundancy discounting: turning a pile of attestations into a count of
//! *independent* ones.
//!
//! Every naive consensus mechanism computes something like "8 of 10 agents
//! agree". That number is only meaningful if the ten agents could have failed
//! independently, and in a Buzz channel they emphatically cannot: they are
//! frequently the same model, on the same runner, having read each other's
//! messages before answering. Counting them as ten is how a room manufactures
//! unanimous confidence in a false belief — and unlike a human meeting, it does
//! it in four seconds and writes it to the audit log.
//!
//! The discount here is deliberately simple enough to audit by hand. Walk the
//! evidence in the order the room learned it; each piece contributes only the
//! fraction of itself that everything already on the record does not explain.

use crucible_core::attestation::Provenance;
use crucible_core::PubKey;

/// One piece of evidence entering the pool.
#[derive(Clone, Debug)]
pub struct Contributor<'a> {
    /// The signing identity. Two entries from the same key are perfectly
    /// redundant, no matter what else differs: an agent cannot vote twice.
    pub key: PubKey,
    pub provenance: &'a Provenance,
    /// Non-negative strength, already decayed for age.
    pub weight: f64,
    /// `+1` supports, `-1` refutes, `0` abstains.
    pub sign: f64,
}

/// What survived the discount, in the same order as the input.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Discounted {
    /// Fraction of this contributor that is genuinely new information, in
    /// `[0, 1]`. This is the honest answer to "how many agents actually
    /// checked?", and the gap between it and 1.0 is the herding.
    pub novelty: f64,
    /// `weight * novelty`, signed. What actually moves belief.
    pub effective: f64,
}

/// Correlation between two contributors, in `[0, 1]`.
fn correlation(a: &Contributor, b: &Contributor) -> f64 {
    if a.key == b.key {
        // Self-agreement is not evidence. Without this, the cheapest attack on
        // the substrate is a `for` loop.
        1.0
    } else {
        a.provenance.similarity(b.provenance)
    }
}

/// Discount a pool of evidence for redundancy.
///
/// Contributors are consumed **in the order given**, which must be the order the
/// room learned them: the claim first, then attestations by timestamp. Each one
/// is scaled by `1 - max correlation with anything already on the record`, so a
/// genuinely independent probe counts in full while the tenth clone of the first
/// adds almost nothing.
///
/// Chronological order rather than strongest-first is a deliberate choice, and
/// the reason is monotonicity. If the pool were re-sorted by strength, a strong
/// late arrival could be admitted ahead of two earlier witnesses and explain
/// them both away, *lowering* the independent count — which would hand an
/// adversary a way to demote a settled claim by adding evidence to it. Ordering
/// by arrival makes the record append-only: nothing already counted can be
/// devalued by what comes later, and "novelty" reads as what it says — how much
/// this adds to what the room already had.
///
/// Using the maximum correlation rather than, say, a sum keeps the result
/// bounded and interpretable: a contributor is discounted by its single closest
/// predecessor, the one that most plausibly explains it away.
pub fn discount(contributors: &[Contributor<'_>]) -> Vec<Discounted> {
    let mut out = Vec::with_capacity(contributors.len());
    for (i, c) in contributors.iter().enumerate() {
        let redundancy = contributors[..i]
            .iter()
            // Only evidence can explain evidence away. An abstention contributes
            // nothing to belief, so letting it absorb a later attestor's novelty
            // would be a free suppression primitive: publish one indeterminate
            // probe wearing the provenance of an honest fleet, and the whole
            // fleet's independent count collapses.
            .filter(|earlier| earlier.sign != 0.0)
            .map(|earlier| correlation(c, earlier))
            .fold(0.0f64, f64::max);
        let novelty = (1.0 - redundancy).clamp(0.0, 1.0);
        out.push(Discounted {
            novelty,
            effective: c.weight * novelty * c.sign,
        });
    }
    out
}

/// Effective number of independent contributors: the sum of novelties over
/// evidence that actually took a side.
///
/// This is the number to show a human. "Twelve attestations, n_eff 1.4" says
/// everything about a room that has been talking to itself.
pub fn effective_count(contributors: &[Contributor<'_>], discounted: &[Discounted]) -> f64 {
    contributors
        .iter()
        .zip(discounted)
        .filter(|(c, _)| c.sign != 0.0)
        .map(|(_, d)| d.novelty)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov(lineage: &str, env: &str, blind: bool) -> Provenance {
        Provenance {
            lineage: lineage.into(),
            env: env.into(),
            blind,
        }
    }

    fn contrib<'a>(n: u8, p: &'a Provenance, weight: f64, sign: f64) -> Contributor<'a> {
        Contributor {
            key: PubKey::from_bytes([n; 32]),
            provenance: p,
            weight,
            sign,
        }
    }

    #[test]
    fn a_lone_contributor_counts_in_full() {
        let p = prov("m", "e", true);
        let c = [contrib(1, &p, 2.0, 1.0)];
        let d = discount(&c);
        assert_eq!(d[0].novelty, 1.0);
        assert_eq!(d[0].effective, 2.0);
        assert_eq!(effective_count(&c, &d), 1.0);
    }

    /// The attack the whole module exists to stop: one agent, many messages.
    #[test]
    fn one_agent_cannot_vote_twice() {
        let p = prov("m", "e", true);
        let spam: Vec<_> = (0..50).map(|_| contrib(1, &p, 2.0, 1.0)).collect();
        let d = discount(&spam);
        let total: f64 = d.iter().map(|x| x.effective).sum();
        assert_eq!(total, 2.0, "50 self-attestations must be worth exactly one");
        assert_eq!(effective_count(&spam, &d), 1.0);
    }

    #[test]
    fn independent_contributors_add_up() {
        let a = prov("claude", "linux", true);
        let b = prov("goose", "darwin", true);
        let c = prov("human", "macbook", true);
        let pool = [
            contrib(1, &a, 1.0, 1.0),
            contrib(2, &b, 1.0, 1.0),
            contrib(3, &c, 1.0, 1.0),
        ];
        let d = discount(&pool);
        assert_eq!(effective_count(&pool, &d), 3.0);
        assert_eq!(d.iter().map(|x| x.effective).sum::<f64>(), 3.0);
    }

    #[test]
    fn near_clones_are_heavily_discounted() {
        let p = prov("claude-opus-5", "runner-7", false);
        let pool: Vec<_> = (1..=10).map(|i| contrib(i, &p, 1.0, 1.0)).collect();
        let d = discount(&pool);
        let n_eff = effective_count(&pool, &d);
        assert!(
            n_eff < 2.5,
            "ten same-model, same-runner, non-blind agents must not look like ten, got {n_eff}"
        );
        assert!(n_eff > 1.0, "they are not literally one agent either");
    }

    /// The append-only property. Whatever arrives later, what the room already
    /// counted keeps its value — so adding evidence can never demote a claim by
    /// making its existing witnesses look redundant.
    #[test]
    fn later_evidence_never_devalues_earlier_evidence() {
        let a = prov("claude", "linux", true);
        let b = prov("goose", "darwin", true);
        // A strong arrival correlated with both of the earlier two.
        let umbrella = prov("claude", "darwin", false);

        let two = [contrib(1, &a, 1.0, 1.0), contrib(2, &b, 1.0, 1.0)];
        let before = discount(&two);

        let three = [
            contrib(1, &a, 1.0, 1.0),
            contrib(2, &b, 1.0, 1.0),
            contrib(3, &umbrella, 9.0, 1.0),
        ];
        let after = discount(&three);

        assert_eq!(before[0], after[0]);
        assert_eq!(before[1], after[1]);
        assert!(after[2].novelty < 0.5, "the latecomer is largely redundant");
    }

    /// A zero-evidence attestation must not be able to devalue real ones.
    /// Publishing one is free and unscored, so if it could soak novelty it
    /// would be the cheapest attack in the system — and it would target other
    /// people's *true* claims.
    #[test]
    fn an_abstention_cannot_suppress_later_evidence() {
        let shared = prov("ci-runner-v3", "gha-ubuntu", true);
        let honest: Vec<_> = (2..=6).map(|i| contrib(i, &shared, 1.0, 1.0)).collect();
        let clean = effective_count(&honest, &discount(&honest));

        let mut poisoned = vec![contrib(1, &shared, 1.0, 0.0)]; // indeterminate
        poisoned.extend(honest);
        let after = effective_count(&poisoned, &discount(&poisoned));

        assert_eq!(
            after, clean,
            "an abstention wearing the fleet's provenance must change nothing"
        );
    }

    #[test]
    fn abstentions_do_not_count_toward_independence() {
        let a = prov("claude", "linux", true);
        let b = prov("goose", "darwin", true);
        let pool = [contrib(1, &a, 1.0, 1.0), contrib(2, &b, 1.0, 0.0)];
        let d = discount(&pool);
        assert_eq!(d[1].effective, 0.0);
        assert_eq!(
            effective_count(&pool, &d),
            1.0,
            "an indeterminate probe is not an independent opinion"
        );
    }

    #[test]
    fn adding_evidence_never_reduces_independence() {
        let provs: Vec<_> = (0..8)
            .map(|i| prov(&format!("m{}", i % 3), &format!("e{}", i % 2), i % 2 == 0))
            .collect();
        let mut pool: Vec<Contributor> = vec![];
        let mut last = 0.0;
        for (i, p) in provs.iter().enumerate() {
            pool.push(contrib(i as u8 + 1, p, 1.0 + i as f64 * 0.1, 1.0));
            let d = discount(&pool);
            let n = effective_count(&pool, &d);
            assert!(n >= last - 1e-12, "n_eff went backwards: {last} -> {n}");
            last = n;
        }
    }

    #[test]
    fn novelty_and_effective_stay_bounded() {
        let a = prov("m", "e", false);
        let b = prov("m", "e", false);
        let pool = [contrib(1, &a, 3.0, 1.0), contrib(2, &b, 3.0, -1.0)];
        for d in discount(&pool) {
            assert!((0.0..=1.0).contains(&d.novelty));
            assert!(d.effective.abs() <= 3.0);
        }
    }

    #[test]
    fn empty_pool_is_not_a_panic() {
        let d = discount(&[]);
        assert!(d.is_empty());
        assert_eq!(effective_count(&[], &d), 0.0);
    }
}
