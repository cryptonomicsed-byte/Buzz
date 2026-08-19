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
//! The discount is a running [effective sample size](https://en.wikipedia.org/wiki/Design_effect)
//! under correlation, in the sense a statistician means it: for `n`
//! equal-weight, equicorrelated witnesses at correlation `ρ`, the classic
//! result is `n_eff = n / (1 + (n-1)ρ)`, which climbs toward `1/ρ` and never
//! past it. Twenty clones at `ρ=0.8` are worth `1.25` witnesses in the limit,
//! not twenty, and not the linearly-growing number an earlier version of this
//! module produced by discounting each newcomer only against its single
//! closest predecessor.
//!
//! Evidence is still walked in the order the room learned it, and each item's
//! credit is still fixed the moment it is processed — nothing arriving later
//! can revise it. That is what makes an append-only replay safe: a verdict a
//! room already trusts cannot be demoted by evidence added after the fact.

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
/// room learned them: the claim first, then attestations by timestamp.
///
/// For each new contributor `c` joining an already-admitted set `S`, this
/// computes the *marginal* effective sample size it adds:
///
/// ```text
/// kish(S) = |S|² / Σ_{i,j∈S} ρ(i,j)          (ρ(i,i) = 1)
/// novelty(c) = max(0, kish(S ∪ {c}) − kish(S))
/// ```
///
/// `kish` is the standard weighted design-effect formula (all correlation
/// weights here are 1, since novelty is meant to measure "how much of a
/// distinct witness is this" independent of how reliable that witness is —
/// reliability is folded in afterward, in `effective`). Two properties fall
/// out of the definition and both are load-bearing:
///
/// * **Bounded.** For a cluster of `n` witnesses pairwise correlated at `ρ`,
///   `kish` evaluates to exactly `n/(1+(n-1)ρ)`, which is the textbook
///   effective-sample-size result and converges to `1/ρ` as the cluster grows
///   — it does not grow without limit the way discounting each newcomer only
///   against its nearest predecessor does.
/// * **Monotonic.** `kish` can, in principle, *fall* when a new item is highly
///   correlated with a *mix* of earlier, less-correlated items (the global
///   recomputation dilutes their combined signal). Flooring the marginal at
///   zero is what turns that into "this item added nothing" rather than "the
///   room now believes less than it did a moment ago" — a verdict already
///   reached must never be worth less because more evidence arrived.
///
/// Only evidence can explain evidence away: an abstention (`sign == 0`)
/// contributes nothing to belief, so it is excluded from `S` entirely and
/// cannot make anyone else look redundant. Publishing a free, unscored
/// indeterminate probe wearing an honest fleet's declared provenance must not
/// collapse that fleet's independent count.
pub fn discount(contributors: &[Contributor<'_>]) -> Vec<Discounted> {
    let mut out = vec![
        Discounted {
            novelty: 0.0,
            effective: 0.0
        };
        contributors.len()
    ];

    // `pair_sum` is Σ_{i,j∈S} ρ(i,j) over the admitted pool `S` built so far;
    // `kish_prev` is kish(S) after the previous admission, so each step's
    // marginal is a single subtraction rather than a full recomputation.
    let mut admitted: Vec<usize> = Vec::with_capacity(contributors.len());
    let mut pair_sum = 0.0f64;
    let mut kish_prev = 0.0f64;

    for (i, c) in contributors.iter().enumerate() {
        if c.sign == 0.0 {
            continue; // stays at the default: novelty 0, effective 0
        }
        let cross: f64 = admitted
            .iter()
            .map(|&j| correlation(c, &contributors[j]))
            .sum();
        // Adding one member to S changes Σρ by twice its cross terms (ρ is
        // symmetric) plus its own self-correlation of 1.
        pair_sum += 2.0 * cross + 1.0;
        let k = (admitted.len() + 1) as f64;
        let kish = k * k / pair_sum;
        let novelty = (kish - kish_prev).max(0.0);
        kish_prev = kish;

        out[i] = Discounted {
            novelty,
            effective: c.weight * novelty * c.sign,
        };
        admitted.push(i);
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
            n_eff < 1.2,
            "ten same-model, same-runner, non-blind agents must not look like ten, got {n_eff}"
        );
        assert!(n_eff > 1.0, "they are not literally one agent either");
    }

    /// The exact scenario an adversarial review measured against the previous
    /// (unbounded) algorithm: twenty containers of one model, twenty distinct
    /// environments, run blind of each other. `lineage` matches (ρ contribution
    /// 0.80) but `env` differs and nobody is herding, so `ρ = 0.80` and the
    /// textbook effective-sample-size ceiling is `1/ρ = 1.25`. The old
    /// algorithm read this as `n_eff ≈ 4.8` — seventeen times the honest count —
    /// and called it `Supported` at mass 0.97.
    #[test]
    fn twenty_containers_of_one_model_are_bounded_near_the_textbook_ceiling() {
        let pool: Vec<_> = (1..=20)
            .map(|i| {
                let env = prov("claude-opus-5", &format!("container-{i}"), true);
                Contributor {
                    key: PubKey::from_bytes([i; 32]),
                    provenance: Box::leak(Box::new(env)),
                    weight: 1.0,
                    sign: 1.0,
                }
            })
            .collect();
        let n_eff = effective_count(&pool, &discount(&pool));
        assert!(
            (n_eff - 1.235).abs() < 0.01,
            "expected the design-effect value for n=20, ρ=0.8 (≈1.235), got {n_eff}"
        );
        assert!(
            n_eff < 1.25 + 1e-9,
            "must never exceed the 1/ρ ceiling, got {n_eff}"
        );
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

    /// The floor at zero that makes bounding safe: a global recomputation of
    /// `kish` can otherwise fall when a new item is correlated with a mix of
    /// earlier witnesses, and letting that show up as negative marginal would
    /// mean a verdict gets *worse* evidence behind it purely because more
    /// evidence arrived.
    #[test]
    fn a_marginal_that_would_be_negative_is_floored_not_subtracted() {
        let a = prov("claude", "linux", true);
        let b = prov("goose", "darwin", true);
        let independent = [contrib(1, &a, 1.0, 1.0), contrib(2, &b, 1.0, 1.0)];
        let before = effective_count(&independent, &discount(&independent));
        assert_eq!(before, 2.0);

        // A third witness correlated with both — a raw (unfloored) Kish
        // recomputation here would put the three-item total *below* 2.0.
        let clone_of_a = prov("claude", "linux", true);
        let mut three = independent.to_vec();
        three.push(contrib(3, &clone_of_a, 1.0, 1.0));
        let after = effective_count(&three, &discount(&three));
        assert!(
            after >= before - 1e-9,
            "adding evidence must never lower the total: {before} -> {after}"
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
