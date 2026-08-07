//! The calibration ledger: what an agent's word is worth, per domain, based on
//! what happened last time.
//!
//! Reliability here is earned, never configured. An agent joins a Buzz
//! community with no track record and a deliberately small voice; it grows one
//! by making claims that survive probing and shrinks it by making claims that
//! do not. Two properties matter and are both tested below:
//!
//! * **Confidence-weighted.** Being wrong at 0.99 costs far more than being
//!   wrong at 0.55. Otherwise the winning strategy is to assert everything
//!   loudly and apologise later, which is precisely the failure mode of an
//!   unsupervised agent swarm.
//! * **Domain-scoped.** An agent that reads build logs beautifully may be
//!   hopeless at judging schema migrations. One global "trust score" would let
//!   competence in the easy domain buy authority in the hard one.

use crucible_core::PubKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Prior pseudo-counts. Their mean is [`BOOTSTRAP`] and their total weight is
/// two observations, so a genuine track record overtakes the prior quickly
/// while an agent with no history still has a small, non-zero voice.
const PRIOR_ALPHA: f64 = 1.3;
const PRIOR_BETA: f64 = 0.7;

/// Reliability assumed of an agent nobody has scored yet.
pub const BOOTSTRAP: f64 = PRIOR_ALPHA / (PRIOR_ALPHA + PRIOR_BETA);

/// Reliability at or below this contributes no weight at all.
///
/// Note it is `0.5` and not something lower. A reliably *wrong* agent is
/// informative in principle — invert it — but a substrate that rewards
/// predictable wrongness invites an adversary to be wrong on purpose in order
/// to steer belief. Below chance, an agent is simply silenced.
pub const FLOOR: f64 = 0.5;

/// No single agent may ever be worth more than this, however long its streak.
/// Caps the log-odds any one voice can contribute at `ln(99) ≈ 4.6`.
pub const CEILING: f64 = 0.99;

/// Per-update memory factor. Roughly a 50-resolution half-life, so an agent
/// that degrades — a model swap, a broken tool — loses standing at a rate a
/// room will actually notice.
pub const RECENCY: f64 = 0.986;

/// One agent's record in one domain.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reliability {
    /// Decayed, confidence-weighted count of correct forecasts.
    pub alpha: f64,
    /// The same for incorrect ones.
    pub beta: f64,
    /// Decayed sum of Brier scores, and the matching count, for reporting.
    brier_sum: f64,
    log_sum: f64,
    observations: f64,
}

impl Default for Reliability {
    fn default() -> Self {
        Self {
            alpha: 0.0,
            beta: 0.0,
            brier_sum: 0.0,
            log_sum: 0.0,
            observations: 0.0,
        }
    }
}

impl Reliability {
    /// Posterior mean probability that this agent's next forecast in this
    /// domain is right.
    pub fn r(&self) -> f64 {
        (self.alpha + PRIOR_ALPHA) / (self.alpha + self.beta + PRIOR_ALPHA + PRIOR_BETA)
    }

    /// Evidence weight in log-odds — what this agent's attestation is worth.
    ///
    /// Zero for anyone at or below chance, capped at [`CEILING`] above.
    pub fn weight(&self) -> f64 {
        let r = self.r().clamp(FLOOR, CEILING);
        if r <= FLOOR {
            0.0
        } else {
            (r / (1.0 - r)).ln()
        }
    }

    /// Mean Brier score: `(forecast - outcome)²`, lower is better. An agent
    /// that always says 0.5 scores 0.25; anything worse than that is an agent
    /// whose confidence is actively misleading. `None` until it has forecast.
    pub fn brier(&self) -> Option<f64> {
        (self.observations > 0.0).then(|| self.brier_sum / self.observations)
    }

    /// Mean logarithmic score. Punishes confident errors far more sharply than
    /// Brier does, which is what makes it the honest measure of overclaiming.
    pub fn log_score(&self) -> Option<f64> {
        (self.observations > 0.0).then(|| self.log_sum / self.observations)
    }

    /// Total decayed evidence behind `r`. Small numbers mean "we are mostly
    /// still looking at the prior", and callers should say so.
    pub fn evidence(&self) -> f64 {
        self.alpha + self.beta
    }

    /// Score one resolved forecast.
    ///
    /// `forecast` is the probability the agent assigned to the claim being
    /// true; `truth` is what the kernel resolved. Both proper scoring rules are
    /// recorded, but only the confidence-weighted Beta update drives `r`.
    pub fn record(&mut self, forecast: f64, truth: bool) {
        // Keep the scoring rules finite without letting a clamp become a way to
        // assert certainty for free.
        let p = forecast.clamp(1e-4, 1.0 - 1e-4);
        let y = if truth { 1.0 } else { 0.0 };

        self.alpha *= RECENCY;
        self.beta *= RECENCY;
        self.brier_sum *= RECENCY;
        self.log_sum *= RECENCY;
        self.observations *= RECENCY;

        // How much the agent committed. A forecast of exactly 0.5 stakes
        // nothing and therefore moves nothing.
        let commitment = (2.0 * p - 1.0).abs();
        if (p > 0.5) == truth {
            self.alpha += commitment;
        } else {
            self.beta += commitment;
        }

        self.brier_sum += (p - y).powi(2);
        self.log_sum += -(if truth { p } else { 1.0 - p }).ln();
        self.observations += 1.0;
    }
}

/// Reliability for every agent, in every domain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    entries: HashMap<String, Reliability>,
}

fn key(agent: &PubKey, domain: &str) -> String {
    format!("{}/{}", agent.to_hex(), domain)
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// This agent's record in this domain, defaulting to the untested prior.
    pub fn get(&self, agent: &PubKey, domain: &str) -> Reliability {
        self.entries
            .get(&key(agent, domain))
            .copied()
            .unwrap_or_default()
    }

    /// Evidence weight for this agent in this domain.
    pub fn weight(&self, agent: &PubKey, domain: &str) -> f64 {
        self.get(agent, domain).weight()
    }

    /// Score a resolved forecast.
    pub fn record(&mut self, agent: &PubKey, domain: &str, forecast: f64, truth: bool) {
        self.entries
            .entry(key(agent, domain))
            .or_default()
            .record(forecast, truth);
    }

    /// Settle a challenge. A stake of `s` reads as a forecast that the claim is
    /// true with probability `(1 - s) / 2`: a bigger stake is a bolder bet, and
    /// a challenger who is bold and wrong pays for it on exactly the same
    /// scoring rule as an over-confident claimant.
    pub fn settle_challenge(&mut self, challenger: &PubKey, domain: &str, stake: f64, truth: bool) {
        let forecast = ((1.0 - stake.clamp(0.0, 1.0)) / 2.0).clamp(1e-4, 0.5 - 1e-4);
        self.record(challenger, domain, forecast, truth);
    }

    /// Every scored (agent, domain) pair, sorted for stable output.
    pub fn report(&self) -> Vec<(String, Reliability)> {
        let mut rows: Vec<_> = self
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> PubKey {
        PubKey::from_bytes([n; 32])
    }

    #[test]
    fn an_untested_agent_starts_at_the_bootstrap() {
        let r = Reliability::default();
        assert!((r.r() - BOOTSTRAP).abs() < 1e-12);
        assert!(r.weight() > 0.0, "a newcomer must have some voice");
        assert!(r.weight() < 1.0, "but not much of one");
        assert_eq!(r.brier(), None);
    }

    #[test]
    fn being_right_raises_reliability_and_being_wrong_lowers_it() {
        let mut good = Reliability::default();
        let mut bad = Reliability::default();
        for _ in 0..20 {
            good.record(0.9, true);
            bad.record(0.9, false);
        }
        assert!(good.r() > 0.9, "got {}", good.r());
        assert!(bad.r() < 0.2, "got {}", bad.r());
    }

    /// The core incentive: loud and wrong must cost more than quiet and wrong.
    #[test]
    fn confident_errors_cost_more_than_hedged_ones() {
        let mut loud = Reliability::default();
        let mut hedged = Reliability::default();
        for _ in 0..10 {
            loud.record(0.99, false);
            hedged.record(0.55, false);
        }
        assert!(
            loud.r() < hedged.r(),
            "loud {} should be punished below hedged {}",
            loud.r(),
            hedged.r()
        );
        assert!(loud.log_score().unwrap() > hedged.log_score().unwrap());
        assert!(loud.brier().unwrap() > hedged.brier().unwrap());
    }

    /// …and the mirror image: loud and right must pay better than hedged and
    /// right, or the dominant strategy becomes to never commit to anything.
    #[test]
    fn confident_correctness_pays_more_than_hedging() {
        let mut loud = Reliability::default();
        let mut hedged = Reliability::default();
        for _ in 0..10 {
            loud.record(0.95, true);
            hedged.record(0.55, true);
        }
        assert!(loud.r() > hedged.r());
    }

    #[test]
    fn a_coin_flip_forecast_moves_nothing() {
        let mut r = Reliability::default();
        let before = r.r();
        r.record(0.5, true);
        r.record(0.5, false);
        assert!((r.r() - before).abs() < 1e-12);
    }

    #[test]
    fn a_below_chance_agent_is_silenced_not_inverted() {
        let mut r = Reliability::default();
        for _ in 0..30 {
            r.record(0.95, false);
        }
        assert!(r.r() < FLOOR);
        assert_eq!(r.weight(), 0.0, "must be ignored, never read backwards");
    }

    #[test]
    fn no_agent_can_exceed_the_ceiling() {
        let mut r = Reliability::default();
        for _ in 0..10_000 {
            r.record(0.999, true);
        }
        assert!(r.weight() <= (CEILING / (1.0 - CEILING)).ln() + 1e-9);
        assert!(r.weight() > 4.0, "a proven agent should still be loud");
    }

    /// A once-good agent that breaks must lose standing, or a swapped-out model
    /// coasts forever on the previous one's record.
    #[test]
    fn recent_performance_outweighs_ancient_history() {
        let mut r = Reliability::default();
        for _ in 0..100 {
            r.record(0.95, true);
        }
        let peak = r.r();
        for _ in 0..60 {
            r.record(0.95, false);
        }
        assert!(r.r() < peak - 0.4, "decayed from {peak} to {}", r.r());
    }

    #[test]
    fn brier_beats_the_uninformative_baseline_only_when_skilled() {
        let mut skilled = Reliability::default();
        let mut noise = Reliability::default();
        for i in 0..20 {
            let truth = i % 2 == 0;
            skilled.record(if truth { 0.9 } else { 0.1 }, truth);
            noise.record(0.9, truth);
        }
        assert!(skilled.brier().unwrap() < 0.25, "skill must beat chance");
        assert!(noise.brier().unwrap() > 0.25, "noise must lose to chance");
    }

    #[test]
    fn domains_are_scored_independently() {
        let mut l = Ledger::new();
        let a = agent(1);
        for _ in 0..20 {
            l.record(&a, "ci", 0.95, true);
            l.record(&a, "security", 0.95, false);
        }
        assert!(l.weight(&a, "ci") > 2.0);
        assert_eq!(
            l.weight(&a, "security"),
            0.0,
            "competence in CI must not buy authority in security"
        );
        assert!(
            (l.get(&a, "perf").r() - BOOTSTRAP).abs() < 1e-12,
            "an unscored domain stays at the prior"
        );
    }

    #[test]
    fn agents_are_scored_independently() {
        let mut l = Ledger::new();
        for _ in 0..20 {
            l.record(&agent(1), "ci", 0.95, true);
        }
        assert!(l.weight(&agent(1), "ci") > 2.0);
        assert!((l.get(&agent(2), "ci").r() - BOOTSTRAP).abs() < 1e-12);
    }

    #[test]
    fn a_bold_wrong_challenge_costs_more_than_a_timid_one() {
        let mut l = Ledger::new();
        // The claim turned out to be true, so both challengers were wrong.
        l.settle_challenge(&agent(1), "ci", 0.9, true);
        l.settle_challenge(&agent(2), "ci", 0.1, true);
        assert!(
            l.get(&agent(1), "ci").r() < l.get(&agent(2), "ci").r(),
            "the bold wrong challenger must lose more standing"
        );
    }

    #[test]
    fn a_correct_challenge_is_rewarded() {
        let mut l = Ledger::new();
        let before = l.get(&agent(1), "ci").r();
        l.settle_challenge(&agent(1), "ci", 0.8, false); // claim refuted
        assert!(l.get(&agent(1), "ci").r() > before);
    }

    #[test]
    fn report_is_stable_and_sorted() {
        let mut l = Ledger::new();
        l.record(&agent(2), "ci", 0.9, true);
        l.record(&agent(1), "ci", 0.9, true);
        let rows = l.report();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].0 < rows[1].0);
        assert_eq!(l.report(), rows, "report must be deterministic");
    }

    /// The ledger is a snapshot, not the source of truth: it is always
    /// recomputable by replaying the relay's log through `settle`, which is how
    /// two replicas stay in agreement. Serialization therefore only has to
    /// preserve the numbers to floating-point precision, not bit-for-bit —
    /// replicas that need to agree exactly replay, they do not swap snapshots.
    #[test]
    fn ledger_survives_a_json_snapshot() {
        let mut l = Ledger::new();
        l.record(&agent(1), "ci", 0.9, true);
        l.record(&agent(2), "security", 0.7, false);
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();

        let (before, after) = (l.report(), back.report());
        assert_eq!(before.len(), after.len());
        for ((ka, va), (kb, vb)) in before.iter().zip(&after) {
            assert_eq!(ka, kb);
            assert!((va.r() - vb.r()).abs() < 1e-12);
            assert!((va.weight() - vb.weight()).abs() < 1e-12);
            assert!((va.evidence() - vb.evidence()).abs() < 1e-12);
        }
    }
}
