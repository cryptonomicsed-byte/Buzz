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

use crucible_core::{EventId, PubKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

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

/// How long it takes a track record to lose half its weight.
///
/// Measured in *time*, not in updates. A per-update decay is the same thing as
/// a laundering machine: an agent caught being confidently wrong could bury the
/// evidence under three hundred trivially-true self-dealt claims in a second,
/// because each one aged the history by another notch. Wall-clock decay means
/// rehabilitation takes a month of being right, which is what "recent
/// performance" was supposed to mean in the first place.
pub const RECENCY_HALF_LIFE: Timestamp = 30 * 86_400;

/// Ceiling on decayed evidence in either direction.
///
/// Without it, volume beats truth: enough easy wins outweigh any number of
/// hard failures, so the optimal strategy is to farm trivially-true claims and
/// spend the reputation on one lie. Capped, a caught agent cannot buy its way
/// back past the middle of the range no matter how much noise it generates.
pub const MAX_EVIDENCE: f64 = 50.0;

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
    /// When this record was last touched, for time-based decay. Zero means
    /// never.
    #[serde(default)]
    last_update: Timestamp,
}

impl Default for Reliability {
    fn default() -> Self {
        Self {
            alpha: 0.0,
            beta: 0.0,
            brier_sum: 0.0,
            log_sum: 0.0,
            observations: 0.0,
            last_update: 0,
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

    /// Age this record forward to `now`.
    fn age_to(&mut self, now: Timestamp) {
        if self.last_update == 0 {
            self.last_update = now;
            return;
        }
        // Settlement can arrive out of order; never age backwards.
        let elapsed = now.saturating_sub(self.last_update);
        if elapsed > 0 {
            let f = (-(elapsed as f64) / RECENCY_HALF_LIFE as f64).exp2();
            self.alpha *= f;
            self.beta *= f;
            self.brier_sum *= f;
            self.log_sum *= f;
            self.observations *= f;
            self.last_update = now;
        }
    }

    /// Score one resolved forecast, as of `now`.
    ///
    /// `forecast` is the probability the agent assigned to the claim being
    /// true; `truth` is what the kernel resolved.
    ///
    /// The update is a confidence-weighted Beta posterior, and it is worth
    /// being precise about what that is and is not. It has the two properties
    /// the substrate needs — a confident error costs more than a hedged one,
    /// and a confident success pays more — but it is *not* a proper scoring
    /// rule in the technical sense, and reporting one's honest belief is not
    /// always its argmax. The Brier and logarithmic scores alongside it are
    /// genuinely proper and are what a room should read when judging whether an
    /// agent's confidence means anything; they are reported, not used to drive
    /// weight. Closing that gap needs a scoring rule whose optimum is
    /// independent of the agent's current standing, and this is not one.
    pub fn record(&mut self, forecast: f64, truth: bool, now: Timestamp) {
        // Keep the scoring rules finite without letting a clamp become a way to
        // assert certainty for free.
        let p = forecast.clamp(1e-4, 1.0 - 1e-4);
        let y = if truth { 1.0 } else { 0.0 };

        self.age_to(now);

        // How much the agent committed. A forecast of exactly 0.5 stakes
        // nothing and therefore moves nothing.
        let commitment = (2.0 * p - 1.0).abs();
        if (p > 0.5) == truth {
            self.alpha = (self.alpha + commitment).min(MAX_EVIDENCE);
        } else {
            self.beta = (self.beta + commitment).min(MAX_EVIDENCE);
        }

        self.brier_sum += (p - y).powi(2);
        self.log_sum += -(if truth { p } else { 1.0 - p }).ln();
        self.observations += 1.0;
    }
}

/// Reliability for every agent, in every domain.
/// `serde(default)` throughout, so `{}` deserializes as an empty ledger — the
/// natural thing for a caller with no prior state to send.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Ledger {
    entries: HashMap<String, Reliability>,
    /// Claims already folded in. Settlement must be idempotent: without this,
    /// re-running a resolver over the same log — which a room will do on every
    /// tick — pays every agent again for the same claim, and reputation becomes
    /// a function of how often somebody pressed the button.
    #[serde(default)]
    settled: BTreeSet<String>,
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
    pub fn record(
        &mut self,
        agent: &PubKey,
        domain: &str,
        forecast: f64,
        truth: bool,
        now: Timestamp,
    ) {
        self.entries
            .entry(key(agent, domain))
            .or_default()
            .record(forecast, truth, now);
    }

    /// Claim this settlement, returning `false` if it already happened.
    pub fn mark_settled(&mut self, claim: &EventId) -> bool {
        self.settled.insert(claim.to_hex())
    }

    pub fn is_settled(&self, claim: &EventId) -> bool {
        self.settled.contains(&claim.to_hex())
    }

    pub fn settled_count(&self) -> usize {
        self.settled.len()
    }

    /// Settle a challenge. A stake of `s` reads as a forecast that the claim is
    /// true with probability `(1 - s) / 2`: a bigger stake is a bolder bet, and
    /// a challenger who is bold and wrong pays for it on exactly the same
    /// scoring rule as an over-confident claimant.
    pub fn settle_challenge(
        &mut self,
        challenger: &PubKey,
        domain: &str,
        stake: f64,
        truth: bool,
        now: Timestamp,
    ) {
        let forecast = ((1.0 - stake.clamp(0.0, 1.0)) / 2.0).clamp(1e-4, 0.5 - 1e-4);
        self.record(challenger, domain, forecast, truth, now);
    }

    /// Every scored (agent, domain) pair, sorted for stable output.
    pub fn report(&self) -> Vec<(String, Reliability)> {
        let mut rows: Vec<_> = self.entries.iter().map(|(k, v)| (k.clone(), *v)).collect();
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

    const T: Timestamp = 1_700_000_000;
    const DAY: Timestamp = 86_400;

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
            good.record(0.9, true, T);
            bad.record(0.9, false, T);
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
            loud.record(0.99, false, T);
            hedged.record(0.55, false, T);
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
            loud.record(0.95, true, T);
            hedged.record(0.55, true, T);
        }
        assert!(loud.r() > hedged.r());
    }

    #[test]
    fn a_coin_flip_forecast_moves_nothing() {
        let mut r = Reliability::default();
        let before = r.r();
        r.record(0.5, true, T);
        r.record(0.5, false, T);
        assert!((r.r() - before).abs() < 1e-12);
    }

    #[test]
    fn a_below_chance_agent_is_silenced_not_inverted() {
        let mut r = Reliability::default();
        for _ in 0..30 {
            r.record(0.95, false, T);
        }
        assert!(r.r() < FLOOR);
        assert_eq!(r.weight(), 0.0, "must be ignored, never read backwards");
    }

    #[test]
    fn no_agent_can_exceed_the_ceiling() {
        let mut r = Reliability::default();
        for _ in 0..10_000 {
            r.record(0.999, true, T);
        }
        assert!(r.weight() <= (CEILING / (1.0 - CEILING)).ln() + 1e-9);
        assert!(r.weight() > 4.0, "a proven agent should still be loud");
    }

    /// A once-good agent that breaks must lose standing, or a swapped-out model
    /// coasts forever on the previous one's record.
    #[test]
    fn recent_performance_outweighs_ancient_history() {
        let mut r = Reliability::default();
        for i in 0..100 {
            r.record(0.95, true, T + i * DAY);
        }
        let peak = r.r();
        for i in 0..60 {
            r.record(0.95, false, T + (100 + i) * DAY);
        }
        assert!(r.r() < peak - 0.4, "decayed from {peak} to {}", r.r());
    }

    /// Decay is measured in wall-clock time, not in updates. A per-update decay
    /// is a laundering machine: an agent caught being confidently wrong could
    /// bury the evidence under a burst of trivially-true self-dealt claims,
    /// because each one aged the history by another notch.
    #[test]
    fn a_burst_of_easy_wins_cannot_launder_a_bad_record() {
        let mut r = Reliability::default();
        for i in 0..30 {
            r.record(0.95, false, T + i); // caught, thirty times over
        }
        let disgraced = r.r();
        assert_eq!(r.weight(), 0.0);

        // Three hundred trivially-true claims, all within the same few minutes.
        for i in 0..300 {
            r.record(0.99, true, T + 30 + i);
        }
        assert!(
            r.r() < 0.75,
            "volume must not buy back a reputation: {disgraced} -> {}",
            r.r()
        );
        assert!(
            r.weight() < 1.2,
            "and the recovered weight must stay near a newcomer's, got {}",
            r.weight()
        );
    }

    /// The same agent, rehabilitating honestly over months rather than seconds.
    #[test]
    fn a_bad_record_does_fade_with_time() {
        let mut r = Reliability::default();
        for i in 0..30 {
            r.record(0.95, false, T + i);
        }
        for i in 0..60 {
            r.record(0.95, true, T + 30 + (i + 1) * DAY);
        }
        assert!(
            r.r() > 0.75,
            "two months of being right must genuinely count, got {}",
            r.r()
        );
        assert!(r.weight() > 1.0, "and must restore a real voice");
    }

    #[test]
    fn evidence_is_bounded_in_both_directions() {
        let mut good = Reliability::default();
        let mut bad = Reliability::default();
        for i in 0..10_000 {
            good.record(0.99, true, T + i);
            bad.record(0.99, false, T + i);
        }
        assert!(good.evidence() <= MAX_EVIDENCE + 1e-9);
        assert!(bad.evidence() <= MAX_EVIDENCE + 1e-9);
    }

    #[test]
    fn settlement_is_claimed_exactly_once() {
        let mut l = Ledger::new();
        let claim = crucible_core::EventId::from_bytes([9; 32]);
        assert!(!l.is_settled(&claim));
        assert!(l.mark_settled(&claim), "first settlement must be granted");
        assert!(!l.mark_settled(&claim), "the second must be refused");
        assert!(l.is_settled(&claim));
        assert_eq!(l.settled_count(), 1);
    }

    #[test]
    fn brier_beats_the_uninformative_baseline_only_when_skilled() {
        let mut skilled = Reliability::default();
        let mut noise = Reliability::default();
        for i in 0..20 {
            let truth = i % 2 == 0;
            skilled.record(if truth { 0.9 } else { 0.1 }, truth, T);
            noise.record(0.9, truth, T);
        }
        assert!(skilled.brier().unwrap() < 0.25, "skill must beat chance");
        assert!(noise.brier().unwrap() > 0.25, "noise must lose to chance");
    }

    #[test]
    fn domains_are_scored_independently() {
        let mut l = Ledger::new();
        let a = agent(1);
        for _ in 0..20 {
            l.record(&a, "ci", 0.95, true, T);
            l.record(&a, "security", 0.95, false, T);
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
            l.record(&agent(1), "ci", 0.95, true, T);
        }
        assert!(l.weight(&agent(1), "ci") > 2.0);
        assert!((l.get(&agent(2), "ci").r() - BOOTSTRAP).abs() < 1e-12);
    }

    #[test]
    fn a_bold_wrong_challenge_costs_more_than_a_timid_one() {
        let mut l = Ledger::new();
        // The claim turned out to be true, so both challengers were wrong.
        l.settle_challenge(&agent(1), "ci", 0.9, true, T);
        l.settle_challenge(&agent(2), "ci", 0.1, true, T);
        assert!(
            l.get(&agent(1), "ci").r() < l.get(&agent(2), "ci").r(),
            "the bold wrong challenger must lose more standing"
        );
    }

    #[test]
    fn a_correct_challenge_is_rewarded() {
        let mut l = Ledger::new();
        let before = l.get(&agent(1), "ci").r();
        l.settle_challenge(&agent(1), "ci", 0.8, false, T); // claim refuted
        assert!(l.get(&agent(1), "ci").r() > before);
    }

    #[test]
    fn an_empty_object_is_an_empty_ledger() {
        let l: Ledger = serde_json::from_str("{}").unwrap();
        assert!(l.is_empty());
        assert_eq!(l.settled_count(), 0);
    }

    #[test]
    fn report_is_stable_and_sorted() {
        let mut l = Ledger::new();
        l.record(&agent(2), "ci", 0.9, true, T);
        l.record(&agent(1), "ci", 0.9, true, T);
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
        l.record(&agent(1), "ci", 0.9, true, T);
        l.record(&agent(2), "security", 0.7, false, T);
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
