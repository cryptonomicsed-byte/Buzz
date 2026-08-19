//! The calibration ledger: what an agent's word is worth, per domain, based on
//! what happened last time.
//!
//! Reliability here is earned, never configured, and — unlike an earlier
//! version of this module — earned under a genuinely *proper* scoring rule:
//! the logarithmic score. Properness is a precise claim, not a slogan: for any
//! single observation, an agent that reports its honest belief `p` receives a
//! strictly higher expected score than reporting anything else, *regardless of
//! its current standing*. That last clause is what an ad hoc "confidence
//! weighted" update does not give you — a mechanism whose payoff depends on
//! where you already stand can make hedging pay better than honesty once
//! you're proven, which teaches your most reliable agents to stop committing.
//! The log score has no such regime: each observation is scored on its own,
//! so there is never a standing at which under-reporting your true belief
//! becomes the rational move.
//!
//! Two properties matter beyond propriety, and both are tested below:
//!
//! * **Domain-scoped.** An agent that reads build logs beautifully may be
//!   hopeless at judging schema migrations. One global "trust score" would let
//!   competence in the easy domain buy authority in the hard one.
//! * **Bounded and non-cancelling.** Good and bad track record are accumulated
//!   *separately*, each independently capped, and weight is their difference.
//!   A single pool that let positive and negative evidence net against each
//!   other dollar-for-dollar would let an agent caught being confidently wrong
//!   launder the record with a burst of cheap, easy correct calls; keeping the
//!   pools apart means a deep deficit in one cannot be erased by piling volume
//!   into the other.

use crucible_core::{EventId, PubKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// Score, in nats, of the maximally uninformative forecast (`p = 0.5`)
/// regardless of outcome. Every observation is scored *relative to this* —
/// `ln(0.5)` when right, `ln(0.5)` when wrong, so a coin-flip forecast always
/// nets to zero and moves nothing.
fn baseline() -> f64 {
    0.5f64.ln()
}

/// Starting credit given to an agent nobody has scored yet, in nats.
///
/// This is a Bayesian prior on the accumulator, not a change to the scoring
/// rule: it only shifts where `good` starts, and a prior does not affect which
/// report maximises a *future* observation's expected score, so it costs
/// nothing in propriety. It exists so a fresh community — where nobody has a
/// track record yet — is not frozen at `Insufficient` forever for want of
/// anyone with nonzero weight. Chosen so `r()` for an untested agent lands
/// at [`BOOTSTRAP`].
const PRIOR_GOOD: f64 = 0.619;

/// `r()` for an agent nobody has scored yet — `sigmoid(PRIOR_GOOD)`, kept as a
/// named constant because callers compare against it directly.
pub const BOOTSTRAP: f64 = 0.65; // sigmoid(0.619) ≈ 0.6500

/// Cap on `good` and `bad`, applied to each independently, in nats.
///
/// Independence is what makes the cap resist laundering: `good` cannot buy
/// back what `bad` has accrued just by growing past it, because `bad` is a
/// separate pool with its own ceiling and does not shrink when `good` grows.
/// The value is `ln(0.99/0.01)`, so the most any single voice can ever be
/// worth is what a room would grant an agent it was 99% sure of.
const MAX_WEALTH: f64 = 4.595_119_850_134_589; // ln(99)

/// How long it takes a track record to lose half its weight. Measured in wall
/// clock time, not in observations — an agent caught being confidently wrong
/// cannot bury the record under a burst of easy correct calls, because a burst
/// (by definition) barely advances the clock. Rehabilitation takes roughly a
/// month of genuinely being right, which is what "recent performance" is
/// supposed to mean.
pub const RECENCY_HALF_LIFE: Timestamp = 30 * 86_400;

/// One agent's record in one domain.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reliability {
    /// Decayed, capped nats of log-score earned on observations where the
    /// forecast beat the coin-flip baseline.
    good: f64,
    /// The same, in magnitude, for observations where it fell short.
    bad: f64,
    /// Decayed sum of Brier scores, and the matching count, for reporting.
    /// Independent of `good`/`bad` — this is a second, equally proper measure
    /// (Brier is also strictly proper), kept for a room that wants a more
    /// familiar 0–1 statistic than nats.
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
            good: PRIOR_GOOD,
            bad: 0.0,
            brier_sum: 0.0,
            log_sum: 0.0,
            observations: 0.0,
            last_update: 0,
        }
    }
}

impl Reliability {
    /// Posterior-style summary: roughly, the probability this agent's next
    /// forecast in this domain is right. Derived from [`weight`](Self::weight)
    /// by the inverse of the map that produced it (`weight` is a log-odds-like
    /// quantity, so this is its sigmoid); purely descriptive, and read by
    /// nothing in the kernel — [`weight`](Self::weight) is what actually moves
    /// belief.
    pub fn r(&self) -> f64 {
        let x = self.good - self.bad;
        // Branch on sign so neither `exp` overflows.
        if x >= 0.0 {
            1.0 / (1.0 + (-x).exp())
        } else {
            let e = x.exp();
            e / (1.0 + e)
        }
    }

    /// Evidence weight in nats — what this agent's attestation is worth.
    ///
    /// `good` and `bad` are each capped independently at [`MAX_WEALTH`] and
    /// never cancel below zero, so this is always in `[0, MAX_WEALTH]`: an
    /// agent whose bad record outweighs its good one is silenced, never
    /// inverted. A substrate that read a proven liar backwards would let
    /// lying-on-purpose buy influence.
    pub fn weight(&self) -> f64 {
        (self.good - self.bad).max(0.0)
    }

    /// Mean Brier score: `(forecast - outcome)²`, lower is better. `None`
    /// until the agent has forecast at least once.
    pub fn brier(&self) -> Option<f64> {
        (self.observations > 0.0).then(|| self.brier_sum / self.observations)
    }

    /// Mean logarithmic score (loss form: lower is better). Punishes confident
    /// errors far more sharply than Brier does.
    pub fn log_score(&self) -> Option<f64> {
        (self.observations > 0.0).then(|| self.log_sum / self.observations)
    }

    /// Total decayed evidence, good and bad combined. Small numbers mean "we
    /// are mostly still looking at the prior," and callers should say so.
    pub fn evidence(&self) -> f64 {
        self.good - PRIOR_GOOD + self.bad
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
            self.good *= f;
            self.bad *= f;
            self.brier_sum *= f;
            self.log_sum *= f;
            self.observations *= f;
            self.last_update = now;
        }
    }

    /// Score one resolved forecast, as of `now`.
    ///
    /// `forecast` is the probability the agent assigned to the claim being
    /// true; `truth` is what the kernel resolved. The logarithmic score of
    /// that forecast, relative to the uninformative baseline, is routed to
    /// `good` or `bad` depending on its sign and added under that pool's own
    /// cap — so this is a strictly proper scoring rule with a bounded, capped,
    /// non-cancelling memory, not a compromise between the two.
    pub fn record(&mut self, forecast: f64, truth: bool, now: Timestamp) {
        // Keep the score finite without letting a clamp become a way to
        // assert certainty for free.
        let p = forecast.clamp(1e-4, 1.0 - 1e-4);
        let y = if truth { 1.0 } else { 0.0 };

        self.age_to(now);

        let score = if truth { p.ln() } else { (1.0 - p).ln() };
        let delta = score - baseline();
        if delta > 0.0 {
            self.good = (self.good + delta).min(MAX_WEALTH);
        } else if delta < 0.0 {
            self.bad = (self.bad - delta).min(MAX_WEALTH);
        }
        // delta == 0.0 (p == 0.5 exactly): a coin flip stakes nothing and
        // therefore moves nothing, in either pool.

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
    /// proper scoring rule as an over-confident claimant.
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
        assert!((r.r() - BOOTSTRAP).abs() < 1e-3, "got {}", r.r());
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

    /// The defining test of propriety, checked directly rather than inferred:
    /// for a fixed true belief, misreporting it — in either direction — must
    /// never score better in expectation than reporting it honestly. This is
    /// the property an ad hoc "confidence weighted" heuristic does not have.
    #[test]
    fn honest_reporting_maximises_expected_score() {
        // Monte Carlo the definition directly: an agent whose true belief is
        // q=0.7 reports p; average its score over many draws from that belief.
        // Truthful p=q must beat every mis-report tried, at a fine grid.
        fn expected_delta(p: f64, q: f64, trials: u32, seed: u64) -> f64 {
            let mut state = seed;
            let mut total = 0.0;
            for _ in 0..trials {
                // xorshift, deterministic and dependency-free.
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let draw = (state as f64) / (u64::MAX as f64);
                let truth = draw < q;
                let mut r = Reliability::default();
                let before = r.good - r.bad;
                r.record(p, truth, T);
                total += (r.good - r.bad) - before;
            }
            total / trials as f64
        }

        let q = 0.7;
        let honest = expected_delta(q, q, 20_000, 0xC0FFEE);
        for p in [0.05, 0.2, 0.4, 0.55, 0.8, 0.95, 0.99] {
            let other = expected_delta(p, q, 20_000, 0xC0FFEE);
            assert!(
                honest >= other - 0.02,
                "reporting the truth (q={q}) scored {honest:.4}, but reporting \
                 {p} scored {other:.4} — honesty should never lose"
            );
        }
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
    /// right, or the dominant strategy becomes to never commit to anything —
    /// and this must hold *however proven the agent already is*, which is
    /// exactly the property the earlier commitment-weighted Beta update did
    /// not have (its own regression test for this is below).
    #[test]
    fn confident_correctness_pays_more_than_hedging_at_every_starting_reliability() {
        for starting_calls in [0, 5, 40, 400] {
            let mut base = Reliability::default();
            for _ in 0..starting_calls {
                base.record(0.9, true, T);
            }
            let mut loud = base;
            let mut hedged = base;
            for _ in 0..10 {
                loud.record(0.95, true, T);
                hedged.record(0.55, true, T);
            }
            assert!(
                loud.weight() >= hedged.weight() - 1e-9,
                "at {starting_calls} prior correct calls, hedging ({}) beat \
                 commitment ({}) — a proven agent must never be rewarded for \
                 under-reporting its true confidence",
                hedged.weight(),
                loud.weight()
            );
        }
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
        assert!(r.r() < 0.5);
        assert_eq!(r.weight(), 0.0, "must be ignored, never read backwards");
    }

    #[test]
    fn no_agent_can_exceed_the_ceiling() {
        let mut r = Reliability::default();
        for _ in 0..10_000 {
            r.record(0.999, true, T);
        }
        assert!(r.weight() <= MAX_WEALTH + 1e-9);
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

    /// Decay is measured in wall-clock time, not in updates. Separately capped,
    /// non-cancelling pools are what actually stop a burst from laundering a
    /// bad record; decay being time-based (rather than per-update) is what
    /// stops a burst from *erasing* it outright.
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
            r.r() < 0.55,
            "volume must not buy back a reputation: {disgraced} -> {}",
            r.r()
        );
        assert!(
            r.weight() < 0.3,
            "a burst must not restore a real voice, got {}",
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
        assert!(good.evidence() <= 2.0 * MAX_WEALTH + 1e-9);
        assert!(bad.evidence() <= 2.0 * MAX_WEALTH + 1e-9);
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
            (l.get(&a, "perf").r() - BOOTSTRAP).abs() < 1e-3,
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
        assert!((l.get(&agent(2), "ci").r() - BOOTSTRAP).abs() < 1e-3);
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
