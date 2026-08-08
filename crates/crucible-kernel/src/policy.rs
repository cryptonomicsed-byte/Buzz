//! Per-community epistemic standards.
//!
//! Buzz gives each community its own relay and its own semantic boundary, and
//! the same freedom belongs here: a security channel may reasonably demand four
//! independent probes before it believes anything, while a channel tracking
//! build status is happy with two. These are the knobs, with defaults chosen to
//! be uncomfortable rather than agreeable.

use crucible_core::{PubKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Belief mass at or above which a claim is `Supported`.
    pub support_threshold: f64,
    /// Belief mass at or below which a claim is `Refuted`.
    pub refute_threshold: f64,
    /// Independent probes required before any claim may resolve at all.
    ///
    /// Two, not one. A single probe — however trusted the prober — is one
    /// machine, one toolchain and one blind spot, and a substrate that lets it
    /// mint truth has bought nothing over an agent simply saying so.
    pub min_n_eff: f64,
    /// Log-odds of evidence each side needs before disagreement counts as a
    /// real controversy rather than one straggler.
    pub conflict_floor: f64,
    /// How close the weaker side must be to the stronger, as a ratio, for
    /// `Contested`. Without this, a single dissenter would freeze a claim with
    /// overwhelming support forever.
    pub conflict_ratio: f64,
    /// Total remaining decayed evidence below which a probed claim goes stale.
    pub decay_floor: f64,

    /// Keys entitled to be heard in this community.
    ///
    /// This is the seam Crucible's threat model actually needs. Independence
    /// discounting defends against correlated *error*; it does nothing about an
    /// operator running twenty processes under twenty fresh keys with twenty
    /// invented lineages, which read as twenty witnesses. Nothing computable
    /// from the events can fix that, because the events are exactly what the
    /// adversary controls.
    ///
    /// Buzz already solves it: agents are members an operator admitted with
    /// `buzz-admin`. Populate this from the community's membership set and
    /// attestations from keys nobody admitted are excluded with a stated
    /// reason. Leaving it empty means "trust anyone who can sign", which is
    /// appropriate for a demo and for nothing else.
    pub roster: Option<BTreeSet<PubKey>>,

    /// How far ahead of `now` an event may be dated before it is refused.
    ///
    /// `created_at` is self-declared, and age drives decay. Without this bound,
    /// dating an attestation to the year 2100 pins its decay multiplier at 1.0
    /// forever: a claim with a fifteen-minute half-life that is permanently
    /// fresh, from one integer.
    pub max_clock_skew: Timestamp,

    /// Attestations any single claim may accumulate before the kernel stops
    /// reading. Resolution is quadratic in this number and the input comes from
    /// a relay, so it needs a ceiling that is not "however many arrived".
    pub max_attestations: usize,

    /// Calibration domains this community recognises.
    ///
    /// The domain is chosen by the claim's *author*, and reliability is keyed on
    /// it — so an unconstrained domain is a reset button an adversary may press
    /// per claim, putting every hard-won attestor back at the bootstrap
    /// alongside the sock puppets. Empty means no restriction.
    pub domains: Option<BTreeSet<String>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            support_threshold: 0.90,
            refute_threshold: 0.10,
            min_n_eff: 2.0,
            // Above the weight of a single unproven key (~0.62), deliberately.
            // Below it, one throwaway keypair voting `fails` freezes any claim
            // in `Contested` forever — a status with no arbitration, no expiry
            // and no cost to the attacker. Two independent dissenters, or one
            // with an earned record, still contest immediately.
            conflict_floor: 0.7,
            conflict_ratio: 0.25,
            decay_floor: 0.05,
            roster: None,
            max_clock_skew: 300,
            // Resolution is quadratic in this, with string comparisons in the
            // inner loop. Four thousand is sixteen million comparisons — fine on
            // a server, sluggish on a phone. Five hundred is still far more
            // independent witnesses than any real claim attracts.
            max_attestations: 512,
            domains: None,
        }
    }
}

impl Policy {
    /// A policy for claims a room will act on without a human: four independent
    /// probes and a very high bar.
    pub fn strict() -> Self {
        Self {
            support_threshold: 0.98,
            refute_threshold: 0.02,
            min_n_eff: 4.0,
            conflict_floor: 0.7,
            conflict_ratio: 0.10,
            ..Self::default()
        }
    }

    /// Whether `agent` may be heard at all.
    pub fn admits(&self, agent: &PubKey) -> bool {
        self.roster.as_ref().is_none_or(|r| r.contains(agent))
    }

    /// Whether `domain` is one this community recognises.
    pub fn recognises(&self, domain: &str) -> bool {
        self.domains.as_ref().is_none_or(|d| d.contains(domain))
    }

    /// Reject a policy that cannot mean anything, so a bad config fails at load
    /// rather than silently making every claim `Supported`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(0.0..=1.0).contains(&self.support_threshold)
            || !(0.0..=1.0).contains(&self.refute_threshold)
        {
            return Err("thresholds must be probabilities");
        }
        if self.refute_threshold >= self.support_threshold {
            return Err("refute_threshold must sit below support_threshold");
        }
        if self.min_n_eff < 1.0 {
            return Err("min_n_eff below 1 would let a claim resolve with no probe at all");
        }
        if self.conflict_floor < 0.0 || !(0.0..=1.0).contains(&self.conflict_ratio) {
            return Err("conflict_floor must be non-negative and conflict_ratio a fraction");
        }
        if self.decay_floor < 0.0 {
            return Err("decay_floor must be non-negative");
        }
        if self.max_attestations == 0 {
            return Err("max_attestations of zero would silence every probe");
        }
        if self.roster.as_ref().is_some_and(BTreeSet::is_empty) {
            return Err("an empty roster admits nobody; omit it to admit anyone");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_strict_are_valid() {
        Policy::default().validate().unwrap();
        Policy::strict().validate().unwrap();
    }

    #[test]
    fn an_empty_roster_admits_nobody_and_is_refused() {
        let mut p = Policy::default();
        assert!(
            p.admits(&PubKey::from_bytes([1; 32])),
            "no roster admits anyone"
        );

        p.roster = Some(BTreeSet::new());
        assert!(
            p.validate().is_err(),
            "an empty roster is a footgun, not a policy"
        );

        p.roster = Some([PubKey::from_bytes([1; 32])].into_iter().collect());
        p.validate().unwrap();
        assert!(p.admits(&PubKey::from_bytes([1; 32])));
        assert!(!p.admits(&PubKey::from_bytes([2; 32])));
    }

    #[test]
    fn domains_can_be_restricted_to_a_known_set() {
        let mut p = Policy::default();
        assert!(p.recognises("anything-at-all"));
        p.domains = Some(
            ["ci".to_string(), "security".to_string()]
                .into_iter()
                .collect(),
        );
        assert!(p.recognises("ci"));
        assert!(!p.recognises("migration-safety-q3"));
    }

    /// A single unproven key must not be able to freeze a claim.
    #[test]
    fn the_conflict_floor_sits_above_one_bootstrap_voice() {
        let bootstrap = crate::calibration::Reliability::default().weight();
        assert!(
            Policy::default().conflict_floor > bootstrap,
            "one throwaway key ({bootstrap}) must not reach the conflict floor"
        );
        assert!(
            Policy::default().conflict_floor < 2.0 * bootstrap,
            "but two independent dissenters must"
        );
    }

    #[test]
    fn strict_is_actually_stricter() {
        let (d, s) = (Policy::default(), Policy::strict());
        assert!(s.support_threshold > d.support_threshold);
        assert!(s.refute_threshold < d.refute_threshold);
        assert!(s.min_n_eff > d.min_n_eff);
    }

    #[test]
    fn rejects_incoherent_policies() {
        let cases = [
            Policy {
                support_threshold: 0.1,
                refute_threshold: 0.9,
                ..Default::default()
            },
            Policy {
                min_n_eff: 0.0,
                ..Default::default()
            },
            Policy {
                support_threshold: 1.5,
                ..Default::default()
            },
            Policy {
                conflict_ratio: 2.0,
                ..Default::default()
            },
            Policy {
                decay_floor: -1.0,
                ..Default::default()
            },
            Policy {
                max_attestations: 0,
                ..Default::default()
            },
        ];
        for p in cases {
            assert!(p.validate().is_err(), "{p:?} should not have validated");
        }
    }

    #[test]
    fn round_trips_through_json_with_partial_config() {
        // A community should be able to override one knob without restating all.
        let p: Policy = serde_json::from_str(r#"{"min_n_eff":3.0}"#).unwrap();
        assert_eq!(p.min_n_eff, 3.0);
        assert_eq!(p.support_threshold, Policy::default().support_threshold);
        p.validate().unwrap();
    }
}
