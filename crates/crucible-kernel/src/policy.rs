//! Per-community epistemic standards.
//!
//! Buzz gives each community its own relay and its own semantic boundary, and
//! the same freedom belongs here: a security channel may reasonably demand four
//! independent probes before it believes anything, while a channel tracking
//! build status is happy with two. These are the knobs, with defaults chosen to
//! be uncomfortable rather than agreeable.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
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
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            support_threshold: 0.90,
            refute_threshold: 0.10,
            min_n_eff: 2.0,
            conflict_floor: 0.5,
            conflict_ratio: 0.25,
            decay_floor: 0.05,
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
            conflict_floor: 0.25,
            conflict_ratio: 0.10,
            ..Self::default()
        }
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
