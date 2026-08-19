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

    /// Longest half-life a claim may declare, in seconds.
    ///
    /// A second road to an immortal belief, and it needs no future dating: a
    /// claim with a half-life of a century decays imperceptibly, so it never
    /// reaches the decay floor and never has to be re-checked. Ninety days is
    /// already far longer than anything a room should hold without looking
    /// again; longer half-lives are clamped to this and the clamp is reported.
    pub max_half_life: Timestamp,

    /// Permit resolving with no roster at all.
    ///
    /// Off by default, because a missing roster is the difference between a
    /// demo and a deployment and it fails silently: every key that can sign is
    /// counted as a witness, so three fresh keypairs reach `Supported` in about
    /// a second. Running without one has to be a thing somebody chose.
    pub allow_unrostered: bool,

    /// Require a valid commit-reveal before honouring an attestor's claim of
    /// `blind: true`.
    ///
    /// Off by default, for the same reason `allow_unrostered` defaults the
    /// other way: this closes a real gap (self-reported blindness is free to
    /// claim and only ever raises how independent an attestor looks) but is a
    /// strictly *lower* severity one than an open roster — it overstates
    /// independence rather than manufacturing it outright, since the attestor
    /// still has to be a distinct, admitted key. A community that wants the
    /// guarantee turns this on; one that doesn't gets today's behaviour,
    /// unchanged.
    pub require_verified_blind: bool,

    /// Require a trusted authority's vouch before honouring self-reported
    /// `lineage`/`env` as genuinely distinct.
    ///
    /// Off by default, same reasoning as `require_verified_blind`: fabricating
    /// two distinct strings is free, but a Sybil still needs a distinct,
    /// admitted key first, so this overstates independence rather than
    /// manufacturing it. When on, provenance not backed by a matching, unexpired
    /// [`crate::calibration`]-adjacent vouch (`kind:47009`, signed by a key in
    /// `provenance_authorities`) is floored at
    /// [`crate::independence::UNATTESTED_FLOOR`] correlation rather than trusted
    /// at whatever the self-report claims.
    pub require_attested_provenance: bool,

    /// Keys trusted to vouch for `lineage`/`env` when
    /// `require_attested_provenance` is set. `None` trusts nobody, which — with
    /// the flag on — floors every attestor's provenance; set both together.
    pub provenance_authorities: Option<BTreeSet<PubKey>>,

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
            max_half_life: 90 * 86_400,
            allow_unrostered: false,
            require_verified_blind: false,
            require_attested_provenance: false,
            provenance_authorities: None,
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

    /// Whether `authority` is trusted to vouch for provenance.
    pub fn is_provenance_authority(&self, authority: &PubKey) -> bool {
        self.provenance_authorities
            .as_ref()
            .is_some_and(|a| a.contains(authority))
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
        if self.roster.is_none() && !self.allow_unrostered {
            return Err(
                "no roster: every key that can sign would count as a witness. \
                 Set `roster` to this community's membership set, or \
                 `allow_unrostered: true` if that is genuinely what you want",
            );
        }
        if self.max_half_life == 0 {
            return Err("max_half_life of zero would decay every claim instantly");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy for tests and demos: the defaults, with the roster requirement
    /// explicitly waived.
    fn open() -> Policy {
        Policy {
            allow_unrostered: true,
            ..Policy::default()
        }
    }

    /// The default policy must *not* validate. A missing roster is silent and
    /// fatal, so refusing to start is the only mitigation that cannot be
    /// scrolled past.
    #[test]
    fn the_default_policy_refuses_to_run_without_a_roster() {
        let err = Policy::default().validate().unwrap_err();
        assert!(err.contains("roster"), "got {err}");

        open().validate().unwrap();
        Policy {
            roster: Some([PubKey::from_bytes([1; 32])].into_iter().collect()),
            ..Policy::default()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn strict_is_valid_once_rostered() {
        Policy {
            allow_unrostered: true,
            ..Policy::strict()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn an_empty_roster_admits_nobody_and_is_refused() {
        assert!(
            Policy::default().admits(&PubKey::from_bytes([1; 32])),
            "with no roster, admission is unconditional — which is exactly why \
             validate() refuses to run that way"
        );

        let mut p = open();
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
        let mut p = open();
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
                ..open()
            },
            Policy {
                min_n_eff: 0.0,
                ..open()
            },
            Policy {
                support_threshold: 1.5,
                ..open()
            },
            Policy {
                conflict_ratio: 2.0,
                ..open()
            },
            Policy {
                decay_floor: -1.0,
                ..open()
            },
            Policy {
                max_attestations: 0,
                ..open()
            },
            Policy {
                max_half_life: 0,
                ..open()
            },
        ];
        for p in cases {
            assert!(p.validate().is_err(), "{p:?} should not have validated");
        }
    }

    #[test]
    fn round_trips_through_json_with_partial_config() {
        // A community should be able to override one knob without restating all.
        let p: Policy =
            serde_json::from_str(r#"{"min_n_eff":3.0,"allow_unrostered":true}"#).unwrap();
        assert_eq!(p.min_n_eff, 3.0);
        assert_eq!(p.support_threshold, Policy::default().support_threshold);
        p.validate().unwrap();
    }
}
