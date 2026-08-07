use crate::error::{Error, Result};
use crate::event::NostrEvent;
use crate::ids::{EventId, PubKey};
use crate::{kinds, Timestamp};
use serde::{Deserialize, Serialize};

/// What running the falsifier produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// The falsifier ran and failed to falsify: the claim survived.
    Holds,
    /// The falsifier ran and returned false: the claim is wrong.
    Fails,
    /// The falsifier could not reach a conclusion — a capability was denied, it
    /// ran out of fuel, a dependency was unreachable. Carries no evidence
    /// either way, and is deliberately *not* silently read as "holds".
    Indeterminate,
}

impl Outcome {
    /// `+1` supports the claim, `-1` refutes it, `0` says nothing.
    pub const fn sign(self) -> f64 {
        match self {
            Outcome::Holds => 1.0,
            Outcome::Fails => -1.0,
            Outcome::Indeterminate => 0.0,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::Holds => "holds",
            Outcome::Fails => "fails",
            Outcome::Indeterminate => "indeterminate",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "holds" => Outcome::Holds,
            "fails" => Outcome::Fails,
            "indeterminate" => Outcome::Indeterminate,
            _ => return None,
        })
    }
}

/// The facts that make two attestations correlated rather than independent.
///
/// This is the part naive multi-agent consensus gets wrong. Five agents agreeing
/// is only five pieces of evidence if the five could have failed independently.
/// Five instances of one model, given one context, reading each other's answers,
/// are approximately one piece of evidence wearing five hats — and a system that
/// counts them as five will lock in a confident, unanimous, wrong belief.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Model or implementation lineage, e.g. `claude-opus-5`, `goose/gpt`,
    /// `human`, `ci-runner`. Shared lineage means shared blind spots.
    pub lineage: String,
    /// Fingerprint of the execution environment: OS, arch, toolchain, image
    /// digest. Shared environment means shared environmental lies — the classic
    /// "works on the runner, and every agent used the same runner".
    pub env: String,
    /// True when the attestor ran the falsifier *before* seeing any prior
    /// attestation or verdict on this claim. An informed attestor is anchored by
    /// what it read, so it carries strictly less independent information.
    ///
    /// Self-reported and unverified, like `lineage` and `env` — and claiming it
    /// only ever *raises* how much your agreement counts, so the incentive runs
    /// the wrong way. A commit-then-reveal round (publish `H(outcome ‖ nonce)`
    /// before any verdict exists, reveal after) would make blindness checkable
    /// rather than asserted. That is not implemented, and until it is, this
    /// field is the softest part of the substrate.
    pub blind: bool,
}

impl Provenance {
    /// Similarity in `[0, 1]` on the features that drive correlated error.
    ///
    /// Weights: lineage dominates (shared model, shared reasoning failure),
    /// environment matters, and two non-blind attestors are correlated through
    /// the discussion they both read even if nothing else matches.
    pub fn similarity(&self, other: &Self) -> f64 {
        const LINEAGE: f64 = 0.80;
        const ENV: f64 = 0.35;
        const HERDING: f64 = 0.50;

        // Independent hazards compose multiplicatively: correlation is the
        // probability that *at least one* shared factor links the two, so it
        // rises with each match but never reaches 1 on a single feature.
        let mut independence = 1.0;
        if self.lineage == other.lineage {
            independence *= 1.0 - LINEAGE;
        }
        if self.env == other.env {
            independence *= 1.0 - ENV;
        }
        if !self.blind && !other.blind {
            independence *= 1.0 - HERDING;
        }
        1.0 - independence
    }
}

/// A signed record of one agent independently running a claim's falsifier
/// (`kind:47002`).
#[derive(Clone, Debug, PartialEq)]
pub struct Attestation {
    pub id: EventId,
    pub attestor: PubKey,
    pub created_at: Timestamp,
    pub claim: EventId,
    /// Must equal the claim's [`crate::FalsifierRef::experiment_id`]. An
    /// attestation against a different module, manifest or inputs is evidence
    /// about a different question and the kernel must not pool it.
    pub experiment: [u8; 32],
    pub outcome: Outcome,
    /// SHA-256 of the falsifier's declared output. Two attestations on the same
    /// experiment that disagree here prove the falsifier is non-deterministic —
    /// which is a defect in the *claim*, and worth surfacing rather than
    /// averaging away.
    pub output_digest: [u8; 32],
    /// Fuel consumed by the sandbox. Recorded for readers and for cost
    /// accounting; the kernel does not currently use it, though divergent fuel
    /// on identical inputs would be a cheap second non-determinism signal.
    pub fuel: u64,
    pub provenance: Provenance,
}

fn parse_digest(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (s.len() == 64 && hex::decode_to_slice(s, &mut out).is_ok()).then_some(out)
}

impl Attestation {
    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::ATTESTATION)?;

        let blind = ev.parse_tag("blind", "must be `true` or `false`", |v| match v {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })?;

        Ok(Self {
            id: ev.id,
            attestor: ev.pubkey,
            created_at: ev.created_at,
            claim: ev.subject()?,
            experiment: ev.parse_tag("experiment", "not a 32-byte hex digest", parse_digest)?,
            outcome: ev.parse_tag("outcome", "not holds/fails/indeterminate", Outcome::parse)?,
            output_digest: ev.parse_tag("digest", "not a 32-byte hex digest", parse_digest)?,
            fuel: ev.parse_tag("fuel", "not an integer", |v| v.parse().ok())?,
            provenance: Provenance {
                lineage: ev.require_tag("lineage")?.to_string(),
                env: ev.require_tag("env")?.to_string(),
                blind,
            },
        })
    }

    pub fn to_unsigned_tags(&self) -> Vec<Vec<String>> {
        vec![
            vec![
                "e".into(),
                self.claim.to_hex(),
                String::new(),
                "claim".into(),
            ],
            vec!["experiment".into(), hex::encode(self.experiment)],
            vec!["outcome".into(), self.outcome.as_str().into()],
            vec!["digest".into(), hex::encode(self.output_digest)],
            vec!["fuel".into(), self.fuel.to_string()],
            vec!["lineage".into(), self.provenance.lineage.clone()],
            vec!["env".into(), self.provenance.env.clone()],
            vec!["blind".into(), self.provenance.blind.to_string()],
        ]
    }

    /// Reject an attestation that is about a different experiment than the claim
    /// declares.
    pub fn check_matches(&self, claim: &crate::Claim) -> Result<()> {
        if self.claim != claim.id {
            return Err(Error::BadTag {
                tag: "e",
                value: self.claim.to_hex(),
                reason: "attestation references a different claim",
            });
        }
        if self.experiment != claim.falsifier.experiment_id() {
            return Err(Error::BadTag {
                tag: "experiment",
                value: hex::encode(self.experiment),
                reason: "attestation ran a different module, manifest or inputs",
            });
        }
        Ok(())
    }
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

    #[test]
    fn fully_independent_attestors_are_uncorrelated() {
        let a = prov("claude-opus-5", "linux-x86", true);
        let b = prov("goose-gpt", "darwin-arm", true);
        assert_eq!(a.similarity(&b), 0.0);
    }

    #[test]
    fn identical_non_blind_attestors_are_nearly_perfectly_correlated() {
        let a = prov("claude-opus-5", "linux-x86", false);
        assert!(
            a.similarity(&a) > 0.93,
            "clones must be near-redundant, got {}",
            a.similarity(&a)
        );
    }

    #[test]
    fn correlation_is_symmetric_and_bounded() {
        let cases = [
            prov("m1", "e1", true),
            prov("m1", "e2", false),
            prov("m2", "e1", false),
            prov("m2", "e2", true),
        ];
        for a in &cases {
            for b in &cases {
                let s = a.similarity(b);
                assert_eq!(s, b.similarity(a), "similarity must be symmetric");
                assert!((0.0..=1.0).contains(&s), "similarity {s} out of range");
            }
        }
    }

    #[test]
    fn each_shared_feature_only_increases_correlation() {
        let base = prov("m1", "e1", true).similarity(&prov("m2", "e2", true));
        let lineage = prov("m1", "e1", true).similarity(&prov("m1", "e2", true));
        let env = prov("m1", "e1", true).similarity(&prov("m2", "e1", true));
        let herding = prov("m1", "e1", false).similarity(&prov("m2", "e2", false));
        assert!(base < env, "sharing an environment must correlate");
        assert!(env < herding, "reading each other must correlate more");
        assert!(herding < lineage, "sharing a model must dominate");
        assert!(lineage < prov("m1", "e1", false).similarity(&prov("m1", "e1", false)));
    }

    /// A blind attestor is not herding even if the other side read everything.
    #[test]
    fn one_blind_attestor_breaks_the_herding_link() {
        let informed = prov("m1", "e1", false);
        let blind = prov("m2", "e2", true);
        assert_eq!(blind.similarity(&informed), 0.0);
    }

    #[test]
    fn outcome_signs_are_symmetric() {
        assert_eq!(Outcome::Holds.sign(), -Outcome::Fails.sign());
        assert_eq!(Outcome::Indeterminate.sign(), 0.0);
    }

    #[test]
    fn outcome_round_trips() {
        for o in [Outcome::Holds, Outcome::Fails, Outcome::Indeterminate] {
            assert_eq!(Outcome::parse(o.as_str()), Some(o));
        }
        assert_eq!(Outcome::parse("probably"), None);
    }
}
