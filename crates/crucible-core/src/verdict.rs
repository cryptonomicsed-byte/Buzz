use crate::error::Result;
use crate::event::NostrEvent;
use crate::ids::EventId;
use crate::{kinds, Timestamp};
use serde::{Deserialize, Serialize};

/// The epistemic status of a claim.
///
/// The distinction most systems miss is between *"we do not know"* and *"we
/// have looked hard and the evidence is at war with itself"*. Both sit near
/// probability one-half, and collapsing them is how a room mistakes a genuine
/// controversy for an unexamined guess. `Insufficient` and `Contested` are
/// deliberately separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Strong, independent evidence, and no meaningful evidence against.
    Supported,
    /// Strong, independent evidence that the claim is false.
    Refuted,
    /// Substantial independent evidence on *both* sides. Someone must look.
    Contested,
    /// Not enough independent evidence to say anything yet.
    Insufficient,
    /// Past its expiry, or every piece of evidence has decayed to noise. The
    /// claim is not false — it is stale, and must be re-probed to be believed.
    Decayed,
    /// Attestations on the same experiment disagreed on their output digest.
    /// The falsifier is not a function of its declared inputs, so no amount of
    /// further evidence means anything until the claim's author fixes it.
    Nondeterministic,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Supported => "supported",
            Status::Refuted => "refuted",
            Status::Contested => "contested",
            Status::Insufficient => "insufficient",
            Status::Decayed => "decayed",
            Status::Nondeterministic => "nondeterministic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "supported" => Status::Supported,
            "refuted" => Status::Refuted,
            "contested" => Status::Contested,
            "insufficient" => Status::Insufficient,
            "decayed" => Status::Decayed,
            "nondeterministic" => Status::Nondeterministic,
            _ => return None,
        })
    }

    /// Whether this status settles the claim for calibration purposes. Only
    /// `Supported` and `Refuted` score an agent's forecast: punishing an agent
    /// because a room never got round to probing its claim would teach it to
    /// claim less, which is the opposite of what we want.
    pub const fn is_resolved(self) -> bool {
        matches!(self, Status::Supported | Status::Refuted)
    }

    /// Whether an agent should treat this claim as safe to build on.
    pub const fn is_actionable(self) -> bool {
        matches!(self, Status::Supported)
    }
}

/// The resolution kernel's output for a claim (`kind:47004`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub claim: EventId,
    pub status: Status,
    /// Posterior probability the claim is true, in `[0, 1]`.
    pub mass: f64,
    /// Effective number of *independent* attestations behind `mass`. Ten clones
    /// of one agent yield an `n_eff` near one, and the gap between the raw count
    /// and this number is the thing a reader most needs to see.
    pub n_eff: f64,
    /// Decayed, independence-discounted evidence for the claim, in log-odds.
    pub support: f64,
    /// The same, against it.
    pub opposition: f64,
    /// Attestations considered, before discounting.
    pub attestations: usize,
    pub computed_at: Timestamp,
}

impl Verdict {
    pub fn to_unsigned_tags(&self) -> Vec<Vec<String>> {
        vec![
            vec!["e".into(), self.claim.to_hex(), String::new(), "claim".into()],
            vec!["status".into(), self.status.as_str().into()],
            vec!["mass".into(), format!("{:.6}", self.mass)],
            vec!["neff".into(), format!("{:.6}", self.n_eff)],
            vec!["support".into(), format!("{:.6}", self.support)],
            vec!["opposition".into(), format!("{:.6}", self.opposition)],
            vec!["n".into(), self.attestations.to_string()],
        ]
    }

    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::VERDICT)?;
        let f = |name: &'static str| -> Result<f64> {
            ev.parse_tag(name, "not a number", |v| {
                v.parse::<f64>().ok().filter(|x| x.is_finite())
            })
        };
        Ok(Self {
            claim: ev.subject()?,
            status: ev.parse_tag("status", "not a known status", Status::parse)?,
            mass: f("mass")?,
            n_eff: f("neff")?,
            support: f("support")?,
            opposition: f("opposition")?,
            attestations: ev.parse_tag("n", "not an integer", |v| v.parse().ok())?,
            computed_at: ev.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips() {
        for s in [
            Status::Supported,
            Status::Refuted,
            Status::Contested,
            Status::Insufficient,
            Status::Decayed,
            Status::Nondeterministic,
        ] {
            assert_eq!(Status::parse(s.as_str()), Some(s));
        }
        assert_eq!(Status::parse("maybe"), None);
    }

    #[test]
    fn only_supported_and_refuted_settle_a_forecast() {
        assert!(Status::Supported.is_resolved());
        assert!(Status::Refuted.is_resolved());
        for s in [
            Status::Contested,
            Status::Insufficient,
            Status::Decayed,
            Status::Nondeterministic,
        ] {
            assert!(!s.is_resolved(), "{s:?} must not score anyone");
        }
    }

    /// A decayed claim was probably true once. It is still not something to act
    /// on, and neither is a contested one.
    #[test]
    fn only_supported_is_actionable() {
        assert!(Status::Supported.is_actionable());
        for s in [
            Status::Refuted,
            Status::Contested,
            Status::Insufficient,
            Status::Decayed,
            Status::Nondeterministic,
        ] {
            assert!(!s.is_actionable(), "{s:?} must not be acted on");
        }
    }
}
