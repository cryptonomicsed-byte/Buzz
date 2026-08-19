//! A community-designated oracle's authoritative answer, exogenous to the
//! population `settle` scores.
//!
//! `settle` measures agents by comparing their reports to `resolve`'s
//! verdict — and by default that verdict is itself an aggregate of the same
//! agents' reports. That is not a bug in the arithmetic; it is what happens
//! when there is no ground truth outside the population being scored. A
//! colluding majority is correct by construction, and honest disagreement
//! looks identical to a minority being penalised for being right.
//!
//! This does not manufacture ground truth from nothing — nothing computable
//! from the log can do that. What it provides is a seam: a key (or set of
//! keys) a community already trusts to know the real answer independently —
//! a human adjudicator, a courthouse feed, an escalation path outside the
//! probing population entirely — signs an authoritative outcome for a claim.
//! `resolve` treats a valid oracle verdict as settling `status` outright,
//! ahead of the independence-weighted aggregate; `settle` then scores every
//! attestor's forecast against *that*, not against their own consensus. The
//! property that matters is not that the oracle is infallible — it is that
//! the oracle is not a member of the population its answer scores.

use crate::error::Result;
use crate::event::NostrEvent;
use crate::ids::{EventId, PubKey};
use crate::{kinds, Outcome, Timestamp};

fn parse_digest(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (s.len() == 64 && hex::decode_to_slice(s, &mut out).is_ok()).then_some(out)
}

/// A signed, authoritative answer (`kind:47010`) for one claim's experiment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleVerdict {
    pub id: EventId,
    pub oracle: PubKey,
    pub created_at: Timestamp,
    pub claim: EventId,
    pub experiment: [u8; 32],
    /// `Indeterminate` means the oracle declines to answer this claim — it
    /// does not settle anything and `resolve` falls through to the ordinary
    /// aggregate, the same way an indeterminate probe carries no evidence.
    pub outcome: Outcome,
}

impl OracleVerdict {
    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::ORACLE_VERDICT)?;
        Ok(Self {
            id: ev.id,
            oracle: ev.pubkey,
            created_at: ev.created_at,
            claim: ev.subject()?,
            experiment: ev.parse_tag("experiment", "not a 32-byte hex digest", parse_digest)?,
            outcome: ev.parse_tag("outcome", "not holds/fails/indeterminate", Outcome::parse)?,
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
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Signature;

    fn event(tags: Vec<Vec<String>>) -> NostrEvent {
        let mut ev = NostrEvent {
            id: EventId::from_bytes([0; 32]),
            pubkey: PubKey::from_bytes([9; 32]),
            created_at: 1_700_000_000,
            kind: kinds::ORACLE_VERDICT,
            tags,
            content: String::new(),
            sig: Signature::from_bytes([0; 64]),
        };
        ev.id = ev.compute_id();
        ev
    }

    fn base_tags() -> Vec<Vec<String>> {
        vec![
            vec!["e".into(), "a".repeat(64), String::new(), "claim".into()],
            vec!["experiment".into(), "b".repeat(64)],
            vec!["outcome".into(), "holds".into()],
        ]
    }

    #[test]
    fn parses_and_round_trips() {
        let ov = OracleVerdict::from_event(&event(base_tags())).unwrap();
        assert_eq!(ov.outcome, Outcome::Holds);
        assert_eq!(
            OracleVerdict::from_event(&event(ov.to_unsigned_tags())).unwrap(),
            ov
        );
    }

    #[test]
    fn rejects_the_wrong_kind() {
        let mut ev = event(base_tags());
        ev.kind = kinds::COMMITMENT;
        assert!(OracleVerdict::from_event(&ev).is_err());
    }

    #[test]
    fn rejects_a_malformed_outcome() {
        let mut tags = base_tags();
        tags[2] = vec!["outcome".into(), "maybe".into()];
        assert!(OracleVerdict::from_event(&event(tags)).is_err());
    }
}
