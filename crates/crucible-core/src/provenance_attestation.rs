//! Attested provenance: a trusted authority vouching for an agent's declared
//! `lineage`/`env` rather than the agent vouching for itself.
//!
//! [`crate::attestation::Provenance::similarity`] discounts two witnesses
//! whose `lineage` and `env` genuinely differ — and that is exactly what an
//! adversary defeats for free by fabricating two distinct strings, since
//! nothing checks them. Worse, the incentive runs backwards for anyone
//! honest: a fleet that truthfully declares a shared runner is discounted
//! correctly, while a liar who invents two names gets full credit for
//! independence it does not have.
//!
//! This does not attempt to solve provenance attestation in general — that is
//! SLSA, sigstore, TEE-quote territory, real infrastructure this crate has no
//! business reinventing. What it provides is the *seam*: an authority key a
//! community already trusts (an admission service, a CI identity provider,
//! whatever already vouches for infrastructure in that community) signs a
//! short-lived statement binding a subject's key to the `lineage`/`env` it is
//! about to declare. The kernel treats an attestor's self-reported provenance
//! as attested only when such a statement exists, is signed by a key the
//! community's policy names, and has not expired.

use crate::error::Result;
use crate::event::NostrEvent;
use crate::ids::{EventId, PubKey};
use crate::{kinds, Timestamp};

/// A signed vouch (`kind:47009`) that `subject` really is `lineage`/`env`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceAttestation {
    pub id: EventId,
    pub authority: PubKey,
    pub created_at: Timestamp,
    pub subject: PubKey,
    pub lineage: String,
    pub env: String,
    /// Unix time after which this vouch is no longer honoured. Infrastructure
    /// changes — a runner is decommissioned, a model is swapped — so a
    /// standing vouch with no expiry would let a community rely on facts long
    /// after they stopped being true.
    pub expires_at: Timestamp,
}

impl ProvenanceAttestation {
    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::PROVENANCE_ATTESTATION)?;
        let subject = ev.parse_tag("p", "not a 32-byte hex pubkey", |v| {
            PubKey::parse_hex(v).ok()
        })?;
        let expires_at = ev.parse_tag("expiry", "not a unix timestamp", |v| v.parse().ok())?;
        Ok(Self {
            id: ev.id,
            authority: ev.pubkey,
            created_at: ev.created_at,
            subject,
            lineage: ev.require_tag("lineage")?.to_string(),
            env: ev.require_tag("env")?.to_string(),
            expires_at,
        })
    }

    pub fn to_unsigned_tags(&self) -> Vec<Vec<String>> {
        vec![
            vec!["p".into(), self.subject.to_hex()],
            vec!["lineage".into(), self.lineage.clone()],
            vec!["env".into(), self.env.clone()],
            vec!["expiry".into(), self.expires_at.to_string()],
        ]
    }

    /// Whether this vouch backs exactly `subject`'s declared `lineage`/`env`,
    /// as of `now`.
    pub fn vouches_for(&self, subject: &PubKey, lineage: &str, env: &str, now: Timestamp) -> bool {
        self.subject == *subject
            && self.lineage == lineage
            && self.env == env
            && now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Signature;

    fn event(tags: Vec<Vec<String>>) -> NostrEvent {
        let mut ev = NostrEvent {
            id: EventId::from_bytes([0; 32]),
            pubkey: PubKey::from_bytes([7; 32]),
            created_at: 1_700_000_000,
            kind: kinds::PROVENANCE_ATTESTATION,
            tags,
            content: String::new(),
            sig: Signature::from_bytes([0; 64]),
        };
        ev.id = ev.compute_id();
        ev
    }

    fn base_tags() -> Vec<Vec<String>> {
        vec![
            vec!["p".into(), "a".repeat(64)],
            vec!["lineage".into(), "claude-opus-5".into()],
            vec!["env".into(), "runner-7".into()],
            vec!["expiry".into(), "1700100000".into()],
        ]
    }

    #[test]
    fn parses_and_round_trips() {
        let pa = ProvenanceAttestation::from_event(&event(base_tags())).unwrap();
        assert_eq!(pa.lineage, "claude-opus-5");
        assert_eq!(pa.env, "runner-7");
        assert_eq!(
            ProvenanceAttestation::from_event(&event(pa.to_unsigned_tags())).unwrap(),
            pa
        );
    }

    #[test]
    fn vouches_for_checks_every_field_and_expiry() {
        let pa = ProvenanceAttestation::from_event(&event(base_tags())).unwrap();
        let subject = PubKey::parse_hex(&"a".repeat(64)).unwrap();
        assert!(pa.vouches_for(&subject, "claude-opus-5", "runner-7", 1_700_000_000));
        assert!(!pa.vouches_for(&subject, "goose", "runner-7", 1_700_000_000));
        assert!(!pa.vouches_for(&subject, "claude-opus-5", "other-runner", 1_700_000_000));
        assert!(!pa.vouches_for(
            &PubKey::from_bytes([9; 32]),
            "claude-opus-5",
            "runner-7",
            1_700_000_000
        ));
        assert!(!pa.vouches_for(&subject, "claude-opus-5", "runner-7", 1_700_100_000));
    }

    #[test]
    fn rejects_the_wrong_kind() {
        let mut ev = event(base_tags());
        ev.kind = kinds::COMMITMENT;
        assert!(ProvenanceAttestation::from_event(&ev).is_err());
    }
}
