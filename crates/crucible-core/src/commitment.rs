//! Commit-reveal for the `blind` flag.
//!
//! [`crate::attestation::Provenance::blind`] is otherwise a claim about
//! yourself that nothing checks: an attestor gains weight by *saying* it ran
//! the falsifier before reading the room, and there is no cost to saying so
//! whether or not it's true. A commitment closes that gap the same way every
//! commit-reveal scheme does — publish a hash of your answer before you could
//! have seen anyone else's, then reveal the answer and the nonce that unlocks
//! the hash. A verifier who has both can confirm the reveal matches the
//! commitment, *and* that the commitment predates every other attestation on
//! the claim, which is the actual content of the word "blind."
//!
//! This proves the commitment came first and matches what was later revealed.
//! It cannot prove the committer didn't peek at something outside the
//! protocol entirely — no cryptographic commitment can — so "verified blind"
//! here means "provably committed before seeing any other *attestation or
//! verdict in this log*," which is the property the independence model
//! actually needs, not a stronger claim about the attestor's mind.

use crate::error::Result;
use crate::event::NostrEvent;
use crate::ids::{EventId, PubKey};
use crate::{kinds, Timestamp};
use sha2::{Digest, Sha256};

/// `H(tag ‖ committer ‖ claim ‖ experiment ‖ outcome ‖ output_digest ‖ nonce)`.
///
/// Binding the outcome and digest into the hash — not just committing to "I
/// will attest" — is what makes the commitment mean something: a committer
/// who could swap their answer after seeing the room's reaction has revealed
/// nothing by committing first. The nonce keeps the hash from being trivially
/// invertible: `outcome` has only three values and `output_digest` is often
/// predictable for a given claim, so a fixed hash of just those would be
/// guessable by brute force, defeating the concealment a commitment exists to
/// provide.
pub fn commitment_hash(
    committer: &PubKey,
    claim: &EventId,
    experiment: &[u8; 32],
    outcome: crate::Outcome,
    output_digest: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"crucible/blind-commitment/v1\0");
    h.update(committer.as_bytes());
    h.update(claim.as_bytes());
    h.update(experiment);
    h.update([match outcome {
        crate::Outcome::Holds => 1u8,
        crate::Outcome::Fails => 2,
        crate::Outcome::Indeterminate => 3,
    }]);
    h.update(output_digest);
    h.update(nonce);
    h.finalize().into()
}

/// A published commitment (`kind:47008`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub id: EventId,
    pub committer: PubKey,
    pub created_at: Timestamp,
    pub claim: EventId,
    pub experiment: [u8; 32],
    pub hash: [u8; 32],
}

fn parse_digest(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (s.len() == 64 && hex::decode_to_slice(s, &mut out).is_ok()).then_some(out)
}

impl Commitment {
    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::COMMITMENT)?;
        Ok(Self {
            id: ev.id,
            committer: ev.pubkey,
            created_at: ev.created_at,
            claim: ev.subject()?,
            experiment: ev.parse_tag("experiment", "not a 32-byte hex digest", parse_digest)?,
            hash: ev.parse_tag("hash", "not a 32-byte hex digest", parse_digest)?,
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
            vec!["hash".into(), hex::encode(self.hash)],
        ]
    }

    /// Whether `nonce`, `outcome` and `output_digest` unlock this commitment —
    /// i.e. whether this is a genuine reveal of it, not merely a claim to be
    /// one.
    pub fn opens_with(
        &self,
        attestor: &PubKey,
        outcome: crate::Outcome,
        output_digest: &[u8; 32],
        nonce: &[u8; 32],
    ) -> bool {
        self.committer == *attestor
            && commitment_hash(
                attestor,
                &self.claim,
                &self.experiment,
                outcome,
                output_digest,
                nonce,
            ) == self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Signature;
    use crate::{Error, Outcome};

    fn event(tags: Vec<Vec<String>>) -> NostrEvent {
        let mut ev = NostrEvent {
            id: EventId::from_bytes([0; 32]),
            pubkey: PubKey::from_bytes([5; 32]),
            created_at: 1_700_000_000,
            kind: kinds::COMMITMENT,
            tags,
            content: String::new(),
            sig: Signature::from_bytes([0; 64]),
        };
        ev.id = ev.compute_id();
        ev
    }

    #[test]
    fn a_well_formed_commitment_parses_and_round_trips() {
        let tags = vec![
            vec!["e".into(), "a".repeat(64), String::new(), "claim".into()],
            vec!["experiment".into(), "b".repeat(64)],
            vec!["hash".into(), "c".repeat(64)],
        ];
        let c = Commitment::from_event(&event(tags)).unwrap();
        assert_eq!(c.experiment, [0xbb; 32]);
        assert_eq!(c.hash, [0xcc; 32]);
        assert_eq!(
            Commitment::from_event(&event(c.to_unsigned_tags())).unwrap(),
            c
        );
    }

    #[test]
    fn the_hash_binds_every_input() {
        let committer = PubKey::from_bytes([1; 32]);
        let claim = EventId::from_bytes([2; 32]);
        let experiment = [3u8; 32];
        let digest = [4u8; 32];
        let nonce = [5u8; 32];
        let base = commitment_hash(
            &committer,
            &claim,
            &experiment,
            Outcome::Holds,
            &digest,
            &nonce,
        );

        assert_ne!(
            base,
            commitment_hash(
                &committer,
                &claim,
                &experiment,
                Outcome::Fails,
                &digest,
                &nonce
            ),
            "outcome must be bound"
        );
        assert_ne!(
            base,
            commitment_hash(
                &committer,
                &claim,
                &experiment,
                Outcome::Holds,
                &[9; 32],
                &nonce
            ),
            "output digest must be bound"
        );
        assert_ne!(
            base,
            commitment_hash(
                &committer,
                &claim,
                &experiment,
                Outcome::Holds,
                &digest,
                &[9; 32]
            ),
            "nonce must be bound"
        );
        let other_committer = PubKey::from_bytes([9; 32]);
        assert_ne!(
            base,
            commitment_hash(
                &other_committer,
                &claim,
                &experiment,
                Outcome::Holds,
                &digest,
                &nonce
            ),
            "committer must be bound, or one attestor could open another's commitment"
        );
    }

    #[test]
    fn opens_with_checks_committer_outcome_digest_and_nonce_together() {
        let committer = PubKey::from_bytes([1; 32]);
        let claim = EventId::from_bytes([2; 32]);
        let experiment = [3u8; 32];
        let digest = [4u8; 32];
        let nonce = [5u8; 32];
        let hash = commitment_hash(
            &committer,
            &claim,
            &experiment,
            Outcome::Holds,
            &digest,
            &nonce,
        );
        let c = Commitment {
            id: EventId::from_bytes([0; 32]),
            committer,
            created_at: 0,
            claim,
            experiment,
            hash,
        };

        assert!(c.opens_with(&committer, Outcome::Holds, &digest, &nonce));
        assert!(!c.opens_with(&committer, Outcome::Fails, &digest, &nonce));
        assert!(!c.opens_with(&committer, Outcome::Holds, &digest, &[0; 32]));
        assert!(!c.opens_with(
            &PubKey::from_bytes([9; 32]),
            Outcome::Holds,
            &digest,
            &nonce
        ));
    }

    #[test]
    fn rejects_a_malformed_commitment() {
        let tags = vec![
            vec!["e".into(), "a".repeat(64), String::new(), "claim".into()],
            vec!["experiment".into(), "not-hex".into()],
            vec!["hash".into(), "c".repeat(64)],
        ];
        assert!(matches!(
            Commitment::from_event(&event(tags)),
            Err(Error::BadTag {
                tag: "experiment",
                ..
            })
        ));
    }

    #[test]
    fn rejects_the_wrong_kind() {
        let mut ev = event(vec![
            vec!["e".into(), "a".repeat(64), String::new(), "claim".into()],
            vec!["experiment".into(), "b".repeat(64)],
            vec!["hash".into(), "c".repeat(64)],
        ]);
        ev.kind = kinds::ATTESTATION;
        assert_eq!(
            Commitment::from_event(&ev),
            Err(Error::WrongKind {
                expected: kinds::COMMITMENT,
                got: kinds::ATTESTATION
            })
        );
    }
}
