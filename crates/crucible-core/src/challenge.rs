use crate::error::Result;
use crate::event::NostrEvent;
use crate::ids::{EventId, PubKey};
use crate::{kinds, Timestamp};

/// An adversarial bet that a claim is false (`kind:47003`).
///
/// Probing is work, and a room where nobody is paid to disagree converges on
/// whatever was said first. A challenge puts the challenger's own reliability
/// on the line: if the claim is later `Refuted` the challenger gains, and if it
/// is `Supported` they lose. That is what makes scepticism a strategy an agent
/// will actually adopt, and what stops it from being free to spray doubt at
/// everything.
#[derive(Clone, Debug, PartialEq)]
pub struct Challenge {
    pub id: EventId,
    pub challenger: PubKey,
    pub created_at: Timestamp,
    pub claim: EventId,
    /// Reliability staked, in `(0, 1]` of the challenger's current weight.
    pub stake: f64,
    /// An alternative falsifier the challenger believes will break the claim.
    /// Optional, but a challenge that ships one is doing the work rather than
    /// merely expressing a doubt.
    pub counter_falsifier: Option<[u8; 32]>,
    /// Why. Free text; carries no evidential weight on its own.
    pub reason: String,
}

impl Challenge {
    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::CHALLENGE)?;
        Ok(Self {
            id: ev.id,
            challenger: ev.pubkey,
            created_at: ev.created_at,
            claim: ev.subject()?,
            stake: ev.parse_tag("stake", "not a fraction in (0,1]", |v| {
                v.parse::<f64>().ok().filter(|s| s.is_finite() && *s > 0.0 && *s <= 1.0)
            })?,
            counter_falsifier: match ev.tag("counter") {
                None => None,
                Some(raw) => {
                    let mut out = [0u8; 32];
                    if raw.len() == 64 && hex::decode_to_slice(raw, &mut out).is_ok() {
                        Some(out)
                    } else {
                        return Err(crate::Error::BadTag {
                            tag: "counter",
                            value: raw.to_string(),
                            reason: "not a 32-byte hex module digest",
                        });
                    }
                }
            },
            reason: ev.content.clone(),
        })
    }

    pub fn to_unsigned_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["e".into(), self.claim.to_hex(), String::new(), "claim".into()],
            vec!["stake".into(), format!("{}", self.stake)],
        ];
        if let Some(c) = self.counter_falsifier {
            tags.push(vec!["counter".into(), hex::encode(c)]);
        }
        tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Signature;

    fn event(tags: Vec<Vec<String>>) -> NostrEvent {
        let mut ev = NostrEvent {
            id: EventId::from_bytes([0; 32]),
            pubkey: PubKey::from_bytes([3; 32]),
            created_at: 1_700_000_000,
            kind: kinds::CHALLENGE,
            tags,
            content: "the probe never touched the database".into(),
            sig: Signature::from_bytes([0; 64]),
        };
        ev.id = ev.compute_id();
        ev
    }

    fn base() -> Vec<Vec<String>> {
        vec![
            vec!["e".into(), "c".repeat(64), String::new(), "claim".into()],
            vec!["stake".into(), "0.25".into()],
        ]
    }

    #[test]
    fn parses_and_round_trips() {
        let c = Challenge::from_event(&event(base())).unwrap();
        assert_eq!(c.stake, 0.25);
        assert_eq!(c.counter_falsifier, None);
        assert_eq!(c.reason, "the probe never touched the database");
        assert_eq!(
            Challenge::from_event(&event(c.to_unsigned_tags())).unwrap(),
            c
        );
    }

    #[test]
    fn carries_an_optional_counter_falsifier() {
        let mut tags = base();
        tags.push(vec!["counter".into(), "f".repeat(64)]);
        let c = Challenge::from_event(&event(tags)).unwrap();
        assert_eq!(c.counter_falsifier, Some([0xff; 32]));
    }

    /// A zero stake is a free opinion, which is exactly what a challenge is not.
    #[test]
    fn rejects_stakes_outside_the_range() {
        for bad in ["0", "-0.5", "1.5", "NaN", "lots"] {
            let tags = vec![base()[0].clone(), vec!["stake".into(), bad.into()]];
            assert!(
                matches!(
                    Challenge::from_event(&event(tags)),
                    Err(crate::Error::BadTag { tag: "stake", .. })
                ),
                "stake {bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn rejects_a_malformed_counter_digest() {
        let mut tags = base();
        tags.push(vec!["counter".into(), "nope".into()]);
        assert!(matches!(
            Challenge::from_event(&event(tags)),
            Err(crate::Error::BadTag { tag: "counter", .. })
        ));
    }
}
