use crate::error::{Error, Result};
use crate::ids::{EventId, PubKey, Signature};
use crate::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A NIP-01 tag: a non-empty array of strings whose first element is the tag
/// name. Crucible keeps the raw shape rather than a typed enum so that tags a
/// future Buzz version adds survive a round trip through us untouched.
pub type Tag = Vec<String>;

/// A NIP-01 event, wire-identical to what a Buzz relay stores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: EventId,
    pub pubkey: PubKey,
    pub created_at: Timestamp,
    pub kind: u32,
    pub tags: Vec<Tag>,
    pub content: String,
    pub sig: Signature,
}

impl NostrEvent {
    /// The NIP-01 canonical serialization:
    /// `[0, <pubkey>, <created_at>, <kind>, <tags>, <content>]`, with no
    /// whitespace and only the six mandated escapes.
    ///
    /// `serde_json` emits exactly the escape set NIP-01 specifies (`\"`, `\\`,
    /// `\n`, `\r`, `\t`, `\b`, `\f`, and `\uXXXX` for other control characters)
    /// and leaves `/` and non-ASCII alone, so it is a conforming serializer
    /// here rather than a convenient approximation.
    pub fn canonical_bytes(
        pubkey: &PubKey,
        created_at: Timestamp,
        kind: u32,
        tags: &[Tag],
        content: &str,
    ) -> Vec<u8> {
        // A tuple serializes as a JSON array of mixed types, which is what the
        // spec asks for; building the string by hand would risk escape bugs.
        let doc = (0u8, pubkey.to_hex(), created_at, kind, tags, content);
        serde_json::to_vec(&doc).expect("canonical serialization of plain data cannot fail")
    }

    /// Compute the id this event *should* carry, ignoring the one it claims.
    pub fn compute_id(&self) -> EventId {
        let bytes = Self::canonical_bytes(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        let digest = Sha256::digest(bytes);
        EventId::from_bytes(digest.into())
    }

    /// Full NIP-01 validation: the id must be the hash of the content, and the
    /// signature must be a valid BIP-340 signature over that id by `pubkey`.
    ///
    /// Both halves matter. Checking the signature alone would let an attacker
    /// keep a valid signature while swapping the id an index is keyed on;
    /// checking the id alone authenticates nothing.
    pub fn verify(&self) -> Result<()> {
        let computed = self.compute_id();
        if computed != self.id {
            return Err(Error::IdMismatch {
                computed: computed.to_hex(),
                claimed: self.id.to_hex(),
            });
        }

        let vk = k256::schnorr::VerifyingKey::from_bytes(self.pubkey.as_bytes())
            .map_err(|_| Error::BadPubKey)?;
        let sig = k256::schnorr::Signature::try_from(self.sig.as_bytes().as_slice())
            .map_err(|_| Error::BadSignature)?;

        // `verify_raw`, deliberately, not the `Verifier` trait: that trait's
        // `verify` SHA-256-hashes the message before running BIP-340, and Nostr
        // signs the 32-byte event id itself. Using it would make us reject every
        // genuine Nostr event while happily accepting our own malformed ones.
        vk.verify_raw(self.id.as_bytes(), &sig)
            .map_err(|_| Error::BadSignature)
    }

    /// Value of the first tag named `name`, if any.
    ///
    /// NIP-01 lets a tag repeat; "first wins" is the convention Buzz follows for
    /// single-valued tags, and taking the last would let an appended duplicate
    /// silently override a signed value's intent.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    }

    /// Every value under tags named `name`.
    pub fn tag_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.tags
            .iter()
            .filter(move |t| t.first().map(String::as_str) == Some(name))
            .filter_map(|t| t.get(1))
            .map(String::as_str)
    }

    /// The whole first tag row named `name`, for tags with positional extras.
    pub fn tag_row(&self, name: &str) -> Option<&[String]> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .map(Vec::as_slice)
    }

    pub fn require_tag(&self, name: &'static str) -> Result<&str> {
        self.tag(name).ok_or(Error::MissingTag(name))
    }

    /// Parse a tag value with `f`, reporting which tag failed and why.
    pub fn parse_tag<T>(
        &self,
        name: &'static str,
        reason: &'static str,
        f: impl Fn(&str) -> Option<T>,
    ) -> Result<T> {
        let raw = self.require_tag(name)?;
        f(raw).ok_or_else(|| Error::BadTag {
            tag: name,
            value: raw.to_string(),
            reason,
        })
    }

    pub fn expect_kind(&self, expected: u32) -> Result<()> {
        if self.kind == expected {
            Ok(())
        } else {
            Err(Error::WrongKind {
                expected,
                got: self.kind,
            })
        }
    }

    /// The first `e` tag, i.e. the event this one is about.
    pub fn subject(&self) -> Result<EventId> {
        self.parse_tag("e", "not a 32-byte hex event id", |v| {
            EventId::parse_hex(v).ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, published Nostr event. If our canonical serialization drifts by
    /// so much as a space, this id stops matching.
    fn known_good() -> NostrEvent {
        // Vector from the NIP-01 test corpus: kind 1, no tags, ASCII content.
        serde_json::from_str(
            r#"{
              "id":"4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65",
              "pubkey":"6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93",
              "created_at":1673347337,
              "kind":1,
              "tags":[["e","3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206"],["p","bf2376e17ba4ec269d10fcc996a4746b451152be9031fa48e74553dde5526bce"]],
              "content":"Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls.",
              "sig":"908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262"
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn computes_the_canonical_id() {
        let ev = known_good();
        assert_eq!(ev.compute_id(), ev.id);
    }

    #[test]
    fn verifies_a_real_signature() {
        known_good().verify().expect("known-good event must verify");
    }

    #[test]
    fn rejects_a_tampered_content() {
        let mut ev = known_good();
        ev.content.push('!');
        // Content changed but id did not: caught as an id mismatch.
        assert!(matches!(ev.verify(), Err(Error::IdMismatch { .. })));
    }

    #[test]
    fn rejects_a_recomputed_id_with_a_stale_signature() {
        // The subtler attack: fix up the id so it matches the new content. The
        // signature no longer covers it, and only the Schnorr check catches this.
        let mut ev = known_good();
        ev.content.push('!');
        ev.id = ev.compute_id();
        assert_eq!(ev.verify(), Err(Error::BadSignature));
    }

    #[test]
    fn rejects_a_flipped_signature_bit() {
        let mut ev = known_good();
        let mut sig = *ev.sig.as_bytes();
        sig[63] ^= 0x01;
        ev.sig = Signature::from_bytes(sig);
        assert_eq!(ev.verify(), Err(Error::BadSignature));
    }

    #[test]
    fn canonical_form_escapes_per_nip01() {
        let pk = PubKey::from_bytes([0xab; 32]);
        // Quote, backslash, newline, tab, a control char with no short escape,
        // a solidus, and a non-ASCII codepoint.
        let content = "a\"b\\c\nd\te\u{1}f/g\u{e9}";
        let bytes = NostrEvent::canonical_bytes(&pk, 1, 47001, &[], content);
        let s = String::from_utf8(bytes).unwrap();

        let expected = concat!(
            r#"a\"b\\c\nd\te"#,  // the short escapes NIP-01 mandates
            r#"\u0001"#,           // everything else control -> \uXXXX
            "f/g\u{e9}",           // solidus and non-ASCII pass through raw
        );
        assert!(s.contains(expected), "canonical escaping drifted:\n{s}");
    }

    #[test]
    fn tag_lookup_prefers_the_first_occurrence() {
        let mut ev = known_good();
        ev.tags.push(vec!["conf".into(), "0.9".into()]);
        ev.tags.push(vec!["conf".into(), "0.1".into()]);
        assert_eq!(ev.tag("conf"), Some("0.9"));
        assert_eq!(ev.tag_values("conf").collect::<Vec<_>>(), ["0.9", "0.1"]);
        assert_eq!(ev.tag("nope"), None);
    }

    #[test]
    fn round_trips_through_json() {
        let ev = known_good();
        let back: NostrEvent = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(ev, back);
        back.verify().unwrap();
    }
}
