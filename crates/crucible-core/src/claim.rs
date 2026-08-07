use crate::error::{Error, Result};
use crate::event::NostrEvent;
use crate::ids::{EventId, PubKey};
use crate::{kinds, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How a claim can be proven wrong.
///
/// This is the load-bearing idea of the whole substrate. In a Buzz channel an
/// agent can say "the migration is safe" and the relay will faithfully record
/// *that it said so*. Crucible will not accept the proposition into shared
/// belief unless the author also ships the thing that would embarrass them: a
/// deterministic, content-addressed predicate that returns `false` if the claim
/// is wrong. No falsifier, no claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsifierRef {
    /// SHA-256 of the WASM module bytes. Content addressing means "run the
    /// falsifier" is unambiguous across machines and across time.
    pub module: [u8; 32],
    /// SHA-256 of the capability manifest the module is allowed to use.
    /// Bundling it into the reference makes the claim's blast radius part of
    /// what the author signed.
    pub manifest: [u8; 32],
    /// SHA-256 of the canonical declared inputs. Two attestations are only
    /// comparable when module, manifest *and* inputs all match.
    pub inputs: [u8; 32],
    /// Whether the falsifier is a function of its declared inputs alone.
    ///
    /// This distinction is not decoration; it decides what disagreement *means*.
    /// A pure falsifier — one whose manifest grants no host capabilities — must
    /// produce the same output everywhere, so two agents getting different
    /// output proves the falsifier is broken. An observational falsifier reads
    /// the world (queries CI, resolves a host, opens a socket), so different
    /// output means the *world* looked different to two observers, which is
    /// ordinary disagreement and must be resolved as evidence, not reported as
    /// a defect. Conflating the two would flag every useful probe as broken.
    ///
    /// Derived from the capability manifest, so it cannot be claimed falsely
    /// without changing the manifest digest the author signed.
    pub pure: bool,
}

impl FalsifierRef {
    /// The identity two attestations must share to be talking about the same
    /// experiment.
    pub fn experiment_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.module);
        h.update(self.manifest);
        h.update(self.inputs);
        h.update([u8::from(self.pure)]);
        h.finalize().into()
    }
}

/// The JSON carried in a claim event's `content` field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimBody {
    /// The proposition, in plain language, for humans and for agents that have
    /// to decide whether it is worth probing.
    pub statement: String,
    /// Why the author believes it. Never treated as evidence — only the
    /// falsifier is evidence — but it is what a reader needs to judge the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// Inputs handed to the falsifier. Serialized through `serde_json::Value`,
    /// whose object representation is a sorted map, so the digest is stable.
    #[serde(default)]
    pub inputs: serde_json::Value,
}

impl ClaimBody {
    /// SHA-256 over the canonical (key-sorted, whitespace-free) inputs.
    pub fn inputs_digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(&self.inputs).expect("Value always serializes");
        Sha256::digest(bytes).into()
    }
}

/// A falsifiable proposition (`kind:47001`), parsed from its signed event.
#[derive(Clone, Debug, PartialEq)]
pub struct Claim {
    pub id: EventId,
    pub author: PubKey,
    pub created_at: Timestamp,
    /// Buzz community/channel this claim lives in. Belief is scoped to a room;
    /// two Buzz communities may legitimately believe different things.
    pub community: String,
    /// Calibration bucket, e.g. `ci`, `security`, `perf`. Reliability is
    /// per-domain because an agent excellent at reading build logs may be
    /// terrible at judging schema migrations.
    pub domain: String,
    /// The author's stated probability, in the open interval (0, 1).
    pub confidence: f64,
    /// Seconds after which the claim's evidence is worth half as much. A claim
    /// about `main` being green has a half-life of minutes; a claim about a
    /// licence has one of months. Beliefs here are perishable by construction.
    pub half_life: u64,
    /// Hard stop, after which the claim is `Decayed` regardless of evidence.
    pub expiry: Option<Timestamp>,
    pub falsifier: FalsifierRef,
    pub body: ClaimBody,
    /// The author's own lineage and environment, so the kernel can tell when an
    /// attestor is really just the author agreeing with itself from a second
    /// process. Untagged claims default to values derived from the author's
    /// key, which correlate with nothing — the safe direction to be wrong in,
    /// since the alternative would have every untagged claim in the room look
    /// like one voice.
    pub provenance: crate::attestation::Provenance,
}

fn parse_unit_interval(s: &str) -> Option<f64> {
    let v: f64 = s.parse().ok()?;
    (v.is_finite() && v > 0.0 && v < 1.0).then_some(v)
}

fn parse_digest(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (s.len() == 64 && hex::decode_to_slice(s, &mut out).is_ok()).then_some(out)
}

impl Claim {
    /// Parse and validate a `kind:47001` event.
    ///
    /// This does *not* verify the signature — callers decide when to pay for
    /// that, and [`NostrEvent::verify`] is the single place it happens.
    pub fn from_event(ev: &NostrEvent) -> Result<Self> {
        ev.expect_kind(kinds::CLAIM)?;

        let body: ClaimBody =
            serde_json::from_str(&ev.content).map_err(|e| Error::BadContent(e.to_string()))?;

        let confidence = ev.parse_tag("conf", "not a probability in (0,1)", parse_unit_interval)?;
        let half_life = ev.parse_tag("halflife", "not a positive integer", |v| {
            v.parse::<u64>().ok().filter(|s| *s > 0)
        })?;

        let expiry = match ev.tag("expiry") {
            None => None,
            Some(raw) => Some(raw.parse::<u64>().map_err(|_| Error::BadTag {
                tag: "expiry",
                value: raw.to_string(),
                reason: "not a unix timestamp",
            })?),
        };

        // ["falsifier", <module-digest>, "wasm", <manifest-digest>, <purity>]
        let row = ev.tag_row("falsifier").ok_or(Error::MissingTag("falsifier"))?;
        let bad = |reason| Error::BadTag {
            tag: "falsifier",
            value: row.join(","),
            reason,
        };
        let module = row.get(1).and_then(|s| parse_digest(s)).ok_or_else(|| {
            bad("first value must be the module's 32-byte sha256, hex-encoded")
        })?;
        if row.get(2).map(String::as_str) != Some("wasm") {
            return Err(bad("only the `wasm` falsifier type exists"));
        }
        let manifest = row
            .get(3)
            .and_then(|s| parse_digest(s))
            .ok_or_else(|| bad("third value must be the capability manifest's sha256"))?;
        // Absent means observational — the conservative reading. Defaulting to
        // `pure` would let an untagged world-reading probe be condemned as
        // broken the first time two agents saw different worlds.
        let pure = match row.get(4).map(String::as_str) {
            None | Some("observational") => false,
            Some("pure") => true,
            Some(_) => return Err(bad("purity must be `pure` or `observational`")),
        };

        Ok(Self {
            id: ev.id,
            author: ev.pubkey,
            created_at: ev.created_at,
            community: ev.require_tag("c")?.to_string(),
            domain: ev.require_tag("domain")?.to_string(),
            confidence,
            half_life,
            expiry,
            falsifier: FalsifierRef {
                module,
                manifest,
                inputs: body.inputs_digest(),
                pure,
            },
            provenance: crate::attestation::Provenance {
                lineage: ev
                    .tag("lineage")
                    .map_or_else(|| format!("key:{}", ev.pubkey.to_hex()), str::to_string),
                env: ev
                    .tag("env")
                    .map_or_else(|| format!("key:{}", ev.pubkey.to_hex()), str::to_string),
                // An author asserts before any attestation exists, so it cannot
                // have been herding when it did.
                blind: true,
            },
            body,
        })
    }

    /// Build the unsigned parts of a claim event. Signing stays outside this
    /// crate: keys belong to the agent's Buzz identity, not to Crucible.
    pub fn to_unsigned_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["c".into(), self.community.clone()],
            vec!["domain".into(), self.domain.clone()],
            vec!["conf".into(), format!("{}", self.confidence)],
            vec!["halflife".into(), self.half_life.to_string()],
            vec![
                "falsifier".into(),
                hex::encode(self.falsifier.module),
                "wasm".into(),
                hex::encode(self.falsifier.manifest),
                if self.falsifier.pure { "pure" } else { "observational" }.into(),
            ],
        ];
        if let Some(e) = self.expiry {
            tags.push(vec!["expiry".into(), e.to_string()]);
        }
        tags.push(vec!["lineage".into(), self.provenance.lineage.clone()]);
        tags.push(vec!["env".into(), self.provenance.env.clone()]);
        tags
    }

    /// Weight of evidence gathered `age` seconds ago, under this claim's
    /// half-life. Exactly `0.5` at one half-life, by definition.
    pub fn decay(&self, age_seconds: u64) -> f64 {
        // `exp2(-age/T)` rather than `exp(-ln2*age/T)`: one operation, and it is
        // exactly 0.5 at age == T instead of 0.49999999999999994.
        (-(age_seconds as f64) / self.half_life as f64).exp2()
    }

    /// Whether the claim is past its hard expiry at `now`.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expiry.is_some_and(|e| now >= e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Signature;

    fn event(tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
        let mut ev = NostrEvent {
            id: EventId::from_bytes([0; 32]),
            pubkey: PubKey::from_bytes([7; 32]),
            created_at: 1_700_000_000,
            kind: kinds::CLAIM,
            tags,
            content: content.into(),
            sig: Signature::from_bytes([0; 64]),
        };
        ev.id = ev.compute_id();
        ev
    }

    fn ok_tags() -> Vec<Vec<String>> {
        vec![
            vec!["c".into(), "eng".into()],
            vec!["domain".into(), "ci".into()],
            vec!["conf".into(), "0.82".into()],
            vec!["halflife".into(), "900".into()],
            vec![
                "falsifier".into(),
                "a".repeat(64),
                "wasm".into(),
                "b".repeat(64),
                "pure".into(),
            ],
        ]
    }

    const OK_BODY: &str = r#"{"statement":"main is green","inputs":{"repo":"buzz","sha":"deadbeef"}}"#;

    #[test]
    fn parses_a_well_formed_claim() {
        let c = Claim::from_event(&event(ok_tags(), OK_BODY)).unwrap();
        assert_eq!(c.community, "eng");
        assert_eq!(c.domain, "ci");
        assert_eq!(c.confidence, 0.82);
        assert_eq!(c.half_life, 900);
        assert_eq!(c.expiry, None);
        assert_eq!(c.body.statement, "main is green");
        assert_eq!(c.falsifier.module, [0xaa; 32]);
    }

    #[test]
    fn round_trips_its_tags() {
        let c = Claim::from_event(&event(ok_tags(), OK_BODY)).unwrap();
        let back = Claim::from_event(&event(c.to_unsigned_tags(), OK_BODY)).unwrap();
        assert_eq!(c, back);
    }

    /// The entire premise: an unfalsifiable assertion is not a claim.
    #[test]
    fn rejects_a_claim_with_no_falsifier() {
        let tags: Vec<_> = ok_tags()
            .into_iter()
            .filter(|t| t[0] != "falsifier")
            .collect();
        assert_eq!(
            Claim::from_event(&event(tags, OK_BODY)),
            Err(Error::MissingTag("falsifier"))
        );
    }

    #[test]
    fn rejects_certainty() {
        // 0 and 1 are not probabilities an agent may assert: they are immune to
        // evidence, and a log-odds score of a certain-and-wrong agent is
        // infinite. The scoring rule needs the open interval.
        for bad in ["0", "1", "1.5", "-0.2", "NaN", "inf", "green"] {
            let tags: Vec<_> = ok_tags()
                .into_iter()
                .map(|t| {
                    if t[0] == "conf" {
                        vec!["conf".into(), bad.into()]
                    } else {
                        t
                    }
                })
                .collect();
            assert!(
                matches!(
                    Claim::from_event(&event(tags, OK_BODY)),
                    Err(Error::BadTag { tag: "conf", .. })
                ),
                "confidence {bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn rejects_a_zero_half_life() {
        let tags: Vec<_> = ok_tags()
            .into_iter()
            .map(|t| {
                if t[0] == "halflife" {
                    vec!["halflife".into(), "0".into()]
                } else {
                    t
                }
            })
            .collect();
        assert!(matches!(
            Claim::from_event(&event(tags, OK_BODY)),
            Err(Error::BadTag {
                tag: "halflife",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_non_wasm_falsifier() {
        let tags: Vec<_> = ok_tags()
            .into_iter()
            .map(|t| {
                if t[0] == "falsifier" {
                    vec![
                        "falsifier".into(),
                        "a".repeat(64),
                        "shell".into(),
                        "b".repeat(64),
                    ]
                } else {
                    t
                }
            })
            .collect();
        // A shell probe cannot be replayed identically on another machine, so
        // its results would not be comparable — which is the point of the
        // sandbox.
        assert!(matches!(
            Claim::from_event(&event(tags, OK_BODY)),
            Err(Error::BadTag {
                tag: "falsifier",
                ..
            })
        ));
    }

    #[test]
    fn rejects_the_wrong_kind() {
        let mut ev = event(ok_tags(), OK_BODY);
        ev.kind = kinds::ATTESTATION;
        assert_eq!(
            Claim::from_event(&ev),
            Err(Error::WrongKind {
                expected: kinds::CLAIM,
                got: kinds::ATTESTATION
            })
        );
    }

    /// Two agents writing the same inputs in a different key order must produce
    /// the same experiment id, or every attestation would look incomparable.
    #[test]
    fn inputs_digest_is_key_order_independent() {
        let a: ClaimBody =
            serde_json::from_str(r#"{"statement":"s","inputs":{"a":1,"b":[2,3],"c":{"d":4}}}"#)
                .unwrap();
        let b: ClaimBody =
            serde_json::from_str(r#"{"statement":"s","inputs":{"c":{"d":4},"b":[2,3],"a":1}}"#)
                .unwrap();
        assert_eq!(a.inputs_digest(), b.inputs_digest());
    }

    #[test]
    fn inputs_digest_is_array_order_dependent() {
        // Arrays are sequences, not sets: reordering them changes the experiment.
        let a: ClaimBody = serde_json::from_str(r#"{"statement":"s","inputs":[1,2]}"#).unwrap();
        let b: ClaimBody = serde_json::from_str(r#"{"statement":"s","inputs":[2,1]}"#).unwrap();
        assert_ne!(a.inputs_digest(), b.inputs_digest());
    }

    #[test]
    fn experiment_id_binds_all_three_components() {
        let base = FalsifierRef {
            module: [1; 32],
            manifest: [2; 32],
            inputs: [3; 32],
            pure: true,
        };
        for altered in [
            FalsifierRef {
                module: [9; 32],
                ..base.clone()
            },
            FalsifierRef {
                manifest: [9; 32],
                ..base.clone()
            },
            FalsifierRef {
                inputs: [9; 32],
                ..base.clone()
            },
            FalsifierRef {
                pure: false,
                ..base.clone()
            },
        ] {
            assert_ne!(base.experiment_id(), altered.experiment_id());
        }
    }

    #[test]
    fn decay_halves_at_one_half_life() {
        let c = Claim::from_event(&event(ok_tags(), OK_BODY)).unwrap();
        assert_eq!(c.decay(0), 1.0);
        assert_eq!(c.decay(900), 0.5, "must be exactly a half, not 0.4999…");
        assert_eq!(c.decay(1800), 0.25);
        assert!(c.decay(90_000) < 1e-30);
    }

    #[test]
    fn expiry_is_inclusive() {
        let mut tags = ok_tags();
        tags.push(vec!["expiry".into(), "1700000500".into()]);
        let c = Claim::from_event(&event(tags, OK_BODY)).unwrap();
        assert!(!c.is_expired(1_700_000_499));
        assert!(c.is_expired(1_700_000_500));
    }
}
