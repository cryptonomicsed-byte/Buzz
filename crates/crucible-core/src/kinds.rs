//! Crucible's Nostr kind allocation.
//!
//! Buzz dispatches on the `kind` integer and reserves `40000..=49999` for its own
//! custom events, of which it currently uses `40002`, `40003`, `40100`, `43001`,
//! `45001`, `45003` and `46001..=46012`. Crucible claims the contiguous, unused
//! `47000` block so that a Crucible-aware relay and a stock Buzz relay can share
//! a database without either one reinterpreting the other's events.
//!
//! A stock Buzz relay stores and serves these events untouched — it just has no
//! opinion about them. That is the whole integration story: Crucible needs no
//! relay fork, only a relay that honours NIP-01.

/// A falsifiable proposition entering the shared belief space.
pub const CLAIM: u32 = 47001;

/// The signed record of one agent independently executing a claim's falsifier.
pub const ATTESTATION: u32 = 47002;

/// An adversarial bet, backed by staked reputation, that a claim is false.
pub const CHALLENGE: u32 = 47003;

/// The resolution kernel's derived epistemic status for a claim.
pub const VERDICT: u32 = 47004;

/// A proper-scoring-rule update to an agent's per-domain reliability.
pub const CALIBRATION: u32 = 47005;

/// A digest of current belief, so a joining agent bootstraps in one fetch
/// instead of replaying the whole log.
pub const BELIEF_SNAPSHOT: u32 = 47006;

/// Announcement of a content-addressed falsifier module and its capability
/// manifest, so falsifiers are themselves discoverable and reusable.
pub const FALSIFIER_MANIFEST: u32 = 47007;

/// A commitment to an attestation's outcome, published *before* the attestor
/// could have seen any other attestation or verdict on the claim, so that a
/// later claim of `blind: true` is checkable rather than merely asserted.
pub const COMMITMENT: u32 = 47008;

/// Every kind Crucible defines, in ascending order.
pub const ALL: [u32; 8] = [
    CLAIM,
    ATTESTATION,
    CHALLENGE,
    VERDICT,
    CALIBRATION,
    BELIEF_SNAPSHOT,
    FALSIFIER_MANIFEST,
    COMMITMENT,
];

/// The half-open range Crucible reserves. Anything outside it is not ours, and
/// the kernel must ignore it rather than guess.
pub const RESERVED: core::ops::Range<u32> = 47000..48000;

/// True when `kind` falls inside Crucible's reserved block.
pub const fn is_crucible(kind: u32) -> bool {
    kind >= RESERVED.start && kind < RESERVED.end
}

/// Human-readable name for a Crucible kind, for logs and the CLI.
pub const fn name(kind: u32) -> Option<&'static str> {
    Some(match kind {
        CLAIM => "claim",
        ATTESTATION => "attestation",
        CHALLENGE => "challenge",
        VERDICT => "verdict",
        CALIBRATION => "calibration",
        BELIEF_SNAPSHOT => "belief-snapshot",
        FALSIFIER_MANIFEST => "falsifier-manifest",
        COMMITMENT => "commitment",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the 47000 block is that it cannot collide with Buzz. If
    /// someone widens `ALL` into a kind Buzz already uses, this fails loudly.
    #[test]
    fn does_not_collide_with_known_buzz_kinds() {
        let buzz: Vec<u32> = vec![7, 9, 22242, 27235, 40002, 40003, 40100, 43001, 45001, 45003]
            .into_iter()
            .chain(46001..=46012)
            .collect();
        for k in ALL {
            assert!(is_crucible(k), "kind {k} escaped the reserved block");
            assert!(!buzz.contains(&k), "kind {k} collides with a Buzz kind");
        }
    }

    #[test]
    fn every_reserved_kind_has_a_name() {
        for k in ALL {
            assert!(name(k).is_some(), "kind {k} has no name");
        }
        assert_eq!(name(9), None, "Buzz's own kinds must not be named by us");
    }

    #[test]
    fn all_is_sorted_and_unique() {
        let mut sorted = ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, ALL);
        let mut deduped = ALL.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), ALL.len());
    }
}
