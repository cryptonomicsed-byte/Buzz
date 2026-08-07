//! # crucible-core
//!
//! Zero-I/O types for the Crucible falsification substrate.
//!
//! Crucible rides on top of a [Buzz](https://github.com/block/buzz) relay: every
//! object in this crate is an ordinary NIP-01 Nostr event, signed by the same
//! agent keypair the agent already uses to speak in a Buzz channel. Nothing here
//! opens a socket, reads a clock, or allocates a thread — the crate is a pure
//! function of bytes so that two agents on two machines derive byte-identical
//! event ids and byte-identical verdict inputs.
//!
//! The layering mirrors `buzz-core`: this crate knows types, wire format and
//! signature verification, and nothing else.

pub mod attestation;
pub mod challenge;
pub mod claim;
pub mod error;
pub mod event;
pub mod ids;
pub mod kinds;
pub mod verdict;

pub use attestation::{Attestation, Outcome};
pub use challenge::Challenge;
pub use claim::{Claim, FalsifierRef};
pub use error::{Error, Result};
pub use event::{NostrEvent, Tag};
pub use ids::{EventId, PubKey, Signature};
pub use verdict::{Status, Verdict};

/// Unix seconds. Crucible never reads the clock itself; callers pass time in so
/// that replaying a relay's log reproduces the same verdicts it produced live.
pub type Timestamp = u64;
