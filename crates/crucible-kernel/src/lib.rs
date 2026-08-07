//! # crucible-kernel
//!
//! The resolution kernel: it decides what a Buzz room is entitled to believe.
//!
//! Buzz already proves *who said what*. This crate answers the question Buzz
//! deliberately leaves open — *and was any of it true?* — using only signed
//! events the relay already stores.
//!
//! Three ideas carry the design, and each exists because a simpler one fails in
//! a specific, observable way:
//!
//! 1. [`independence`] — evidence is discounted for redundancy, because ten
//!    agents sharing a model, a runner and a transcript are not ten witnesses.
//! 2. [`calibration`] — an agent's weight is earned per domain under a proper
//!    scoring rule, because otherwise the loudest agent wins.
//! 3. [`resolve`] — claims decay, conflict is distinguished from ignorance, and
//!    a non-deterministic falsifier poisons its own claim rather than being
//!    quietly averaged.
//!
//! Everything is a pure function of `(events, ledger, policy, now)`, so a
//! verdict is not an authority's ruling — it is a computation any member of the
//! room can rerun and contest.
//!
//! ## What this does not defend against
//!
//! Independence discounting defends against *correlated error*, not against an
//! adversary minting keypairs. Twenty sock puppets with distinct lineages and
//! distinct environments will read as twenty witnesses here. That defence is
//! Buzz's, not ours: agents are community members admitted by an operator with
//! `buzz-admin`, and a key that was never admitted has no standing. This is the
//! clearest single reason Crucible is built *on* Buzz instead of beside it — it
//! inherits exactly the admission control its threat model requires.

pub mod calibration;
pub mod independence;
pub mod policy;
pub mod resolve;

pub use calibration::{Ledger, Reliability};
pub use independence::{discount, effective_count, Contributor, Discounted};
pub use policy::Policy;
pub use resolve::{resolve, settle, Contribution, Exclusion, Resolution, Role};

#[cfg(test)]
mod tests;
