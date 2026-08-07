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
//! 2. [`calibration`] — an agent's weight is earned per domain, and confident
//!    errors cost more than hedged ones, because otherwise the loudest agent
//!    wins. (The update is a confidence-weighted Beta posterior, *not* a proper
//!    scoring rule; see [`calibration::Reliability::record`] for what that does
//!    and does not buy.)
//! 3. [`resolve`] — claims decay, conflict is distinguished from ignorance, and
//!    a non-deterministic falsifier poisons its own claim rather than being
//!    quietly averaged.
//!
//! Everything is a pure function of `(events, ledger, policy, now)`, so a
//! verdict is not an authority's ruling — it is a computation any member of the
//! room can rerun and contest.
//!
//! Two caveats on that, both real. The arithmetic uses `exp`/`ln`, which are
//! not correctly rounded and may differ in the last bit between libm
//! implementations; agreement across platforms is therefore near-certain rather
//! than guaranteed, and a claim sitting exactly on a threshold could in
//! principle resolve differently. And determinism given identical inputs says
//! nothing about whether your inputs were *complete* — a relay that withholds
//! the refuting attestations yields a confident, fully auditable, wrong
//! verdict. Reading from more than one relay is the mitigation, and Crucible
//! does not implement it.
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
//!
//! [`Policy::roster`] is where that membership set goes, and it is the
//! difference between a demo and a deployment: with no roster, three free
//! keypairs declaring three invented lineages reach `Supported` in under a
//! second, and no amount of arithmetic over the events can prevent it, because
//! the events are exactly what the adversary controls.

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
