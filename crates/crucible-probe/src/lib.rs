//! # crucible-probe
//!
//! The sandbox a falsifier runs in.
//!
//! A claim in Crucible ships the executable that would prove it wrong, which
//! only works if running a stranger's executable is a reasonable thing to
//! agree to. This crate is what makes it reasonable: falsifiers are WebAssembly
//! modules with no imports beyond four host functions, metered in fuel rather
//! than seconds, and permitted to learn about the world only through
//! observation keys their manifest named in advance.
//!
//! ## The guest ABI
//!
//! A falsifier exports `memory` and `crucible_falsify()`, and may import from
//! the `crucible` module:
//!
//! ```text
//! input_len()                            -> i32   bytes of declared input JSON
//! input_read(ptr)                                 copy that JSON into memory
//! observe_len(key_ptr, key_len)          -> i32   size of an observation, -1 if ungathered
//! observe_read(key_ptr, key_len, out)             copy the observation in
//! emit(verdict, ptr, len)                         1 = holds, 2 = fails, 3 = indeterminate
//! ```
//!
//! There is deliberately no allocator, no clock, no randomness and no I/O. A
//! module that wants scratch space brings its own static buffer.
//!
//! ## Why an interpreter
//!
//! [`wasmi`] executes rather than compiles, which costs throughput and buys the
//! property the whole substrate is built on: two agents on two architectures
//! running the same module over the same inputs produce the same bytes. A JIT
//! would be faster and would make "the outputs diverged" ambiguous between *the
//! falsifier is broken* and *the backend optimised differently*. Probes are
//! small; determinism is not negotiable.

pub mod manifest;
pub mod sandbox;
pub mod vacuity;

pub use manifest::Manifest;
pub use sandbox::{Falsifier, Observations, ProbeError, ProbeResult, ENTRY_POINT, HOST_MODULE};
pub use vacuity::{audit_vacuity, VacuityAudit};

#[cfg(test)]
mod tests;
