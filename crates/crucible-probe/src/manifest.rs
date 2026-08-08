//! Capability manifests: what a falsifier is allowed to know.
//!
//! A falsifier that could do anything would be a remote code execution
//! primitive with a philosophy attached. The manifest is the opposite: a
//! falsifier is a pure function, and the *only* way the world reaches it is
//! through observation keys the manifest names in advance. The runner gathers
//! those observations outside the sandbox and hands them in; the module itself
//! never opens a socket, reads a file, or reads a clock, because there is no
//! import through which it could.
//!
//! Two things fall out of that, and both are load-bearing elsewhere:
//!
//! * The blast radius of running a stranger's falsifier is exactly the
//!   observation list, which is signed into the claim as part of the manifest
//!   digest and can be read before deciding to run it.
//! * A manifest that names no observations describes a *pure* falsifier, which
//!   must produce identical output on every machine. That is what lets the
//!   kernel treat divergent output as a defect for some claims and as ordinary
//!   disagreement for others.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ceilings the sandbox will not exceed regardless of what a manifest asks for.
/// A manifest is written by whoever wrote the claim, which is to say: not
/// necessarily by someone acting in the prober's interest.
/// Roughly a second of interpreted execution, not a minute of it. A claim's
/// author picks the fuel figure, and whoever runs the probe pays for it — on a
/// phone, a generous cap is a claim that costs a stranger their battery.
pub const MAX_FUEL: u64 = 200_000_000;
pub const MAX_MEMORY_PAGES: u32 = 512; // 32 MiB
pub const MAX_OUTPUT: u32 = 65_536;

/// `serde(default)` so a manifest can state only what it grants. The
/// observation list is the part a reviewer must read; making them restate three
/// resource limits to say "this falsifier reads nothing" would be noise around
/// the one line that matters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Manifest {
    /// Observation keys the falsifier may request, e.g.
    /// `ci:status/block/buzz@deadbeef`. Anything else is refused at the host
    /// boundary. Sorted and deduplicated so the digest is canonical.
    pub observations: Vec<String>,
    /// Interpreter fuel. Bounds runtime without a wall clock, so the limit is
    /// itself deterministic — a probe that runs out of fuel does so identically
    /// on a fast machine and a slow one.
    pub fuel: u64,
    /// Linear memory ceiling, in 64 KiB pages.
    pub memory_pages: u32,
    /// Largest explanation the falsifier may emit.
    pub max_output: u32,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            observations: Vec::new(),
            fuel: 50_000_000,
            memory_pages: 64,
            max_output: 8192,
        }
    }
}

impl Manifest {
    /// A manifest granting nothing: the falsifier is a closed computation over
    /// its declared inputs.
    pub fn pure() -> Self {
        Self::default()
    }

    /// A manifest permitting exactly these observation keys.
    pub fn observing<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            observations: keys.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Sort and deduplicate so that two authors writing the same permissions in
    /// a different order produce the same digest.
    pub fn canonical(mut self) -> Self {
        self.observations.sort();
        self.observations.dedup();
        self.fuel = self.fuel.min(MAX_FUEL);
        self.memory_pages = self.memory_pages.min(MAX_MEMORY_PAGES);
        self.max_output = self.max_output.min(MAX_OUTPUT);
        self
    }

    /// True when the falsifier cannot observe anything, and so must produce
    /// identical output everywhere.
    pub fn is_pure(&self) -> bool {
        self.observations.is_empty()
    }

    pub fn permits(&self, key: &str) -> bool {
        self.observations.iter().any(|k| k == key)
    }

    /// SHA-256 of the canonical manifest — the value a claim signs.
    pub fn digest(&self) -> [u8; 32] {
        let canonical = self.clone().canonical();
        let bytes = serde_json::to_vec(&canonical).expect("manifest always serializes");
        Sha256::digest(bytes).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_granting_nothing_is_pure() {
        assert!(Manifest::pure().is_pure());
        assert!(!Manifest::observing(["ci:status"]).is_pure());
    }

    #[test]
    fn digest_is_order_and_duplicate_independent() {
        let a = Manifest::observing(["b", "a", "b"]);
        let b = Manifest::observing(["a", "b"]);
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn digest_changes_with_every_meaningful_field() {
        let base = Manifest::pure();
        let variants = [
            Manifest::observing(["ci:status"]),
            Manifest {
                fuel: 1,
                ..base.clone()
            },
            Manifest {
                memory_pages: 1,
                ..base.clone()
            },
            Manifest {
                max_output: 1,
                ..base.clone()
            },
        ];
        for v in variants {
            assert_ne!(base.digest(), v.digest(), "{v:?} hashed the same as base");
        }
    }

    /// A claim author choosing the limits must not be able to choose limits
    /// that hurt whoever runs the probe.
    #[test]
    fn canonicalization_clamps_hostile_limits() {
        let m = Manifest {
            fuel: u64::MAX,
            memory_pages: u32::MAX,
            max_output: u32::MAX,
            observations: vec![],
        }
        .canonical();
        assert_eq!(m.fuel, MAX_FUEL);
        assert_eq!(m.memory_pages, MAX_MEMORY_PAGES);
        assert_eq!(m.max_output, MAX_OUTPUT);
    }

    #[test]
    fn permits_only_what_is_listed() {
        let m = Manifest::observing(["ci:status", "git:head"]);
        assert!(m.permits("ci:status"));
        assert!(!m.permits("ci:statu"));
        assert!(!m.permits("secrets:aws"));
    }

    #[test]
    fn a_partial_manifest_takes_the_default_limits() {
        let m: Manifest = serde_json::from_str(r#"{"observations":["ci:status"]}"#).unwrap();
        assert_eq!(m.fuel, Manifest::default().fuel);
        assert!(!m.is_pure());

        let m: Manifest = serde_json::from_str("{}").unwrap();
        assert!(m.is_pure(), "granting nothing is the default");
        assert_eq!(m.digest(), Manifest::pure().digest());
    }

    #[test]
    fn round_trips_through_json() {
        let m = Manifest::observing(["a", "b"]).canonical();
        let back: Manifest = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.digest(), m.digest());
    }
}
