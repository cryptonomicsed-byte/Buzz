//! Sandbox tests.
//!
//! The falsifiers here are written in WebAssembly text so that what the guest
//! actually does is visible in the test rather than hidden behind a build step.
//! Several of them are deliberately hostile: the sandbox's job is to make
//! running a stranger's code a reasonable thing to agree to, and that claim is
//! only worth anything if the strangers in the test suite are trying.

use crate::manifest::Manifest;
use crate::sandbox::{Falsifier, Observations, ProbeError};
use crucible_core::Outcome;
use sha2::{Digest, Sha256};

fn wasm(text: &str) -> Vec<u8> {
    wat::parse_str(text).expect("test module must assemble")
}

fn load(text: &str, manifest: Manifest) -> Falsifier {
    Falsifier::load(&wasm(text), manifest, None).expect("test module must load")
}

/// Emits `holds` with a fixed explanation. The simplest well-behaved falsifier.
const ALWAYS_HOLDS: &str = r#"
(module
  (import "crucible" "emit" (func $emit (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "ok")
  (func (export "crucible_falsify")
    (call $emit (i32.const 1) (i32.const 0) (i32.const 2))))
"#;

/// Reads its declared inputs and refutes when the first byte is `x`.
const READS_INPUT: &str = r#"
(module
  (import "crucible" "input_len" (func $input_len (result i32)))
  (import "crucible" "input_read" (func $input_read (param i32)))
  (import "crucible" "emit" (func $emit (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "checked")
  (func (export "crucible_falsify")
    (if (i32.eqz (call $input_len)) (then (call $emit (i32.const 3) (i32.const 100) (i32.const 0)) (return)))
    (call $input_read (i32.const 0))
    (if (i32.eq (i32.load8_u (i32.const 0)) (i32.const 120))
      (then (call $emit (i32.const 2) (i32.const 100) (i32.const 7)))
      (else (call $emit (i32.const 1) (i32.const 100) (i32.const 7))))))
"#;

/// Asks the host for `ci:status` and holds when it starts with `g`.
const OBSERVES_CI: &str = r#"
(module
  (import "crucible" "observe_len" (func $olen (param i32 i32) (result i32)))
  (import "crucible" "observe_read" (func $oread (param i32 i32 i32)))
  (import "crucible" "emit" (func $emit (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "ci:status")
  (func (export "crucible_falsify")
    (local $n i32)
    (local.set $n (call $olen (i32.const 0) (i32.const 9)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (call $emit (i32.const 3) (i32.const 0) (i32.const 0)) (return)))
    (call $oread (i32.const 0) (i32.const 9) (i32.const 200))
    (if (i32.eq (i32.load8_u (i32.const 200)) (i32.const 103))
      (then (call $emit (i32.const 1) (i32.const 200) (local.get $n)))
      (else (call $emit (i32.const 2) (i32.const 200) (local.get $n))))))
"#;

/// Reaches for something no manifest here grants.
const READS_SECRETS: &str = r#"
(module
  (import "crucible" "observe_len" (func $olen (param i32 i32) (result i32)))
  (import "crucible" "emit" (func $emit (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "secrets:aws")
  (func (export "crucible_falsify")
    (drop (call $olen (i32.const 0) (i32.const 11)))
    (call $emit (i32.const 1) (i32.const 0) (i32.const 0))))
"#;

const SPINS_FOREVER: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "crucible_falsify") (loop $l (br $l))))
"#;

const TRAPS: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "crucible_falsify") (unreachable)))
"#;

const SAYS_NOTHING: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "crucible_falsify")))
"#;

// ------------------------------------------------------------------- happy path

#[test]
fn a_well_behaved_falsifier_reports_its_verdict() {
    let r = load(ALWAYS_HOLDS, Manifest::pure()).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Holds);
    assert_eq!(r.explanation, b"ok");
    assert_eq!(r.failure, None);
    assert!(r.fuel_used > 0, "fuel accounting must actually count");
}

#[test]
fn a_falsifier_sees_its_declared_inputs() {
    let f = load(READS_INPUT, Manifest::pure());
    assert_eq!(f.run(b"ok", Observations::new()).outcome, Outcome::Holds);
    assert_eq!(f.run(b"xx", Observations::new()).outcome, Outcome::Fails);
}

#[test]
fn a_falsifier_sees_the_observations_its_manifest_grants() {
    let f = load(OBSERVES_CI, Manifest::observing(["ci:status"]));

    let mut green = Observations::new();
    green.insert("ci:status".into(), b"green".to_vec());
    let r = f.run(b"{}", green);
    assert_eq!(r.outcome, Outcome::Holds);
    assert_eq!(r.observed, ["ci:status"]);

    let mut red = Observations::new();
    red.insert("ci:status".into(), b"red".to_vec());
    assert_eq!(f.run(b"{}", red).outcome, Outcome::Fails);
}

/// An observation the manifest permits but the runner never gathered must not
/// look like an empty one, or the falsifier would confidently judge a world it
/// never saw.
#[test]
fn an_ungathered_observation_is_reported_as_missing() {
    let f = load(OBSERVES_CI, Manifest::observing(["ci:status"]));
    let r = f.run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
}

// ------------------------------------------------------------------ containment

/// The central promise: a falsifier learns nothing its manifest did not name.
#[test]
fn a_falsifier_cannot_reach_past_its_manifest() {
    let r = load(READS_SECRETS, Manifest::observing(["ci:status"])).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
    let failure = r.failure.unwrap();
    assert!(
        failure.contains("secrets:aws") && failure.contains("manifest"),
        "the refusal must name what was refused: {failure}"
    );
}

/// …and being refused must stop it, not merely disappoint it. A guest that
/// could treat denial as an empty value would go on to emit a verdict.
#[test]
fn a_refused_observation_halts_the_run() {
    let r = load(READS_SECRETS, Manifest::pure()).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
    assert!(
        r.explanation.is_empty(),
        "it must not have reached its emit"
    );
}

/// Even when the runner has the secret sitting in memory for another probe.
#[test]
fn gathered_observations_outside_the_manifest_stay_invisible() {
    let mut obs = Observations::new();
    obs.insert("secrets:aws".into(), b"AKIA...".to_vec());
    obs.insert("ci:status".into(), b"green".to_vec());

    let r = load(READS_SECRETS, Manifest::observing(["ci:status"])).run(b"{}", obs);
    assert_eq!(r.outcome, Outcome::Indeterminate);
    assert!(!r.explanation.windows(4).any(|w| w == b"AKIA"));
}

#[test]
fn a_module_importing_anything_else_is_rejected_before_it_runs() {
    let hostile = wasm(
        r#"(module
             (import "wasi_snapshot_preview1" "fd_write"
               (func $w (param i32 i32 i32 i32) (result i32)))
             (memory (export "memory") 1)
             (func (export "crucible_falsify")))"#,
    );
    let err = Falsifier::load(&hostile, Manifest::pure(), None).unwrap_err();
    assert!(
        matches!(err, ProbeError::UnknownImport(ref s) if s.contains("fd_write")),
        "got {err}"
    );
}

/// A falsifier that costs too much is a fact about the falsifier, and the
/// budget is measured in fuel rather than seconds so the answer is the same on
/// a fast machine and a slow one.
#[test]
fn an_endless_falsifier_runs_out_of_fuel_rather_than_hanging() {
    let m = Manifest {
        fuel: 100_000,
        ..Manifest::pure()
    };
    let r = load(SPINS_FOREVER, m).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
    let failure = r.failure.unwrap();
    assert!(failure.contains("fuel"), "got {failure}");
}

/// The distinction an agent needs in order to know whose bug it is: too
/// expensive and simply broken are different problems.
#[test]
fn a_crash_is_reported_differently_from_an_overrun_budget() {
    let r = load(TRAPS, Manifest::pure()).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
    let failure = r.failure.unwrap();
    assert!(failure.contains("trapped"), "got {failure}");
    assert!(!failure.contains("fuel"));
}

/// The most important line in the crate. A falsifier that crashes has said
/// nothing about the claim — and reading a crash as a refutation would let
/// anyone refute anything by shipping a module that divides by zero.
#[test]
fn a_broken_falsifier_never_refutes_a_claim() {
    for hostile in [TRAPS, SPINS_FOREVER, SAYS_NOTHING] {
        let m = Manifest {
            fuel: 100_000,
            ..Manifest::pure()
        };
        let r = load(hostile, m).run(b"{}", Observations::new());
        assert_ne!(
            r.outcome,
            Outcome::Fails,
            "a falsifier's own failure must not read as evidence"
        );
        assert_eq!(r.outcome, Outcome::Indeterminate);
    }
}

#[test]
fn silence_is_not_assent() {
    let r = load(SAYS_NOTHING, Manifest::pure()).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
    assert!(r.failure.unwrap().contains("without emitting"));
}

/// A module must not be able to look at how much fuel it has left and then
/// revise what it already said.
#[test]
fn the_first_verdict_is_final() {
    let two_minds = r#"
      (module
        (import "crucible" "emit" (func $emit (param i32 i32 i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "first")
        (data (i32.const 32) "second")
        (func (export "crucible_falsify")
          (call $emit (i32.const 1) (i32.const 0) (i32.const 5))
          (call $emit (i32.const 2) (i32.const 32) (i32.const 6))))"#;
    let r = load(two_minds, Manifest::pure()).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Holds);
    assert_eq!(r.explanation, b"first");
}

#[test]
fn an_oversized_explanation_is_refused() {
    let m = Manifest {
        max_output: 4,
        ..Manifest::pure()
    };
    let r = load(ALWAYS_HOLDS, m).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Holds, "two bytes is under the cap");

    let shouty = r#"
      (module
        (import "crucible" "emit" (func $emit (param i32 i32 i32)))
        (memory (export "memory") 1)
        (func (export "crucible_falsify")
          (call $emit (i32.const 1) (i32.const 0) (i32.const 4096))))"#;
    let m = Manifest {
        max_output: 16,
        ..Manifest::pure()
    };
    let r = load(shouty, m).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
    assert!(r.failure.unwrap().contains("exceeds"));
}

/// Out-of-bounds pointers are the guest's problem, not a host crash.
#[test]
fn wild_pointers_do_not_escape_the_sandbox() {
    let wild = r#"
      (module
        (import "crucible" "emit" (func $emit (param i32 i32 i32)))
        (memory (export "memory") 1)
        (func (export "crucible_falsify")
          (call $emit (i32.const 1) (i32.const 2000000000) (i32.const 16))))"#;
    let r = load(wild, Manifest::pure()).run(b"{}", Observations::new());
    assert_eq!(r.outcome, Outcome::Indeterminate);
}

// ------------------------------------------------------------------ addressing

/// Content addressing is what makes "run the falsifier" mean one specific
/// thing. Without the check, it would mean "run whatever is being served".
#[test]
fn a_substituted_module_is_refused() {
    let honest = wasm(ALWAYS_HOLDS);
    let digest: [u8; 32] = Sha256::digest(&honest).into();
    Falsifier::load(&honest, Manifest::pure(), Some(digest)).unwrap();

    let swapped = wasm(TRAPS);
    let err = Falsifier::load(&swapped, Manifest::pure(), Some(digest)).unwrap_err();
    assert!(matches!(err, ProbeError::WrongModule { .. }), "got {err}");
}

#[test]
fn a_non_wasm_payload_is_refused() {
    let err = Falsifier::load(b"#!/bin/sh\nrm -rf /", Manifest::pure(), None).unwrap_err();
    assert!(matches!(err, ProbeError::InvalidModule(_)), "got {err}");
}

// ----------------------------------------------------------------- determinism

/// The property the kernel's non-determinism check depends on: same module,
/// same inputs, same bytes out. Every time.
#[test]
fn identical_runs_produce_identical_digests() {
    let f = load(READS_INPUT, Manifest::pure());
    let a = f.run(b"ok", Observations::new());
    let b = f.run(b"ok", Observations::new());
    assert_eq!(a.output_digest, b.output_digest);
    assert_eq!(a.fuel_used, b.fuel_used, "even the fuel must match");
}

#[test]
fn a_different_verdict_produces_a_different_digest() {
    let f = load(READS_INPUT, Manifest::pure());
    let holds = f.run(b"ok", Observations::new());
    let fails = f.run(b"xx", Observations::new());
    assert_ne!(holds.output_digest, fails.output_digest);
}

/// Two agents whose runs failed for unrelated reasons must not read as a
/// divergent experiment — that would flag the claim as broken when it was the
/// probes that were.
#[test]
fn different_failures_share_one_inconclusive_digest() {
    let m = Manifest {
        fuel: 100_000,
        ..Manifest::pure()
    };
    let trapped = load(TRAPS, m.clone()).run(b"{}", Observations::new());
    let starved = load(SPINS_FOREVER, m).run(b"{}", Observations::new());
    assert_eq!(trapped.output_digest, starved.output_digest);
    assert_ne!(trapped.failure, starved.failure);
}

/// The digest must commit to the boundary between verdict and explanation, or
/// a falsifier could forge another one's output by choosing its prose.
#[test]
fn the_digest_commits_to_length_not_just_content() {
    let template = |a: &str, b: &str| {
        format!(
            r#"(module
                 (import "crucible" "emit" (func $emit (param i32 i32 i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "{a}")
                 (func (export "crucible_falsify")
                   (call $emit (i32.const 1) (i32.const 0) (i32.const {b}))))"#
        )
    };
    let short = load(&template("ab", "2"), Manifest::pure()).run(b"", Observations::new());
    let long = load(&template("abc", "3"), Manifest::pure()).run(b"", Observations::new());
    assert_ne!(short.output_digest, long.output_digest);
}

#[test]
fn purity_is_derived_from_the_manifest_not_asserted() {
    assert!(load(ALWAYS_HOLDS, Manifest::pure()).manifest().is_pure());
    assert!(!load(OBSERVES_CI, Manifest::observing(["ci:status"]))
        .manifest()
        .is_pure());
}

/// The digest a claim signs must be the digest of the bytes that ran.
#[test]
fn the_reported_digest_is_the_module_hash() {
    let bytes = wasm(ALWAYS_HOLDS);
    let f = Falsifier::load(&bytes, Manifest::pure(), None).unwrap();
    assert_eq!(f.digest(), <[u8; 32]>::from(Sha256::digest(&bytes)));
}
