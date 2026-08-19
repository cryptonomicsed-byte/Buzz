//! Detecting a falsifier that does not actually depend on its declared inputs.
//!
//! "The room ships the thing that would prove it wrong" only means something if
//! running that thing over different inputs can actually produce a different
//! answer. A pure module that emits `holds` unconditionally is a valid,
//! deterministic, content-addressed WASM module for any claim you attach it to
//! — nothing in the digest chain distinguishes it from a module that really
//! checked something. No signature can prove a predicate is *correct*; this
//! module proves something weaker and mechanical: whether it is *sensitive to
//! its own declared inputs at all*. A predicate that is not is not testing
//! them, whatever its author's `statement` claims.
//!
//! This is deliberately scoped to pure falsifiers. An observational module
//! reads the world through its manifest's granted observations, not through
//! `inputs`, and may legitimately ignore most or all declared input fields —
//! flagging that would be noise, not signal.

use crate::sandbox::{Falsifier, Observations};
use serde_json::Value;

/// Structurally invert every leaf: booleans flip, numbers negate, strings
/// reverse (and get a marker appended so an empty or palindromic string still
/// changes), objects and arrays keep their shape but get inverted contents,
/// with array order reversed too. Deterministic, so an audit is reproducible.
fn structural_negation(v: &Value) -> Value {
    match v {
        Value::Null => Value::Bool(true),
        Value::Bool(b) => Value::Bool(!b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i.checked_neg().unwrap_or(i).wrapping_sub(1))
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(-f - 1.0)
                    .map(Value::Number)
                    .unwrap_or(Value::Bool(true))
            } else {
                Value::Bool(true)
            }
        }
        Value::String(s) => {
            let mut reversed: String = s.chars().rev().collect();
            reversed.push('\u{2603}');
            Value::String(reversed)
        }
        Value::Array(items) => {
            let mut mutated: Vec<Value> = items.iter().map(structural_negation).collect();
            mutated.reverse();
            mutated.push(Value::String("\u{2603}".into()));
            Value::Array(mutated)
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), structural_negation(v)))
                .collect(),
        ),
    }
}

/// Every leaf replaced with `null`, shape preserved. Catches a module that
/// only checks "is a field present" rather than its value.
fn null_out(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, _)| (k.clone(), Value::Null)).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(|_| Value::Null).collect()),
        _ => Value::Null,
    }
}

/// Canonical, deterministic mutations of `inputs` to probe input-sensitivity
/// against. Skips any mutation that happens to equal the real inputs (e.g.
/// `{}` mutated against `{}`), since running that would tell us nothing.
fn canonical_mutations(inputs: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let empty = serde_json::json!({});
    if empty != *inputs {
        out.push(empty);
    }
    let negated = structural_negation(inputs);
    if negated != *inputs && !out.contains(&negated) {
        out.push(negated);
    }
    let nulled = null_out(inputs);
    if nulled != *inputs && !out.contains(&nulled) {
        out.push(nulled);
    }
    // A shape-changing sentinel, so inputs with no internal structure to
    // invert at all (e.g. `{}`) still get at least one mutation to test
    // sensitivity against — an audit that could never run on such inputs
    // would silently exempt the trivial case the check exists to catch.
    let sentinel = Value::String("\u{1F480}crucible-vacuity-probe".into());
    if sentinel != *inputs && !out.contains(&sentinel) {
        out.push(sentinel);
    }
    out
}

/// What a vacuity audit found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VacuityAudit {
    /// `false` when the check could not meaningfully run — an observational
    /// falsifier, an inconclusive baseline, or inputs with no distinct
    /// mutation to try (e.g. no declared inputs at all).
    pub applicable: bool,
    /// `true` only when `applicable` and the outcome never moved.
    pub vacuous: bool,
    pub mutations_tried: usize,
    pub reason: String,
}

/// Run `falsifier` against `real_inputs` and against several structural
/// mutations of them; flag `vacuous` if the outcome is identical every time.
///
/// This is a heuristic, not a proof. A predicate genuinely insensitive to
/// every field these mutations touch, while depending on some other structure
/// entirely, would false-positive here — the audit only claims to catch the
/// literal failure mode it targets: a module that ignores its inputs outright.
/// It never widens what the kernel treats as evidence; it is a pre-publication
/// check an author or reviewer runs deliberately.
pub fn audit_vacuity(
    falsifier: &Falsifier,
    real_inputs: &Value,
    observations: &Observations,
) -> VacuityAudit {
    if !falsifier.manifest().is_pure() {
        return VacuityAudit {
            applicable: false,
            vacuous: false,
            mutations_tried: 0,
            reason: "not applicable: an observational falsifier may legitimately depend on \
                     what it observes rather than on `inputs`"
                .into(),
        };
    }

    let real_bytes = serde_json::to_vec(real_inputs).expect("Value always serializes");
    let real = falsifier.run(&real_bytes, observations.clone());
    if real.failure.is_some() {
        return VacuityAudit {
            applicable: false,
            vacuous: false,
            mutations_tried: 0,
            reason: "not applicable: the real run did not reach a conclusion, so there is no \
                     baseline outcome to compare mutations against"
                .into(),
        };
    }

    let mutations = canonical_mutations(real_inputs);
    if mutations.is_empty() {
        return VacuityAudit {
            applicable: false,
            vacuous: false,
            mutations_tried: 0,
            reason: "not applicable: no structurally distinct mutation of these inputs could be \
                     constructed"
                .into(),
        };
    }

    for m in &mutations {
        let bytes = serde_json::to_vec(m).expect("Value always serializes");
        let mutated = falsifier.run(&bytes, observations.clone());
        if mutated.failure.is_none() && mutated.outcome != real.outcome {
            return VacuityAudit {
                applicable: true,
                vacuous: false,
                mutations_tried: mutations.len(),
                reason: format!(
                    "outcome moved from `{}` to `{}` under a structural mutation of the \
                     declared inputs",
                    real.outcome.as_str(),
                    mutated.outcome.as_str()
                ),
            };
        }
    }

    VacuityAudit {
        applicable: true,
        vacuous: true,
        mutations_tried: mutations.len(),
        reason: format!(
            "outcome stayed `{}` for the declared inputs and every one of {} structural \
             mutations tried; a falsifier this insensitive to its own declared inputs is not \
             testing them",
            real.outcome.as_str(),
            mutations.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::sandbox::Falsifier;

    fn wasm(text: &str) -> Vec<u8> {
        wat::parse_str(text).expect("test module must assemble")
    }

    fn load(text: &str, manifest: Manifest) -> Falsifier {
        Falsifier::load(&wasm(text), manifest, None).expect("test module must load")
    }

    const ALWAYS_HOLDS: &str = r#"
    (module
      (import "crucible" "emit" (func $emit (param i32 i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "ok")
      (func (export "crucible_falsify")
        (call $emit (i32.const 1) (i32.const 0) (i32.const 2))))
    "#;

    /// `probe.run` hands the falsifier its declared inputs as JSON bytes, so a
    /// realistic input-sensitive module checks something JSON encoding
    /// actually varies — here, raw byte length — rather than a fixed byte
    /// offset, which every JSON string shares as a leading quote.
    const LENGTH_SENSITIVE: &str = r#"
    (module
      (import "crucible" "input_len" (func $input_len (result i32)))
      (import "crucible" "emit" (func $emit (param i32 i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 100) "checked")
      (func (export "crucible_falsify")
        (if (i32.lt_s (call $input_len) (i32.const 10))
          (then (call $emit (i32.const 1) (i32.const 100) (i32.const 7)))
          (else (call $emit (i32.const 2) (i32.const 100) (i32.const 7))))))
    "#;

    const TRAPS: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "crucible_falsify") (unreachable)))
    "#;

    /// Reaches for an observation, so `is_pure()` is false.
    const OBSERVES_CI: &str = r#"
    (module
      (import "crucible" "observe_len" (func $olen (param i32 i32) (result i32)))
      (import "crucible" "emit" (func $emit (param i32 i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "ci:status")
      (func (export "crucible_falsify")
        (drop (call $olen (i32.const 0) (i32.const 9)))
        (call $emit (i32.const 1) (i32.const 0) (i32.const 0))))
    "#;

    #[test]
    fn a_module_that_ignores_its_inputs_is_flagged_vacuous() {
        let f = load(ALWAYS_HOLDS, Manifest::pure());
        let audit = audit_vacuity(
            &f,
            &serde_json::json!({"sha": "deadbeef"}),
            &Observations::new(),
        );
        assert!(audit.applicable);
        assert!(audit.vacuous, "{}", audit.reason);
        assert!(audit.mutations_tried > 0);
    }

    #[test]
    fn a_module_that_actually_reads_its_input_is_not_flagged() {
        let f = load(LENGTH_SENSITIVE, Manifest::pure());
        // `"checked"` JSON-encodes to 9 bytes (under the threshold); the
        // structural negation lengthens it well past 10 by construction.
        let audit = audit_vacuity(&f, &serde_json::json!("checked"), &Observations::new());
        assert!(audit.applicable);
        assert!(
            !audit.vacuous,
            "a real predicate must not be flagged: {}",
            audit.reason
        );
    }

    #[test]
    fn an_observational_module_is_not_applicable() {
        let f = load(OBSERVES_CI, Manifest::observing(["ci:status"]));
        let audit = audit_vacuity(&f, &serde_json::json!({}), &Observations::new());
        assert!(!audit.applicable);
        assert!(!audit.vacuous);
    }

    #[test]
    fn an_inconclusive_baseline_is_not_applicable() {
        let f = load(TRAPS, Manifest::pure());
        let audit = audit_vacuity(
            &f,
            &serde_json::json!({"sha": "deadbeef"}),
            &Observations::new(),
        );
        assert!(!audit.applicable);
        assert!(!audit.vacuous);
    }

    #[test]
    fn empty_inputs_still_produce_a_mutation_to_try() {
        // `{}` mutated against `{}` would be a no-op, but the structural
        // negation of `{}` is still `{}` (no keys to invert) — the audit
        // must fall back to something, not silently report zero mutations.
        let f = load(ALWAYS_HOLDS, Manifest::pure());
        let audit = audit_vacuity(&f, &serde_json::json!({}), &Observations::new());
        assert!(audit.applicable);
        assert!(audit.vacuous);
    }
}
