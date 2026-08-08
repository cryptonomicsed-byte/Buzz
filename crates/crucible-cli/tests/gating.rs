//! Process-level tests for the environment gates.
//!
//! These run the real binary in a child process rather than calling the verbs
//! in-process, because the behaviour under test is *the absence* of an
//! environment variable — and unsetting one inside a test binary would race
//! every other test sharing that process.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(verb: &str, input: &str, env: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crucible"));
    cmd.arg(verb)
        .env_remove("CRUCIBLE_ALLOW_DEMO_KEYS")
        .env_remove("CRUCIBLE_FALSIFIER_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("binary must run");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// Deterministic keys are right for fixtures and wrong for anything else. The
/// danger is habit — a demo that works without ceremony teaches the hands to
/// reach for it — so using them takes a deliberate act.
#[test]
fn the_demo_key_verbs_are_refused_by_default() {
    for (verb, input) in [
        ("keygen", r#"{"seed":"x"}"#),
        (
            "event.sign",
            r#"{"event":{"kind":1,"created_at":1,"tags":[],"content":""},"secret_key":"01"}"#,
        ),
    ] {
        let (ok, text) = run(verb, input, &[]);
        assert!(!ok, "{verb} succeeded without the opt-in");
        assert!(
            text.contains("CRUCIBLE_ALLOW_DEMO_KEYS"),
            "{verb} did not say how to opt in: {text}"
        );
    }

    let (ok, _) = run(
        "keygen",
        r#"{"seed":"x"}"#,
        &[("CRUCIBLE_ALLOW_DEMO_KEYS", "1")],
    );
    assert!(ok, "the opt-in must actually work");
}

/// The falsifier store must not silently default to somewhere readable.
#[test]
fn module_paths_are_refused_when_no_store_exists() {
    let (ok, text) = run(
        "probe.run",
        r#"{"manifest":{},"module_path":"/etc/passwd"}"#,
        &[("CRUCIBLE_FALSIFIER_DIR", "/nonexistent-falsifier-store")],
    );
    assert!(!ok);
    assert!(
        text.contains("falsifier store"),
        "unexpected refusal: {text}"
    );
    // Above all, no digest.
    assert!(!text.contains("cc4683"), "leaked a digest: {text}");
}

/// `tools` must work with no configuration at all — it is how an agent
/// discovers everything else, including that the other verbs are gated.
#[test]
fn the_catalogue_needs_no_opt_in() {
    let (ok, text) = run("tools", "", &[]);
    assert!(ok, "tools failed: {text}");
    assert!(text.contains("falsifier_store"));
    assert!(text.contains("CRUCIBLE_ALLOW_DEMO_KEYS"));
}
