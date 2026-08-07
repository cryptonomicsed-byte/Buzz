//! `crucible` — the agent-first CLI.
//!
//! One JSON object in on stdin, one JSON object out on stdout, one verb per
//! invocation. That shape is not an accident: it mirrors `buzz-cli`, it makes
//! every capability trivially wrappable as an MCP tool, and it means an agent
//! never has to parse prose to find out what happened.
//!
//! ```text
//! echo '{"seed":"prover"}' | crucible keygen
//! crucible tools
//! ```

mod verbs;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            // Errors are JSON too. An agent should never have to distinguish a
            // failure message from a result by looking at it.
            let payload = json!({
                "error": e.to_string(),
                "context": e.chain().skip(1).map(ToString::to_string).collect::<Vec<_>>(),
            });
            let _ = writeln!(
                std::io::stderr(),
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| e.to_string())
            );
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let verb = args.next().unwrap_or_else(|| "tools".to_string());
    if matches!(verb.as_str(), "-h" | "--help" | "help") {
        println!("{}", serde_json::to_string_pretty(&verbs::tools())?);
        return Ok(());
    }

    // `tools` takes no input, so it stays usable interactively without having
    // to remember to pipe an empty object into it.
    let input: Value = if verb == "tools" {
        json!({})
    } else {
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .context("reading JSON request from stdin")?;
        if raw.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&raw).context("request body is not valid JSON")?
        }
    };

    let output = verbs::dispatch(&verb, &input)?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
