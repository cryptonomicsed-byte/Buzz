//! Verb implementations.
//!
//! Every verb is `JSON -> JSON` with no hidden state, which is what makes them
//! safe to expose over MCP, to call from a workflow step, or to pipe into
//! `buzz-cli`. Nothing here reads a clock or a config file: if a verb needs the
//! time, the caller passes it, so a replay of a relay log reproduces exactly
//! what the room saw when it happened.

use anyhow::{anyhow, bail, Context, Result};
use crucible_core::attestation::Provenance;
use crucible_core::claim::{ClaimBody, FalsifierRef};
use crucible_core::{
    kinds, Attestation, Challenge, Claim, EventId, NostrEvent, PubKey, Signature, Timestamp,
};
use crucible_kernel::{resolve, settle, Ledger, Policy};
use crucible_probe::{Falsifier, Manifest, Observations};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// An event that has not been signed yet. The agent's Buzz key does that —
/// Crucible never asks to hold one in normal operation.
#[derive(Serialize)]
pub struct Unsigned {
    pub kind: u32,
    pub created_at: Timestamp,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    /// The 32 bytes to sign. Present so a caller holding a key in an HSM, an
    /// agent runtime, or `buzz-cli` can sign without re-deriving the id.
    pub id: String,
}

fn unsigned(
    pubkey: &PubKey,
    kind: u32,
    created_at: Timestamp,
    tags: Vec<Vec<String>>,
    content: String,
) -> Unsigned {
    let bytes = NostrEvent::canonical_bytes(pubkey, created_at, kind, &tags, &content);
    Unsigned {
        kind,
        created_at,
        tags,
        content,
        id: hex::encode(Sha256::digest(bytes)),
    }
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    v.get(name)
        .ok_or_else(|| anyhow!("missing required field `{name}`"))
}

fn str_field<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    field(v, name)?
        .as_str()
        .ok_or_else(|| anyhow!("field `{name}` must be a string"))
}

fn pubkey(v: &Value, name: &str) -> Result<PubKey> {
    PubKey::parse_hex(str_field(v, name)?).map_err(|e| anyhow!("field `{name}`: {e}"))
}

fn parse_manifest(v: &Value) -> Result<Manifest> {
    Ok(serde_json::from_value::<Manifest>(v.clone())
        .context("manifest")?
        .canonical())
}

/// Read a falsifier module from a path or from inline hex.
///
/// A `.wat` path is assembled on the way in. Falsifiers are small predicates,
/// and a reviewer deciding whether to run one is far better served by readable
/// text than by a binary they have to take on trust.
fn module_bytes(v: &Value) -> Result<Vec<u8>> {
    match (v.get("module_path"), v.get("module_hex")) {
        (Some(p), None) => {
            let p = p.as_str().ok_or_else(|| anyhow!("module_path must be a string"))?;
            let raw = std::fs::read(p).with_context(|| format!("reading falsifier module {p}"))?;
            if p.ends_with(".wat") {
                wat::parse_bytes(&raw)
                    .map(|c| c.into_owned())
                    .with_context(|| format!("assembling {p}"))
            } else {
                Ok(raw)
            }
        }
        (None, Some(h)) => {
            let h = h.as_str().ok_or_else(|| anyhow!("module_hex must be a string"))?;
            hex::decode(h).context("module_hex is not valid hex")
        }
        (Some(_), Some(_)) => bail!("give module_path or module_hex, not both"),
        (None, None) => bail!("give one of module_path or module_hex"),
    }
}

// ---------------------------------------------------------------- manifest

pub fn manifest_digest(input: &Value) -> Result<Value> {
    let m = parse_manifest(input)?;
    Ok(json!({
        "manifest": m,
        "digest": hex::encode(m.digest()),
        "pure": m.is_pure(),
    }))
}

// ------------------------------------------------------------------- claim

pub fn claim_build(input: &Value) -> Result<Value> {
    let author = pubkey(input, "pubkey")?;
    let created_at = field(input, "created_at")?
        .as_u64()
        .ok_or_else(|| anyhow!("created_at must be a unix timestamp"))?;
    let manifest = parse_manifest(field(input, "manifest")?)?;
    let module = module_bytes(input)?;

    let body = ClaimBody {
        statement: str_field(input, "statement")?.to_string(),
        rationale: input
            .get("rationale")
            .and_then(Value::as_str)
            .map(str::to_string),
        inputs: input.get("inputs").cloned().unwrap_or(json!({})),
    };

    let confidence = field(input, "confidence")?
        .as_f64()
        .filter(|c| c.is_finite() && *c > 0.0 && *c < 1.0)
        .ok_or_else(|| anyhow!("confidence must be a probability strictly between 0 and 1"))?;

    let claim = Claim {
        id: EventId::from_bytes([0; 32]), // filled in by the id below
        author,
        created_at,
        community: str_field(input, "community")?.to_string(),
        domain: str_field(input, "domain")?.to_string(),
        confidence,
        half_life: field(input, "half_life")?
            .as_u64()
            .filter(|h| *h > 0)
            .ok_or_else(|| anyhow!("half_life must be a positive number of seconds"))?,
        expiry: input.get("expiry").and_then(Value::as_u64),
        falsifier: FalsifierRef {
            module: Sha256::digest(&module).into(),
            manifest: manifest.digest(),
            inputs: body.inputs_digest(),
            pure: manifest.is_pure(),
        },
        provenance: Provenance {
            lineage: input
                .get("lineage")
                .and_then(Value::as_str)
                .map_or_else(|| format!("key:{author}"), str::to_string),
            env: input
                .get("env")
                .and_then(Value::as_str)
                .map_or_else(|| format!("key:{author}"), str::to_string),
            blind: true,
        },
        body,
    };

    let content = serde_json::to_string(&claim.body)?;
    let ev = unsigned(
        &author,
        kinds::CLAIM,
        created_at,
        claim.to_unsigned_tags(),
        content,
    );
    Ok(json!({
        "event": ev,
        "experiment": hex::encode(claim.falsifier.experiment_id()),
        "pure": claim.falsifier.pure,
    }))
}

// ------------------------------------------------------------------- probe

pub fn probe_run(input: &Value) -> Result<Value> {
    let manifest = parse_manifest(field(input, "manifest")?)?;
    let module = module_bytes(input)?;
    let expected = match input.get("module_digest").and_then(Value::as_str) {
        Some(h) => {
            let raw = hex::decode(h).context("module_digest is not hex")?;
            Some(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| anyhow!("module_digest must be 32 bytes"))?)
        }
        None => None,
    };

    let falsifier = Falsifier::load(&module, manifest.clone(), expected)?;
    let inputs = input.get("inputs").cloned().unwrap_or(json!({}));
    let inputs_bytes = serde_json::to_vec(&inputs)?;

    let mut observations = Observations::new();
    if let Some(map) = input.get("observations").and_then(Value::as_object) {
        for (k, v) in map {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("observation `{k}` must be a string"))?;
            observations.insert(k.clone(), s.as_bytes().to_vec());
        }
    }

    let result = falsifier.run(&inputs_bytes, observations);

    let mut out = json!({
        "outcome": result.outcome.as_str(),
        "output_digest": hex::encode(result.output_digest),
        "fuel_used": result.fuel_used,
        "explanation": String::from_utf8_lossy(&result.explanation),
        "observed": result.observed,
        "failure": result.failure,
        "module_digest": hex::encode(falsifier.digest()),
    });

    // When the caller says which claim this was probing, hand back the
    // attestation ready to sign. An agent should not have to assemble tags.
    if let (Some(claim_id), Some(pk), Some(at)) = (
        input.get("claim").and_then(Value::as_str),
        input.get("pubkey").and_then(Value::as_str),
        input.get("created_at").and_then(Value::as_u64),
    ) {
        let claim = EventId::parse_hex(claim_id).map_err(|e| anyhow!("claim: {e}"))?;
        let attestor = PubKey::parse_hex(pk).map_err(|e| anyhow!("pubkey: {e}"))?;
        let experiment = hex::decode(str_field(input, "experiment")?)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .ok_or_else(|| anyhow!("experiment must be a 32-byte hex digest"))?;

        let att = Attestation {
            id: EventId::from_bytes([0; 32]),
            attestor,
            created_at: at,
            claim,
            experiment,
            outcome: result.outcome,
            output_digest: result.output_digest,
            fuel: result.fuel_used,
            provenance: Provenance {
                lineage: str_field(input, "lineage")?.to_string(),
                env: str_field(input, "env")?.to_string(),
                // Self-reported, and the kernel treats it as such: claiming to
                // be blind only ever *raises* how much your agreement counts,
                // so it is a claim about yourself that others can dispute.
                blind: input
                    .get("blind")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("blind must be stated explicitly, true or false"))?,
            },
        };
        out["attestation"] = serde_json::to_value(unsigned(
            &attestor,
            kinds::ATTESTATION,
            at,
            att.to_unsigned_tags(),
            String::from_utf8_lossy(&result.explanation).to_string(),
        ))?;
    }

    Ok(out)
}

// ----------------------------------------------------------------- resolving

/// Everything the kernel needs, parsed out of a pile of signed events.
struct Gathered {
    claim: Claim,
    attestations: Vec<Attestation>,
    challenges: Vec<Challenge>,
    rejected: Vec<Value>,
}

fn gather(events: &[NostrEvent], claim_id: Option<EventId>, verify: bool) -> Result<Gathered> {
    let mut rejected = Vec::new();
    let mut valid = Vec::new();
    for ev in events {
        if verify {
            if let Err(e) = ev.verify() {
                rejected.push(json!({"id": ev.id.to_hex(), "reason": e.to_string()}));
                continue;
            }
        }
        valid.push(ev);
    }

    let claim_event = match claim_id {
        Some(want) => valid
            .iter()
            .find(|e| e.id == want && e.kind == kinds::CLAIM)
            .ok_or_else(|| anyhow!("no valid claim event with id {want}"))?,
        None => valid
            .iter()
            .find(|e| e.kind == kinds::CLAIM)
            .ok_or_else(|| anyhow!("no claim event in the input"))?,
    };
    let claim = Claim::from_event(claim_event)?;

    let mut attestations = Vec::new();
    let mut challenges = Vec::new();
    for ev in &valid {
        match ev.kind {
            kinds::ATTESTATION => match Attestation::from_event(ev) {
                Ok(a) if a.claim == claim.id => attestations.push(a),
                Ok(_) => {}
                Err(e) => rejected.push(json!({"id": ev.id.to_hex(), "reason": e.to_string()})),
            },
            kinds::CHALLENGE => match Challenge::from_event(ev) {
                Ok(c) if c.claim == claim.id => challenges.push(c),
                Ok(_) => {}
                Err(e) => rejected.push(json!({"id": ev.id.to_hex(), "reason": e.to_string()})),
            },
            _ => {}
        }
    }

    Ok(Gathered {
        claim,
        attestations,
        challenges,
        rejected,
    })
}

fn parse_common(input: &Value) -> Result<(Vec<NostrEvent>, Policy, Ledger, Timestamp, bool)> {
    let events: Vec<NostrEvent> =
        serde_json::from_value(field(input, "events")?.clone()).context("events")?;
    let policy: Policy = match input.get("policy") {
        Some(p) => serde_json::from_value(p.clone()).context("policy")?,
        None => Policy::default(),
    };
    policy.validate().map_err(|e| anyhow!("policy: {e}"))?;
    let ledger: Ledger = match input.get("ledger") {
        Some(l) => serde_json::from_value(l.clone()).context("ledger")?,
        None => Ledger::new(),
    };
    let now = field(input, "now")?
        .as_u64()
        .ok_or_else(|| anyhow!("now must be a unix timestamp"))?;
    // Verification is on unless explicitly disabled, and disabling it is for
    // working with drafts that have not been signed yet.
    let verify = input
        .get("verify_signatures")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    Ok((events, policy, ledger, now, verify))
}

pub fn resolve_verb(input: &Value) -> Result<Value> {
    let (events, policy, ledger, now, verify) = parse_common(input)?;
    let claim_id = match input.get("claim").and_then(Value::as_str) {
        Some(s) => Some(EventId::parse_hex(s).map_err(|e| anyhow!("claim: {e}"))?),
        None => None,
    };
    let g = gather(&events, claim_id, verify)?;

    let resolution = resolve(
        &g.claim,
        &g.attestations,
        &g.challenges,
        &ledger,
        &policy,
        now,
    );

    let verdict_event = unsigned(
        &g.claim.author,
        kinds::VERDICT,
        now,
        resolution.verdict.to_unsigned_tags(),
        String::new(),
    );

    Ok(json!({
        "resolution": resolution,
        "statement": g.claim.body.statement,
        "rejected_events": g.rejected,
        "verdict_event": verdict_event,
    }))
}

/// Replay a whole log: resolve every claim in it, settle the ones that
/// resolved, and report the calibration that falls out.
///
/// This is the orchestrator loop in miniature, and it is deliberately a pure
/// function of the log so that anyone can rerun it and get the same ledger.
pub fn ledger_replay(input: &Value) -> Result<Value> {
    let (events, policy, mut ledger, now, verify) = parse_common(input)?;

    let mut claim_ids: Vec<EventId> = events
        .iter()
        .filter(|e| e.kind == kinds::CLAIM)
        .map(|e| e.id)
        .collect();
    // Chronological, so reliability earned on an early claim is available to
    // weigh a later one — the loop that makes the ledger mean anything.
    claim_ids.sort_by_key(|id| {
        let ev = events.iter().find(|e| e.id == *id).expect("id came from events");
        (ev.created_at, *id.as_bytes())
    });

    let mut verdicts = Vec::new();
    for id in claim_ids {
        let g = match gather(&events, Some(id), verify) {
            Ok(g) => g,
            Err(_) => continue,
        };
        let r = resolve(
            &g.claim,
            &g.attestations,
            &g.challenges,
            &ledger,
            &policy,
            now,
        );
        let settled = settle(
            &mut ledger,
            &g.claim,
            &g.attestations,
            &g.challenges,
            &r.verdict,
        );
        verdicts.push(json!({
            "claim": id.to_hex(),
            "statement": g.claim.body.statement,
            "status": r.verdict.status.as_str(),
            "mass": r.verdict.mass,
            "n_eff": r.verdict.n_eff,
            "attestations": r.verdict.attestations,
            "settled": settled,
        }));
    }

    let report: Vec<Value> = ledger
        .report()
        .into_iter()
        .map(|(k, r)| {
            let (agent, domain) = k.split_once('/').unwrap_or((k.as_str(), ""));
            json!({
                "agent": agent,
                "domain": domain,
                "reliability": r.r(),
                "weight": r.weight(),
                "evidence": r.evidence(),
                "brier": r.brier(),
                "log_score": r.log_score(),
            })
        })
        .collect();

    Ok(json!({ "verdicts": verdicts, "ledger": ledger, "calibration": report }))
}

// ------------------------------------------------------------------ events

pub fn event_verify(input: &Value) -> Result<Value> {
    let events: Vec<NostrEvent> =
        serde_json::from_value(field(input, "events")?.clone()).context("events")?;
    let results: Vec<Value> = events
        .iter()
        .map(|ev| {
            let (ok, reason) = match ev.verify() {
                Ok(()) => (true, Value::Null),
                Err(e) => (false, json!(e.to_string())),
            };
            json!({
                "id": ev.id.to_hex(),
                "kind": ev.kind,
                "kind_name": kinds::name(ev.kind),
                "pubkey": ev.pubkey.to_hex(),
                "valid": ok,
                "reason": reason,
            })
        })
        .collect();
    let all_valid = results.iter().all(|r| r["valid"] == json!(true));
    Ok(json!({ "events": results, "all_valid": all_valid }))
}

/// Sign an unsigned event with a raw secret key.
///
/// For development, fixtures and tests. In a live Buzz community an agent signs
/// with the keypair the community admitted, which lives in its own runtime —
/// Crucible has no business holding it, and no verb here needs it.
pub fn event_sign(input: &Value) -> Result<Value> {
    let sk_hex = str_field(input, "secret_key")?;
    let sk = k256::schnorr::SigningKey::from_bytes(
        &hex::decode(sk_hex).context("secret_key is not hex")?,
    )
    .map_err(|_| anyhow!("secret_key is not a valid secp256k1 scalar"))?;
    let pubkey = PubKey::from_bytes(sk.verifying_key().to_bytes().into());

    let ev = field(input, "event")?;
    let kind = field(ev, "kind")?.as_u64().ok_or_else(|| anyhow!("kind"))? as u32;
    let created_at = field(ev, "created_at")?
        .as_u64()
        .ok_or_else(|| anyhow!("created_at"))?;
    let tags: Vec<Vec<String>> = serde_json::from_value(field(ev, "tags")?.clone())?;
    let content = str_field(ev, "content")?.to_string();

    let bytes = NostrEvent::canonical_bytes(&pubkey, created_at, kind, &tags, &content);
    let id = EventId::from_bytes(Sha256::digest(bytes).into());
    // Zero aux randomness: BIP-340 permits any value, and a fixed one makes
    // fixtures byte-reproducible.
    let sig = sk
        .sign_raw(id.as_bytes(), &[0u8; 32])
        .map_err(|e| anyhow!("signing failed: {e}"))?;

    let signed = NostrEvent {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: Signature::from_bytes(sig.to_bytes()),
    };
    signed.verify().context("freshly signed event failed to verify")?;
    Ok(serde_json::to_value(signed)?)
}

pub fn keygen(input: &Value) -> Result<Value> {
    // Deterministic from a seed so demos and fixtures are reproducible. Never
    // use this for an identity that matters.
    let seed = str_field(input, "seed")?;
    let mut material: [u8; 32] = Sha256::digest(format!("crucible/demo-key/v1\0{seed}")).into();
    let sk = loop {
        match k256::schnorr::SigningKey::from_bytes(&material) {
            Ok(k) => break k,
            // Vanishingly unlikely; rehash rather than fail.
            Err(_) => material = Sha256::digest(material).into(),
        }
    };
    Ok(json!({
        "secret_key": hex::encode(sk.to_bytes()),
        "pubkey": hex::encode(sk.verifying_key().to_bytes()),
        "warning": "derived from a seed for reproducible demos; not an identity to trust",
    }))
}

// ---------------------------------------------------------- self-description

/// The catalogue every other surface is generated from.
///
/// A system meant for agents has to be discoverable by one: an agent that has
/// never seen Crucible should be able to call a single verb and learn every
/// other verb, its arguments, and what it is for.
pub fn tools() -> Value {
    json!({
        "name": "crucible",
        "about": "Falsifiable claims for Buzz: assert, probe, resolve, and score.",
        "protocol": "each verb reads one JSON object on stdin and writes one JSON object on stdout",
        "kinds": kinds::ALL.iter().map(|k| json!({"kind": k, "name": kinds::name(*k)})).collect::<Vec<_>>(),
        "verbs": [
            {
                "name": "tools",
                "summary": "This catalogue.",
                "input": {},
            },
            {
                "name": "manifest.digest",
                "summary": "Canonicalize a capability manifest and hash it. Determines whether a falsifier is pure.",
                "input": {"observations": "[string]", "fuel": "u64", "memory_pages": "u32", "max_output": "u32"},
            },
            {
                "name": "claim.build",
                "summary": "Build an unsigned claim event. Fails unless a falsifier module is supplied: an assertion with no way to be proven wrong is not a claim.",
                "input": {
                    "pubkey": "hex", "created_at": "unix", "community": "string", "domain": "string",
                    "statement": "string", "rationale": "string?", "confidence": "0<p<1",
                    "half_life": "seconds", "expiry": "unix?", "inputs": "json",
                    "manifest": "manifest", "module_path|module_hex": "wasm or .wat",
                    "lineage": "string?", "env": "string?"
                },
            },
            {
                "name": "probe.run",
                "summary": "Run a falsifier in the sandbox and, given a claim, return the attestation to sign.",
                "input": {
                    "manifest": "manifest", "module_path|module_hex": "wasm", "module_digest": "hex?",
                    "inputs": "json", "observations": "{key: string}",
                    "claim": "hex?", "experiment": "hex?", "pubkey": "hex?", "created_at": "unix?",
                    "lineage": "string?", "env": "string?", "blind": "bool?"
                },
            },
            {
                "name": "resolve",
                "summary": "Derive a claim's epistemic status from signed events. Pure in (events, ledger, policy, now) — rerun it to check the answer.",
                "input": {"events": "[event]", "claim": "hex?", "now": "unix", "policy": "policy?", "ledger": "ledger?", "verify_signatures": "bool?"},
            },
            {
                "name": "ledger.replay",
                "summary": "Resolve every claim in a log, settle the resolved ones, and report the calibration that falls out.",
                "input": {"events": "[event]", "now": "unix", "policy": "policy?", "ledger": "ledger?", "verify_signatures": "bool?"},
            },
            {
                "name": "event.verify",
                "summary": "Check NIP-01 ids and BIP-340 signatures.",
                "input": {"events": "[event]"},
            },
            {
                "name": "event.sign",
                "summary": "Sign an unsigned event. Development only — in a live community an agent signs with its own Buzz key.",
                "input": {"event": "unsigned", "secret_key": "hex"},
            },
            {
                "name": "keygen",
                "summary": "Derive a reproducible demo keypair from a seed. Not an identity to trust.",
                "input": {"seed": "string"},
            },
        ],
    })
}

/// Dispatch. Unknown verbs list the known ones rather than merely complaining.
pub fn dispatch(verb: &str, input: &Value) -> Result<Value> {
    match verb {
        "tools" => Ok(tools()),
        "manifest.digest" => manifest_digest(input),
        "claim.build" => claim_build(input),
        "probe.run" => probe_run(input),
        "resolve" => resolve_verb(input),
        "ledger.replay" => ledger_replay(input),
        "event.verify" => event_verify(input),
        "event.sign" => event_sign(input),
        "keygen" => keygen(input),
        other => {
            let catalogue = tools();
            let known: Vec<&str> = catalogue["verbs"]
                .as_array()
                .map(|vs| vs.iter().filter_map(|v| v["name"].as_str()).collect())
                .unwrap_or_default();
            bail!("unknown verb `{other}`; known verbs: {}", known.join(", "))
        }
    }
}
