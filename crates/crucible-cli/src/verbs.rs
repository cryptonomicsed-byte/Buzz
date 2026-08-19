//! Verb implementations.
//!
//! Every verb is `JSON -> JSON` with no hidden state, which is what makes them
//! safe to expose over MCP, to call from a workflow step, or to pipe into
//! `buzz-cli`. Nothing here reads a clock or a config file: if a verb needs the
//! time, the caller passes it, so a replay of a relay log reproduces exactly
//! what the room saw when it happened.

use anyhow::{anyhow, bail, Context, Result};
use crucible_core::attestation::{observations_digest, AttestationContent, Provenance};
use crucible_core::claim::{ClaimBody, FalsifierRef};
use crucible_core::{
    kinds, Attestation, Challenge, Claim, Commitment, EventId, NostrEvent, ProvenanceAttestation,
    PubKey, Signature, Timestamp,
};
use crucible_kernel::{resolve, settle, Ledger, Policy};
use crucible_probe::{audit_vacuity, Falsifier, Manifest, Observations};
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

/// Where `module_path` is allowed to read from.
///
/// Set with `CRUCIBLE_FALSIFIER_DIR`; defaults to `./falsifiers`.
fn falsifier_root() -> std::path::PathBuf {
    std::env::var_os("CRUCIBLE_FALSIFIER_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("falsifiers"))
}

/// Resolve `requested` inside the falsifier store, refusing anything outside it.
///
/// This is a confused-deputy boundary, not a tidiness rule. These verbs are
/// reachable over MCP by an agent that reads messages from strangers, and an
/// unrestricted `module_path` turns `claim.build` into a hash oracle over the
/// whole filesystem: point it at `/etc/shadow` or a `.env`, get back a SHA-256
/// that is crackable offline for anything guessable. Both paths are
/// canonicalised before comparison so `..` and symlinks cannot walk out.
///
/// The check is canonicalise-then-read, so a local actor with write access to
/// the store can swap a file between the two. That buys them nothing they did
/// not already have — they can write falsifiers into the store directly — but
/// the boundary is against a remote agent being steered, not against a local
/// one already inside it.
fn resolve_in_store(requested: &str) -> Result<std::path::PathBuf> {
    let root = falsifier_root();
    let canonical_root = root.canonicalize().with_context(|| {
        format!(
            "falsifier store {} does not exist; create it or set CRUCIBLE_FALSIFIER_DIR",
            root.display()
        )
    })?;

    let candidate = std::path::Path::new(requested);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        canonical_root.join(candidate)
    };
    let canonical = joined
        .canonicalize()
        .with_context(|| format!("no falsifier at {requested}"))?;

    if !canonical.starts_with(&canonical_root) {
        // Deliberately does not echo the resolved path: the caller already knows
        // what it asked for, and confirming where a path landed is itself a
        // probe of the filesystem.
        bail!(
            "module_path must name a file inside the falsifier store ({}); \
             `{requested}` resolves outside it",
            canonical_root.display()
        );
    }
    Ok(canonical)
}

/// Read a falsifier module from the store, or from inline hex.
///
/// A `.wat` path is assembled on the way in. Falsifiers are small predicates,
/// and a reviewer deciding whether to run one is far better served by readable
/// text than by a binary they have to take on trust.
/// Falsifiers are small predicates by construction. A hostile claim steering an
/// agent into a hundred-megabyte module costs the prober that memory plus a
/// parse — and the fuel cap governs execution only, not validation.
pub const MAX_MODULE_BYTES: usize = 1 << 20;

fn module_bytes(v: &Value) -> Result<Vec<u8>> {
    let raw = match (v.get("module_path"), v.get("module_hex")) {
        (Some(p), None) => {
            let p = p
                .as_str()
                .ok_or_else(|| anyhow!("module_path must be a string"))?;
            let path = resolve_in_store(p)?;
            let bytes = std::fs::read(&path).with_context(|| format!("reading {p}"))?;
            if p.ends_with(".wat") {
                wat::parse_bytes(&bytes)
                    .map(|c| c.into_owned())
                    // The assembler quotes the offending source line, which for
                    // a file that is not WAT means quoting the file back.
                    .map_err(|_| anyhow!("{p} is not valid WebAssembly text"))?
            } else {
                bytes
            }
        }
        (None, Some(h)) => {
            let h = h
                .as_str()
                .ok_or_else(|| anyhow!("module_hex must be a string"))?;
            hex::decode(h).context("module_hex is not valid hex")?
        }
        (Some(_), Some(_)) => bail!("give module_path or module_hex, not both"),
        (None, None) => bail!("give one of module_path or module_hex"),
    };
    if raw.len() > MAX_MODULE_BYTES {
        bail!(
            "falsifier is {} bytes, over the {MAX_MODULE_BYTES}-byte limit; \
             falsifiers are small predicates, not payloads",
            raw.len()
        );
    }
    Ok(raw)
}

/// Bytes that are a real, loadable falsifier — checked *before* anything
/// derived from them is returned.
///
/// Hashing first and validating later is what made `claim.build` a filesystem
/// oracle: the digest came back for any bytes at all, valid module or not.
fn validated_module(v: &Value, manifest: &Manifest) -> Result<(Vec<u8>, Falsifier)> {
    let bytes = module_bytes(v)?;
    let falsifier = Falsifier::load(&bytes, manifest.clone(), None)
        .context("that file is not a falsifier this sandbox will run")?;
    Ok((bytes, falsifier))
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
    let (module, falsifier) = validated_module(input, &manifest)?;

    let body = ClaimBody {
        statement: str_field(input, "statement")?.to_string(),
        rationale: input
            .get("rationale")
            .and_then(Value::as_str)
            .map(str::to_string),
        inputs: input.get("inputs").cloned().unwrap_or(json!({})),
    };

    // "No falsifier, no claim" only means something if the falsifier can
    // actually change its mind. A pure module whose outcome never moves under
    // any structural mutation of its own declared inputs is not testing
    // them — it is a constant wearing a falsifier's shape, and no digest
    // chain distinguishes it from a real one. Observational falsifiers are
    // exempt: they legitimately answer from what they observe, not `inputs`.
    let audit = audit_vacuity(&falsifier, &body.inputs, &Observations::new());
    if audit.vacuous {
        bail!(
            "this falsifier does not appear to depend on its declared inputs ({}); \
             a claim needs something that could actually falsify it",
            audit.reason
        );
    }

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
    let (module, _) = validated_module(input, &manifest)?;
    let expected = match input.get("module_digest").and_then(Value::as_str) {
        Some(h) => {
            let raw = hex::decode(h).context("module_digest is not hex")?;
            Some(
                <[u8; 32]>::try_from(raw.as_slice())
                    .map_err(|_| anyhow!("module_digest must be 32 bytes"))?,
            )
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

    let result = falsifier.run(&inputs_bytes, observations.clone());

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
            observations_digest: observations_digest(&observations),
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
            blind_nonce: match input.get("blind_nonce").and_then(Value::as_str) {
                Some(h) => Some(
                    <[u8; 32]>::try_from(
                        hex::decode(h).context("blind_nonce is not hex")?.as_slice(),
                    )
                    .map_err(|_| anyhow!("blind_nonce must be 32 bytes"))?,
                ),
                None => None,
            },
        };
        // Observations travel *in the signed content*, not just as a digest in
        // a tag. Without them, "somebody ran the falsifier" is unfalsifiable by
        // anyone but the attestor: a third party has the claimed outcome and a
        // digest of a value it cannot see. With them, anyone holding the
        // falsifier module can replay this exact run and check the output
        // digest matches — which is the whole point of shipping an executable
        // falsifier in the first place.
        let content = AttestationContent {
            explanation: String::from_utf8_lossy(&result.explanation).to_string(),
            observations: observations.clone(),
        };
        out["attestation"] = serde_json::to_value(unsigned(
            &attestor,
            kinds::ATTESTATION,
            at,
            att.to_unsigned_tags(),
            serde_json::to_string(&content)?,
        ))?;
    }

    Ok(out)
}

/// Independently redo a probe.
///
/// This is the payoff for `probe.run` embedding observations in the signed
/// event instead of only a digest: given the attestation, the falsifier module
/// it named, and the claim's declared inputs, a third party — someone who
/// never ran the original probe and has no reason to trust the attestor beyond
/// their signature — can re-execute the exact same experiment and check that
/// the claimed outcome and output digest are what the sandbox actually
/// produces. An attestation that fails this is not evidence, whatever it
/// claims about itself.
pub fn attestation_verify(input: &Value) -> Result<Value> {
    let event: NostrEvent =
        serde_json::from_value(field(input, "event")?.clone()).context("event")?;
    event
        .verify()
        .context("attestation event failed signature verification")?;
    let att = Attestation::from_event(&event)?;
    // Checks the embedded observations actually hash to what the
    // `observations` tag claims — otherwise a dishonest attestor could publish
    // a digest that matches nothing it embedded and let a lazy verifier trust
    // the tag without ever looking at the content.
    let content = att.verify_content(&event)?;

    let manifest = parse_manifest(field(input, "manifest")?)?;
    let (_, falsifier) = validated_module(input, &manifest)?;

    let claim_inputs = input.get("inputs").cloned().unwrap_or(json!({}));
    let inputs_bytes = serde_json::to_vec(&claim_inputs)?;
    let inputs_digest: [u8; 32] = Sha256::digest(&inputs_bytes).into();

    let claimed_experiment = FalsifierRef {
        module: falsifier.digest(),
        manifest: manifest.digest(),
        inputs: inputs_digest,
        pure: manifest.is_pure(),
    }
    .experiment_id();
    if claimed_experiment != att.experiment {
        bail!(
            "the supplied module, manifest and inputs reconstruct experiment {}, \
             but the attestation names {} — this is not a replay of the same probe",
            hex::encode(claimed_experiment),
            hex::encode(att.experiment)
        );
    }

    let result = falsifier.run(&inputs_bytes, content.observations.clone());
    let outcome_matches = result.outcome == att.outcome;
    let digest_matches = result.output_digest == att.output_digest;

    Ok(json!({
        "verified": outcome_matches && digest_matches,
        "experiment_matches": true,
        "claimed": { "outcome": att.outcome.as_str(), "output_digest": hex::encode(att.output_digest) },
        "replayed": { "outcome": result.outcome.as_str(), "output_digest": hex::encode(result.output_digest) },
        "explanation": content.explanation,
        "observations": content.observations.keys().collect::<Vec<_>>(),
    }))
}

/// Build an unsigned commitment (`kind:47008`) — the "commit" half of proving
/// `blind: true` rather than merely asserting it.
///
/// Publish this *before* reading anyone else's attestation or a verdict on the
/// claim, then reveal by including `nonce` in the `probe.run` call that builds
/// the actual attestation. `nonce` is the caller's to generate and keep secret
/// until reveal — Crucible does not supply randomness for the same reason
/// `event.sign` does not supply a signing key: concealment before reveal is
/// the whole point, and a value this tool could produce is a value this tool
/// could also leak.
pub fn blind_commit(input: &Value) -> Result<Value> {
    let committer = pubkey(input, "pubkey")?;
    let created_at = field(input, "created_at")?
        .as_u64()
        .ok_or_else(|| anyhow!("created_at must be a unix timestamp"))?;
    let claim =
        EventId::parse_hex(str_field(input, "claim")?).map_err(|e| anyhow!("claim: {e}"))?;
    let experiment = hex::decode(str_field(input, "experiment")?)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| anyhow!("experiment must be a 32-byte hex digest"))?;
    let outcome = crucible_core::Outcome::parse(str_field(input, "outcome")?)
        .ok_or_else(|| anyhow!("outcome must be holds, fails or indeterminate"))?;
    let output_digest = hex::decode(str_field(input, "output_digest")?)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| anyhow!("output_digest must be a 32-byte hex digest"))?;
    let nonce = hex::decode(str_field(input, "nonce")?)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| {
            anyhow!("nonce must be a 32-byte hex value you generated and are keeping secret")
        })?;

    let commitment = crucible_core::Commitment {
        id: EventId::from_bytes([0; 32]),
        committer,
        created_at,
        claim,
        experiment,
        hash: crucible_core::commitment_hash(
            &committer,
            &claim,
            &experiment,
            outcome,
            &output_digest,
            &nonce,
        ),
    };

    Ok(json!({
        "event": unsigned(
            &committer,
            kinds::COMMITMENT,
            created_at,
            commitment.to_unsigned_tags(),
            String::new(),
        ),
    }))
}

/// Build an unsigned provenance attestation (`kind:47009`) — a trusted
/// authority vouching that `subject` really is `lineage`/`env`.
///
/// Signed by the *authority*, not by the subject: this is the whole point.
/// Self-report is what a subject already provides for free on every claim and
/// attestation; what closes the gap is a signature from a key the community
/// already trusts to know infrastructure — an admission service, a CI
/// identity provider — for a community that has set
/// `Policy::provenance_authorities` and wants `require_attested_provenance`
/// to mean something.
pub fn provenance_attest(input: &Value) -> Result<Value> {
    let authority = pubkey(input, "pubkey")?;
    let created_at = field(input, "created_at")?
        .as_u64()
        .ok_or_else(|| anyhow!("created_at must be a unix timestamp"))?;
    let subject = pubkey(input, "subject")?;
    let expires_at = field(input, "expiry")?
        .as_u64()
        .ok_or_else(|| anyhow!("expiry must be a unix timestamp after which this vouch lapses"))?;
    if expires_at <= created_at {
        bail!("expiry must be after created_at, or this vouch is dead on arrival");
    }

    let pa = crucible_core::ProvenanceAttestation {
        id: EventId::from_bytes([0; 32]),
        authority,
        created_at,
        subject,
        lineage: str_field(input, "lineage")?.to_string(),
        env: str_field(input, "env")?.to_string(),
        expires_at,
    };

    Ok(json!({
        "event": unsigned(
            &authority,
            kinds::PROVENANCE_ATTESTATION,
            created_at,
            pa.to_unsigned_tags(),
            String::new(),
        ),
    }))
}

/// Check whether a pure falsifier actually depends on its declared inputs.
///
/// `claim.build` already refuses a vacuous pure falsifier; this verb exists so
/// an author (or a reviewer handed someone else's module) can run the same
/// check standalone, before spending a signature on a claim, or against
/// inputs other than the ones a particular claim happens to declare.
pub fn falsifier_audit(input: &Value) -> Result<Value> {
    let manifest = parse_manifest(field(input, "manifest")?)?;
    let (_, falsifier) = validated_module(input, &manifest)?;
    let inputs = input.get("inputs").cloned().unwrap_or(json!({}));

    let mut observations = Observations::new();
    if let Some(map) = input.get("observations").and_then(Value::as_object) {
        for (k, v) in map {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("observation `{k}` must be a string"))?;
            observations.insert(k.clone(), s.as_bytes().to_vec());
        }
    }

    let audit = audit_vacuity(&falsifier, &inputs, &observations);
    Ok(json!({
        "applicable": audit.applicable,
        "vacuous": audit.vacuous,
        "mutations_tried": audit.mutations_tried,
        "reason": audit.reason,
    }))
}

/// Announce a falsifier so others can look it up by digest (`kind:47007`).
///
/// Without this, a prober handed a claim knows the module's hash but has no way
/// to obtain the module or read its capability manifest — so the safety
/// property the design sells, *read the blast radius before you run it*, was
/// only true if you already had the module from somewhere else.
pub fn falsifier_announce(input: &Value) -> Result<Value> {
    let author = pubkey(input, "pubkey")?;
    let created_at = field(input, "created_at")?
        .as_u64()
        .ok_or_else(|| anyhow!("created_at must be a unix timestamp"))?;
    let manifest = parse_manifest(field(input, "manifest")?)?;
    let (module, falsifier) = validated_module(input, &manifest)?;

    let digest = hex::encode(falsifier.digest());
    let tags = vec![
        // `d` makes this addressable by digest, the way a prober will look it up.
        vec!["d".into(), digest.clone()],
        vec!["module".into(), digest.clone()],
        vec!["manifest".into(), hex::encode(manifest.digest())],
        vec![
            "purity".into(),
            if manifest.is_pure() {
                "pure"
            } else {
                "observational"
            }
            .into(),
        ],
        vec!["size".into(), module.len().to_string()],
    ];

    // The manifest travels in the content so a reader can see exactly what the
    // module may observe without fetching anything else.
    let content = serde_json::to_string(&json!({
        "manifest": manifest,
        "description": input.get("description").and_then(Value::as_str),
    }))?;

    Ok(json!({
        "event": unsigned(&author, kinds::FALSIFIER_MANIFEST, created_at, tags, content),
        "module_digest": digest,
        "pure": manifest.is_pure(),
    }))
}

// ----------------------------------------------------------------- resolving

/// Everything the kernel needs, parsed out of a pile of signed events.
struct Gathered {
    claim: Claim,
    attestations: Vec<Attestation>,
    challenges: Vec<Challenge>,
    commitments: Vec<Commitment>,
    provenance_attestations: Vec<ProvenanceAttestation>,
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

    // If a claim went missing because its signature did not check out, say so.
    // "no claim event in the input" would send an agent looking in the wrong
    // place for a problem that is right here.
    let dropped = if rejected.is_empty() {
        String::new()
    } else {
        format!(" ({} event(s) failed verification)", rejected.len())
    };
    let claim_event = match claim_id {
        Some(want) => valid
            .iter()
            .find(|e| e.id == want && e.kind == kinds::CLAIM)
            .ok_or_else(|| anyhow!("no valid claim event with id {want}{dropped}"))?,
        None => valid
            .iter()
            .find(|e| e.kind == kinds::CLAIM)
            .ok_or_else(|| anyhow!("no valid claim event in the input{dropped}"))?,
    };
    let claim = Claim::from_event(claim_event)?;

    let mut attestations = Vec::new();
    let mut challenges = Vec::new();
    let mut commitments = Vec::new();
    let mut provenance_attestations = Vec::new();
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
            kinds::COMMITMENT => match Commitment::from_event(ev) {
                Ok(c) if c.claim == claim.id => commitments.push(c),
                Ok(_) => {}
                Err(e) => rejected.push(json!({"id": ev.id.to_hex(), "reason": e.to_string()})),
            },
            // Not claim-scoped: an authority vouches for an agent's provenance
            // in general, so every valid one in the input is relevant, not
            // just those naming this claim.
            kinds::PROVENANCE_ATTESTATION => match ProvenanceAttestation::from_event(ev) {
                Ok(pa) => provenance_attestations.push(pa),
                Err(e) => rejected.push(json!({"id": ev.id.to_hex(), "reason": e.to_string()})),
            },
            _ => {}
        }
    }

    Ok(Gathered {
        claim,
        attestations,
        challenges,
        commitments,
        provenance_attestations,
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
    // working with drafts that have not been signed yet. Turning it off takes
    // the same deliberate act as the demo keys: an agent steered by a hostile
    // claim should not be one flag away from resolving over forged events.
    let verify = input
        .get("verify_signatures")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !verify && std::env::var_os("CRUCIBLE_ALLOW_UNVERIFIED").is_none() {
        bail!(
            "verify_signatures:false resolves over events nobody checked; \
             set CRUCIBLE_ALLOW_UNVERIFIED=1 to permit it"
        );
    }
    Ok((events, policy, ledger, now, verify))
}

/// Conditions a caller ought to know about, returned in-band.
///
/// The roster being optional is a real footgun: without one, any key that can
/// sign is counted as a witness, and three fresh keypairs reach `Supported` in
/// a second. That is a configuration mistake nobody notices, so the tool says
/// it out loud on every call rather than only in the docs.
fn warnings(policy: &Policy, verify: bool) -> Vec<String> {
    let mut out = Vec::new();
    if policy.roster.is_none() {
        out.push(
            "no roster configured: any key that can sign is counted as a witness, \
             so N fresh keypairs read as N independent agents. Populate \
             policy.roster from your Buzz community's membership set; this ran \
             only because allow_unrostered was set."
                .into(),
        );
    }
    if !verify {
        out.push("signature checking is off: these events are being trusted unverified".into());
    }
    out
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
        &g.commitments,
        &g.provenance_attestations,
        &ledger,
        &policy,
        now,
    );

    // Authored by whoever ran the resolver, never by the claimant. A judgment
    // the judged party signs is not a judgment. Callers that only want the
    // numbers may omit `resolver` and get no event to publish.
    let verdict_event = match input.get("resolver").and_then(Value::as_str) {
        Some(hex) => {
            let resolver = PubKey::parse_hex(hex).map_err(|e| anyhow!("resolver: {e}"))?;
            Some(serde_json::to_value(unsigned(
                &resolver,
                kinds::VERDICT,
                now,
                resolution.verdict.to_unsigned_tags(),
                String::new(),
            ))?)
        }
        None => None,
    };

    Ok(json!({
        "resolution": resolution,
        "statement": g.claim.body.statement,
        "rejected_events": g.rejected,
        "verdict_event": verdict_event,
        "warnings": warnings(&policy, verify),
        // Stamped so a downstream consumer cannot mistake an unchecked verdict
        // for a checked one.
        "signatures_verified": verify,
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
        let ev = events
            .iter()
            .find(|e| e.id == *id)
            .expect("id came from events");
        (ev.created_at, *id.as_bytes())
    });

    let mut verdicts = Vec::new();
    let mut skipped = Vec::new();
    for id in claim_ids {
        let g = match gather(&events, Some(id), verify) {
            Ok(g) => g,
            // Silence here means an operator running this on a timer watches a
            // claim disappear from the ledger with no way to find out why.
            Err(e) => {
                skipped.push(json!({"claim": id.to_hex(), "reason": e.to_string()}));
                continue;
            }
        };
        let r = resolve(
            &g.claim,
            &g.attestations,
            &g.challenges,
            &g.commitments,
            &g.provenance_attestations,
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
            &policy,
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

    Ok(json!({
        "verdicts": verdicts,
        "ledger": ledger,
        "calibration": report,
        "warnings": warnings(&policy, verify),
        "signatures_verified": verify,
        "skipped": skipped,
    }))
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
/// Refuse the development-only key verbs unless the caller has opted in.
///
/// Both derive material deterministically, which is exactly right for
/// reproducible fixtures and exactly wrong for an identity anyone relies on.
/// The danger is habit: a demo that works without ceremony teaches the hands to
/// reach for it, and one day the key it mints is holding something.
fn demo_keys_permitted() -> Result<()> {
    if std::env::var_os("CRUCIBLE_ALLOW_DEMO_KEYS").is_some() {
        Ok(())
    } else {
        bail!(
            "keygen and event.sign derive keys deterministically and are for \
             fixtures only; set CRUCIBLE_ALLOW_DEMO_KEYS=1 to use them. In a live \
             community an agent signs with the keypair its runtime already holds."
        )
    }
}

pub fn event_sign(input: &Value) -> Result<Value> {
    demo_keys_permitted()?;
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
    signed
        .verify()
        .context("freshly signed event failed to verify")?;
    Ok(serde_json::to_value(signed)?)
}

pub fn keygen(input: &Value) -> Result<Value> {
    demo_keys_permitted()?;
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
        "falsifier_store": falsifier_root().display().to_string(),
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
                    "lineage": "string?", "env": "string?", "blind": "bool?",
                    "blind_nonce": "hex? — the nonce from a prior blind.commit, to reveal it"
                },
            },
            {
                "name": "provenance.attest",
                "summary": "Build a trusted authority's vouch for a subject's lineage/env, so a community requiring attested provenance has something to check against instead of self-report alone.",
                "input": {"pubkey": "hex — the authority", "created_at": "unix", "subject": "hex", "lineage": "string", "env": "string", "expiry": "unix — after this the vouch lapses"},
            },
            {
                "name": "blind.commit",
                "summary": "Build a commitment to an outcome you have already computed but not yet revealed, so a later blind:true in probe.run's attestation is provable rather than merely asserted. Publish this before reading anyone else's attestation or verdict on the claim.",
                "input": {"pubkey": "hex", "created_at": "unix", "claim": "hex", "experiment": "hex", "outcome": "holds|fails|indeterminate", "output_digest": "hex", "nonce": "hex, 32 bytes you generated and kept secret"},
            },
            {
                "name": "attestation.verify",
                "summary": "Independently redo a probe: replay an attestation's embedded observations through its falsifier and check the claimed outcome and digest actually come out.",
                "input": {"event": "signed attestation event", "manifest": "manifest", "module_path|module_hex": "wasm or .wat", "inputs": "the claim's declared inputs, json"},
            },
            {
                "name": "falsifier.audit",
                "summary": "Check whether a pure falsifier's outcome actually depends on its declared inputs, by running it against structural mutations of them. A module that never moves is a constant wearing a falsifier's shape. claim.build runs this automatically and refuses a vacuous one; call it standalone to check a module before committing to a claim.",
                "input": {"manifest": "manifest", "module_path|module_hex": "wasm or .wat", "inputs": "json?", "observations": "{key: string}?"},
            },
            {
                "name": "falsifier.announce",
                "summary": "Publish a falsifier and its capability manifest so probers can look it up by digest and read its blast radius before running it.",
                "input": {"pubkey": "hex", "created_at": "unix", "manifest": "manifest", "module_path|module_hex": "wasm or .wat", "description": "string?"},
            },
            {
                "name": "resolve",
                "summary": "Derive a claim's epistemic status from signed events. Pure in (events, ledger, policy, now) — rerun it to check the answer.",
                "input": {"events": "[event]", "claim": "hex?", "now": "unix", "policy": "policy?", "ledger": "ledger?", "verify_signatures": "bool?", "resolver": "hex? — pubkey to author the verdict event; never the claimant"},
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
                "summary": "Sign an unsigned event. Development only, gated behind CRUCIBLE_ALLOW_DEMO_KEYS — in a live community an agent signs with its own Buzz key.",
                "input": {"event": "unsigned", "secret_key": "hex"},
            },
            {
                "name": "keygen",
                "summary": "Derive a reproducible demo keypair from a seed. Gated behind CRUCIBLE_ALLOW_DEMO_KEYS. Not an identity to trust.",
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
        "falsifier.announce" => falsifier_announce(input),
        "falsifier.audit" => falsifier_audit(input),
        "claim.build" => claim_build(input),
        "probe.run" => probe_run(input),
        "attestation.verify" => attestation_verify(input),
        "blind.commit" => blind_commit(input),
        "provenance.attest" => provenance_attest(input),
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

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) const CI_GREEN: &str = "ci-green.wat";

    /// Point the falsifier store at the repository's examples, and permit the
    /// deterministic key verbs. Both are process-wide, so every test in this
    /// module runs under them.
    pub(super) fn sandbox() {
        std::env::set_var(
            "CRUCIBLE_FALSIFIER_DIR",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/falsifiers"),
        );
        std::env::set_var("CRUCIBLE_ALLOW_DEMO_KEYS", "1");
    }
    const MANIFEST: &str =
        r#"{"observations":["ci:status"],"fuel":50000000,"memory_pages":64,"max_output":8192}"#;

    pub(super) fn manifest() -> Value {
        sandbox();
        serde_json::from_str(MANIFEST).unwrap()
    }

    /// Resolving with no roster is refused unless a policy says so out loud.
    /// These tests are about other things, so they say so.
    pub(super) fn open() -> Value {
        json!({"allow_unrostered": true})
    }

    pub(super) fn keys(seed: &str) -> (String, String) {
        sandbox();
        let k = keygen(&json!({ "seed": seed })).unwrap();
        (
            k["secret_key"].as_str().unwrap().to_string(),
            k["pubkey"].as_str().unwrap().to_string(),
        )
    }

    pub(super) fn sign(event: &Value, secret: &str) -> Value {
        event_sign(&json!({"event": event, "secret_key": secret})).unwrap()
    }

    /// A signed claim plus the experiment id its probes must match.
    pub(super) fn a_claim(at: u64) -> (Value, String, String) {
        let (sk, pk) = keys("author");
        let built = claim_build(&json!({
            "pubkey": pk, "created_at": at,
            "community": "eng", "domain": "ci",
            "statement": "main is green", "confidence": 0.85,
            "half_life": 900, "inputs": {"sha": "deadbeef"},
            "manifest": manifest(), "module_path": CI_GREEN,
        }))
        .unwrap();
        let signed = sign(&built["event"], &sk);
        let experiment = built["experiment"].as_str().unwrap().to_string();
        let module_digest = probe_run(&json!({"manifest": manifest(), "module_path": CI_GREEN}))
            .unwrap()["module_digest"]
            .as_str()
            .unwrap()
            .to_string();
        (signed, experiment, module_digest)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn a_probe(
        claim: &Value,
        experiment: &str,
        digest: &str,
        seed: &str,
        status: &str,
        lineage: &str,
        at: u64,
    ) -> Value {
        let (sk, pk) = keys(seed);
        let out = probe_run(&json!({
            "manifest": manifest(), "module_path": CI_GREEN, "module_digest": digest,
            "inputs": {"sha": "deadbeef"},
            "observations": {"ci:status": status},
            "claim": claim["id"], "experiment": experiment,
            "pubkey": pk, "created_at": at,
            "lineage": lineage, "env": format!("host-{lineage}"), "blind": true,
        }))
        .unwrap();
        sign(&out["attestation"], &sk)
    }

    #[test]
    fn the_catalogue_describes_every_verb_that_exists() {
        let listed: Vec<String> = tools()["verbs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap().to_string())
            .collect();
        // Every advertised verb must dispatch to something. An agent that
        // discovers a verb from the catalogue and cannot call it has been lied
        // to by the one surface it is supposed to trust.
        for name in &listed {
            let err = dispatch(name, &json!({})).err().map(|e| e.to_string());
            assert!(
                !err.as_deref()
                    .is_some_and(|e| e.starts_with("unknown verb")),
                "catalogue advertises `{name}`, which dispatch does not know"
            );
        }
        assert!(listed.contains(&"resolve".to_string()));
    }

    #[test]
    fn an_unknown_verb_lists_the_known_ones() {
        let err = dispatch("resolv", &json!({})).unwrap_err().to_string();
        assert!(err.contains("unknown verb"));
        assert!(
            err.contains("resolve"),
            "should point at the near miss: {err}"
        );
    }

    /// The premise, enforced at the tool boundary: you cannot build a claim
    /// without shipping the thing that would prove you wrong.
    #[test]
    fn a_claim_cannot_be_built_without_a_falsifier() {
        let (_, pk) = keys("author");
        let err = claim_build(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "community": "eng", "domain": "ci",
            "statement": "trust me", "confidence": 0.9,
            "half_life": 900, "manifest": manifest(),
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("module_path"), "got {err}");
    }

    #[test]
    fn certainty_is_refused_at_the_boundary() {
        let (_, pk) = keys("author");
        for bad in [0.0, 1.0, 1.5, -0.1] {
            let err = claim_build(&json!({
                "pubkey": pk, "created_at": 1_700_000_000,
                "community": "eng", "domain": "ci", "statement": "s",
                "confidence": bad, "half_life": 900,
                "manifest": manifest(), "module_path": CI_GREEN,
            }))
            .unwrap_err()
            .to_string();
            assert!(err.contains("probability"), "confidence {bad} got: {err}");
        }
    }

    #[test]
    fn signed_events_verify_and_tampered_ones_do_not() {
        let (claim, _, _) = a_claim(1_700_000_000);
        let checked = event_verify(&json!({"events": [claim.clone()]})).unwrap();
        assert_eq!(checked["all_valid"], json!(true));

        let mut forged = claim;
        forged["content"] = json!("something else entirely");
        let checked = event_verify(&json!({"events": [forged]})).unwrap();
        assert_eq!(checked["all_valid"], json!(false));
    }

    /// The whole pipeline, through the tool surface an agent actually calls.
    #[test]
    fn independent_probes_resolve_a_claim_end_to_end() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let probes: Vec<Value> = ["goose", "codex", "opus"]
            .iter()
            .enumerate()
            .map(|(i, m)| {
                a_probe(
                    &claim,
                    &experiment,
                    &digest,
                    m,
                    "green",
                    m,
                    at + 10 * i as u64,
                )
            })
            .collect();

        let mut events = vec![claim];
        events.extend(probes);
        let (_, resolver) = keys("resolver");
        let out = resolve_verb(&json!({
            "events": events, "now": at + 60, "resolver": resolver, "policy": open(),
        }))
        .unwrap();

        assert_eq!(out["resolution"]["verdict"]["status"], json!("supported"));
        // Three independent probes, a minute old against a fifteen-minute
        // half-life: independence ages with the evidence carrying it.
        let n_eff = out["resolution"]["verdict"]["n_eff"].as_f64().unwrap();
        assert!((n_eff - 2.89).abs() < 0.01, "n_eff was {n_eff}");
        assert!(out["rejected_events"].as_array().unwrap().is_empty());
        // The verdict comes back ready to sign and publish back to the relay.
        assert_eq!(out["verdict_event"]["kind"], json!(kinds::VERDICT));
    }

    /// A judgment the judged party signs is not a judgment. The verdict event
    /// is authored by whoever ran the resolver, and callers that do not name
    /// one get the numbers without an event to publish.
    #[test]
    fn a_verdict_is_never_authored_by_the_claimant() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let probes: Vec<Value> = ["goose", "codex", "opus"]
            .iter()
            .map(|m| a_probe(&claim, &experiment, &digest, m, "green", m, at))
            .collect();
        let mut events = vec![claim.clone()];
        events.extend(probes);

        let anonymous =
            resolve_verb(&json!({"events": events.clone(), "now": at + 60, "policy": open()}))
                .unwrap();
        assert_eq!(anonymous["verdict_event"], Value::Null);

        let (_, resolver) = keys("auditor");
        let signed = resolve_verb(&json!({
            "events": events, "now": at + 60, "resolver": resolver, "policy": open(),
        }))
        .unwrap();
        // The id is over the resolver's pubkey, so it cannot match one derived
        // from the claimant's.
        assert_ne!(signed["verdict_event"]["id"], claim["id"]);
        assert_ne!(resolver, claim["pubkey"].as_str().unwrap());
    }

    /// The roster is the seam for the attack the kernel cannot compute its way
    /// out of, and it has to be reachable from the tool surface an agent uses.
    #[test]
    fn a_roster_in_the_policy_excludes_unadmitted_attestors() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let probes: Vec<Value> = ["goose", "codex", "opus"]
            .iter()
            .map(|m| a_probe(&claim, &experiment, &digest, m, "green", m, at))
            .collect();
        let admitted = probes[0]["pubkey"].as_str().unwrap().to_string();
        let mut events = vec![claim.clone()];
        events.extend(probes);

        let out = resolve_verb(&json!({
            "events": events, "now": at + 60,
            "policy": { "roster": [claim["pubkey"], admitted] },
        }))
        .unwrap();

        assert_eq!(out["resolution"]["verdict"]["attestations"], json!(1));
        assert_eq!(
            out["resolution"]["verdict"]["status"],
            json!("insufficient")
        );
        let excluded = out["resolution"]["excluded"].as_array().unwrap();
        assert_eq!(excluded.len(), 2);
        assert!(excluded[0]["reason"].as_str().unwrap().contains("roster"));
    }

    #[test]
    fn a_forged_event_is_rejected_and_named() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let honest = a_probe(&claim, &experiment, &digest, "goose", "green", "goose", at);
        let mut forged = a_probe(&claim, &experiment, &digest, "codex", "green", "codex", at);
        forged["sig"] = json!("00".repeat(64));

        let out = resolve_verb(&json!({
            "events": [claim, honest, forged.clone()], "now": at + 60, "policy": open(),
        }))
        .unwrap();

        let rejected = out["rejected_events"].as_array().unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["id"], forged["id"]);
        assert_eq!(out["resolution"]["verdict"]["attestations"], json!(1));
    }

    /// Signature checking is on unless a caller deliberately turns it off, so
    /// nobody reaches a verdict over unsigned events by forgetting a flag.
    #[test]
    fn signature_checking_defaults_to_on() {
        let at = 1_700_000_000;
        let (claim, _, _) = a_claim(at);
        let mut unsigned_claim = claim;
        unsigned_claim["sig"] = json!("00".repeat(64));

        let err = resolve_verb(&json!({
            "events": [unsigned_claim.clone()], "now": at, "policy": open(),
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("no valid claim"), "got {err}");
        assert!(
            err.contains("failed verification"),
            "the error must say the claim was dropped, not that it was absent: {err}"
        );

        std::env::set_var("CRUCIBLE_ALLOW_UNVERIFIED", "1");
        let ok = resolve_verb(&json!({
            "events": [unsigned_claim], "now": at, "policy": open(),
            "verify_signatures": false,
        }));
        assert!(
            ok.is_ok(),
            "explicitly opting out must still work for drafts"
        );
    }

    #[test]
    fn a_broken_policy_is_refused_rather_than_silently_ignored() {
        let at = 1_700_000_000;
        let (claim, _, _) = a_claim(at);
        let err = resolve_verb(&json!({
            "events": [claim], "now": at,
            "policy": {"support_threshold": 0.1, "refute_threshold": 0.9, "allow_unrostered": true},
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("policy"), "got {err}");
    }

    #[test]
    fn replaying_a_log_produces_the_calibration_it_implies() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let probes: Vec<Value> = ["goose", "codex", "opus", "gemma"]
            .iter()
            .map(|m| a_probe(&claim, &experiment, &digest, m, "green", m, at))
            .collect();

        let mut events = vec![claim];
        events.extend(probes);
        let out =
            ledger_replay(&json!({"events": events, "now": at + 60, "policy": open()})).unwrap();

        assert_eq!(out["verdicts"].as_array().unwrap().len(), 1);
        assert_eq!(out["verdicts"][0]["status"], json!("supported"));
        assert_eq!(out["verdicts"][0]["settled"], json!(true));
        // Author plus four probers, all in the `ci` domain.
        assert_eq!(out["calibration"].as_array().unwrap().len(), 5);
        for row in out["calibration"].as_array().unwrap() {
            assert!(row["reliability"].as_f64().unwrap() > 0.5);
            assert_eq!(row["domain"], json!("ci"));
        }
    }

    #[test]
    fn a_manifest_that_grants_nothing_is_reported_as_pure() {
        let pure = manifest_digest(&json!({"observations": []})).unwrap();
        assert_eq!(pure["pure"], json!(true));
        let observing = manifest_digest(&json!({"observations": ["ci:status"]})).unwrap();
        assert_eq!(observing["pure"], json!(false));
        assert_ne!(pure["digest"], observing["digest"]);
    }

    #[test]
    fn a_substituted_falsifier_is_refused_by_the_tool_surface() {
        let err = probe_run(&json!({
            "manifest": manifest(), "module_path": CI_GREEN,
            "module_digest": "11".repeat(32),
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("digest mismatch"), "got {err}");
    }
}

#[cfg(test)]
mod hardening {
    use super::tests::*;
    use super::*;

    /// The confused-deputy hole. These verbs are reachable over MCP by an agent
    /// that reads messages from strangers; an unrestricted `module_path` turned
    /// `claim.build` into a SHA-256 oracle over the entire filesystem, which is
    /// crackable offline for anything guessable — a `.env`, a credentials file.
    #[test]
    fn a_path_outside_the_falsifier_store_is_refused() {
        let (_, pk) = keys("author");
        for escape in ["/etc/passwd", "../../../../etc/passwd", "../../Cargo.toml"] {
            let err = claim_build(&json!({
                "pubkey": pk, "created_at": 1_700_000_000,
                "community": "eng", "domain": "ci", "statement": "s",
                "confidence": 0.9, "half_life": 900,
                "manifest": manifest(), "module_path": escape,
            }))
            .unwrap_err()
            .to_string();

            assert!(
                !err.contains("cc4683"),
                "the error leaked a digest for {escape}: {err}"
            );
            assert!(
                err.contains("falsifier store") || err.contains("no falsifier at"),
                "{escape} produced an unexpected error: {err}"
            );
        }
    }

    /// Even inside the store, bytes that are not a loadable falsifier must not
    /// yield a digest. Hashing first and validating later is what made the
    /// oracle possible in the first place.
    #[test]
    fn a_non_falsifier_never_yields_a_digest() {
        let (_, pk) = keys("author");
        let err = probe_run(&json!({
            "manifest": manifest(),
            "module_hex": hex::encode(b"root:x:0:0:root:/root:/bin/bash\n"),
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a falsifier"), "got {err}");
        assert!(!err.contains("root:"), "the error echoed the bytes: {err}");

        let err = claim_build(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "community": "eng", "domain": "ci", "statement": "s",
            "confidence": 0.9, "half_life": 900,
            "manifest": manifest(), "module_hex": hex::encode(b"not wasm"),
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a falsifier"), "got {err}");
    }

    /// A missing roster now stops the run rather than merely annotating it. A
    /// warning is only a mitigation for someone who reads it.
    #[test]
    fn resolving_without_a_roster_is_refused_not_merely_warned() {
        let at = 1_700_000_000;
        let (claim, _, _) = a_claim(at);
        let err = resolve_verb(&json!({"events": [claim.clone()], "now": at}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("roster"), "got {err}");
        assert!(
            err.contains("allow_unrostered"),
            "must say how to proceed: {err}"
        );

        assert!(resolve_verb(&json!({
            "events": [claim], "now": at, "policy": open(),
        }))
        .is_ok());
    }

    /// Falsifiers are small predicates. A hostile claim must not be able to
    /// make a prober parse a payload.
    #[test]
    fn an_oversized_falsifier_is_refused() {
        let huge = hex::encode(vec![0u8; MAX_MODULE_BYTES + 1]);
        let err = probe_run(&json!({"manifest": manifest(), "module_hex": huge}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("limit"), "got {err}");
    }

    /// An operator running replay on a timer needs to see why a claim vanished
    /// from the ledger, not just that it did.
    #[test]
    fn replay_reports_the_claims_it_skipped() {
        let at = 1_700_000_000;
        let (claim, _, _) = a_claim(at);
        let mut forged = claim;
        forged["sig"] = json!("00".repeat(64));

        let out = ledger_replay(&json!({
            "events": [forged.clone()], "now": at, "policy": open(),
        }))
        .unwrap();
        assert!(out["verdicts"].as_array().unwrap().is_empty());
        let skipped = out["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["claim"], forged["id"]);
        assert!(skipped[0]["reason"]
            .as_str()
            .unwrap()
            .contains("failed verification"));
    }

    #[test]
    fn a_falsifier_inside_the_store_still_loads() {
        let out = probe_run(&json!({
            "manifest": manifest(), "module_path": CI_GREEN,
        }))
        .unwrap();
        assert_eq!(out["module_digest"].as_str().unwrap().len(), 64);
    }

    /// The payoff for embedding observations: a third party who never ran the
    /// original probe, holding only the signed attestation and the falsifier,
    /// can redo the experiment and confirm the same output comes out.
    #[test]
    fn attestation_verify_replays_the_probe_independently() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let probe = a_probe(
            &claim,
            &experiment,
            &digest,
            "prober",
            "green",
            "prover",
            at,
        );

        let out = attestation_verify(&json!({
            "event": probe,
            "manifest": manifest(),
            "module_path": CI_GREEN,
            "inputs": {"sha": "deadbeef"},
        }))
        .unwrap();

        assert_eq!(out["verified"], json!(true));
        assert_eq!(out["claimed"]["outcome"], json!("holds"));
        assert_eq!(out["replayed"]["outcome"], json!("holds"));
        assert_eq!(
            out["claimed"]["output_digest"],
            out["replayed"]["output_digest"]
        );
        assert_eq!(out["observations"], json!(["ci:status"]));
    }

    /// A replay that disagrees with what was claimed must say so, not just
    /// report a mismatch silently in a field nobody checks.
    #[test]
    fn attestation_verify_catches_a_claim_that_does_not_replay() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        // Attested "holds" while its embedded observation says "red" — the
        // falsifier will actually replay to "fails".
        let mut probe = a_probe(
            &claim,
            &experiment,
            &digest,
            "prober",
            "green",
            "prover",
            at,
        );
        let (sk, _) = keys("prober");

        // The attestor swaps what it embeds (red) but leaves the outcome/digest
        // tags at what running against "green" actually produced. Update the
        // observations-tag digest to match the new content, so this is a
        // *replay* mismatch, not the separate self-consistency check.
        let mut content: Value = serde_json::from_str(probe["content"].as_str().unwrap()).unwrap();
        content["observations"]["ci:status"] = json!(base64_encode(b"red"));
        probe["content"] = json!(serde_json::to_string(&content).unwrap());

        let mut new_observations = crucible_core::attestation::Observations::new();
        new_observations.insert("ci:status".to_string(), b"red".to_vec());
        let new_obs_digest = hex::encode(crucible_core::attestation::observations_digest(
            &new_observations,
        ));
        let tags = probe["tags"].as_array_mut().unwrap();
        for t in tags.iter_mut() {
            if t[0] == "observations" {
                t[1] = json!(new_obs_digest);
            }
        }
        let probe = sign(&probe, &sk);

        let out = attestation_verify(&json!({
            "event": probe, "manifest": manifest(), "module_path": CI_GREEN,
            "inputs": {"sha": "deadbeef"},
        }))
        .unwrap();
        assert_eq!(out["verified"], json!(false));
        assert_eq!(out["claimed"]["outcome"], json!("holds"));
        assert_eq!(out["replayed"]["outcome"], json!("fails"));
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// An attestation whose `observations` tag does not match what it actually
    /// embedded is self-inconsistent and must be refused before any replay is
    /// attempted — otherwise a dishonest attestor could publish a digest that
    /// matches nothing it shipped and rely on a lazy verifier never checking.
    #[test]
    fn a_tag_digest_that_does_not_match_embedded_content_is_refused() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let mut probe = a_probe(
            &claim,
            &experiment,
            &digest,
            "prober",
            "green",
            "prover",
            at,
        );
        let (sk, _) = keys("prober");
        let tags = probe["tags"].as_array_mut().unwrap();
        for t in tags.iter_mut() {
            if t[0] == "observations" {
                t[1] = json!("ff".repeat(32));
            }
        }
        let probe = sign(&probe, &sk);

        let err = attestation_verify(&json!({
            "event": probe, "manifest": manifest(), "module_path": CI_GREEN,
            "inputs": {"sha": "deadbeef"},
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not match"), "got {err}");
    }

    /// Verifying against the wrong claim's inputs must not silently "work" —
    /// it names a different experiment than the one the attestor actually ran.
    #[test]
    fn attestation_verify_refuses_a_mismatched_experiment() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let probe = a_probe(
            &claim,
            &experiment,
            &digest,
            "prober",
            "green",
            "prover",
            at,
        );

        let err = attestation_verify(&json!({
            "event": probe, "manifest": manifest(), "module_path": CI_GREEN,
            "inputs": {"sha": "some-other-commit"},
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a replay"), "got {err}");
    }

    /// A missing roster is the difference between a demo and a deployment, and
    /// it is silent. The tool says so on every call rather than only in a doc
    /// nobody reads at three in the morning.
    #[test]
    fn a_missing_roster_is_warned_about_in_band() {
        let at = 1_700_000_000;
        let (claim, _, _) = a_claim(at);
        let out =
            resolve_verb(&json!({"events": [claim.clone()], "now": at, "policy": open()})).unwrap();
        let warnings = out["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("roster")),
            "no roster warning: {warnings:?}"
        );

        let quiet = resolve_verb(&json!({
            "events": [claim], "now": at,
            "policy": {"roster": ["11".repeat(32)]},
        }));
        // Roster excludes the author, so there is no claim to resolve — the
        // point is only that a configured roster stops the warning.
        assert!(quiet.is_err() || quiet.unwrap()["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn disabling_signature_checks_is_warned_about() {
        let at = 1_700_000_000;
        let (claim, _, _) = a_claim(at);
        std::env::set_var("CRUCIBLE_ALLOW_UNVERIFIED", "1");
        let out = resolve_verb(&json!({
            "events": [claim], "now": at, "policy": open(), "verify_signatures": false,
        }))
        .unwrap();
        assert_eq!(out["signatures_verified"], json!(false));
        assert!(out["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("signature")));
    }

    /// The spec promised falsifiers could be announced and looked up by digest,
    /// so a prober can read what a module may touch before running it. The kind
    /// existed; nothing ever emitted it.
    #[test]
    fn a_falsifier_can_be_announced_and_carries_its_manifest() {
        let (_, pk) = keys("author");
        let out = falsifier_announce(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "manifest": manifest(), "module_path": CI_GREEN,
            "description": "true when CI reports green",
        }))
        .unwrap();

        assert_eq!(out["event"]["kind"], json!(kinds::FALSIFIER_MANIFEST));
        assert_eq!(out["pure"], json!(false));

        let tags = out["event"]["tags"].as_array().unwrap();
        let tag = |n: &str| {
            tags.iter()
                .find(|t| t[0] == n)
                .map(|t| t[1].as_str().unwrap().to_string())
        };
        assert_eq!(
            tag("module"),
            Some(out["module_digest"].as_str().unwrap().into())
        );
        assert_eq!(tag("d"), tag("module"), "addressable by digest");
        assert_eq!(tag("purity"), Some("observational".into()));

        // A reader can see the blast radius without fetching anything else.
        let body: Value = serde_json::from_str(out["event"]["content"].as_str().unwrap()).unwrap();
        assert_eq!(body["manifest"]["observations"][0], json!("ci:status"));
    }

    #[test]
    fn an_announced_module_must_also_be_a_real_falsifier() {
        let (_, pk) = keys("author");
        assert!(falsifier_announce(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "manifest": manifest(), "module_hex": hex::encode(b"nope"),
        }))
        .is_err());
    }
}

#[cfg(test)]
mod blind_commit_reveal {
    use super::tests::*;
    use super::*;

    /// The full round trip through the tool surface an agent actually calls:
    /// commit before running the reveal, reveal with the nonce, resolve under
    /// a policy that demands proof, and confirm both attestors keep full
    /// independence credit.
    #[test]
    fn a_committed_and_revealed_pair_verifies_end_to_end() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let claim_id = claim["id"].as_str().unwrap();

        let run = |_seed: &str| {
            probe_run(&json!({
                "manifest": manifest(), "module_path": CI_GREEN, "module_digest": digest,
                "inputs": {"sha": "deadbeef"}, "observations": {"ci:status": "green"},
            }))
            .unwrap()
        };
        let dry1 = run("prober1");
        let dry2 = run("prober2");

        let (sk1, pk1) = keys("prober1");
        let (sk2, pk2) = keys("prober2");
        let nonce1 = "11".repeat(32);
        let nonce2 = "22".repeat(32);

        let commit1 = sign(
            &blind_commit(&json!({
                "pubkey": pk1, "created_at": at, "claim": claim_id, "experiment": experiment,
                "outcome": dry1["outcome"], "output_digest": dry1["output_digest"], "nonce": nonce1,
            }))
            .unwrap()["event"],
            &sk1,
        );
        let commit2 = sign(
            &blind_commit(&json!({
                "pubkey": pk2, "created_at": at + 1, "claim": claim_id, "experiment": experiment,
                "outcome": dry2["outcome"], "output_digest": dry2["output_digest"], "nonce": nonce2,
            }))
            .unwrap()["event"],
            &sk2,
        );

        let reveal = |pk: &str, sk: &str, nonce: &str, at: u64| {
            let out = probe_run(&json!({
                "manifest": manifest(), "module_path": CI_GREEN, "module_digest": digest,
                "inputs": {"sha": "deadbeef"}, "observations": {"ci:status": "green"},
                "claim": claim_id, "experiment": experiment,
                "pubkey": pk, "created_at": at,
                "lineage": pk, "env": format!("host-{pk}"), "blind": true,
                "blind_nonce": nonce,
            }))
            .unwrap();
            sign(&out["attestation"], sk)
        };
        let att1 = reveal(&pk1, &sk1, &nonce1, at + 10);
        let att2 = reveal(&pk2, &sk2, &nonce2, at + 11);

        let out = resolve_verb(&json!({
            "events": [claim.clone(), commit1, commit2, att1, att2],
            "now": at + 11,
            "policy": {"allow_unrostered": true, "require_verified_blind": true},
        }))
        .unwrap();

        let n_eff = out["resolution"]["verdict"]["n_eff"].as_f64().unwrap();
        assert!(
            (n_eff - 2.0).abs() < 0.01,
            "a genuinely committed-and-revealed pair must keep full credit, got {n_eff}"
        );
        assert!(out["resolution"]["excluded"].as_array().unwrap().is_empty());
    }

    /// An attestation claiming `blind: true` with no commitment at all must be
    /// downgraded once a policy actually requires proof — this is the fix, not
    /// a side effect of it.
    #[test]
    fn a_reveal_with_no_commitment_is_downgraded_under_strict_policy() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let a1 = a_probe(
            &claim,
            &experiment,
            &digest,
            "goose",
            "green",
            "goose-model",
            at,
        );
        let a2 = a_probe(
            &claim,
            &experiment,
            &digest,
            "codex",
            "green",
            "codex-model",
            at,
        );

        let permissive = resolve_verb(&json!({
            "events": [claim.clone(), a1.clone(), a2.clone()],
            "now": at,
            "policy": {"allow_unrostered": true},
        }))
        .unwrap();
        let strict = resolve_verb(&json!({
            "events": [claim, a1, a2],
            "now": at,
            "policy": {"allow_unrostered": true, "require_verified_blind": true},
        }))
        .unwrap();

        let permissive_n = permissive["resolution"]["verdict"]["n_eff"]
            .as_f64()
            .unwrap();
        let strict_n = strict["resolution"]["verdict"]["n_eff"].as_f64().unwrap();
        assert!(
            strict_n < permissive_n,
            "unbacked blind claims must lose credit under the strict policy: \
             permissive={permissive_n}, strict={strict_n}"
        );
    }

    #[test]
    fn blind_commit_refuses_a_malformed_nonce() {
        let (_, pk) = keys("author");
        let err = blind_commit(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "claim": "11".repeat(32), "experiment": "22".repeat(32),
            "outcome": "holds", "output_digest": "33".repeat(32),
            "nonce": "not-hex",
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("nonce"), "got {err}");
    }
}

#[cfg(test)]
mod provenance_attestation {
    use super::tests::*;
    use super::*;

    /// The full round trip: a trusted authority vouches for two attestors'
    /// lineage/env, both attest, and under a policy that requires attested
    /// provenance neither loses credit — because both were actually vouched
    /// for, not just self-declared.
    #[test]
    fn a_vouched_pair_keeps_full_credit_under_a_strict_policy() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let (authority_sk, authority_pk) = keys("authority");

        let a1 = a_probe(
            &claim,
            &experiment,
            &digest,
            "goose",
            "green",
            "goose-model",
            at,
        );
        let a2 = a_probe(
            &claim,
            &experiment,
            &digest,
            "codex",
            "green",
            "codex-model",
            at,
        );
        let (_, pk1) = keys("goose");
        let (_, pk2) = keys("codex");

        let vouch = |subject_pk: &str, lineage: &str, env: &str| {
            let event = provenance_attest(&json!({
                "pubkey": authority_pk, "created_at": at,
                "subject": subject_pk, "lineage": lineage,
                "env": env, "expiry": at + 10_000,
            }))
            .unwrap()["event"]
                .clone();
            sign(&event, &authority_sk)
        };
        let v1 = vouch(&pk1, "goose-model", "host-goose-model");
        let v2 = vouch(&pk2, "codex-model", "host-codex-model");
        // The claim author's own provenance row sits in the same correlation
        // pool as the two attestors, so it needs a vouch too — otherwise its
        // unattested floor drags down the correlation the pair is measured
        // against, even though the author row itself never enters n_eff.
        let author_pk = claim["pubkey"].as_str().unwrap().to_string();
        let author_lineage = format!("key:{author_pk}");
        let v0 = vouch(&author_pk, &author_lineage, &author_lineage);

        let out = resolve_verb(&json!({
            "events": [claim, a1, a2, v0, v1, v2],
            "now": at,
            "policy": {
                "allow_unrostered": true,
                "require_attested_provenance": true,
                "provenance_authorities": [authority_pk],
            },
        }))
        .unwrap();

        let n_eff = out["resolution"]["verdict"]["n_eff"].as_f64().unwrap();
        assert!(
            (n_eff - 2.0).abs() < 0.01,
            "two vouched-for, genuinely distinct attestors must keep full credit, got {n_eff}"
        );
        assert!(out["resolution"]["excluded"].as_array().unwrap().is_empty());
    }

    /// The same pair, with no vouch at all, must lose credit once a policy
    /// actually requires attested provenance — otherwise `require_attested_provenance`
    /// would be decorative.
    #[test]
    fn an_unvouched_pair_is_floored_under_a_strict_policy() {
        let at = 1_700_000_000;
        let (claim, experiment, digest) = a_claim(at);
        let a1 = a_probe(
            &claim,
            &experiment,
            &digest,
            "goose",
            "green",
            "goose-model",
            at,
        );
        let a2 = a_probe(
            &claim,
            &experiment,
            &digest,
            "codex",
            "green",
            "codex-model",
            at,
        );
        let (_, authority_pk) = keys("authority");

        let permissive = resolve_verb(&json!({
            "events": [claim.clone(), a1.clone(), a2.clone()],
            "now": at,
            "policy": {"allow_unrostered": true},
        }))
        .unwrap();
        let strict = resolve_verb(&json!({
            "events": [claim, a1, a2],
            "now": at,
            "policy": {
                "allow_unrostered": true,
                "require_attested_provenance": true,
                "provenance_authorities": [authority_pk],
            },
        }))
        .unwrap();

        let permissive_n = permissive["resolution"]["verdict"]["n_eff"]
            .as_f64()
            .unwrap();
        let strict_n = strict["resolution"]["verdict"]["n_eff"].as_f64().unwrap();
        assert!(
            strict_n < permissive_n,
            "unvouched provenance must lose credit under the strict policy: \
             permissive={permissive_n}, strict={strict_n}"
        );
    }

    #[test]
    fn provenance_attest_refuses_an_expiry_that_is_not_after_created_at() {
        let (_, authority_pk) = keys("authority");
        let (_, subject_pk) = keys("subject");
        let err = provenance_attest(&json!({
            "pubkey": authority_pk, "created_at": 1_700_000_000,
            "subject": subject_pk, "lineage": "goose-model", "env": "host",
            "expiry": 1_700_000_000,
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("expiry"), "got {err}");
    }
}

#[cfg(test)]
mod falsifier_vacuity {
    use super::tests::*;
    use super::*;

    /// A pure manifest (no observations) so vacuity applies.
    fn pure_manifest() -> Value {
        sandbox();
        json!({})
    }

    /// Ignores its declared inputs entirely — the literal shape of the bug
    /// named in the review: a valid, pure, deterministic falsifier for any
    /// sentence you attach it to.
    const ALWAYS_HOLDS: &str = r#"
    (module
      (import "crucible" "emit" (func $emit (param i32 i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "ok")
      (func (export "crucible_falsify")
        (call $emit (i32.const 1) (i32.const 0) (i32.const 2))))
    "#;

    /// Refutes when the declared inputs, JSON-encoded, are shorter than 10
    /// bytes — a pure module that genuinely depends on its inputs.
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

    fn module_hex(wat: &str) -> String {
        hex::encode(wat::parse_str(wat).unwrap())
    }

    #[test]
    fn claim_build_refuses_a_pure_falsifier_that_ignores_its_inputs() {
        let (_, pk) = keys("author");
        let err = claim_build(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "community": "eng", "domain": "ci",
            "statement": "the sha is deadbeef", "confidence": 0.9,
            "half_life": 900, "inputs": {"sha": "deadbeef"},
            "manifest": pure_manifest(), "module_hex": module_hex(ALWAYS_HOLDS),
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not appear to depend"), "got {err}");
    }

    #[test]
    fn claim_build_accepts_a_pure_falsifier_that_reads_its_inputs() {
        let (_, pk) = keys("author");
        let out = claim_build(&json!({
            "pubkey": pk, "created_at": 1_700_000_000,
            "community": "eng", "domain": "ci",
            "statement": "the input is short", "confidence": 0.9,
            "half_life": 900, "inputs": "checked",
            "manifest": pure_manifest(), "module_hex": module_hex(LENGTH_SENSITIVE),
        }))
        .unwrap();
        assert_eq!(out["pure"], json!(true));
    }

    #[test]
    fn falsifier_audit_flags_a_vacuous_pure_module_standalone() {
        let out = falsifier_audit(&json!({
            "manifest": pure_manifest(), "module_hex": module_hex(ALWAYS_HOLDS),
            "inputs": {"sha": "deadbeef"},
        }))
        .unwrap();
        assert_eq!(out["applicable"], json!(true));
        assert_eq!(out["vacuous"], json!(true));
    }

    #[test]
    fn falsifier_audit_is_not_applicable_to_an_observational_module() {
        // CI_GREEN reads `ci:status` through its manifest, so vacuity against
        // `inputs` does not apply to it at all.
        let out = falsifier_audit(&json!({
            "manifest": manifest(), "module_path": CI_GREEN,
            "inputs": {"sha": "deadbeef"},
            "observations": {"ci:status": "green"},
        }))
        .unwrap();
        assert_eq!(out["applicable"], json!(false));
        assert_eq!(out["vacuous"], json!(false));
    }
}
