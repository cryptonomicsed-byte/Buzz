//! The falsifier sandbox.
//!
//! Running a falsifier means executing code an agent you have never met wrote,
//! on your machine, because it told you doing so would settle an argument. The
//! sandbox exists so that this is a reasonable thing to agree to.
//!
//! A falsifier module gets: its declared inputs, the observations its manifest
//! names, a fuel budget, and a way to report a verdict. It does not get a clock,
//! a socket, a filesystem, an allocator it did not bring, or any import at all
//! beyond the four functions below — so the worst a hostile falsifier can do is
//! waste its own fuel and lie in its explanation, and lying is what the
//! independence and calibration machinery is for.

use crate::manifest::Manifest;
use crucible_core::Outcome;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use wasmi::{Caller, Engine, Extern, Linker, Memory, Module, Store, StoreLimitsBuilder};

/// Domain separator, so an output digest can never be confused with any other
/// SHA-256 in the protocol.
const DIGEST_TAG: &[u8] = b"crucible/probe-output/v1\0";

/// The entry point every falsifier module must export.
pub const ENTRY_POINT: &str = "crucible_falsify";

/// The import module name the host functions live under.
pub const HOST_MODULE: &str = "crucible";

/// Facts the runner gathered from the world on the falsifier's behalf.
///
/// The impurity lives here, outside the sandbox and in the open, rather than
/// inside a module that could hide it.
pub type Observations = BTreeMap<String, Vec<u8>>;

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("module digest mismatch: claim names {expected}, module hashes to {actual}")]
    WrongModule { expected: String, actual: String },
    #[error("module is not valid wasm: {0}")]
    InvalidModule(String),
    #[error("module imports `{0}`, which the sandbox does not provide")]
    UnknownImport(String),
}

/// What running a falsifier produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub outcome: Outcome,
    /// SHA-256 over the verdict and the explanation. Two agents comparing this
    /// are comparing the experiment, not their prose about it.
    pub output_digest: [u8; 32],
    pub fuel_used: u64,
    /// The falsifier's own account of what it saw, capped by the manifest.
    pub explanation: Vec<u8>,
    /// Observation keys actually requested. A falsifier that never looked at
    /// anything is worth knowing about.
    pub observed: Vec<String>,
    /// Why the run was inconclusive, when it was.
    pub failure: Option<String>,
}

impl ProbeResult {
    fn digest(outcome: Outcome, explanation: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIGEST_TAG);
        h.update([match outcome {
            Outcome::Holds => 1u8,
            Outcome::Fails => 2,
            Outcome::Indeterminate => 3,
        }]);
        h.update((explanation.len() as u64).to_le_bytes());
        h.update(explanation);
        h.finalize().into()
    }

    /// A run that could not reach a conclusion. Deliberately *not* `Fails`: a
    /// falsifier that crashed, ran out of fuel or asked for something it was
    /// not permitted is telling you about itself, not about the claim. Reading
    /// a crash as a refutation would let anyone refute anything by shipping a
    /// module that divides by zero.
    fn inconclusive(reason: impl Into<String>, fuel_used: u64, observed: Vec<String>) -> Self {
        let reason = reason.into();
        Self {
            outcome: Outcome::Indeterminate,
            // The digest covers only the verdict, so two agents whose runs
            // failed for different reasons do not read as a divergent
            // experiment. The reason is reported separately.
            output_digest: Self::digest(Outcome::Indeterminate, b""),
            fuel_used,
            explanation: Vec::new(),
            observed,
            failure: Some(reason),
        }
    }
}

/// Mutable state the host functions share with the running module.
struct HostState {
    manifest: Manifest,
    inputs: Vec<u8>,
    observations: Observations,
    observed: Vec<String>,
    emitted: Option<(Outcome, Vec<u8>)>,
    limits: wasmi::StoreLimits,
}

/// Read `len` bytes at `ptr` from the guest's memory.
fn read_guest(mem: &Memory, store: &impl wasmi::AsContext, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let (ptr, len) = (usize::try_from(ptr).ok()?, usize::try_from(len).ok()?);
    let data = mem.data(store);
    data.get(ptr..ptr.checked_add(len)?).map(<[u8]>::to_vec)
}

/// A refusal by the host, surfaced to the guest as a trap it cannot catch.
///
/// The guest is never handed an error value it might choose to ignore: every
/// refusal ends the run. A falsifier that could carry on after being denied an
/// observation would go on to judge a world it never saw.
#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl wasmi::core::HostError for Refusal {}

fn trap(msg: impl Into<String>) -> wasmi::Error {
    wasmi::Error::host(Refusal(msg.into()))
}

fn memory_of(caller: &Caller<'_, HostState>) -> Result<Memory, wasmi::Error> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(trap("module does not export its memory")),
    }
}

/// A falsifier module, verified against the digest a claim named.
pub struct Falsifier {
    engine: Engine,
    module: Module,
    manifest: Manifest,
    digest: [u8; 32],
}

impl std::fmt::Debug for Falsifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Falsifier")
            .field("digest", &hex::encode(self.digest))
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl Falsifier {
    /// Compile `wasm`, checking it against the digest the claim signed.
    ///
    /// The digest check is the whole reason a claim can name a falsifier at all:
    /// without it, "run the falsifier" would mean "run whatever the person
    /// serving it feels like today".
    pub fn load(
        wasm: &[u8],
        manifest: Manifest,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<Self, ProbeError> {
        let digest: [u8; 32] = Sha256::digest(wasm).into();
        if let Some(expected) = expected_digest {
            if expected != digest {
                return Err(ProbeError::WrongModule {
                    expected: hex::encode(expected),
                    actual: hex::encode(digest),
                });
            }
        }

        let manifest = manifest.canonical();
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        // Interpreted, not compiled: determinism across machines matters more
        // here than throughput, and a probe is small by construction.
        let engine = Engine::new(&config);
        let module =
            Module::new(&engine, wasm).map_err(|e| ProbeError::InvalidModule(e.to_string()))?;

        for import in module.imports() {
            if import.module() != HOST_MODULE {
                return Err(ProbeError::UnknownImport(format!(
                    "{}::{}",
                    import.module(),
                    import.name()
                )));
            }
        }

        Ok(Self {
            engine,
            module,
            manifest,
            digest,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Run the falsifier.
    ///
    /// Never returns an error for anything the *module* did — a trap, an
    /// overrun budget, a forbidden observation all come back as an
    /// `Indeterminate` result with a reason, because those are outcomes of the
    /// experiment and belong in the record. Errors are reserved for a module
    /// that could not be set up at all.
    pub fn run(&self, inputs: &[u8], observations: Observations) -> ProbeResult {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.manifest.memory_pages as usize * 64 * 1024)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                manifest: self.manifest.clone(),
                inputs: inputs.to_vec(),
                observations,
                observed: Vec::new(),
                emitted: None,
                limits,
            },
        );
        store.limiter(|s| &mut s.limits);
        let budget = self.manifest.fuel;
        if store.set_fuel(budget).is_err() {
            return ProbeResult::inconclusive("fuel metering unavailable", 0, Vec::new());
        }

        let mut linker = Linker::new(&self.engine);
        if let Err(e) = Self::link_host(&mut linker) {
            return ProbeResult::inconclusive(format!("host setup failed: {e}"), 0, Vec::new());
        }

        let spent = |store: &Store<HostState>| budget.saturating_sub(store.get_fuel().unwrap_or(0));

        let instance = match linker
            .instantiate(&mut store, &self.module)
            .and_then(|pre| pre.start(&mut store))
        {
            Ok(i) => i,
            Err(e) => {
                let used = spent(&store);
                return ProbeResult::inconclusive(
                    format!("instantiation failed: {e}"),
                    used,
                    store.data().observed.clone(),
                );
            }
        };

        if !matches!(instance.get_export(&store, "memory"), Some(Extern::Memory(_))) {
            return ProbeResult::inconclusive("module does not export its memory", 0, Vec::new());
        }

        let entry = match instance.get_typed_func::<(), ()>(&store, ENTRY_POINT) {
            Ok(f) => f,
            Err(_) => {
                return ProbeResult::inconclusive(
                    format!("module does not export `{ENTRY_POINT}`"),
                    spent(&store),
                    store.data().observed.clone(),
                )
            }
        };

        let run = entry.call(&mut store, ());
        let used = spent(&store);
        let observed = store.data().observed.clone();

        if let Err(e) = run {
            // Distinguish the budget from a genuine fault: "your falsifier is
            // too expensive" and "your falsifier is broken" need different
            // fixes, and an agent reading the record has to be able to tell.
            let reason = if store.get_fuel().is_ok_and(|f| f == 0) {
                format!("exhausted its {budget}-unit fuel budget")
            } else {
                format!("trapped: {e}")
            };
            return ProbeResult::inconclusive(reason, used, observed);
        }

        match store.data().emitted.clone() {
            Some((outcome, explanation)) => ProbeResult {
                output_digest: ProbeResult::digest(outcome, &explanation),
                outcome,
                fuel_used: used,
                explanation,
                observed,
                failure: None,
            },
            // Ran to completion without saying anything. Silence is not assent.
            None => ProbeResult::inconclusive("returned without emitting a verdict", used, observed),
        }
    }

    fn link_host(linker: &mut Linker<HostState>) -> Result<(), wasmi::Error> {
        linker.func_wrap(HOST_MODULE, "input_len", |caller: Caller<'_, HostState>| {
            caller.data().inputs.len() as i32
        })?;

        linker.func_wrap(
            HOST_MODULE,
            "input_read",
            |mut caller: Caller<'_, HostState>, ptr: i32| -> Result<(), wasmi::Error> {
                let mem = memory_of(&caller)?;
                let inputs = caller.data().inputs.clone();
                let ptr = usize::try_from(ptr).map_err(|_| trap("negative pointer"))?;
                mem.write(&mut caller, ptr, &inputs)
                    .map_err(|e| trap(format!("input_read out of bounds: {e}")))
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "observe_len",
            |mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32| -> Result<i32, wasmi::Error> {
                let mem = memory_of(&caller)?;
                let key = read_guest(&mem, &caller, key_ptr, key_len)
                    .ok_or_else(|| trap("observe_len key out of bounds"))?;
                let key = String::from_utf8(key).map_err(|_| trap("observation key is not utf-8"))?;

                // Refusal is a trap, not a sentinel return. A guest that
                // mistook "denied" for "empty" would silently probe a world it
                // never actually saw, and report a confident verdict about it.
                if !caller.data().manifest.permits(&key) {
                    return Err(trap(format!(
                        "observation `{key}` is not granted by the manifest"
                    )));
                }
                if !caller.data().observed.contains(&key) {
                    caller.data_mut().observed.push(key.clone());
                }
                Ok(caller
                    .data()
                    .observations
                    .get(&key)
                    .map_or(-1, |v| v.len() as i32))
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "observe_read",
            |mut caller: Caller<'_, HostState>,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32|
             -> Result<(), wasmi::Error> {
                let mem = memory_of(&caller)?;
                let key = read_guest(&mem, &caller, key_ptr, key_len)
                    .ok_or_else(|| trap("observe_read key out of bounds"))?;
                let key = String::from_utf8(key).map_err(|_| trap("observation key is not utf-8"))?;
                if !caller.data().manifest.permits(&key) {
                    return Err(trap(format!(
                        "observation `{key}` is not granted by the manifest"
                    )));
                }
                let value = caller
                    .data()
                    .observations
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| trap(format!("observation `{key}` was not gathered")))?;
                let out = usize::try_from(out_ptr).map_err(|_| trap("negative pointer"))?;
                mem.write(&mut caller, out, &value)
                    .map_err(|e| trap(format!("observe_read out of bounds: {e}")))
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "emit",
            |mut caller: Caller<'_, HostState>,
             verdict: i32,
             ptr: i32,
             len: i32|
             -> Result<(), wasmi::Error> {
                let outcome = match verdict {
                    1 => Outcome::Holds,
                    2 => Outcome::Fails,
                    3 => Outcome::Indeterminate,
                    other => return Err(trap(format!("emit: unknown verdict {other}"))),
                };
                let cap = caller.data().manifest.max_output;
                if len < 0 || len as u32 > cap {
                    return Err(trap(format!("emit: explanation exceeds {cap} bytes")));
                }
                let mem = memory_of(&caller)?;
                let explanation = read_guest(&mem, &caller, ptr, len)
                    .ok_or_else(|| trap("emit: explanation out of bounds"))?;

                // First verdict wins. Letting a module overwrite its own
                // verdict would let it decide what to say after seeing how much
                // fuel it had left.
                if caller.data().emitted.is_none() {
                    caller.data_mut().emitted = Some((outcome, explanation));
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
