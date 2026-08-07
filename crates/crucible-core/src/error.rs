use thiserror::Error;

// No `Eq`: some variants carry the f64 the caller got wrong, which is worth more
// in a message than the marker trait is worth in a match.
#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("expected {expected} hex chars, got {got}")]
    BadHexLength { expected: usize, got: usize },

    #[error("invalid hex: {0}")]
    BadHex(String),

    #[error("event id mismatch: computed {computed}, event claims {claimed}")]
    IdMismatch { computed: String, claimed: String },

    #[error("schnorr signature verification failed")]
    BadSignature,

    #[error("not a valid secp256k1 x-only public key")]
    BadPubKey,

    #[error("expected kind {expected}, got {got}")]
    WrongKind { expected: u32, got: u32 },

    #[error("missing required tag `{0}`")]
    MissingTag(&'static str),

    #[error("tag `{tag}` has malformed value {value:?}: {reason}")]
    BadTag {
        tag: &'static str,
        value: String,
        reason: &'static str,
    },

    #[error("malformed content json: {0}")]
    BadContent(String),

    #[error("confidence {0} outside the open interval (0, 1)")]
    ConfidenceOutOfRange(f64),

    #[error("half-life must be a positive number of seconds, got {0}")]
    BadHalfLife(u64),
}

pub type Result<T> = core::result::Result<T, Error>;
