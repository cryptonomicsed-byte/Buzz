use crate::error::{Error, Result};
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! hex_newtype {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn to_hex(self) -> String {
                hex::encode(self.0)
            }

            pub fn parse_hex(s: &str) -> Result<Self> {
                if s.len() != $len * 2 {
                    return Err(Error::BadHexLength {
                        expected: $len * 2,
                        got: s.len(),
                    });
                }
                let mut out = [0u8; $len];
                hex::decode_to_slice(s, &mut out).map_err(|e| Error::BadHex(e.to_string()))?;
                Ok(Self(out))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Full value: these are public identifiers, and truncating them
                // in logs is how provenance bugs hide.
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse_hex(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_newtype!(
    EventId,
    32,
    "A NIP-01 event id: the SHA-256 of the canonical serialization."
);
hex_newtype!(
    PubKey,
    32,
    "A secp256k1 x-only public key — the portable identity Buzz already gives every human and agent."
);
hex_newtype!(Signature, 64, "A BIP-340 Schnorr signature.");
