//! Secure-storage value types shared by the [`crate::traits::SecureStore`]
//! contract (spec §8 "Profile trwałe", §10).
//!
//! These are the *data* types (salts, KDF parameters, sealed blobs, secret
//! wrappers). The cryptography itself lives in the `secure-storage` crate. Keeping
//! the types here lets `profile-store` depend only on `aegis-core` while still
//! sealing/opening data through an injected implementation.
//!
//! Secrets are wrapped in types that zero their memory on drop and refuse to be
//! printed (spec §8 "brak kluczy w logach").

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A password or passphrase supplied by the user. Never serialized, never
/// printed, zeroed on drop.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wrap secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(mut s: String) -> Self {
        let secret = Self::new(s.as_bytes().to_vec());
        s.zeroize();
        secret
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A 32-byte symmetric key. Zeroed on drop; never printed or serialized.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// A random salt for key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Salt(pub Vec<u8>);

/// Argon2id cost parameters. Defaults follow OWASP guidance for interactive use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration (time) cost.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
    /// The salt.
    pub salt: Salt,
}

impl KdfParams {
    /// Reasonable interactive defaults (Argon2id, ~64 MiB, 3 passes).
    #[must_use]
    pub fn interactive(salt: Salt) -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
            salt,
        }
    }
}

/// The AEAD algorithm used to seal a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AeadAlg {
    /// XChaCha20-Poly1305 (24-byte nonce, misuse-resistant nonce size).
    XChaCha20Poly1305,
}

/// A sealed (encrypted + authenticated) blob at rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    /// The AEAD algorithm.
    pub alg: AeadAlg,
    /// The nonce (public, unique per seal).
    pub nonce: Vec<u8>,
    /// The ciphertext + authentication tag.
    pub ciphertext: Vec<u8>,
    /// The KDF parameters, present when the key was derived from a password.
    #[serde(default)]
    pub kdf: Option<KdfParams>,
}

/// A convenience alias for plaintext that zeroes on drop.
pub type Plaintext = Zeroizing<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::from("hunter2".to_string());
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(s.expose(), b"hunter2");
    }

    #[test]
    fn key_debug_is_redacted() {
        let k = SecretKey::from_bytes([7u8; 32]);
        assert_eq!(format!("{k:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn sealed_blob_roundtrips() {
        let blob = SealedBlob {
            alg: AeadAlg::XChaCha20Poly1305,
            nonce: vec![0u8; 24],
            ciphertext: vec![1, 2, 3],
            kdf: Some(KdfParams::interactive(Salt(vec![9u8; 16]))),
        };
        let json = serde_json::to_string(&blob).unwrap();
        let back: SealedBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(blob, back);
    }
}
