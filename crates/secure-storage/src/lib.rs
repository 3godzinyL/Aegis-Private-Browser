//! # secure-storage
//!
//! The concrete [`aegis_core::traits::SecureStore`] implementation for the Aegis
//! Private Browser (spec §8 "Profile trwałe", §10).
//!
//! It provides two primitives, wired together through a single [`SecureStorage`]
//! value:
//!
//! * **Key derivation** — `Argon2id` turns a user password plus
//!   `KdfParams` (memory/time/parallelism cost
//!   and a random salt) into a 32-byte
//!   `SecretKey`.
//! * **Authenticated sealing** — `XChaCha20-Poly1305` seals a
//!   plaintext under a key with a fresh random 24-byte nonce, producing a
//!   self-describing `SealedBlob`, and opens it
//!   again with tamper detection.
//!
//! ## Security properties
//!
//! * **No custom crypto.** All confidentiality/integrity comes from the vetted
//!   `argon2` and `chacha20poly1305` crates. Constant-time comparison of the
//!   authentication tag is handled inside the AEAD; this crate never rolls its
//!   own comparison.
//! * **Fail-closed.** Every failure — a bad password-derived key, a tampered
//!   blob, an unexpected algorithm — is mapped to
//!   [`aegis_core::Error::Crypto`], which classifies as
//!   [`FailureClass::Cryptography`](aegis_core::FailureClass::Cryptography).
//! * **No secrets in logs.** Keys and plaintext live in zero-on-drop wrappers
//!   (`SecretKey`,
//!   `Plaintext`) and are never formatted into
//!   error strings.
//! * **Nonce uniqueness by randomness.** XChaCha20's 192-bit nonce is large
//!   enough that fresh random nonces from a CSPRNG make reuse negligibly
//!   unlikely, so a monotonic counter is not required.
//!
//! ## Testability
//!
//! The single source of non-determinism — the CSPRNG — is abstracted behind the
//! [`RandomSource`] trait. Production uses [`OsRandom`] (the operating system
//! CSPRNG); tests can inject a deterministic source to assert exact nonce/salt
//! bytes without weakening the shipped code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use aegis_core::secure::{AeadAlg, KdfParams, Plaintext, Salt, SealedBlob, Secret, SecretKey};
use aegis_core::traits::SecureStore;
use aegis_core::{Error, Result};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Length in bytes of a symmetric key and of a derived KDF output.
const KEY_LEN: usize = 32;
/// Length in bytes of an XChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 24;
/// Length in bytes of a freshly generated KDF salt.
const SALT_LEN: usize = 16;

/// A source of cryptographically secure random bytes.
///
/// Abstracting the CSPRNG behind this trait keeps [`SecureStorage`] logic (nonce
/// generation, salt generation, key generation) unit-testable with a
/// deterministic stand-in while production code uses the OS CSPRNG. It is *not* a
/// place to plug in a weak RNG in production — only [`OsRandom`] should be used
/// outside tests.
pub trait RandomSource: Send + Sync {
    /// Fill `dst` completely with random bytes.
    fn fill(&self, dst: &mut [u8]);
}

/// The operating-system CSPRNG ([`rand::rngs::OsRng`]).
///
/// This is the only [`RandomSource`] that should be used in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, dst: &mut [u8]) {
        // `OsRng::fill_bytes` reads from the OS entropy source and panics only if
        // the OS RNG itself fails, which is treated as unrecoverable everywhere.
        OsRng.fill_bytes(dst);
    }
}

/// The Argon2id + XChaCha20-Poly1305 secure store.
///
/// Construct with [`SecureStorage::new`] (uses the OS CSPRNG) or
/// [`SecureStorage::with_random`] to inject a custom [`RandomSource`] (tests).
/// The value is cheap to clone-by-reference and holds no secret state itself.
pub struct SecureStorage<R: RandomSource = OsRandom> {
    rng: R,
}

impl<R: RandomSource> std::fmt::Debug for SecureStorage<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The RNG holds no secret material worth printing; a stable, opaque
        // representation keeps this out of the way of `missing_debug_impls`.
        f.debug_struct("SecureStorage").finish_non_exhaustive()
    }
}

impl Default for SecureStorage<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage<OsRandom> {
    /// Create a store backed by the operating-system CSPRNG.
    #[must_use]
    pub fn new() -> Self {
        Self { rng: OsRandom }
    }
}

impl<R: RandomSource> SecureStorage<R> {
    /// Create a store backed by a custom [`RandomSource`].
    ///
    /// Intended for tests that need deterministic nonces/salts. Production code
    /// should use [`SecureStorage::new`].
    #[must_use]
    pub fn with_random(rng: R) -> Self {
        Self { rng }
    }

    /// Generate an **ephemeral, RAM-only** 32-byte key.
    ///
    /// This is a semantic alias for [`SecureStore::generate_key`] intended for
    /// disposable profiles (spec §8 "losowy klucz szyfrowania w RAM"). The
    /// returned [`SecretKey`] is a zero-on-drop wrapper and MUST NOT be
    /// persisted to disk: for a disposable session the key exists only for the
    /// lifetime of the process and the encrypted overlay it protects is shredded
    /// on teardown. Callers are responsible for never serializing it.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if the RNG cannot produce key material.
    pub fn generate_ephemeral_key(&self) -> Result<SecretKey> {
        self.random_key()
    }

    /// Seal `plaintext` under a key derived from `password` and `params`,
    /// embedding those `params` in the returned blob's `kdf` field.
    ///
    /// This is the persistent-profile convenience path: the caller stores the
    /// blob alone and can later re-derive the key from the same password via
    /// [`SecureStorage::open_with_password`] because the salt/costs travel with
    /// the ciphertext. The password itself is never stored.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] on key-derivation or encryption failure.
    pub fn seal_with_password(
        &self,
        password: &Secret,
        params: &KdfParams,
        plaintext: &[u8],
    ) -> Result<SealedBlob> {
        let key = self.derive_key(password, params)?;
        let mut blob = self.seal(&key, plaintext)?;
        blob.kdf = Some(params.clone());
        Ok(blob)
    }

    /// Open a blob produced by [`SecureStorage::seal_with_password`], re-deriving
    /// the key from `password` and the [`KdfParams`] carried inside the blob.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if the blob carries no KDF parameters, if key
    /// derivation fails, or if authentication/decryption fails (wrong password
    /// or tampered ciphertext). The error message never reveals which.
    pub fn open_with_password(&self, password: &Secret, blob: &SealedBlob) -> Result<Plaintext> {
        let params = blob
            .kdf
            .as_ref()
            .ok_or_else(|| Error::Crypto("sealed blob carries no KDF parameters".into()))?;
        let key = self.derive_key(password, params)?;
        self.open(&key, blob)
    }

    /// Fill a fresh 32-byte key from the random source.
    fn random_key(&self) -> Result<SecretKey> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        self.rng.fill(bytes.as_mut_slice());
        Ok(SecretKey::from_bytes(*bytes))
    }
}

impl<R: RandomSource> aegis_core::traits::SecureStore for SecureStorage<R> {
    fn generate_key(&self) -> Result<SecretKey> {
        self.random_key()
    }

    fn new_kdf_params(&self) -> Result<KdfParams> {
        let mut salt = vec![0u8; SALT_LEN];
        self.rng.fill(&mut salt);
        Ok(KdfParams::interactive(Salt(salt)))
    }

    fn derive_key(&self, password: &Secret, params: &KdfParams) -> Result<SecretKey> {
        // Build Argon2id with the caller's cost parameters, fixing the output
        // length to a 32-byte key.
        let a2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|e| Error::Crypto(format!("invalid KDF parameters: {e}")))?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);

        // Derive directly into a zero-on-drop buffer; never copy the key into a
        // loggable or long-lived place.
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        argon
            .hash_password_into(password.expose(), &params.salt.0, out.as_mut_slice())
            .map_err(|e| Error::Crypto(format!("key derivation failed: {e}")))?;

        Ok(SecretKey::from_bytes(*out))
    }

    fn seal(&self, key: &SecretKey, plaintext: &[u8]) -> Result<SealedBlob> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));

        // Fresh 24-byte random nonce per seal. XChaCha20's 192-bit nonce makes
        // random selection safe against reuse.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::Crypto("sealing failed".into()))?;

        Ok(SealedBlob {
            alg: AeadAlg::XChaCha20Poly1305,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            kdf: None,
        })
    }

    fn open(&self, key: &SecretKey, blob: &SealedBlob) -> Result<Plaintext> {
        // Reject anything we did not seal ourselves before touching key material.
        match blob.alg {
            AeadAlg::XChaCha20Poly1305 => {}
        }

        if blob.nonce.len() != NONCE_LEN {
            return Err(Error::Crypto("sealed blob has malformed nonce".into()));
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let nonce = XNonce::from_slice(&blob.nonce);

        // A failing tag verification (wrong key or tampered ciphertext) yields an
        // opaque error: we never leak which of the two it was.
        let plaintext = cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|_| Error::Crypto("open failed: authentication error".into()))?;

        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A deterministic, counter-based `RandomSource` for tests only.
    ///
    /// It produces a distinct, reproducible byte stream so we can assert that
    /// two seals use *different* nonces and inspect exact salt bytes. It is
    /// emphatically NOT secure and never used outside `#[cfg(test)]`.
    struct SeqRandom {
        counter: Mutex<u8>,
    }

    impl SeqRandom {
        fn new() -> Self {
            Self {
                counter: Mutex::new(0),
            }
        }
    }

    impl RandomSource for SeqRandom {
        fn fill(&self, dst: &mut [u8]) {
            let mut c = self.counter.lock().unwrap();
            for byte in dst.iter_mut() {
                *byte = *c;
                *c = c.wrapping_add(1);
            }
        }
    }

    /// A `RandomSource` that always returns the same constant byte.
    struct ConstRandom(u8);
    impl RandomSource for ConstRandom {
        fn fill(&self, dst: &mut [u8]) {
            dst.iter_mut().for_each(|b| *b = self.0);
        }
    }

    fn store() -> SecureStorage<OsRandom> {
        SecureStorage::new()
    }

    #[test]
    fn generate_key_is_32_bytes() {
        let s = store();
        let k = s.generate_key().unwrap();
        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn generate_key_produces_distinct_keys() {
        let s = store();
        let a = s.generate_key().unwrap();
        let b = s.generate_key().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "OS RNG must not repeat keys");
    }

    #[test]
    fn ephemeral_key_is_32_bytes_and_random() {
        let s = store();
        let a = s.generate_ephemeral_key().unwrap();
        let b = s.generate_ephemeral_key().unwrap();
        assert_eq!(a.as_bytes().len(), 32);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn new_kdf_params_have_16_byte_salt_and_interactive_costs() {
        let s = store();
        let p = s.new_kdf_params().unwrap();
        assert_eq!(p.salt.0.len(), 16);
        // Must match KdfParams::interactive defaults from aegis-core.
        let expected = KdfParams::interactive(p.salt.clone());
        assert_eq!(p.m_cost, expected.m_cost);
        assert_eq!(p.t_cost, expected.t_cost);
        assert_eq!(p.p_cost, expected.p_cost);
    }

    #[test]
    fn new_kdf_params_salts_differ() {
        let s = store();
        let a = s.new_kdf_params().unwrap();
        let b = s.new_kdf_params().unwrap();
        assert_ne!(a.salt.0, b.salt.0, "each params set must get a fresh salt");
    }

    // --- derive_key -------------------------------------------------------

    // Use cheap Argon2 costs in derive tests to keep them fast but exercise the
    // real KDF path.
    fn cheap_params(salt: &[u8]) -> KdfParams {
        KdfParams {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
            salt: Salt(salt.to_vec()),
        }
    }

    #[test]
    fn derive_key_is_deterministic_for_same_password_and_params() {
        let s = store();
        let pw = Secret::from("correct horse battery staple".to_string());
        let params = cheap_params(&[42u8; 16]);
        let k1 = s.derive_key(&pw, &params).unwrap();
        let k2 = s.derive_key(&pw, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        assert_eq!(k1.as_bytes().len(), 32);
    }

    #[test]
    fn derive_key_differs_for_different_salt() {
        let s = store();
        let pw = Secret::from("same password".to_string());
        let k1 = s.derive_key(&pw, &cheap_params(&[1u8; 16])).unwrap();
        let k2 = s.derive_key(&pw, &cheap_params(&[2u8; 16])).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_key_differs_for_different_password() {
        let s = store();
        let params = cheap_params(&[7u8; 16]);
        let k1 = s
            .derive_key(&Secret::from("alpha".to_string()), &params)
            .unwrap();
        let k2 = s
            .derive_key(&Secret::from("bravo".to_string()), &params)
            .unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_key_rejects_invalid_params() {
        let s = store();
        let pw = Secret::from("pw".to_string());
        // m_cost = 0 is invalid for Argon2 and must map to a Crypto error.
        let bad = KdfParams {
            m_cost: 0,
            t_cost: 1,
            p_cost: 1,
            salt: Salt(vec![0u8; 16]),
        };
        let err = s.derive_key(&pw, &bad).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
        assert_eq!(err.class(), aegis_core::FailureClass::Cryptography);
    }

    #[test]
    fn derive_key_rejects_too_short_salt() {
        let s = store();
        let pw = Secret::from("pw".to_string());
        // Argon2 requires a salt of at least 8 bytes.
        let bad = cheap_params(&[0u8; 4]);
        let err = s.derive_key(&pw, &bad).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    // --- seal / open ------------------------------------------------------

    #[test]
    fn seal_open_roundtrip() {
        let s = store();
        let key = s.generate_key().unwrap();
        let msg = b"the vault contents";
        let blob = s.seal(&key, msg).unwrap();
        assert_eq!(blob.alg, AeadAlg::XChaCha20Poly1305);
        assert_eq!(blob.nonce.len(), 24);
        assert!(blob.kdf.is_none());
        let opened = s.open(&key, &blob).unwrap();
        assert_eq!(&opened[..], msg);
    }

    #[test]
    fn seal_open_roundtrip_empty_plaintext() {
        let s = store();
        let key = s.generate_key().unwrap();
        let blob = s.seal(&key, b"").unwrap();
        let opened = s.open(&key, &blob).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let s = store();
        let key = s.generate_key().unwrap();
        let msg = b"secret payload that should be hidden";
        let blob = s.seal(&key, msg).unwrap();
        // AEAD output must not contain the plaintext, and must be longer (tag).
        assert!(blob.ciphertext.windows(msg.len()).all(|w| w != msg));
        assert!(blob.ciphertext.len() > msg.len());
    }

    #[test]
    fn two_seals_of_same_plaintext_differ() {
        let s = store();
        let key = s.generate_key().unwrap();
        let msg = b"repeatable message";
        let a = s.seal(&key, msg).unwrap();
        let b = s.seal(&key, msg).unwrap();
        assert_ne!(a.nonce, b.nonce, "nonces must be fresh per seal");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "ciphertext must differ per seal"
        );
        // Both still open to the same plaintext.
        assert_eq!(&s.open(&key, &a).unwrap()[..], msg);
        assert_eq!(&s.open(&key, &b).unwrap()[..], msg);
    }

    #[test]
    fn deterministic_rng_still_produces_distinct_nonces_across_seals() {
        // With a counter RNG the two nonces are different because the counter
        // advances; this guards against accidentally caching a nonce.
        let s = SecureStorage::with_random(SeqRandom::new());
        let key = s.generate_key().unwrap();
        let a = s.seal(&key, b"x").unwrap();
        let b = s.seal(&key, b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let s = store();
        let key = s.generate_key().unwrap();
        let mut blob = s.seal(&key, b"integrity matters").unwrap();
        // Flip one bit in the ciphertext body.
        blob.ciphertext[0] ^= 0x01;
        let err = s.open(&key, &blob).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
        assert_eq!(err.class(), aegis_core::FailureClass::Cryptography);
    }

    #[test]
    fn tampered_tag_fails_to_open() {
        let s = store();
        let key = s.generate_key().unwrap();
        let mut blob = s.seal(&key, b"tag check").unwrap();
        let last = blob.ciphertext.len() - 1;
        blob.ciphertext[last] ^= 0x80;
        assert!(matches!(s.open(&key, &blob).unwrap_err(), Error::Crypto(_)));
    }

    #[test]
    fn tampered_nonce_fails_to_open() {
        let s = store();
        let key = s.generate_key().unwrap();
        let mut blob = s.seal(&key, b"nonce bound").unwrap();
        blob.nonce[0] ^= 0xFF;
        assert!(matches!(s.open(&key, &blob).unwrap_err(), Error::Crypto(_)));
    }

    #[test]
    fn truncated_ciphertext_fails_to_open() {
        let s = store();
        let key = s.generate_key().unwrap();
        let mut blob = s.seal(&key, b"do not truncate me").unwrap();
        blob.ciphertext.truncate(blob.ciphertext.len() / 2);
        assert!(matches!(s.open(&key, &blob).unwrap_err(), Error::Crypto(_)));
    }

    #[test]
    fn malformed_nonce_length_fails_to_open() {
        let s = store();
        let key = s.generate_key().unwrap();
        let mut blob = s.seal(&key, b"payload").unwrap();
        blob.nonce.push(0); // now 25 bytes
        let err = s.open(&key, &blob).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let s = store();
        let k1 = s.generate_key().unwrap();
        let k2 = s.generate_key().unwrap();
        let blob = s.seal(&k1, b"only k1 may read this").unwrap();
        let err = s.open(&k2, &blob).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    // --- password convenience path ---------------------------------------

    #[test]
    fn seal_with_password_roundtrip_embeds_kdf() {
        let s = store();
        let pw = Secret::from("vault master password".to_string());
        let params = cheap_params(&[3u8; 16]);
        let blob = s
            .seal_with_password(&pw, &params, b"profile secrets")
            .unwrap();
        assert_eq!(blob.kdf.as_ref(), Some(&params));
        let opened = s.open_with_password(&pw, &blob).unwrap();
        assert_eq!(&opened[..], b"profile secrets");
    }

    #[test]
    fn open_with_password_wrong_password_fails() {
        let s = store();
        let params = cheap_params(&[4u8; 16]);
        let blob = s
            .seal_with_password(&Secret::from("right".to_string()), &params, b"data")
            .unwrap();
        let err = s
            .open_with_password(&Secret::from("wrong".to_string()), &blob)
            .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn open_with_password_requires_kdf_present() {
        let s = store();
        let key = s.generate_key().unwrap();
        // A blob sealed with a raw key carries kdf: None.
        let blob = s.seal(&key, b"x").unwrap();
        let err = s
            .open_with_password(&Secret::from("pw".to_string()), &blob)
            .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn seal_with_password_new_params_roundtrip() {
        // End-to-end using freshly generated interactive params (real costs).
        let s = store();
        let pw = Secret::from("end to end".to_string());
        let params = s.new_kdf_params().unwrap();
        let blob = s.seal_with_password(&pw, &params, b"e2e payload").unwrap();
        let opened = s.open_with_password(&pw, &blob).unwrap();
        assert_eq!(&opened[..], b"e2e payload");
    }

    // --- trait-object usage ----------------------------------------------

    #[test]
    fn usable_as_trait_object() {
        let boxed: Box<dyn SecureStore> = Box::new(SecureStorage::new());
        let key = boxed.generate_key().unwrap();
        let blob = boxed.seal(&key, b"via trait object").unwrap();
        assert_eq!(&boxed.open(&key, &blob).unwrap()[..], b"via trait object");
    }

    #[test]
    fn deterministic_salt_bytes_with_const_rng() {
        // Verify new_kdf_params actually draws from the injected RNG.
        let s = SecureStorage::with_random(ConstRandom(0xAB));
        let p = s.new_kdf_params().unwrap();
        assert_eq!(p.salt.0, vec![0xAB; 16]);
    }

    #[test]
    fn blob_serializes_and_reopens() {
        // Persistence path: seal, serialize to JSON, reload, open.
        let s = store();
        let pw = Secret::from("json roundtrip".to_string());
        let params = cheap_params(&[9u8; 16]);
        let blob = s.seal_with_password(&pw, &params, b"persisted").unwrap();
        let json = serde_json::to_string(&blob).unwrap();
        let back: SealedBlob = serde_json::from_str(&json).unwrap();
        let opened = s.open_with_password(&pw, &back).unwrap();
        assert_eq!(&opened[..], b"persisted");
    }
}
