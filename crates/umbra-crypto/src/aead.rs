//! ChaCha20-Poly1305 AEAD wrapper (CRYPTOGRAPHY.md §1, RFC 8439).
//!
//! Nonces are single-use and drawn from the OS entropy source on every seal;
//! message keys in the Double Ratchet are single-use by construction.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, AeadInOut, Payload},
};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::rng;

/// Symmetric key length in bytes (256-bit).
pub const KEY_LEN: usize = 32;

/// Nonce length in bytes (96-bit, single use).
pub const NONCE_LEN: usize = 12;

/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Authenticated-encryption cipher instance for one key.
pub struct AeadCipher {
    /// Inner RustCrypto cipher (key held inside; zeroized via the key array).
    cipher: ChaCha20Poly1305,
}

impl AeadCipher {
    /// Creates a cipher from a 32-byte symmetric key.
    ///
    /// The key bytes are zeroized after being loaded into the cipher key
    /// schedule via [`Zeroizing`].
    #[must_use]
    pub fn new(key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        let key_array = Key::from(*key);
        Self {
            cipher: ChaCha20Poly1305::new(&key_array),
        }
    }

    /// Encrypts `plaintext` with a fresh random nonce written to `nonce_out`.
    ///
    /// Returns ciphertext with an appended 16-byte Poly1305 tag.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RngFailure`] if the OS entropy fails, or
    /// [`CryptoError::EncryptFailed`] if the AEAD rejects the input.
    pub fn seal(
        &self,
        aad: &[u8],
        plaintext: &[u8],
        nonce_out: &mut [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, CryptoError> {
        rng::fill(nonce_out)?;
        let nonce = Nonce::from(*nonce_out);
        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_e| CryptoError::EncryptFailed)
    }

    /// Encrypts `plaintext` under a caller-supplied single-use nonce.
    ///
    /// Used by the Double Ratchet, where the nonce is derived from the
    /// single-use message key (never repeats).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EncryptFailed`] if the AEAD rejects the input.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_e| CryptoError::EncryptFailed)
    }

    /// Decrypts `buffer` in place (payload + 16-byte tag → plaintext)
    /// and verifies `aad`. Allocation-free verify path — the constant-
    /// time suite measures this boundary directly.
    ///
    /// Failure invariant (verified upstream, chacha20poly1305 0.11): the
    /// Poly1305 tag is checked BEFORE any keystream is applied, so on
    /// [`CryptoError::DecryptFailed`] the buffer is left byte-for-byte
    /// unchanged (still ciphertext) — no partial-decryption residue.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecryptFailed`] if authentication fails.
    pub fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .decrypt_in_place(&nonce, aad, buffer)
            .map_err(|_e| CryptoError::DecryptFailed)
    }

    /// Decrypts `ciphertext` (payload + 16-byte tag) and verifies `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecryptFailed`] if authentication fails.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_e| CryptoError::DecryptFailed)
    }
}
