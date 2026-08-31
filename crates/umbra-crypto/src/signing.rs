//! ML-DSA-65 post-quantum signatures (CRYPTOGRAPHY.md §1, NIST FIPS 204).
//!
//! Used for identity attestation; SLH-DSA (FIPS 205) lands as the hash-based
//! fallback with the A.1 hardening pass.

use core::mem::size_of;

use crypto_common::Key;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyExport, KeyInit, MlDsa65, Signature, SigningKey,
    VerifyingKey,
};
use rand_core::Rng;

use crate::error::CryptoError;
use crate::rng;

/// ML-DSA-65 key-generation seed length in bytes (FIPS 204: ξ).
pub const DSA_SEED_LEN: usize = 32;

/// Serialized verification key length (NIST FIPS 204, ML-DSA-65).
pub const VK_LEN: usize = size_of::<EncodedVerifyingKey<MlDsa65>>();

/// Encoded signature length (NIST FIPS 204, ML-DSA-65).
pub const SIG_LEN: usize = size_of::<EncodedSignature<MlDsa65>>();

/// Byte-array type of the ML-DSA-65 verification key.
type VkKey = Key<VerifyingKey<MlDsa65>>;

/// ML-DSA-65 signing key pair.
pub struct MlDsaKeyPair {
    /// Signing (private) key.
    sk: SigningKey<MlDsa65>,
    /// Verification (public) key.
    vk: VerifyingKey<MlDsa65>,
}

impl MlDsaKeyPair {
    /// Generates a fresh ML-DSA-65 key pair from a random 32-byte seed
    /// (`ML-DSA.KeyGen_internal(ξ)` — FIPS 204). The seed is retained for
    /// keystore serialization.
    ///
    /// See [`crate::rng`] for the documented panic boundary of key generation.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; DSA_SEED_LEN];
        // Infallible fill — entropy failure panics at the documented
        // boundary (see `rng::system_rng`).
        rng::system_rng().fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Reconstructs a key pair from its 32-byte seed
    /// (`ML-DSA.KeyGen_internal`).
    #[must_use]
    pub fn from_seed(seed: &[u8; DSA_SEED_LEN]) -> Self {
        // `from_slice` is deprecated in favor of TryFrom, but the length
        // here is statically guaranteed by the `&[u8; DSA_SEED_LEN]`
        // parameter (32 == Seed size).
        #[allow(deprecated)]
        let seed_ref = ml_dsa::Seed::from_slice(seed);
        let sk = SigningKey::<MlDsa65>::from_seed(seed_ref);
        Self {
            vk: sk.verifying_key(),
            sk,
        }
    }

    /// The 32-byte key-generation seed.
    ///
    /// SECRET MATERIAL — keystore use only. `SigningKey::to_bytes`
    /// (KeyExport) returns the ξ seed per FIPS 204.
    #[must_use]
    pub fn seed_bytes(&self) -> [u8; DSA_SEED_LEN] {
        let mut out = [0u8; DSA_SEED_LEN];
        out.copy_from_slice(self.sk.to_bytes().as_ref());
        out
    }

    /// Signs `message` and returns the encoded signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature<MlDsa65> = self.sk.sign(message);
        let encoded: EncodedSignature<MlDsa65> = sig.encode();
        let bytes: &[u8] = encoded.as_ref();
        bytes.to_vec()
    }

    /// Serializes the verification (public) key.
    #[must_use]
    pub fn public_bytes(&self) -> Vec<u8> {
        let arr = self.vk.to_bytes();
        let bytes: &[u8] = arr.as_ref();
        bytes.to_vec()
    }

    /// Verifies `signature` over `message` for a serialized public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] for malformed inputs and
    /// [`CryptoError::InvalidSignature`] if verification fails.
    pub fn verify(vk_bytes: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if vk_bytes.len() != VK_LEN {
            return Err(CryptoError::InvalidLength {
                expected: VK_LEN,
                actual: vk_bytes.len(),
            });
        }
        if signature.len() != SIG_LEN {
            return Err(CryptoError::InvalidLength {
                expected: SIG_LEN,
                actual: signature.len(),
            });
        }
        let vk_arr: &VkKey =
            <&VkKey>::try_from(vk_bytes).map_err(|_e| CryptoError::InvalidLength {
                expected: VK_LEN,
                actual: vk_bytes.len(),
            })?;
        let vk = VerifyingKey::<MlDsa65>::new(vk_arr);

        let sig_arr: &EncodedSignature<MlDsa65> = <&EncodedSignature<MlDsa65>>::try_from(signature)
            .map_err(|_e| CryptoError::InvalidLength {
                expected: SIG_LEN,
                actual: signature.len(),
            })?;
        let sig = Signature::<MlDsa65>::decode(sig_arr).ok_or(CryptoError::InvalidSignature)?;

        vk.verify(message, &sig)
            .map_err(|_e| CryptoError::InvalidSignature)
    }
}
