//! Key material: X25519 identities, ML-KEM-768 KEM pairs, and the aggregate
//! identity bundle. All secret-bearing types zeroize on drop (CODE_MANIFESTO
//! §7, `zeroize` doctrine).

use crypto_common::Key;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, MlKem768,
    Seed as KemSeed, kem::FromSeed,
};
use rand_core::Rng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::rng;

/// ML-KEM-768 encapsulation key (public) length in bytes.
pub const KEM_PK_LEN: usize = 1184;

/// ML-KEM-768 ciphertext (encapsulated secret) length in bytes.
pub const KEM_CT_LEN: usize = 1088;

/// ML-KEM-768 shared secret length in bytes.
pub const KEM_SS_LEN: usize = 32;

/// ML-KEM-768 key-generation seed length in bytes (FIPS 203: d ∥ z).
pub const KEM_SEED_LEN: usize = 64;

/// ML-DSA-65 key-generation seed length in bytes (FIPS 204: ξ).
pub const DSA_SEED_LEN: usize = 32;

/// X25519 public key length in bytes.
pub const X25519_PK_LEN: usize = 32;

/// Byte-array type of an ML-KEM-768 encapsulation key.
type EkKey = Key<EncapsulationKey<MlKem768>>;

/// X25519 identity or ephemeral key pair with zeroize-on-drop secret.
#[derive(Clone)]
pub struct X25519KeyPair {
    /// Private scalar (zeroized on drop via the `x25519-dalek` `zeroize`
    /// feature).
    secret: StaticSecret,
}

impl X25519KeyPair {
    /// Generates a fresh key pair from OS entropy.
    ///
    /// See [`crate::rng`] for the documented panic boundary of key generation.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rng::system_rng();
        Self {
            secret: StaticSecret::random_from_rng(&mut rng),
        }
    }

    /// Reconstructs a key pair from raw scalar bytes.
    #[must_use]
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(*bytes),
        }
    }

    /// Clones the key pair (secret included) for handing a copy to a
    /// consumer that takes ownership, without moving the original.
    #[must_use]
    pub fn secret_clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }

    /// Serializes the raw secret scalar (keystore roundtrip only).
    ///
    /// SECRET MATERIAL — the returned bytes recreate this key pair via
    /// `from_secret_bytes`.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Serializes the derived public key.
    ///
    /// x25519-dalek 3.0 clamps scalars at DH time, so the public key MUST be
    /// derived via `From<&StaticSecret>` (basepoint multiplication); the
    /// raw `to_bytes()` output is an unclamped scalar, not a curve point.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    /// Computes the X25519 shared secret with `peer`, rejecting
    /// non-contributory (low-order) results.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] for non-contributory outputs.
    pub fn dh(&self, peer: &X25519PublicKey) -> Result<[u8; 32], CryptoError> {
        let shared = self.secret.diffie_hellman(&peer.key);
        if !shared.was_contributory() {
            return Err(CryptoError::HandshakeFailed);
        }
        Ok(*shared.as_bytes())
    }
}

/// X25519 public key wrapper.
pub struct X25519PublicKey {
    /// Inner dalek public key.
    key: PublicKey,
}

impl X25519PublicKey {
    /// Imports a public key from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: PublicKey::from(*bytes),
        }
    }

    /// Serializes the public key.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 32] {
        *self.key.as_bytes()
    }
}

/// ML-KEM-768 key pair (decapsulation + encapsulation key). The
/// key-generation seed is retained for keystore serialization
/// (`ML-KEM.KeyGen_internal(d ∥ z)` — FIPS 203) and zeroized on drop
/// (the ml-kem `zeroize` feature also wipes the decapsulation key).
pub struct MlKemKeyPair {
    /// Decapsulation (private) key.
    decap: DecapsulationKey<MlKem768>,
    /// Encapsulation (public) key.
    encaps: EncapsulationKey<MlKem768>,
    /// Key-generation seed (secret material, keystore use only).
    seed: [u8; KEM_SEED_LEN],
}

impl Drop for MlKemKeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl MlKemKeyPair {
    /// Generates a fresh ML-KEM-768 key pair from OS entropy.
    ///
    /// See [`crate::rng`] for the documented panic boundary of key generation.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; KEM_SEED_LEN];
        // Fallible fill surfaced as Result: entropy failure here would hit
        // the documented panic boundary in `rng::system_rng` — we surface
        // it as an error instead by trying the fallible path first.
        rng::fill(&mut seed).unwrap_or_else(|_e| {
            // Zero-panic doctrine: degenerate-entropy fallback is NOT
            // acceptable for key material — mirror `rng::system_rng`'s
            // documented panic boundary (RNG failure = unrecoverable).
            rng::system_rng().fill_bytes(&mut seed);
        });
        Self::from_seed(&seed)
    }

    /// Reconstructs a key pair from its 64-byte seed
    /// (`ML-KEM.KeyGen_internal`).
    #[must_use]
    pub fn from_seed(seed: &[u8; KEM_SEED_LEN]) -> Self {
        // `from_slice` is deprecated in favor of TryFrom, but the length
        // here is statically guaranteed by the `&[u8; KEM_SEED_LEN]`
        // parameter (64 == KemSeed size), so the panic path the deprecation
        // guards against is unreachable.
        #[allow(deprecated)]
        let kem_seed = KemSeed::from_slice(seed);
        let (decap, encaps) = MlKem768::from_seed(kem_seed);
        Self {
            decap,
            encaps,
            seed: *seed,
        }
    }

    /// The 64-byte key-generation seed.
    ///
    /// SECRET MATERIAL — keystore use only.
    #[must_use]
    pub const fn seed_bytes(&self) -> &[u8; KEM_SEED_LEN] {
        &self.seed
    }

    /// Serializes the encapsulation (public) key.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; KEM_PK_LEN] {
        let mut out = [0u8; KEM_PK_LEN];
        let arr = self.encaps.to_bytes();
        out.copy_from_slice(&arr);
        out
    }

    /// Encapsulates a fresh shared secret toward this pair's public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    ///
    /// See [`crate::rng`] for the documented panic boundary.
    #[must_use]
    pub fn encapsulate(&self) -> ([u8; KEM_CT_LEN], [u8; KEM_SS_LEN]) {
        let mut rng = rng::system_rng();
        let (ct, ss) = self.encaps.encapsulate_with_rng(&mut rng);
        let mut ct_out = [0u8; KEM_CT_LEN];
        ct_out.copy_from_slice(&ct);
        let mut ss_out = [0u8; KEM_SS_LEN];
        ss_out.copy_from_slice(&ss);
        (ct_out, ss_out)
    }

    /// Decapsulates a ciphertext produced for this pair's public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] if `ct` is malformed.
    pub fn decapsulate(&self, ct: &[u8; KEM_CT_LEN]) -> Result<[u8; KEM_SS_LEN], CryptoError> {
        let ct_ref: &Ciphertext<MlKem768> = <&Ciphertext<MlKem768>>::try_from(ct.as_slice())
            .map_err(|_e| CryptoError::InvalidLength {
                expected: KEM_CT_LEN,
                actual: ct.len(),
            })?;
        let ss = self.decap.decapsulate(ct_ref);
        let mut out = [0u8; KEM_SS_LEN];
        out.copy_from_slice(&ss);
        Ok(out)
    }
}

/// Peer-side ML-KEM-768 encapsulation key imported from the wire.
pub struct MlKemPeerKey {
    /// Encapsulation (public) key of the peer.
    encaps: EncapsulationKey<MlKem768>,
}

impl MlKemPeerKey {
    /// Imports a peer encapsulation key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] on encoding-length mismatch
    /// and [`CryptoError::InvalidKey`] if the KEM rejects the key encoding.
    pub fn from_bytes(bytes: &[u8; KEM_PK_LEN]) -> Result<Self, CryptoError> {
        let key: &EkKey =
            <&EkKey>::try_from(bytes.as_slice()).map_err(|_e| CryptoError::InvalidLength {
                expected: KEM_PK_LEN,
                actual: bytes.len(),
            })?;
        let encaps =
            EncapsulationKey::<MlKem768>::new(key).map_err(|_e| CryptoError::InvalidKey)?;
        Ok(Self { encaps })
    }

    /// Encapsulates a fresh shared secret toward the peer.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    ///
    /// See [`crate::rng`] for the documented panic boundary.
    #[must_use]
    pub fn encapsulate(&self) -> ([u8; KEM_CT_LEN], [u8; KEM_SS_LEN]) {
        let mut rng = rng::system_rng();
        let (ct, ss) = self.encaps.encapsulate_with_rng(&mut rng);
        let mut ct_out = [0u8; KEM_CT_LEN];
        ct_out.copy_from_slice(&ct);
        let mut ss_out = [0u8; KEM_SS_LEN];
        ss_out.copy_from_slice(&ss);
        (ct_out, ss_out)
    }
}

/// Secret seeds of an [`IdentityBundle`] (keystore serialization form).
/// Zeroized on drop (CODE_MANIFESTO §7).
#[derive(ZeroizeOnDrop)]
pub struct IdentitySeeds {
    /// X25519 identity secret scalar.
    pub x25519: [u8; 32],
    /// SPK secret scalar.
    pub spk: [u8; 32],
    /// ML-KEM-768 key-generation seed (d ∥ z).
    pub kem: [u8; KEM_SEED_LEN],
    /// ML-DSA-65 key-generation seed (ξ).
    pub dsa: [u8; DSA_SEED_LEN],
}

/// Aggregate identity: X25519 identity key, signed prekey, ML-KEM-768 KEM
/// pair, and ML-DSA-65 signing key. Identity IS the key pair — no phone
/// number, e-mail, or username (README "Zero-PII Identity").
pub struct IdentityBundle {
    /// Classical identity key pair.
    pub x25519: X25519KeyPair,
    /// Signed prekey pair for the PQXDH ratchet (PQXDH SPK slot).
    pub spk: X25519KeyPair,
    /// ML-DSA-65 signature over the SPK public bytes, made by `dsa`.
    pub spk_signature: Vec<u8>,
    /// Post-quantum KEM pair.
    pub kem: MlKemKeyPair,
    /// Post-quantum signature key pair.
    pub dsa: crate::signing::MlDsaKeyPair,
}

impl IdentityBundle {
    /// Generates a full identity bundle from OS entropy.
    ///
    /// The SPK is signed by the ML-DSA key at generation time
    /// (`verify_spk_signature`); peer-side SPK-signature verification
    /// during pairing is part of the session-layer wiring (TODO A.3).
    ///
    /// See [`crate::rng`] for the documented panic boundary.
    #[must_use]
    pub fn generate() -> Self {
        let spk = X25519KeyPair::generate();
        let kem = MlKemKeyPair::generate();
        let dsa = crate::signing::MlDsaKeyPair::generate();
        let spk_signature = dsa.sign(&spk.public_bytes());
        Self {
            x25519: X25519KeyPair::generate(),
            spk,
            spk_signature,
            kem,
            dsa,
        }
    }

    /// Reconstructs a bundle from its secret seeds (keystore load path).
    /// The SPK signature is recomputed from the reconstructed ML-DSA key.
    #[must_use]
    pub fn from_seeds(seeds: &IdentitySeeds) -> Self {
        let spk = X25519KeyPair::from_secret_bytes(&seeds.spk);
        let dsa = crate::signing::MlDsaKeyPair::from_seed(&seeds.dsa);
        let spk_signature = dsa.sign(&spk.public_bytes());
        Self {
            x25519: X25519KeyPair::from_secret_bytes(&seeds.x25519),
            spk,
            spk_signature,
            kem: MlKemKeyPair::from_seed(&seeds.kem),
            dsa,
        }
    }

    /// The secret seeds, in keystore serialization form.
    ///
    /// SECRET MATERIAL — keystore serialization only.
    #[must_use]
    pub fn secret_seeds(&self) -> IdentitySeeds {
        IdentitySeeds {
            x25519: self.x25519.secret_bytes(),
            spk: self.spk.secret_bytes(),
            kem: *self.kem.seed_bytes(),
            dsa: self.dsa.seed_bytes(),
        }
    }

    /// Replaces and returns the SPK key pair (moving it into the Double
    /// Ratchet without cloning secret bytes). The replacement pair is
    /// re-signed by the bundle's ML-DSA key, so `spk_signature` stays
    /// consistent with the new `spk`.
    ///
    /// See [`crate::rng`] for the documented panic boundary of key
    /// generation.
    #[must_use]
    pub fn take_spk(&mut self) -> X25519KeyPair {
        let fresh = X25519KeyPair::generate();
        self.spk_signature = self.dsa.sign(&fresh.public_bytes());
        std::mem::replace(&mut self.spk, fresh)
    }

    /// Verifies the bundle's SPK signature with a peer's ML-DSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSignature`] if the signature does not
    /// verify.
    pub fn verify_spk_signature(peer_dsa_public: &[u8], bundle: &Self) -> Result<(), CryptoError> {
        crate::signing::MlDsaKeyPair::verify(
            peer_dsa_public,
            &bundle.spk.public_bytes(),
            &bundle.spk_signature,
        )
    }
}
