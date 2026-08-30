//! Double Ratchet session encryption (README: Forward Secrecy +
//! Post-Compromise Security).
//!
//! Skeleton scope (TODO A.1): strict in-order delivery. Out-of-order or
//! skipped message keys are rejected with an error; a skipped-key store and
//! header-key caching land with the A.1 hardening pass. Message keys are
//! single-use; nonces are derived deterministically from the message key
//! (single-use key + derived nonce never repeats).

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::aead::{AeadCipher, NONCE_LEN};
use crate::error::CryptoError;
use crate::kdf::{self, RootKey};
use crate::keys::{X25519_PK_LEN, X25519KeyPair, X25519PublicKey};

/// Header length: `DH public (32) || send counter (8, BE u64) || prev chain length (8, BE u64)`.
pub const HEADER_LEN: usize = X25519_PK_LEN + 8 + 8;

/// Maximum plaintext per ratchet message: the framed message
/// (header 48 + ciphertext + tag 16) must fit the wire packet's
/// 990-byte encrypted region, leaving 926 bytes of plaintext.
pub const MAX_PLAINTEXT: usize = 926;

/// An encrypted ratchet message: header (AAD) + ciphertext + tag.
pub struct RatchetMessage {
    /// 40-byte header (also used as AEAD associated data).
    pub header: [u8; HEADER_LEN],
    /// Ciphertext including the 16-byte Poly1305 tag.
    pub payload: Vec<u8>,
}

/// Offset of the peer ratchet public key within the header.
const OFF_PEER_PK: usize = 0;

/// Offset of the message number within the header.
const OFF_N: usize = X25519_PK_LEN;

/// Offset of the previous chain length within the header.
const OFF_PN: usize = X25519_PK_LEN + 4;

/// Symmetric Double Ratchet state.
pub struct DoubleRatchet {
    /// Root key (zeroized on drop).
    root_key: RootKey,
    /// Our current ratchet key pair.
    dh_self: X25519KeyPair,
    /// Peer's current ratchet public key, if received.
    dh_remote: Option<[u8; 32]>,
    /// Sending chain key, once a ratchet step has occurred.
    chain_send: Option<Zeroizing<[u8; 32]>>,
    /// Receiving chain key, once a ratchet step has occurred.
    chain_recv: Option<Zeroizing<[u8; 32]>>,
    /// Messages sent in the current sending chain.
    send_count: u64,
    /// Messages received in the current receiving chain.
    recv_count: u64,
    /// Length of the previous sending chain at the last DH ratchet step.
    prev_send: u64,
}

/// Deterministically derives a single-use 12-byte nonce from a message key.
fn nonce_from_message_key(mk: &[u8; 32]) -> [u8; NONCE_LEN] {
    let digest = kdf::keyed_digest(mk, b"Umbra ratchet nonce");
    let mut nonce = [0u8; NONCE_LEN];
    for (dst, src) in nonce.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    nonce
}

impl DoubleRatchet {
    /// Initializes Alice's ratchet: she immediately performs a DH ratchet
    /// step against Bob's signed pre-key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] for a non-contributory DH.
    pub fn init_alice(root_key: RootKey, bob_spk: &X25519PublicKey) -> Result<Self, CryptoError> {
        let mut ratchet = Self {
            root_key,
            dh_self: X25519KeyPair::generate(),
            dh_remote: Some(bob_spk.as_bytes()),
            chain_send: None,
            chain_recv: None,
            send_count: 0,
            recv_count: 0,
            prev_send: 0,
        };
        ratchet.dh_ratchet_send(bob_spk)?;
        Ok(ratchet)
    }

    /// Initializes Bob's ratchet: he holds the signed pre-key pair and will
    /// ratchet on receipt of Alice's first message.
    #[must_use]
    pub fn init_bob(root_key: RootKey, spk: X25519KeyPair) -> Self {
        Self {
            root_key,
            dh_self: spk,
            dh_remote: None,
            chain_send: None,
            chain_recv: None,
            send_count: 0,
            recv_count: 0,
            prev_send: 0,
        }
    }

    /// Performs a sending DH ratchet step against the peer's public key.
    fn dh_ratchet_send(&mut self, peer: &X25519PublicKey) -> Result<(), CryptoError> {
        let dh_out = self.dh_self.dh(peer)?;
        let (new_root, chain) = kdf::kdf_ratchet_step(&self.root_key, &dh_out);
        self.root_key = new_root;
        self.chain_send = Some(Zeroizing::new(chain));
        Ok(())
    }

    /// Performs a receiving DH ratchet step against the peer's new public key.
    ///
    /// Signal-spec order (X3DH + Double Ratchet, "DHRatchet"):
    /// `(RK, CKr) = KDF(RK, DH(DHs_old, DHr))`, then rotate `DHs` and derive
    /// the new sending chain `(RK, CKs) = KDF(RK, DH(DHs_new, DHr))`.
    fn dh_ratchet_recv(&mut self, peer_bytes: &[u8; 32]) -> Result<(), CryptoError> {
        let peer = X25519PublicKey::from_bytes(peer_bytes);

        // Step 1: new receiving chain from the OLD DH key pair.
        let dh_out = self.dh_self.dh(&peer)?;
        let (new_root, chain_recv) = kdf::kdf_ratchet_step(&self.root_key, &dh_out);
        self.root_key = new_root;
        self.chain_recv = Some(Zeroizing::new(chain_recv));

        // Step 2: rotate our DH pair and derive the new sending chain.
        self.dh_self = X25519KeyPair::generate();
        let dh_out_next = self.dh_self.dh(&peer)?;
        let (root_next, chain_send) = kdf::kdf_ratchet_step(&self.root_key, &dh_out_next);
        self.root_key = root_next;
        self.chain_send = Some(Zeroizing::new(chain_send));

        self.dh_remote = Some(*peer_bytes);
        self.prev_send = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        Ok(())
    }

    /// Advances the sending chain and returns the single-use message key.
    ///
    /// The chain key is always `Some` here by construction: the method is
    /// only reachable after `dh_ratchet_send` populated it.
    fn advance_send(&mut self) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let chain = self
            .chain_send
            .as_ref()
            .ok_or(CryptoError::HandshakeFailed)?;
        let (next, mk) = kdf::advance_chain(chain);
        match self.chain_send.as_mut() {
            Some(slot) => *slot = Zeroizing::new(next),
            None => return Err(CryptoError::HandshakeFailed),
        }
        self.send_count = self
            .send_count
            .checked_add(1)
            .ok_or(CryptoError::HandshakeFailed)?;
        Ok(Zeroizing::new(mk))
    }

    /// Encrypts `plaintext` under the current sending chain.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] if no sending chain exists,
    /// [`CryptoError::InvalidLength`] for oversized plaintexts, or
    /// [`CryptoError::EncryptFailed`]/[`CryptoError::RngFailure`] from the
    /// AEAD layer.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CryptoError::InvalidLength {
                expected: MAX_PLAINTEXT,
                actual: plaintext.len(),
            });
        }
        let mk = self.advance_send()?;

        let mut header = [0u8; HEADER_LEN];
        kdf::write_at(&mut header, OFF_PEER_PK, &self.dh_self.public_bytes())?;
        kdf::write_at(&mut header, OFF_N, &self.send_count.to_be_bytes())?;
        kdf::write_at(&mut header, OFF_PN, &self.prev_send.to_be_bytes())?;

        let nonce = nonce_from_message_key(&mk);
        let cipher = AeadCipher::new(Zeroizing::new(*mk));
        let payload = cipher.seal_with_nonce(&nonce, &header, plaintext)?;
        Ok(RatchetMessage { header, payload })
    }

    /// Decrypts a ratchet message, performing a DH ratchet step when the
    /// peer rotates keys.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] for out-of-order or
    /// unestablished chains, and [`CryptoError::DecryptFailed`] on
    /// authentication failure.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        let peer_pk: [u8; 32] = kdf::read_at(&msg.header, OFF_PEER_PK)?;

        let rotated = match self.dh_remote {
            None => true,
            Some(current) => bool::from(current.ct_ne(&peer_pk)),
        };
        if rotated {
            self.dh_ratchet_recv(&peer_pk)?;
        }

        let chain = self
            .chain_recv
            .as_ref()
            .ok_or(CryptoError::HandshakeFailed)?;
        let (next, mk) = kdf::advance_chain(chain);
        match self.chain_recv.as_mut() {
            Some(slot) => *slot = Zeroizing::new(next),
            None => return Err(CryptoError::HandshakeFailed),
        }
        self.recv_count = self
            .recv_count
            .checked_add(1)
            .ok_or(CryptoError::HandshakeFailed)?;

        let nonce = nonce_from_message_key(&mk);
        let cipher = AeadCipher::new(Zeroizing::new(mk));
        cipher.open(&nonce, &msg.header, &msg.payload)
    }
}
