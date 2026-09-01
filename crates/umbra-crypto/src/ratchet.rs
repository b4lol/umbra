//! Double Ratchet session encryption (README: Forward Secrecy +
//! Post-Compromise Security).
//!
//! Signal-spec delivery semantics (TODO A.1 recovery): message keys for
//! out-of-order arrivals are derived ahead of time and held in a bounded
//! skipped-key store ([`MAX_SKIP_PER_CHAIN`] per receiving chain,
//! [`MAX_SKIPPED_KEYS`] total, oldest evicted first), so reordered
//! delivery decrypts instead of desynchronizing the session. Replayed or
//! evicted-too-old messages fail closed with
//! [`CryptoError::DecryptFailed`]. A message lost beyond the store is
//! unrecoverable in-band; recovery means establishing a fresh PQXDH
//! session (which is also how every messenger stream begins). Message keys are single-use;
//! nonces are derived deterministically from the message key
//! (single-use key + derived nonce never repeats).
//!
//! Header layout (v1.0 revision note: the counters were previously
//! written overlapping; nothing read them before the skipped-key store
//! landed): `DH public (32) || N (8, BE u64, 0-based index in the
//! sender's current chain) || PN (8, BE u64, previous chain length)`.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::aead::{AeadCipher, NONCE_LEN};
use crate::error::CryptoError;
use crate::kdf::{self, RootKey};
use crate::keys::{X25519_PK_LEN, X25519KeyPair, X25519PublicKey};

/// Header length: `DH public (32) || N (8, BE u64) || PN (8, BE u64)`.
pub const HEADER_LEN: usize = X25519_PK_LEN + 8 + 8;

/// Maximum messages the receiver will pre-derive in ONE receiving chain
/// when a gap opens (hostile-input bound against `N`/`PN` header values).
pub const MAX_SKIP_PER_CHAIN: u64 = 128;

/// Maximum keys held in the skipped-key store across all chains; the
/// oldest is evicted first (bounded-memory DoS trade-off, documented).
pub const MAX_SKIPPED_KEYS: usize = 256;

/// Maximum plaintext per ratchet message: the framed message
/// (header 48 + ciphertext + tag 16) must fit the wire packet's
/// 990-byte encrypted region, leaving 926 bytes of plaintext.
pub const MAX_PLAINTEXT: usize = 926;

/// An encrypted ratchet message: header (AAD) + ciphertext + tag.
pub struct RatchetMessage {
    /// [`HEADER_LEN`]-byte header (also used as AEAD associated data).
    pub header: [u8; HEADER_LEN],
    /// Ciphertext including the 16-byte Poly1305 tag.
    pub payload: Vec<u8>,
}

/// Offset of the peer ratchet public key within the header.
const OFF_PEER_PK: usize = 0;

/// Offset of the message number within the header (0-based chain index).
const OFF_N: usize = X25519_PK_LEN;

/// Offset of the previous chain length within the header.
const OFF_PN: usize = X25519_PK_LEN + 8;

/// One pre-derived message key held for a future out-of-order delivery.
#[derive(Clone)]
struct SkippedKey {
    /// Peer ratchet public key of the chain the key belongs to.
    dh: [u8; 32],
    /// 0-based index of the message within that chain.
    n: u64,
    /// Single-use message key (zeroized on drop).
    mk: Zeroizing<[u8; 32]>,
}

/// Symmetric Double Ratchet state.
#[derive(Clone)]
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
    /// Pre-derived message keys for out-of-order delivery, oldest first.
    skipped: Vec<SkippedKey>,
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
            skipped: Vec::new(),
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
            skipped: Vec::new(),
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
        // Keep only store entries belonging to the previous or the new
        // peer ratchet key; attacker-crafted rotation churn cannot pin
        // arbitrary keys in the store.
        let previous = self.dh_remote;
        self.skipped
            .retain(|entry| Some(&entry.dh) == previous.as_ref() || &entry.dh == peer_bytes);

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
        let n = self.send_count;
        let mk = self.advance_send()?;

        let mut header = [0u8; HEADER_LEN];
        kdf::write_at(&mut header, OFF_PEER_PK, &self.dh_self.public_bytes())?;
        kdf::write_at(&mut header, OFF_N, &n.to_be_bytes())?;
        kdf::write_at(&mut header, OFF_PN, &self.prev_send.to_be_bytes())?;

        let nonce = nonce_from_message_key(&mk);
        let cipher = AeadCipher::new(Zeroizing::new(*mk));
        let payload = cipher.seal_with_nonce(&nonce, &header, plaintext)?;
        Ok(RatchetMessage { header, payload })
    }

    /// Stashes one message key in the bounded skipped-key store, evicting
    /// the oldest entry when the store is full.
    fn stash_skipped(&mut self, dh: [u8; 32], n: u64, mk: Zeroizing<[u8; 32]>) {
        if self.skipped.len() >= MAX_SKIPPED_KEYS {
            self.skipped.remove(0);
        }
        self.skipped.push(SkippedKey { dh, n, mk });
    }

    /// Takes a pre-derived message key for `(dh, n)` out of the store, if
    /// one was stashed.
    fn take_skipped(&mut self, dh: &[u8; 32], n: u64) -> Option<Zeroizing<[u8; 32]>> {
        let index = self
            .skipped
            .iter()
            .position(|entry| bool::from(entry.dh.ct_eq(dh)) && entry.n == n)?;
        let entry = self.skipped.remove(index);
        // Best-effort register scrub (ADR-025 revision note): the store
        // index arithmetic and comparison intermediates transit
        // caller-saved registers.
        umbra_hardware::hardening::scrub_volatile_registers();
        Some(entry.mk)
    }

    /// Pre-derives message keys up to (excluding) index `until` of the
    /// current receiving chain into the skipped-key store, advancing the
    /// receiving chain position.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecryptFailed`] when the gap exceeds
    /// [`MAX_SKIP_PER_CHAIN`] (hostile header bound).
    fn skip_message_keys(&mut self, until: u64) -> Result<(), CryptoError> {
        if self.chain_recv.is_none() || self.recv_count >= until {
            return Ok(());
        }
        let Some(dh) = self.dh_remote else {
            return Ok(());
        };
        let span = until
            .checked_sub(self.recv_count)
            .ok_or(CryptoError::DecryptFailed)?;
        if span > MAX_SKIP_PER_CHAIN {
            return Err(CryptoError::DecryptFailed);
        }
        let span = usize::try_from(span).map_err(|_e| CryptoError::DecryptFailed)?;
        for _ in 0..span {
            let chain = self
                .chain_recv
                .as_ref()
                .ok_or(CryptoError::HandshakeFailed)?;
            let (next, mk) = kdf::advance_chain(chain);
            match self.chain_recv.as_mut() {
                Some(slot) => *slot = Zeroizing::new(next),
                None => return Err(CryptoError::HandshakeFailed),
            }
            self.stash_skipped(dh, self.recv_count, Zeroizing::new(mk));
            self.recv_count = self
                .recv_count
                .checked_add(1)
                .ok_or(CryptoError::HandshakeFailed)?;
        }
        Ok(())
    }

    /// Decrypts a ratchet message, performing a DH ratchet step when the
    /// peer rotates keys and stashing pre-derived keys for any messages
    /// that arrived out of order (Signal-spec "SkipMessageKeys").
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] for unestablished chains
    /// and [`CryptoError::DecryptFailed`] on authentication failure,
    /// replay, a message older than the store, or a header gap beyond
    /// [`MAX_SKIP_PER_CHAIN`]. On any error the ratchet state is left
    /// exactly as it was (transactional).
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        // Signal spec §3.5: on an exception (e.g. authentication
        // failure) the message is discarded AND the state changes made
        // while processing it are discarded. Clone the small scalar
        // state, mutate tentatively, commit only on success.
        let snapshot = self.clone();
        match self.decrypt_inner(msg) {
            Ok(plaintext) => Ok(plaintext),
            Err(failure) => {
                *self = snapshot;
                Err(failure)
            }
        }
    }

    /// Mutating decrypt body; wrapped transactionally by [`Self::decrypt`].
    fn decrypt_inner(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        let peer_pk: [u8; 32] = kdf::read_at(&msg.header, OFF_PEER_PK)?;
        let n = u64::from_be_bytes(kdf::read_at(&msg.header, OFF_N)?);
        let pn = u64::from_be_bytes(kdf::read_at(&msg.header, OFF_PN)?);

        // Reordered delivery: the key was pre-derived when a later
        // message of the same chain arrived.
        if let Some(mk) = self.take_skipped(&peer_pk, n) {
            let nonce = nonce_from_message_key(&mk);
            let cipher = AeadCipher::new(Zeroizing::new(*mk));
            return cipher.open(&nonce, &msg.header, &msg.payload);
        }

        let rotated = match self.dh_remote {
            None => true,
            Some(current) => bool::from(current.ct_ne(&peer_pk)),
        };
        if rotated {
            // Tail of the peer's PREVIOUS sending chain, then the step.
            self.skip_message_keys(pn)?;
            self.dh_ratchet_recv(&peer_pk)?;
        }
        self.skip_message_keys(n)?;

        if self.recv_count != n {
            // Behind the chain position and not in the store: replayed
            // or evicted too old. Fail closed without touching the chain.
            return Err(CryptoError::DecryptFailed);
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
