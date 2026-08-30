//! Typestate session state machine (SPECIFICATION.md §2, ADR-021).
//!
//! Data-channel multiplexer: every ratchet plaintext carries a 1-byte tag
//! (`0x00` user text, `0x01` SMP carriage). SMP payloads larger than the
//! ratchet budget are chunked (`send_smp`) and reassembled on receipt
//! (`SmpCarriage`, bounded at [`MAX_SMP_CHUNKS`]); chunk index 0 defines
//! (or restarts) a transfer. Effective user-text budget per packet is
//! `MAX_PLAINTEXT - 1` bytes.
//!
//! States mirror the protocol state machine:
//! `Disconnected → OutOfBandPairing → TorBootstrap → Handshaking →
//! Established → Terminated` collapses here into
//! [`Unauthenticated`] → [`HandshakeInProgress`] → [`EstablishedSession`].
//! Only [`EstablishedSession`] exposes `send_data`/`receive`, making illegal
//! transitions unrepresentable at the type level.

use core::marker::PhantomData;

use zeroize::Zeroizing;

use umbra_crypto::kdf::{self, RootKey};
use umbra_crypto::keys::{IdentityBundle, MlKemPeerKey, X25519KeyPair, X25519PublicKey};
use umbra_crypto::ratchet::DoubleRatchet;

use crate::error::ProtocolError;
use crate::newtypes::SequenceNumber;
use crate::packet::{self, SealedPacket, UnsealedPacket};
use crate::types::PacketType;

/// Marker state: no peer, no handshake.
#[derive(Debug, Default)]
pub struct Unauthenticated;

/// Marker state: PQXDH in flight.
#[derive(Debug, Default)]
pub struct HandshakeInProgress;

/// Marker state: ratchet established, data exchange allowed.
#[derive(Debug, Default)]
pub struct EstablishedSession;

/// Sealed trait of all session states.
pub trait SessionState {}

impl SessionState for Unauthenticated {}
impl SessionState for HandshakeInProgress {}
impl SessionState for EstablishedSession {}

/// Context string for deriving the packet-sealing key from the root key.
const PACKET_KEY_CONTEXT: &str = "Umbra packet seal key v1";

/// Handshake role: who derived the root key and how the ratchet boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeRole {
    /// We ran `initiator_start`; the ratchet boots with `init_alice`
    /// against the peer's SPK.
    Outgoing,
    /// We ran `responder_respond`; the ratchet boots with `init_bob` on
    /// our own SPK pair.
    Incoming,
}

/// Handshake bookkeeping held between the handshake exchange and completion.
struct HandshakeState {
    /// PQXDH root key (initiator- or responder-derived).
    root: RootKey,
    /// Handshake role.
    role: HandshakeRole,
    /// Outgoing: peer SPK public bytes used to bootstrap the ratchet.
    peer_spk: Option<[u8; 32]>,
    /// Incoming: our own SPK pair, moved out of the identity bundle.
    own_spk: Option<X25519KeyPair>,
}

/// Established-state internals.
struct EstablishedState {
    /// Double Ratchet engine.
    ratchet: DoubleRatchet,
    /// Symmetric key for the wire-level packet layer.
    packet_key: Zeroizing<[u8; 32]>,
    /// In-progress SMP carriage reassembly, if any.
    smp_reassembly: Option<SmpCarriage>,
    /// Set when SESSION_TERMINATE was sent or received.
    terminated: bool,
}

impl EstablishedState {
    /// Wipes the state in place: ratchet chains and the packet key all
    /// zeroize on drop.
    fn wipe(&mut self) {
        self.smp_reassembly = None;
        // `packet_key` is Zeroizing; the ratchet's chain/message keys are
        // Zeroizing wrappers too — dropping them wipes the bytes.
        self.packet_key = Zeroizing::new([0u8; 32]);
        self.ratchet = DoubleRatchet::init_bob(
            umbra_crypto::kdf::RootKey::from_bytes([0u8; 32]),
            X25519KeyPair::from_secret_bytes(&[0u8; 32]),
        );
    }
}

/// Payload multiplexer tags carried as the first byte of every ratchet
/// plaintext (SPECIFICATION: SMP rides the encrypted data channel, like
/// OTR's SMP TLVs).
const TAG_TEXT: u8 = 0x00;

/// Tag for multi-packet SMP carriage frames.
const TAG_SMP: u8 = 0x01;

/// Header size of an SMP carriage frame: tag(1) + index(4) + total(4).
const SMP_CARRIAGE_HEADER: usize = 9;

/// Maximum ratchet plaintext per SMP carriage chunk.
const SMP_CHUNK_DATA: usize = umbra_crypto::ratchet::MAX_PLAINTEXT - SMP_CARRIAGE_HEADER;

/// Maximum SMP carriage chunks per message (hostile-input bound).
const MAX_SMP_CHUNKS: u32 = 4096;

/// In-progress SMP carriage reassembly state.
struct SmpCarriage {
    /// Expected total chunk count.
    total: u32,
    /// Received data slots (index-ordered).
    slots: Vec<Option<Vec<u8>>>,
    /// Number of filled slots.
    received: u32,
}

/// A decrypted inbound payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundPayload {
    /// A user text payload (tag `0x00`).
    Text(Vec<u8>),
    /// A fully reassembled SMP message (tag `0x01`; partial chunks are
    /// buffered internally and yield `None` until complete).
    Smp(Vec<u8>),
    /// The peer sent SESSION_TERMINATE (SPECIFICATION opcode `0x09`):
    /// the local session state has been zeroized and the session is dead.
    Terminate,
}

/// Protocol session parameterized by its typestate.
pub struct Session<S: SessionState> {
    /// Typestate marker.
    _state: PhantomData<S>,
    /// Local identity bundle (X25519 + ML-KEM + ML-DSA).
    identity: IdentityBundle,
    /// Present from `begin_handshake` until the ratchet is established.
    handshake: Option<HandshakeState>,
    /// Present only in the established state.
    established: Option<EstablishedState>,
    /// Outbound message counter.
    sequence: SequenceNumber,
}

impl Session<Unauthenticated> {
    /// Creates a session in the initial state with a fresh identity.
    ///
    /// See [`umbra_crypto::rng`] for the documented panic boundary.
    #[must_use]
    pub fn new() -> Self {
        Self::with_identity(IdentityBundle::generate())
    }

    /// Creates a session bound to a caller-provided identity bundle
    /// (used when the identity comes from persistent storage).
    #[must_use]
    pub fn with_identity(identity: IdentityBundle) -> Self {
        Self {
            _state: PhantomData,
            identity,
            handshake: None,
            established: None,
            sequence: SequenceNumber::INITIAL,
        }
    }

    /// Borrowed view of the local identity.
    #[must_use]
    pub const fn identity(&self) -> &IdentityBundle {
        &self.identity
    }

    /// Starts the PQXDH handshake toward a peer.
    ///
    /// The peer's SPK signature (`peer_spk_signature`, made by the peer's
    /// ML-DSA identity key `peer_dsa_public`) is verified BEFORE any key
    /// derivation: an active MITM cannot substitute a prekey/KEM bundle
    /// without holding the peer's signature key. Note the residual: the
    /// ML-DSA identity itself is per-run ephemeral until a
    /// pairing-authenticated fingerprint exchange is wired (TODO A.3).
    ///
    /// Returns the initiator handshake blob for the transport layer.
    ///
    /// # Errors
    ///
    /// Propagates [`umbra_crypto::CryptoError`] from PQXDH and signature
    /// verification.
    pub fn begin_handshake(
        mut self,
        peer_ik: &X25519PublicKey,
        peer_spk: &X25519PublicKey,
        peer_spk_signature: &[u8],
        peer_dsa_public: &[u8],
        peer_kem: &MlKemPeerKey,
    ) -> Result<(Session<HandshakeInProgress>, Vec<u8>), ProtocolError> {
        umbra_crypto::signing::MlDsaKeyPair::verify(
            peer_dsa_public,
            &peer_spk.as_bytes(),
            peer_spk_signature,
        )?;
        let (handshake, root) = umbra_crypto::pqxdh::initiator_start(
            &self.identity.x25519,
            peer_ik,
            peer_spk,
            peer_kem,
        )?;
        self.handshake = Some(HandshakeState {
            root,
            role: HandshakeRole::Outgoing,
            peer_spk: Some(peer_spk.as_bytes()),
            own_spk: None,
        });
        Ok((
            Session {
                _state: PhantomData,
                identity: self.identity,
                handshake: self.handshake,
                established: None,
                sequence: self.sequence,
            },
            handshake.encode(),
        ))
    }
}

impl Session<Unauthenticated> {
    /// Accepts an incoming PQXDH handshake blob (responder side).
    ///
    /// Verifies nothing yet — authentication is completed out of band via
    /// SAS/SMP (CRYPTOGRAPHY.md §5); this derives the shared root key and
    /// arms the responder role.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Crypto`] for a malformed blob and for
    /// non-contributory DH ('HandshakeFailed').
    pub fn accept_handshake(
        mut self,
        blob: &[u8],
    ) -> Result<Session<HandshakeInProgress>, ProtocolError> {
        let handshake = umbra_crypto::pqxdh::InitialHandshake::decode(blob)?;
        let root = umbra_crypto::pqxdh::responder_respond(
            &self.identity.x25519,
            &self.identity.spk,
            &self.identity.kem,
            &handshake,
        )?;
        let own_spk = self.identity.take_spk();
        self.handshake = Some(HandshakeState {
            root,
            role: HandshakeRole::Incoming,
            peer_spk: None,
            own_spk: Some(own_spk),
        });
        Ok(Session {
            _state: PhantomData,
            identity: self.identity,
            handshake: self.handshake,
            established: None,
            sequence: self.sequence,
        })
    }
}

impl Default for Session<Unauthenticated> {
    fn default() -> Self {
        Self::new()
    }
}

impl Session<HandshakeInProgress> {
    /// Completes the handshake and enters the established state.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::StateViolation`] if the handshake state is
    /// missing, or crypto errors from ratchet initialization.
    pub fn complete_handshake(mut self) -> Result<Session<EstablishedSession>, ProtocolError> {
        let handshake = self.handshake.take().ok_or(ProtocolError::StateViolation)?;
        if handshake.role != HandshakeRole::Outgoing {
            return Err(ProtocolError::StateViolation);
        }
        let peer_spk = handshake.peer_spk.ok_or(ProtocolError::StateViolation)?;
        let packet_key = Zeroizing::new(kdf::derive_key(
            PACKET_KEY_CONTEXT,
            handshake.root.as_bytes(),
        ));
        let ratchet =
            DoubleRatchet::init_alice(handshake.root, &X25519PublicKey::from_bytes(&peer_spk))?;
        self.established = Some(EstablishedState {
            ratchet,
            packet_key,
            smp_reassembly: None,
            terminated: false,
        });
        Ok(Session {
            _state: PhantomData,
            identity: self.identity,
            handshake: None,
            established: self.established,
            sequence: self.sequence,
        })
    }

    /// Completes an incoming (responder-side) handshake: the ratchet boots
    /// with our own SPK pair (spec `init_bob`).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::StateViolation`] on a wrong role or a
    /// missing handshake state, or crypto errors from ratchet init.
    pub fn complete_handshake_incoming(
        mut self,
    ) -> Result<Session<EstablishedSession>, ProtocolError> {
        let handshake = self.handshake.take().ok_or(ProtocolError::StateViolation)?;
        if handshake.role != HandshakeRole::Incoming {
            return Err(ProtocolError::StateViolation);
        }
        let own_spk = handshake.own_spk.ok_or(ProtocolError::StateViolation)?;
        let packet_key = Zeroizing::new(kdf::derive_key(
            PACKET_KEY_CONTEXT,
            handshake.root.as_bytes(),
        ));
        let ratchet = DoubleRatchet::init_bob(handshake.root, own_spk);
        self.established = Some(EstablishedState {
            ratchet,
            packet_key,
            smp_reassembly: None,
            terminated: false,
        });
        Ok(Session {
            _state: PhantomData,
            identity: self.identity,
            handshake: None,
            established: self.established,
            sequence: self.sequence,
        })
    }
}

impl Session<EstablishedSession> {
    /// Borrowed view of the local identity.
    #[must_use]
    pub const fn identity(&self) -> &IdentityBundle {
        &self.identity
    }

    /// Encrypts and seals a data message under the ratchet and wire packet.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::StateViolation`] if the established state is
    /// missing, plus ratchet and packet-layer failures.
    pub fn send_data(&mut self, payload: &[u8]) -> Result<SealedPacket, ProtocolError> {
        let established = self
            .established
            .as_mut()
            .ok_or(ProtocolError::StateViolation)?;
        if established.terminated {
            return Err(ProtocolError::StateViolation);
        }
        // Payload multiplexer: user text carries the 0x00 tag.
        let mut tagged = Vec::with_capacity(payload.len().saturating_add(1));
        tagged.push(TAG_TEXT);
        tagged.extend_from_slice(payload);
        let message = established.ratchet.encrypt(&tagged)?;
        let framed_len = message
            .header
            .len()
            .checked_add(message.payload.len())
            .ok_or(ProtocolError::InvalidLength {
                expected: umbra_crypto::ratchet::MAX_PLAINTEXT,
                actual: tagged.len(),
            })?;
        let mut framed = Vec::with_capacity(framed_len);
        framed.extend_from_slice(&message.header);
        framed.extend_from_slice(&message.payload);
        let sealed = packet::seal(
            PacketType::DataMessage,
            established.packet_key.clone(),
            &framed,
        )?;
        self.sequence = self.sequence.next().ok_or(ProtocolError::StateViolation)?;
        Ok(sealed)
    }

    /// Sends `smp_bytes` as a multi-packet SMP carriage transfer
    /// (tag `0x01`), chunked to fit the ratchet plaintext budget.
    ///
    /// Partial-send contract: if the loop fails mid-way, the ratchet has
    /// already advanced for the sealed prefix and the receiver's
    /// reassembly is discarded on the next `index == 0` chunk. Callers
    /// must re-send the whole transfer on retry.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLength`] if the chunk count would
    /// exceed [`MAX_SMP_CHUNKS`], plus ratchet/packet failures.
    pub fn send_smp(&mut self, smp_bytes: &[u8]) -> Result<Vec<SealedPacket>, ProtocolError> {
        let total = smp_bytes.len().div_ceil(SMP_CHUNK_DATA).max(1);
        let total32 = u32::try_from(total).map_err(|_e| ProtocolError::InvalidLength {
            expected: MAX_SMP_CHUNKS as usize,
            actual: total,
        })?;
        if total32 > MAX_SMP_CHUNKS {
            return Err(ProtocolError::InvalidLength {
                expected: MAX_SMP_CHUNKS as usize,
                actual: total,
            });
        }
        let mut packets = Vec::with_capacity(total);
        for index in 0..total {
            let start = index.checked_mul(SMP_CHUNK_DATA).unwrap_or(smp_bytes.len());
            let end = start
                .checked_add(SMP_CHUNK_DATA)
                .unwrap_or(smp_bytes.len())
                .min(smp_bytes.len());
            let data = smp_bytes.get(start..end).unwrap_or(&[]);
            let mut frame = Vec::with_capacity(SMP_CARRIAGE_HEADER.saturating_add(data.len()));
            frame.push(TAG_SMP);
            let index32 = u32::try_from(index).map_err(|_e| ProtocolError::StateViolation)?;
            frame.extend_from_slice(&index32.to_be_bytes());
            frame.extend_from_slice(&total32.to_be_bytes());
            frame.extend_from_slice(data);
            // Seal directly: send_data would prepend another TAG_TEXT byte
            // and push the frame past the ratchet plaintext budget.
            let established = self
                .established
                .as_mut()
                .ok_or(ProtocolError::StateViolation)?;
            if established.terminated {
                return Err(ProtocolError::StateViolation);
            }
            let message = established.ratchet.encrypt(&frame)?;
            let framed_len = message
                .header
                .len()
                .checked_add(message.payload.len())
                .ok_or(ProtocolError::InvalidLength {
                    expected: umbra_crypto::ratchet::MAX_PLAINTEXT,
                    actual: frame.len(),
                })?;
            let mut wire = Vec::with_capacity(framed_len);
            wire.extend_from_slice(&message.header);
            wire.extend_from_slice(&message.payload);
            let sealed = packet::seal(
                PacketType::DataMessage,
                established.packet_key.clone(),
                &wire,
            )?;
            self.sequence = self.sequence.next().ok_or(ProtocolError::StateViolation)?;
            packets.push(sealed);
        }
        Ok(packets)
    }

    /// Feeds one SMP carriage chunk into reassembly; returns the full
    /// message when the last chunk arrives.
    fn absorb_smp_chunk(
        established: &mut EstablishedState,
        plaintext: &[u8],
    ) -> Result<Option<InboundPayload>, ProtocolError> {
        if plaintext.len() < SMP_CARRIAGE_HEADER {
            return Err(ProtocolError::InvalidLength {
                expected: SMP_CARRIAGE_HEADER,
                actual: plaintext.len(),
            });
        }
        let index = u32::from_be_bytes(kdf::read_at(plaintext, 1)?);
        let total = u32::from_be_bytes(kdf::read_at(plaintext, 5)?);
        if total > MAX_SMP_CHUNKS || index >= total {
            return Err(ProtocolError::StateViolation);
        }
        let carriage = established
            .smp_reassembly
            .get_or_insert_with(|| SmpCarriage {
                total,
                slots: vec![None; total as usize],
                received: 0,
            });
        if carriage.total != total || carriage.slots.len() != total as usize {
            return Err(ProtocolError::StateViolation);
        }
        let slot = carriage.slots.get_mut(index as usize);
        match slot {
            Some(Some(_existing)) => {} // duplicate: ignore
            Some(target) => {
                // Length >= SMP_CARRIAGE_HEADER was validated above.
                let data =
                    plaintext
                        .get(SMP_CARRIAGE_HEADER..)
                        .ok_or(ProtocolError::InvalidLength {
                            expected: SMP_CARRIAGE_HEADER,
                            actual: plaintext.len(),
                        })?;
                *target = Some(data.to_vec());
                carriage.received = carriage.received.saturating_add(1);
            }
            None => return Err(ProtocolError::StateViolation),
        }
        if carriage.received as usize != carriage.slots.len() {
            return Ok(None);
        }
        let mut assembled = Vec::new();
        for slot in carriage.slots.iter().flatten() {
            assembled.extend_from_slice(slot);
        }
        established.smp_reassembly = None;
        Ok(Some(InboundPayload::Smp(assembled)))
    }

    /// Unseals a wire packet and decrypts its content.
    ///
    /// Cover-traffic packets ([`PacketType::DummyCover`]) are destroyed
    /// silently and yield `None` (SPECIFICATION.md opcode 0x04). Data
    /// messages decrypt to a tagged payload: user text yields
    /// [`InboundPayload::Text`]; SMP carriage chunks accumulate and yield
    /// [`InboundPayload::Smp`] once the transfer completes.
    ///
    /// SESSION_TERMINATE (opcode `0x09`): the packet is decrypted (empty
    /// payload, authenticated by the packet AEAD), then the ENTIRE
    /// established state — ratchet chains, message keys, packet key — is
    /// zeroized and dropped, and [`InboundPayload::Terminate`] is
    /// returned. Subsequent sends/receives yield
    /// [`ProtocolError::StateViolation`] (SPECIFICATION.md opcode 0x09).
    ///
    /// Ordering contract (MVP): the Double Ratchet is strict in-order —
    /// Tor circuits deliver ordered streams, so no reordering is expected.
    /// A tampered or replayed packet fails decryption; because a message
    /// key is consumed per receipt, such a failure desynchronizes the
    /// session (recovery / skipped-key store: TODO A.1).
    ///
    /// # Errors
    ///
    /// Returns packet-layer and ratchet failures; non-data opcodes that
    /// require transport-layer handling yield
    /// [`ProtocolError::StateViolation`].
    pub fn receive(
        &mut self,
        wire: &SealedPacket,
    ) -> Result<Option<InboundPayload>, ProtocolError> {
        let established = self
            .established
            .as_mut()
            .ok_or(ProtocolError::StateViolation)?;
        if established.terminated {
            return Err(ProtocolError::StateViolation);
        }
        let unsealed: UnsealedPacket = packet::unseal(wire, established.packet_key.clone())?;
        if unsealed.packet_type == PacketType::SessionTerminate {
            // Authenticated termination: wipe the established state
            // immediately (drop of Zeroizing keys zeroizes the bytes).
            established.wipe();
            established.terminated = true;
            return Ok(Some(InboundPayload::Terminate));
        }
        match unsealed.packet_type {
            PacketType::DummyCover => Ok(None),
            PacketType::DataMessage => {
                let header: [u8; umbra_crypto::ratchet::HEADER_LEN] =
                    kdf::read_at(&unsealed.payload, 0)?;
                let message = umbra_crypto::ratchet::RatchetMessage {
                    header,
                    payload: unsealed.payload.into_iter().skip(header.len()).collect(),
                };
                let plaintext = established.ratchet.decrypt(&message)?;
                let tag = plaintext
                    .first()
                    .copied()
                    .ok_or(ProtocolError::InvalidLength {
                        expected: 1,
                        actual: 0,
                    })?;
                match tag {
                    TAG_TEXT => Ok(Some(InboundPayload::Text(
                        plaintext.into_iter().skip(1).collect(),
                    ))),
                    TAG_SMP => Self::absorb_smp_chunk(established, &plaintext),
                    _ => Err(ProtocolError::StateViolation),
                }
            }
            _ => Err(ProtocolError::StateViolation),
        }
    }

    /// Seals a SESSION_TERMINATE signal (SPECIFICATION.md opcode `0x09`)
    /// and immediately wipes the local established state (ratchet chains,
    /// message keys, packet key). The caller transmits the returned
    /// packet; afterwards every send/receive yields
    /// [`ProtocolError::StateViolation`].
    ///
    /// The terminate signal is authenticated by the packet AEAD but
    /// carries no ratchet message, so it cannot desynchronize chains. If
    /// the caller drops the returned packet, the peer never learns of the
    /// termination and simply times out — acceptable for MVP.
    ///
    /// Sequence note: `sequence` is not advanced (post-wipe it is dead
    /// state).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::StateViolation`] if already terminated.
    pub fn send_termination(&mut self) -> Result<SealedPacket, ProtocolError> {
        let established = self
            .established
            .as_mut()
            .ok_or(ProtocolError::StateViolation)?;
        if established.terminated {
            return Err(ProtocolError::StateViolation);
        }
        let sealed = packet::seal(
            PacketType::SessionTerminate,
            established.packet_key.clone(),
            &[],
        )?;
        established.wipe();
        established.terminated = true;
        Ok(sealed)
    }

    /// Whether the session has been terminated (locally or by the peer).
    #[must_use]
    pub fn terminated(&self) -> bool {
        self.established
            .as_ref()
            .map(|state| state.terminated)
            .unwrap_or(true)
    }

    /// Produces a Poisson cover-traffic packet indistinguishable from data.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::StateViolation`] if the established state is
    /// missing, plus packet-layer failures.
    pub fn cover_packet(&mut self) -> Result<SealedPacket, ProtocolError> {
        let established = self
            .established
            .as_mut()
            .ok_or(ProtocolError::StateViolation)?;
        if established.terminated {
            return Err(ProtocolError::StateViolation);
        }
        let mut filler = [0u8; 64];
        umbra_crypto::rng::fill(&mut filler).map_err(ProtocolError::from)?;
        packet::seal(
            PacketType::DummyCover,
            established.packet_key.clone(),
            &filler,
        )
    }
}
