//! Typestate session state machine (SPECIFICATION.md §2, ADR-021).
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
use umbra_crypto::keys::{IdentityBundle, MlKemPeerKey, X25519PublicKey};
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

/// Handshake bookkeeping held between `begin_handshake` and completion.
struct HandshakeState {
    /// PQXDH root key derived by the initiator.
    root: RootKey,
    /// Peer signed pre-key bytes used to bootstrap the ratchet.
    peer_spk: [u8; 32],
}

/// Established-state internals.
struct EstablishedState {
    /// Double Ratchet engine.
    ratchet: DoubleRatchet,
    /// Symmetric key for the wire-level packet layer.
    packet_key: Zeroizing<[u8; 32]>,
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
        Self {
            _state: PhantomData,
            identity: IdentityBundle::generate(),
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
    /// Returns the initiator handshake blob for the transport layer.
    ///
    /// # Errors
    ///
    /// Propagates [`umbra_crypto::CryptoError`] from PQXDH.
    pub fn begin_handshake(
        mut self,
        peer_ik: &X25519PublicKey,
        peer_spk: &X25519PublicKey,
        peer_kem: &MlKemPeerKey,
    ) -> Result<(Session<HandshakeInProgress>, Vec<u8>), ProtocolError> {
        let (handshake, root) = umbra_crypto::pqxdh::initiator_start(
            &self.identity.x25519,
            peer_ik,
            peer_spk,
            peer_kem,
        )?;
        self.handshake = Some(HandshakeState {
            root,
            peer_spk: peer_spk.as_bytes(),
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
        let packet_key = Zeroizing::new(kdf::derive_key(
            PACKET_KEY_CONTEXT,
            handshake.root.as_bytes(),
        ));
        let ratchet = DoubleRatchet::init_alice(
            handshake.root,
            &X25519PublicKey::from_bytes(&handshake.peer_spk),
        )?;
        self.established = Some(EstablishedState {
            ratchet,
            packet_key,
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
        let message = established.ratchet.encrypt(payload)?;
        let framed_len = message
            .header
            .len()
            .checked_add(message.payload.len())
            .ok_or(ProtocolError::InvalidLength {
                expected: crate::types::PAYLOAD_MAX,
                actual: usize::MAX,
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

    /// Unseals a wire packet and decrypts its content.
    ///
    /// Cover-traffic packets ([`PacketType::DummyCover`]) are destroyed
    /// silently and yield `None` (SPECIFICATION.md opcode 0x04); data
    /// messages yield the decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns packet-layer and ratchet failures; non-data opcodes that
    /// require transport-layer handling yield
    /// [`ProtocolError::StateViolation`].
    pub fn receive(&mut self, wire: &SealedPacket) -> Result<Option<Vec<u8>>, ProtocolError> {
        let established = self
            .established
            .as_mut()
            .ok_or(ProtocolError::StateViolation)?;
        let unsealed: UnsealedPacket = packet::unseal(wire, established.packet_key.clone())?;
        match unsealed.packet_type {
            PacketType::DummyCover => Ok(None),
            PacketType::DataMessage => {
                let header: [u8; umbra_crypto::ratchet::HEADER_LEN] =
                    kdf::read_at(&unsealed.payload, 0)?;
                let message = umbra_crypto::ratchet::RatchetMessage {
                    header,
                    payload: unsealed.payload.into_iter().skip(header.len()).collect(),
                };
                Ok(Some(established.ratchet.decrypt(&message)?))
            }
            _ => Err(ProtocolError::StateViolation),
        }
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
        let mut filler = [0u8; 64];
        umbra_crypto::rng::fill(&mut filler).map_err(ProtocolError::from)?;
        packet::seal(
            PacketType::DummyCover,
            established.packet_key.clone(),
            &filler,
        )
    }
}
