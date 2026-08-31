//! End-to-end messenger flow over Tor streams (TODO A.3 wiring).
//!
//! Wires the PQXDH handshake, the Double Ratchet session, and the wire
//! packets into one operation per direction, over ANY byte stream
//! (embedded-Arti `DataStream` in production, `tokio::io::DuplexStream`
//! in hermetic tests):
//!
//! - **Initiator**: `Session::new` (fresh ephemeral identity per send —
//!   deniability) → `begin_handshake(peer public keys)` → write the
//!   handshake blob (1152 B) → `complete_handshake` → `send_data` →
//!   write packet → `send_termination` → write packet.
//! - **Responder**: `accept_handshake(blob)` on the keystore identity →
//!   `complete_handshake_incoming` → read packets until Terminate,
//!   yielding the text payload.
//!
//! The responder's long-term keys come from the keystore; the initiator
//! holds the peer's public keys from the pairing payload.
//!
//! Honest scope:
//! - **No cover traffic**: the messenger sends exactly one handshake +
//!   one message + one termination per stream — the ADR-005 Poisson pump
//!   (`crate::cover`) must be run alongside for GPA resistance (TODO).
//! - **Unauthenticated initiator**: the responder accepts any PQXDH
//!   handshake; peer authentication is the SAS/SMP pairing layer's job
//!   (SMP driver still TODO — engine complete in `umbra_protocol::smp`).
//! - **Read bound**: every stream read is time-bounded
//!   ([`READ_IDLE_TIMEOUT`]) so a stalled peer cannot park the task.

use umbra_crypto::keys::{IdentityBundle, MlKemPeerKey, X25519PublicKey};
use umbra_protocol::session::{InboundPayload, Session};

use crate::error::TransportError;

/// Idle bound per stream read: a stalled peer cannot park the task
/// longer than this between bytes.
const READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The peer's PQXDH public keys, taken from a verified pairing payload.
pub struct PeerPqxdhKeys {
    /// Peer X25519 identity public key.
    pub ik: X25519PublicKey,
    /// Peer SPK public key (ratchet bootstrap target).
    pub spk: X25519PublicKey,
    /// Peer SPK signature (verified against the payload's ML-DSA key).
    pub spk_signature: Vec<u8>,
    /// Peer ML-DSA verification key.
    pub dsa_public: Vec<u8>,
    /// Peer ML-KEM-768 encapsulation key.
    pub kem: MlKemPeerKey,
}

impl PeerPqxdhKeys {
    /// Builds the key set from raw public bytes (pairing payload fields).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the KEM key encoding is invalid.
    pub fn from_parts(
        ik: &[u8; 32],
        spk: &[u8; 32],
        spk_signature: Vec<u8>,
        dsa_public: Vec<u8>,
        kem: &[u8; 1184],
    ) -> Result<Self, TransportError> {
        Ok(Self {
            ik: X25519PublicKey::from_bytes(ik),
            spk: X25519PublicKey::from_bytes(spk),
            spk_signature,
            dsa_public,
            kem: MlKemPeerKey::from_bytes(kem)
                .map_err(|e| TransportError::Protocol(umbra_protocol::ProtocolError::Crypto(e)))?,
        })
    }
}

/// Runs the initiator side over `stream`: PQXDH handshake, one encrypted
/// `plaintext` message, and an authenticated termination signal.
///
/// # Errors
///
/// Returns [`TransportError`] for I/O and session failures.
pub async fn send_message<S>(
    stream: &mut S,
    peer: &PeerPqxdhKeys,
    plaintext: &[u8],
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::AsyncWriteExt;

    let (handshake_session, blob) = Session::new().begin_handshake(
        &peer.ik,
        &peer.spk,
        &peer.spk_signature,
        &peer.dsa_public,
        &peer.kem,
    )?;
    stream.write_all(&blob).await.map_err(TransportError::Io)?;
    let mut session = handshake_session.complete_handshake()?;
    let packet = session.send_data(plaintext)?;
    stream
        .write_all(packet.as_bytes())
        .await
        .map_err(TransportError::Io)?;
    let termination = session.send_termination()?;
    stream
        .write_all(termination.as_bytes())
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;
    Ok(())
}

/// Runs the responder side over `stream`: reconstructs the handshake,
/// decrypts packets until the authenticated termination arrives, and
/// returns the received text payload.
///
/// # Errors
///
/// Returns [`TransportError`] for I/O and session failures.
pub async fn receive_message<S>(
    identity: IdentityBundle,
    stream: &mut S,
) -> Result<Vec<u8>, TransportError>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    use tokio::io::AsyncReadExt;

    let blob_len = umbra_crypto::pqxdh::HANDSHAKE_BLOB_LEN;
    let mut blob = vec![0u8; blob_len];
    stream
        .read_exact(&mut blob)
        .await
        .map_err(TransportError::Io)?;
    let session = Session::with_identity(identity)
        .accept_handshake(&blob)?
        .complete_handshake_incoming()?;

    let mut session = session;
    let mut text: Option<Vec<u8>> = None;
    loop {
        let mut packet = [0u8; umbra_protocol::types::PACKET_LEN];
        // Idle bound: a stalled peer cannot park the task forever.
        match tokio::time::timeout(READ_IDLE_TIMEOUT, stream.read_exact(&mut packet)).await {
            Ok(Ok(_read)) => {}
            // Stream closed by the peer: treated as a failed transfer.
            Ok(Err(_io)) => {
                return Err(TransportError::Timeout {
                    operation: "messenger stream read",
                });
            }
            Err(_elapsed) => {
                return Err(TransportError::Timeout {
                    operation: "messenger stream read",
                });
            }
        }
        let sealed = umbra_protocol::packet::SealedPacket::from_bytes(&packet)
            .map_err(TransportError::Protocol)?;
        match session.receive(&sealed)? {
            Some(InboundPayload::Terminate) => break,
            Some(InboundPayload::Text(payload)) => {
                // First text wins (MVP sends exactly one).
                if text.is_none() {
                    text = Some(payload);
                }
            }
            Some(InboundPayload::Smp(_)) => {
                return Err(TransportError::Unsupported(
                    "SMP carriage over live streams lands with the pairing driver",
                ));
            }
            None => {} // cover traffic: silently destroyed
        }
    }
    text.ok_or(TransportError::Unsupported(
        "stream closed before a text payload arrived",
    ))
}
