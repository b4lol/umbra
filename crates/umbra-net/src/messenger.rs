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
//!   (the SMP driver below folds the pairing-level `bound_secret` with
//!   the per-handshake transcript SSID, so relays between distinct
//!   sessions fail).
//! - **Read bound**: every stream read is time-bounded
//!   ([`READ_IDLE_TIMEOUT`]) so a stalled peer cannot park the task.

use num_bigint::BigUint;
use umbra_crypto::keys::{IdentityBundle, MlKemPeerKey, X25519PublicKey};
use umbra_protocol::session::{EstablishedSession, InboundPayload, Session};

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
    // Idle bound: the handshake blob read is time-bounded too — a peer
    // that connects and stalls must not park the task forever.
    match tokio::time::timeout(READ_IDLE_TIMEOUT, stream.read_exact(&mut blob)).await {
        Ok(Ok(_read)) => {}
        Ok(Err(_io)) => {
            return Err(TransportError::Timeout {
                operation: "messenger handshake read",
            });
        }
        Err(_elapsed) => {
            return Err(TransportError::Timeout {
                operation: "messenger handshake read",
            });
        }
    }
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

/// Reads one fully reassembled SMP message from the stream: packets are
/// authenticated through the session (ratchet + wire AEAD) and SMP
/// carriage chunks are reassembled by the session layer.
async fn read_smp_message<S>(
    session: &mut Session<EstablishedSession>,
    stream: &mut S,
) -> Result<Vec<u8>, TransportError>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    use tokio::io::AsyncReadExt;

    loop {
        let mut packet = [0u8; umbra_protocol::types::PACKET_LEN];
        match tokio::time::timeout(READ_IDLE_TIMEOUT, stream.read_exact(&mut packet)).await {
            Ok(Ok(_read)) => {}
            Ok(Err(_io)) => {
                return Err(TransportError::Timeout {
                    operation: "SMP message read",
                });
            }
            Err(_elapsed) => {
                return Err(TransportError::Timeout {
                    operation: "SMP message read",
                });
            }
        }
        let sealed = umbra_protocol::packet::SealedPacket::from_bytes(&packet)
            .map_err(TransportError::Protocol)?;
        match session.receive(&sealed)? {
            Some(InboundPayload::Smp(payload)) => return Ok(payload),
            // Cover traffic and non-SMP payloads are skipped: SMP chunks
            // are the only payloads expected during verification.
            None | Some(InboundPayload::Text(_)) => continue,
            Some(InboundPayload::Terminate) => {
                return Err(TransportError::Unsupported(
                    "peer terminated during SMP verification",
                ));
            }
        }
    }
}

/// Sends one serialized SMP message over the session's chunked carriage.
async fn write_smp_message<S>(
    session: &mut Session<EstablishedSession>,
    stream: &mut S,
    message_bytes: &[u8],
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::AsyncWriteExt;

    for packet in session.send_smp(message_bytes)? {
        stream
            .write_all(packet.as_bytes())
            .await
            .map_err(TransportError::Io)?;
    }
    stream.flush().await.map_err(TransportError::Io)?;
    Ok(())
}

/// Derives the engine-level SMP secret from the pairing-level material
/// and this session's transcript SSID. The SSID mix is what breaks a
/// relay that forwards SMP messages verbatim between two distinct
/// sessions sharing the same pairing material.
fn session_engine_secret(material: &[u8; 32], ssid: &[u8; 32]) -> BigUint {
    let mut domain =
        Vec::with_capacity(material.len().saturating_add(ssid.len()).saturating_add(2));
    domain.extend_from_slice(b"Umbra SMP session secret v1");
    domain.push(0x00);
    domain.extend_from_slice(material);
    domain.extend_from_slice(ssid);
    BigUint::from_bytes_be(&umbra_crypto::kdf::derive_key(
        "Umbra SMP session secret v1",
        &domain,
    ))
}

/// Runs the INITIATOR side of SMP verification over an established
/// session (CRYPTOGRAPHY.md §5): sends SMP1, processes SMP2, sends SMP3,
/// processes SMP4, and returns whether the shared secret matches.
///
/// `secret` is the PAIRING-level material
/// (`umbra_protocol::smp::bound_secret`); the per-session transcript
/// SSID is mixed in here.
///
/// # Errors
///
/// Returns [`TransportError`] for I/O failures and
/// [`TransportError::Protocol`] for SMP proof failures.
pub async fn smp_verify_initiator<S>(
    session: &mut Session<EstablishedSession>,
    stream: &mut S,
    secret: &[u8; 32],
) -> Result<bool, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    use umbra_protocol::smp::{SmpFirstParty, SmpMsg2, SmpMsg4};

    let engine_secret = session_engine_secret(secret, &session.transcript_ssid());
    let (first, msg1) = SmpFirstParty::start(&engine_secret).map_err(TransportError::Protocol)?;
    write_smp_message(session, stream, &msg1.to_bytes()).await?;
    let msg2 = SmpMsg2::from_bytes(&read_smp_message(session, stream).await?)
        .map_err(TransportError::Protocol)?;
    let (first, msg3) = first.receive_msg2(msg2).map_err(TransportError::Protocol)?;
    write_smp_message(session, stream, &msg3.to_bytes()).await?;
    let msg4 = SmpMsg4::from_bytes(&read_smp_message(session, stream).await?)
        .map_err(TransportError::Protocol)?;
    first.finish(msg4).map_err(TransportError::Protocol)
}

/// Runs the RESPONDER side of SMP verification over an established
/// session: waits for SMP1, answers with SMP2/SMP4, and returns whether
/// the shared secret matches. `secret` is the PAIRING-level material
/// (`umbra_protocol::smp::bound_secret`); the per-session transcript
/// SSID is mixed in here.
///
/// # Errors
///
/// Returns [`TransportError`] for I/O failures and
/// [`TransportError::Protocol`] for SMP proof failures.
pub async fn smp_verify_responder<S>(
    session: &mut Session<EstablishedSession>,
    stream: &mut S,
    secret: &[u8; 32],
) -> Result<bool, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    use umbra_protocol::smp::{SmpMsg1, SmpMsg3, SmpSecondParty};

    let engine_secret = session_engine_secret(secret, &session.transcript_ssid());
    let msg1 = SmpMsg1::from_bytes(&read_smp_message(session, stream).await?)
        .map_err(TransportError::Protocol)?;
    let (second, msg2) =
        SmpSecondParty::receive_msg1(&engine_secret, msg1).map_err(TransportError::Protocol)?;
    write_smp_message(session, stream, &msg2.to_bytes()).await?;
    let msg3 = SmpMsg3::from_bytes(&read_smp_message(session, stream).await?)
        .map_err(TransportError::Protocol)?;
    let (_second, verdict, msg4) = second
        .receive_msg3(msg3)
        .map_err(TransportError::Protocol)?;
    write_smp_message(session, stream, &msg4.to_bytes()).await?;
    Ok(verdict)
}
