//! End-to-end messenger flow over Tor streams (TODO A.3 wiring).
//!
//! Wires the PQXDH handshake, the Double Ratchet session, and the wire
//! packets into one operation per direction, over ANY byte stream
//! (embedded-Arti `DataStream` in production, `tokio::io::DuplexStream`
//! in hermetic tests):
//!
//! - **Initiator**: `Session::new` (fresh ephemeral identity per send —
//!   deniability) → `begin_handshake(peer public keys)` → write a
//!   leading connection-type marker byte (TODO B.2 groundwork, see
//!   [`ConnectionType`]) → write the handshake blob (1152 B) →
//!   `complete_handshake` → `send_data` → write packet →
//!   `send_termination` → write packet.
//! - **Responder**: the caller consumes the leading marker byte via
//!   [`peek_connection_type`] BEFORE calling `receive_message` — this
//!   module's `receive_message` itself starts by reading the handshake
//!   blob and has no knowledge of the marker. `accept_handshake(blob)`
//!   on the keystore identity → `complete_handshake_incoming` → read
//!   packets until Terminate, yielding the text payload.
//!
//! The responder's long-term keys come from the keystore; the initiator
//! holds the peer's public keys from the pairing payload.
//!
//! Honest scope:
//! - **Burst-level cover traffic** (ADR-005): `send_text_stream`
//!   interleaves Poisson-driven `DUMMY_COVER` frames with real data
//!   frames (bounded by [`MAX_COVER_PER_SEND`]); the receiver destroys
//!   them silently. Idle-gap cover (dummies BETWEEN bursts/sessions)
//!   is v2 — it needs a cancel-safe frame reader.
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

/// Upper bound for a reassembled inbound text message. Mirrors the
/// sender's 64 KiB Tor-send ceiling: without it, an anonymous client
/// could pin unbounded RAM under `mlockall` across concurrent streams
/// (lock-exhaustion DoS). Fail closed beyond the cap.
pub const MAX_TEXT_MESSAGE: usize = 64 * 1024;

/// Probability that a burst-level cover frame follows any given data
/// frame (Bernoulli draw from the Poisson scheduler's uniform source).
/// Hides real message count and size WITHIN a send burst; idle-gap
/// cover (between bursts) is v2 scope — see the module docs.
pub const COVER_PROBABILITY: f64 = 0.5;

/// Hard cap on cover frames per send burst (doctrine: bounded memory
/// and bounded amplification, whatever the draw sequence).
pub const MAX_COVER_PER_SEND: u64 = 64;

/// Leading marker byte for a two-party PQXDH handshake (TODO B.2
/// groundwork: distinguishes it from a group ciphertext frame on the
/// same accept loop).
const CONNECTION_TYPE_PQXDH: u8 = 0x00;

/// Leading marker byte for a group (PQ-MLS) ciphertext frame (TODO
/// B.2). `pub` so `umbra-group`'s fan-out delivery code can write the
/// same byte value as this module's single source of truth, rather
/// than duplicating the constant.
pub const CONNECTION_TYPE_GROUP: u8 = 0x01;

/// The first byte of every inbound connection, distinguishing a
/// two-party PQXDH handshake from a group ciphertext frame (TODO B.2).
/// [`receive_message`] itself is unchanged and assumes this byte has
/// ALREADY been consumed by the caller via [`peek_connection_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// A PQXDH handshake blob follows — the existing two-party path.
    PqxdhHandshake,
    /// A group (PQ-MLS) ciphertext frame follows.
    GroupFrame,
}

/// Reads exactly one byte from `stream` and classifies the connection.
/// Callers (e.g. `serve.rs`'s inbound loop) must call this BEFORE
/// [`receive_message`] and branch on the result; `receive_message`'s
/// own body starts reading the handshake blob immediately and does
/// NOT expect this byte to still be on the wire.
///
/// # Errors
///
/// Returns [`TransportError::Io`] on I/O failure and
/// [`TransportError::Unsupported`] for an unrecognized marker byte.
pub async fn peek_connection_type<S>(stream: &mut S) -> Result<ConnectionType, TransportError>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    use tokio::io::AsyncReadExt;
    let mut marker = [0u8; 1];
    stream
        .read_exact(&mut marker)
        .await
        .map_err(TransportError::Io)?;
    match marker[0] {
        CONNECTION_TYPE_PQXDH => Ok(ConnectionType::PqxdhHandshake),
        CONNECTION_TYPE_GROUP => Ok(ConnectionType::GroupFrame),
        _other => Err(TransportError::Unsupported(
            "unrecognized connection-type marker byte",
        )),
    }
}

/// Draws the number of cover frames that follow one data frame (0, 1
/// or 2 — a stochastically bounded amplification, hard-capped by
/// [`MAX_COVER_PER_SEND`] across the burst).
fn draw_cover_count() -> Result<u64, TransportError> {
    let uniform = umbra_protocol::cover::PoissonScheduler::sample_uniform()
        .map_err(TransportError::Protocol)?;
    let count = if uniform < COVER_PROBABILITY / 2.0 {
        2
    } else if uniform < COVER_PROBABILITY {
        1
    } else {
        0
    };
    Ok(count)
}

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
    // Single-message special case of [`send_text_stream`].
    send_text_stream(stream, peer, plaintext)
        .await
        .map(|_frames| ())
}

/// Sends a plaintext of ARBITRARY length over `stream` on ONE PQXDH
/// session: handshake blob, the plaintext split into max-size ratchet
/// messages, then the authenticated termination. Returns the number of
/// data frames written.
///
/// # Errors
///
/// Returns [`TransportError`] for I/O and session failures.
pub async fn send_text_stream<S>(
    stream: &mut S,
    peer: &PeerPqxdhKeys,
    plaintext: &[u8],
) -> Result<u64, TransportError>
where
    S: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::AsyncWriteExt;

    // MAX_PLAINTEXT - 1: the session layer spends one payload byte on
    // the text/SMP multiplexer tag ("user-text budget per packet").
    const CHUNK: usize = umbra_crypto::ratchet::MAX_PLAINTEXT - 1;
    let (handshake_session, blob) = Session::new().begin_handshake(
        &peer.ik,
        &peer.spk,
        &peer.spk_signature,
        &peer.dsa_public,
        &peer.kem,
    )?;
    // Leading connection-type marker (TODO B.2 groundwork): every
    // caller of `receive_message` must consume this via
    // `peek_connection_type` first — see the module docs.
    stream
        .write_all(&[CONNECTION_TYPE_PQXDH])
        .await
        .map_err(TransportError::Io)?;
    stream.write_all(&blob).await.map_err(TransportError::Io)?;
    let mut session = handshake_session.complete_handshake()?;

    let mut frames: u64 = 0;
    let mut cover_sent: u64 = 0;
    for chunk in plaintext.chunks(CHUNK) {
        let packet = session.send_data(chunk)?;
        stream
            .write_all(packet.as_bytes())
            .await
            .map_err(TransportError::Io)?;
        frames = frames
            .checked_add(1)
            .ok_or(TransportError::Unsupported("frame counter overflow"))?;
        // Burst-level cover: hide the real frame count and size within
        // the session (ADR-005). Cover frames ride the packet key, so
        // the ratchet chains and the receiver's skipped-key store are
        // unaffected; the responder destroys them silently.
        while cover_sent < MAX_COVER_PER_SEND {
            let dummies = draw_cover_count()?;
            if dummies == 0 {
                break;
            }
            let cover = session.cover_packet()?;
            stream
                .write_all(cover.as_bytes())
                .await
                .map_err(TransportError::Io)?;
            cover_sent = cover_sent
                .checked_add(1)
                .ok_or(TransportError::Unsupported("cover counter overflow"))?;
        }
    }
    let termination = session.send_termination()?;
    stream
        .write_all(termination.as_bytes())
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;
    Ok(frames)
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
                // Concatenate: `send_text_stream` splits long messages
                // into ordered ratchet messages on the same session.
                // BOUNDED: an anonymous client must not pin unbounded RAM
                // under mlockall (lock-exhaustion DoS).
                let over_cap = text.as_ref().is_some_and(|collected| {
                    collected.len().saturating_add(payload.len()) > MAX_TEXT_MESSAGE
                });
                if over_cap {
                    return Err(TransportError::Unsupported(
                        "inbound message exceeds the 64 KiB reassembly ceiling",
                    ));
                }
                match text.as_mut() {
                    Some(collected) => collected.extend_from_slice(&payload),
                    None => text = Some(payload),
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
/// session (docs/CRYPTOGRAPHY.md §5): sends SMP1, processes SMP2, sends SMP3,
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
