//! One-shot stdin/stdout pipe transport (TODO A.5 "Standard Pipeline
//! Support"). `umbra send` establishes a fresh PQXDH session against a
//! stored peer record, encrypts stdin through the Double Ratchet and
//! emits a pipe framing on stdout:
//!
//! ```text
//! [u32 BE handshake-blob length][handshake blob][1024-byte sealed frames...] [0x09 terminate frame]
//! ```
//!
//! `umbra recv` consumes the same framing and writes the decrypted
//! plaintext bytes to stdout. This is the transport-agnostic core of the
//! messenger: the Tor layer (umbra-net) and the pipe layer (this module)
//! are interchangeable byte carriers. `--json` switches stdout to NDJSON
//! events with base64url `data` fields so standard tools can parse the
//! stream without corrupting binary framing.

use std::io::{Read, Write};

use base64::Engine as _;
use zeroize::Zeroizing;

use umbra_crypto::keys::IdentityBundle;
use umbra_protocol::packet::SealedPacket;
use umbra_protocol::session::{InboundPayload, Session};

use crate::cli::CliError;
use crate::pairing::PeerIdentity;

/// Hard cap on the handshake blob length read by the receiver
/// (hostile-input bound; a genuine PQXDH blob is well under 4 KiB).
const MAX_BLOB_LEN: u32 = 65_535;

/// Maximum user plaintext per data frame (ratchet budget minus the
/// internal payload tag byte).
const MAX_CHUNK: usize = umbra_crypto::ratchet::MAX_PLAINTEXT - 1;

/// stdout framing selected by `--json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Raw bytes: handshake length-prefix + blob + sealed frames.
    Binary,
    /// NDJSON events with base64url `data` fields.
    Json,
}

/// Reads until `buf` is full; `Ok(None)` on clean EOF at a frame
/// boundary, [`std::io::Error`] (`UnexpectedEof`) on a truncated frame.
fn read_exact_opt<R: Read>(input: &mut R, buf: &mut [u8]) -> std::io::Result<Option<()>> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let (_, tail) = buf.split_at_mut(filled);
        match input.read(tail)? {
            0 => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                ));
            }
            n => filled = filled.saturating_add(n),
        }
    }
    Ok(Some(()))
}

/// Reads one big-endian `u32` length prefix; `Ok(None)` on clean EOF.
fn read_u32_be<R: Read>(input: &mut R) -> std::io::Result<Option<u32>> {
    let mut len_bytes = [0u8; 4];
    if read_exact_opt(input, &mut len_bytes)?.is_none() {
        return Ok(None);
    }
    Ok(Some(u32::from_be_bytes(len_bytes)))
}

/// base64url-encodes `data` without padding (NDJSON `data` fields).
fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Writes one NDJSON event line.
fn json_event<W: Write>(output: &mut W, event: &str, data: Option<&[u8]>) -> Result<(), CliError> {
    let mut line = format!("{{\"event\":\"{event}\"");
    if let Some(bytes) = data {
        line.push_str(&format!(",\"data\":\"{}\"", b64(bytes)));
    }
    line.push_str("}\n");
    write_all_or_pipe(output, line.as_bytes())
}

/// Writes `bytes`, mapping `EPIPE` (consumer closed the pipe) to a
/// silent success per Zero-Panic / Unix pipe etiquette.
fn write_all_or_pipe<W: Write>(output: &mut W, bytes: &[u8]) -> Result<(), CliError> {
    match output.write_all(bytes).and_then(|()| output.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(CliError::Io(e)),
    }
}

/// Implements `umbra send`: reads stdin until EOF, encrypts every chunk
/// through a fresh PQXDH + Double Ratchet session bound to `peer`, and
/// emits the pipe framing (or NDJSON events) on `output`.
///
/// # Errors
///
/// Returns [`CliError`] on handshake, crypto, or I/O failure. A peer
/// closing the pipe mid-stream is a silent success (`EPIPE`).
pub fn send_stream<R: Read, W: Write>(
    identity: IdentityBundle,
    peer: &PeerIdentity,
    input: &mut R,
    output: &mut W,
    mode: OutputMode,
) -> Result<(), CliError> {
    let peer_ik = umbra_crypto::keys::X25519PublicKey::from_bytes(&peer.ik_arr);
    let peer_spk = umbra_crypto::keys::X25519PublicKey::from_bytes(&peer.spk_arr);
    let peer_kem = umbra_crypto::keys::MlKemPeerKey::from_bytes(&peer.kem_arr)?;

    let (handshake, blob) = Session::with_identity(identity).begin_handshake(
        &peer_ik,
        &peer_spk,
        &peer.spk_signature,
        &peer.dsa,
        &peer_kem,
    )?;
    let mut session = handshake.complete_handshake()?;

    match mode {
        OutputMode::Binary => {
            let mut header = u32::try_from(blob.len())
                .map_err(|_e| CliError::Pipe("handshake blob exceeds u32".into()))?
                .to_be_bytes()
                .to_vec();
            header.extend_from_slice(&blob);
            write_all_or_pipe(output, &header)?;
        }
        OutputMode::Json => json_event(output, "handshake", Some(&blob))?,
    }

    let mut chunk = [0u8; MAX_CHUNK];
    loop {
        let n = match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CliError::Io(e)),
        };
        let (filled, _rest) = chunk.split_at(n);
        let sealed = session.send_data(filled)?;
        emit_frame(output, sealed.as_bytes(), "packet", mode)?;
    }

    let terminate = session.send_termination()?;
    emit_frame(output, terminate.as_bytes(), "terminate", mode)?;
    Ok(())
}

/// Emits one fixed-size sealed frame in the selected output mode.
fn emit_frame<W: Write>(
    output: &mut W,
    frame: &[u8; umbra_protocol::types::PACKET_LEN],
    event: &str,
    mode: OutputMode,
) -> Result<(), CliError> {
    match mode {
        OutputMode::Binary => write_all_or_pipe(output, frame),
        OutputMode::Json => json_event(output, event, Some(frame)),
    }
}

/// Implements `umbra recv`: consumes the pipe framing from `input`,
/// completes the PQXDH handshake as responder, decrypts every sealed
/// frame, and writes plaintext bytes (or NDJSON events) to `output`.
/// The SESSION_TERMINATE frame ends the stream; trailing bytes are
/// ignored.
///
/// # Errors
///
/// Returns [`CliError`] on malformed framing, handshake, or AEAD
/// failure.
pub fn recv_stream<R: Read, W: Write>(
    identity: IdentityBundle,
    input: &mut R,
    output: &mut W,
    mode: OutputMode,
) -> Result<(), CliError> {
    let blob_len = match read_u32_be(input)? {
        Some(len) if len <= MAX_BLOB_LEN => usize::try_from(len)
            .map_err(|_e| CliError::Keystore("handshake blob length overflow".into()))?,
        _ => {
            return Err(CliError::Keystore(
                "handshake blob length out of range".into(),
            ));
        }
    };
    let mut blob = vec![0u8; blob_len];
    if read_exact_opt(input, &mut blob)?.is_none() {
        return Err(CliError::Keystore(
            "truncated stream: blob announced but missing".into(),
        ));
    }

    let mut session = Session::with_identity(identity)
        .accept_handshake(&blob)?
        .complete_handshake_incoming()?;

    loop {
        let mut frame = [0u8; umbra_protocol::types::PACKET_LEN];
        if read_exact_opt(input, &mut frame)?.is_none() {
            return Err(CliError::Pipe(
                "truncated stream: no SESSION_TERMINATE frame".into(),
            ));
        }
        let sealed = SealedPacket::from_bytes(&frame)?;
        let payload = session.receive(&sealed)?.ok_or(CliError::Keystore(
            "unexpected partial SMP chunk in pipe mode".into(),
        ))?;
        match payload {
            InboundPayload::Text(plaintext) => {
                // Same heap buffer, now zeroized on drop; the base64url
                // event string in JSON mode is a documented residual.
                let plaintext = Zeroizing::new(plaintext);
                match mode {
                    OutputMode::Binary => write_all_or_pipe(output, &plaintext)?,
                    OutputMode::Json => json_event(output, "text", Some(&plaintext))?,
                }
            }
            InboundPayload::Smp(_) => {
                return Err(CliError::Pipe(
                    "unexpected complete SMP message in pipe mode".into(),
                ));
            }
            InboundPayload::Terminate => return Ok(()),
        }
    }
}
