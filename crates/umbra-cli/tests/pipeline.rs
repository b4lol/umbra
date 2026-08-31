//! End-to-end pipe-transport tests: `send_stream` → `recv_stream`
//! roundtrips over in-memory buffers, in both binary and NDJSON modes,
//! plus hostile-input framing checks.

use std::io::Cursor;

use base64::Engine as _;

use umbra_cli::pairing::{parse_payload, payload_for};
use umbra_cli::pipeline::{OutputMode, recv_stream, send_stream};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Builds a peer record for `identity` through the public pairing path,
/// mirroring what `umbra pair` stores on disk.
fn peer_of(
    identity: &umbra_crypto::keys::IdentityBundle,
) -> Result<umbra_cli::pairing::PeerIdentity, Box<dyn std::error::Error + Send + Sync>> {
    let payload = payload_for(identity)?;
    Ok(parse_payload(&payload)?)
}

/// Fills `len` bytes with deterministic non-uniform data.
fn test_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i.wrapping_mul(37).wrapping_add(i / 251) % 256).unwrap_or(0))
        .collect()
}

#[test]
fn pipe_roundtrip_binary_multi_frame() -> TestResult {
    let alice = umbra_crypto::keys::IdentityBundle::generate();
    let bob = umbra_crypto::keys::IdentityBundle::generate();
    let plaintext = test_bytes(4_321); // spans several 925-byte frames

    let mut wire = Vec::new();
    send_stream(
        alice,
        &peer_of(&bob)?,
        &mut Cursor::new(&plaintext),
        &mut wire,
        OutputMode::Binary,
    )?;

    let mut recovered = Vec::new();
    recv_stream(
        bob,
        &mut Cursor::new(wire),
        &mut recovered,
        OutputMode::Binary,
    )?;
    assert_eq!(recovered, plaintext);
    Ok(())
}

#[test]
fn pipe_roundtrip_empty_input() -> TestResult {
    let alice = umbra_crypto::keys::IdentityBundle::generate();
    let bob = umbra_crypto::keys::IdentityBundle::generate();

    let mut wire = Vec::new();
    send_stream(
        alice,
        &peer_of(&bob)?,
        &mut Cursor::new(Vec::new()),
        &mut wire,
        OutputMode::Binary,
    )?;

    let mut recovered = Vec::new();
    recv_stream(
        bob,
        &mut Cursor::new(wire),
        &mut recovered,
        OutputMode::Binary,
    )?;
    assert!(recovered.is_empty());
    Ok(())
}

#[test]
fn pipe_roundtrip_json_mode() -> TestResult {
    let alice = umbra_crypto::keys::IdentityBundle::generate();
    let bob = umbra_crypto::keys::IdentityBundle::generate();
    let plaintext = test_bytes(2_000);

    let mut wire = Vec::new();
    send_stream(
        alice,
        &peer_of(&bob)?,
        &mut Cursor::new(&plaintext),
        &mut wire,
        OutputMode::Json,
    )?;

    // NDJSON lines parse without serde. Rebuild the binary wire from the
    // emitted events, feed it to recv (also in JSON mode), and parse the
    // "text" events recv emits.
    let stream = String::from_utf8(wire)?;
    let data_marker = "\"data\":\"";
    let mut rebuilt = Vec::new();
    for line in stream.lines() {
        assert!(line.starts_with("{\"event\":\""), "ndjson shape: {line}");
        let Some(start) = line.find(data_marker) else {
            continue;
        };
        let data_start = start.saturating_add(data_marker.len());
        let Some(rest) = line.get(data_start..) else {
            continue;
        };
        let end = rest
            .find('"')
            .ok_or("ndjson data field is missing its closing quote")?;
        let field = rest
            .get(..end)
            .ok_or("ndjson data field slice out of range")?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(field)?;
        if line.contains("\"event\":\"handshake\"") {
            rebuilt.extend_from_slice(&u32::try_from(decoded.len())?.to_be_bytes());
            rebuilt.extend_from_slice(&decoded);
        } else if line.contains("\"event\":\"packet\"") || line.contains("\"event\":\"terminate\"")
        {
            assert_eq!(decoded.len(), 1024, "sealed frames must be PACKET_LEN");
            rebuilt.extend_from_slice(&decoded);
        }
    }

    let mut json_out = Vec::new();
    recv_stream(
        bob,
        &mut Cursor::new(rebuilt),
        &mut json_out,
        OutputMode::Json,
    )?;
    let recv_text = String::from_utf8(json_out)?;
    let mut recovered = Vec::new();
    for line in recv_text.lines() {
        assert!(line.starts_with("{\"event\":\""), "ndjson shape: {line}");
        if !line.contains("\"event\":\"text\"") {
            continue;
        }
        let Some(start) = line.find(data_marker) else {
            continue;
        };
        let data_start = start.saturating_add(data_marker.len());
        let Some(rest) = line.get(data_start..) else {
            continue;
        };
        let end = rest
            .find('"')
            .ok_or("ndjson data field is missing its closing quote")?;
        let field = rest
            .get(..end)
            .ok_or("ndjson data field slice out of range")?;
        recovered
            .extend_from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(field)?);
    }
    assert_eq!(recovered, plaintext);
    Ok(())
}

#[test]
fn recv_rejects_wrong_identity() -> TestResult {
    let alice = umbra_crypto::keys::IdentityBundle::generate();
    let bob = umbra_crypto::keys::IdentityBundle::generate();
    let mallory = umbra_crypto::keys::IdentityBundle::generate();

    let mut wire = Vec::new();
    send_stream(
        alice,
        &peer_of(&bob)?,
        &mut Cursor::new(b"secret".to_vec()),
        &mut wire,
        OutputMode::Binary,
    )?;

    let mut recovered = Vec::new();
    assert!(
        recv_stream(
            mallory,
            &mut Cursor::new(wire),
            &mut recovered,
            OutputMode::Binary
        )
        .is_err(),
        "a non-recipient must not be able to decrypt the stream"
    );
    assert!(recovered.is_empty());
    Ok(())
}

#[test]
fn recv_rejects_corrupted_midstream_frame() -> TestResult {
    let alice = umbra_crypto::keys::IdentityBundle::generate();
    let bob = umbra_crypto::keys::IdentityBundle::generate();

    let mut wire = Vec::new();
    send_stream(
        alice,
        &peer_of(&bob)?,
        &mut Cursor::new(test_bytes(2_000)),
        &mut wire,
        OutputMode::Binary,
    )?;

    // Flip one bit inside the last sealed frame (ciphertext area).
    let last = wire.len().saturating_sub(1);
    if let Some(byte) = wire.get_mut(last) {
        *byte ^= 0x01;
    }
    let mut recovered = Vec::new();
    assert!(
        recv_stream(
            bob,
            &mut Cursor::new(wire),
            &mut recovered,
            OutputMode::Binary
        )
        .is_err(),
        "a corrupted frame must fail the stream"
    );
    Ok(())
}

#[test]
fn recv_rejects_missing_terminate_frame() -> TestResult {
    let alice = umbra_crypto::keys::IdentityBundle::generate();
    let bob = umbra_crypto::keys::IdentityBundle::generate();

    let mut wire = Vec::new();
    send_stream(
        alice,
        &peer_of(&bob)?,
        &mut Cursor::new(test_bytes(64)),
        &mut wire,
        OutputMode::Binary,
    )?;

    // Drop the final 1024-byte SESSION_TERMINATE frame.
    let keep = wire.len().saturating_sub(1024);
    wire.truncate(keep);
    assert!(
        recv_stream(
            bob,
            &mut Cursor::new(wire),
            &mut Vec::new(),
            OutputMode::Binary
        )
        .is_err(),
        "a stream without SESSION_TERMINATE must be rejected"
    );
    Ok(())
}

#[test]
fn recv_rejects_truncated_and_oversized_framing() -> TestResult {
    // Oversized length prefix (hostile cap).
    let wire = 65_536u32.to_be_bytes().to_vec();
    assert!(
        recv_stream(
            umbra_crypto::keys::IdentityBundle::generate(),
            &mut Cursor::new(&wire),
            &mut Vec::new(),
            OutputMode::Binary
        )
        .is_err()
    );

    // Announced blob missing (truncated stream).
    let mut wire = 1_000u32.to_be_bytes().to_vec();
    wire.extend_from_slice(&[0u8; 10]);
    assert!(
        recv_stream(
            umbra_crypto::keys::IdentityBundle::generate(),
            &mut Cursor::new(&wire),
            &mut Vec::new(),
            OutputMode::Binary
        )
        .is_err()
    );
    Ok(())
}
