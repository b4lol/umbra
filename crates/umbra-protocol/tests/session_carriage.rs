//! End-to-end session carriage tests (TODO A.3): full hermetic
//! initiator/responder handshake, text payloads, SMP carriage with
//! multi-packet chunking, silent cover-traffic destruction, role gates,
//! and SPK signature verification.

use umbra_crypto::keys::{IdentityBundle, MlKemPeerKey, X25519KeyPair, X25519PublicKey};
use umbra_crypto::pqxdh::initiator_start;
use umbra_protocol::session::{EstablishedSession, InboundPayload, Session};

/// Established-session type alias to keep signatures short.
type Established = Session<EstablishedSession>;

/// Establishes two sessions (Alice initiator, Bob responder) in-process.
fn established_pair() -> Result<(Established, Established), Box<dyn std::error::Error>> {
    let alice_bundle = IdentityBundle::generate();
    let bob_bundle = IdentityBundle::generate();

    let peer_ik = X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes());
    let peer_spk = X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes());
    let peer_kem = MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())?;

    let (handshake, blob) = Session::with_identity(alice_bundle).begin_handshake(
        &peer_ik,
        &peer_spk,
        &bob_bundle.spk_signature,
        &bob_bundle.dsa.public_bytes(),
        &peer_kem,
    )?;
    let alice = handshake.complete_handshake()?;
    let bob = Session::with_identity(bob_bundle)
        .accept_handshake(&blob)?
        .complete_handshake_incoming()?;
    Ok((alice, bob))
}

/// Full responder-side handshake works and both sides exchange text.
#[test]
fn text_roundtrip_both_directions() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;

    let packet = alice.send_data(b"hello bob")?;
    assert!(matches!(
        bob.receive(&packet)?,
        Some(InboundPayload::Text(ref text)) if text == b"hello bob"
    ));

    let reply = bob.send_data(b"hello alice")?;
    assert!(matches!(
        alice.receive(&reply)?,
        Some(InboundPayload::Text(ref text)) if text == b"hello alice"
    ));
    Ok(())
}

/// An SMP payload spanning multiple ratchet chunks is reassembled.
#[test]
fn smp_carriage_multi_chunk() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    let smp_payload: Vec<u8> = (0..2000usize).map(|i| (i % 251) as u8).collect();

    let packets = alice.send_smp(&smp_payload)?;
    assert!(packets.len() >= 3, "2000 bytes must span >= 3 chunks");

    let mut reassembled = None;
    for sealed in &packets {
        if let Some(InboundPayload::Smp(bytes)) = bob.receive(sealed)? {
            reassembled = Some(bytes);
        }
    }
    assert_eq!(
        reassembled.ok_or("SMP payload not reassembled")?,
        smp_payload
    );
    Ok(())
}

/// Replaying an already consumed packet fails closed (store miss on the
/// skipped-key store), with the ratchet state rolled back transactionally.
#[test]
fn smp_carriage_strict_in_order() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    let smp_payload: Vec<u8> = (0..1500usize).map(|i| (i % 249) as u8).collect();
    let packets = alice.send_smp(&smp_payload)?;
    assert!(packets.len() >= 2);

    // Consume all chunks in order, then replay the first: it must fail
    // authentication (message keys are single-use, strict in-order).
    for sealed in &packets {
        bob.receive(sealed)?;
    }
    let first = packets.first().ok_or("at least one packet")?;
    assert!(bob.receive(first).is_err());
    Ok(())
}

/// Cover packets are silently destroyed (SPECIFICATION opcode 0x04).
#[test]
fn cover_packet_yields_none() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    let cover = alice.cover_packet()?;
    assert!(bob.receive(&cover)?.is_none());
    Ok(())
}

/// SPK signatures verify against the signer's ML-DSA public key.
#[test]
fn spk_signatures_verify() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = IdentityBundle::generate();
    IdentityBundle::verify_spk_signature(&bundle.dsa.public_bytes(), &bundle)?;
    Ok(())
}

/// SPK signature verification fails with the WRONG ML-DSA key (the
/// cross-party MITM substitution path).
#[test]
fn spk_signature_wrong_key_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = IdentityBundle::generate();
    let other = IdentityBundle::generate();
    assert!(matches!(
        IdentityBundle::verify_spk_signature(&other.dsa.public_bytes(), &bundle),
        Err(umbra_crypto::CryptoError::InvalidSignature)
    ));
    Ok(())
}

/// Wrong-role completion is refused: an outgoing handshake cannot be
/// completed with the responder method.
#[test]
fn wrong_role_completion_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bob_bundle = IdentityBundle::generate();
    let peer_ik = X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes());
    let peer_spk = X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes());
    let peer_kem = MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())?;

    let (incoming, _blob) = Session::new().begin_handshake(
        &peer_ik,
        &peer_spk,
        &bob_bundle.spk_signature,
        &bob_bundle.dsa.public_bytes(),
        &peer_kem,
    )?;
    assert!(incoming.complete_handshake_incoming().is_err());
    Ok(())
}

/// An accepted (incoming) session cannot be completed with the initiator
/// method.
#[test]
fn incoming_role_rejects_initiator_completion() -> Result<(), Box<dyn std::error::Error>> {
    let bob_bundle = IdentityBundle::generate();
    let alice_bundle = IdentityBundle::generate();
    let peer_kem = MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())?;
    let (handshake, _root) = initiator_start(
        &alice_bundle.x25519,
        &X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes()),
        &X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes()),
        &peer_kem,
    )?;

    let accepted = Session::with_identity(bob_bundle)
        .accept_handshake(&handshake.encode())?
        .complete_handshake();
    assert!(accepted.is_err());
    Ok(())
}

/// A peer that abandons a transfer mid-way (never sending the remaining
/// chunks) does NOT wedge the session: the ratchet tolerates the gap
/// (skipped-key store), and the next fresh transfer restarts reassembly
/// at its `index == 0` chunk and completes normally.
#[test]
fn abandoned_transfer_recovered_by_fresh_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    // Transfer A: 3 chunks; the transport delivers only chunk 0 before
    // "dying" (the rest never reaches Bob).
    let abandoned: Vec<u8> = vec![7u8; 2000];
    let abandoned_packets = alice.send_smp(&abandoned)?;
    let first = abandoned_packets.first().ok_or("first chunk")?;
    bob.receive(first)?;

    // Transfer B (fresh, complete): the index-0 chunk restarts
    // reassembly and the whole transfer decrypts.
    let fresh: Vec<u8> = vec![9u8; 1200];
    let fresh_packets = alice.send_smp(&fresh)?;
    let mut got = None;
    for sealed in &fresh_packets {
        if let Some(InboundPayload::Smp(bytes)) = bob.receive(sealed)? {
            got = Some(bytes);
        }
    }
    assert_eq!(got.ok_or("fresh transfer not delivered")?, fresh);
    Ok(())
}

/// An empty SMP payload still produces a single (zero-data) chunk.
#[test]
fn empty_smp_payload_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    let packets = alice.send_smp(&[])?;
    assert_eq!(packets.len(), 1);
    let mut got = None;
    for sealed in &packets {
        if let Some(InboundPayload::Smp(bytes)) = bob.receive(sealed)? {
            got = Some(bytes);
        }
    }
    assert_eq!(got.ok_or("empty payload not delivered")?, Vec::<u8>::new());
    Ok(())
}

/// Text payloads keep their tag opaque to callers (tag byte consumed).
#[test]
fn text_payload_has_no_tag_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    let payload = vec![0x01u8, 0x02, 0x03];
    let packet = alice.send_data(&payload)?;
    assert!(matches!(
        bob.receive(&packet)?,
        Some(InboundPayload::Text(ref text)) if text == &payload
    ));
    Ok(())
}

/// SESSION_TERMINATE roundtrip (SPECIFICATION opcode 0x09): the sender
/// wipes on send, the receiver wipes on receipt, and both sessions are
/// dead afterwards (double-terminate rejected).
#[test]
fn session_terminate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, mut bob) = established_pair()?;
    assert!(!alice.terminated());

    let terminate = alice.send_termination()?;
    assert!(alice.terminated());
    // Post-termination sends are refused on the sender side.
    assert!(matches!(
        alice.send_data(b"too late"),
        Err(umbra_protocol::ProtocolError::StateViolation)
    ));
    // Double-terminate is refused.
    assert!(alice.send_termination().is_err());

    // The receiver wipes and reports the termination.
    assert!(matches!(
        bob.receive(&terminate)?,
        Some(InboundPayload::Terminate)
    ));
    assert!(bob.terminated());
    assert!(matches!(
        bob.send_data(b"too late"),
        Err(umbra_protocol::ProtocolError::StateViolation)
    ));
    assert!(matches!(
        bob.cover_packet(),
        Err(umbra_protocol::ProtocolError::StateViolation)
    ));
    Ok(())
}

/// The unused-key guard for fixture completeness.
#[test]
fn key_pair_helper_compiles() {
    let pair = X25519KeyPair::generate();
    let _ = pair.public_bytes();
}
