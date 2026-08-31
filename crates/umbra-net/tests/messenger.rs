//! End-to-end messenger tests (TODO A.3 wiring): full PQXDH handshake +
//! ratchet + text + termination over hermetic duplex streams.

use tokio::io::{AsyncWriteExt, DuplexStream};
use umbra_crypto::keys::IdentityBundle;
use umbra_net::OnionAddr;
use umbra_net::messenger::{PeerPqxdhKeys, receive_message, send_message};

/// Fixture: Alice's keystore identity (responder) + Bob's pairing payload
/// (initiator ephemeral session).
fn fixtures() -> Result<(IdentityBundle, PeerPqxdhKeys), Box<dyn std::error::Error>> {
    let alice_bundle = IdentityBundle::generate();
    let keys = PeerPqxdhKeys::from_parts(
        &alice_bundle.x25519.public_bytes(),
        &alice_bundle.spk.public_bytes(),
        alice_bundle.spk_signature.clone(),
        alice_bundle.dsa.public_bytes(),
        &alice_bundle.kem.public_bytes(),
    )?;
    Ok((alice_bundle, keys))
}

/// The full flow: initiator connects, sends handshake + text +
/// termination; responder accepts, decrypts, wipes.
#[tokio::test]
async fn messenger_e2e_text() -> Result<(), Box<dyn std::error::Error>> {
    let (alice_identity, peer_keys) = fixtures()?;
    let (alice_side, mut bob_side) = tokio::io::duplex(4096);

    let sender = tokio::spawn(async move {
        let mut stream: DuplexStream = alice_side;
        send_message(&mut stream, &peer_keys, b"meet at midnight").await
    });
    let received = receive_message(alice_identity, &mut bob_side).await?;

    assert_eq!(received, b"meet at midnight".to_vec());
    sender.await??;
    Ok(())
}

/// A tampered handshake blob fails the responder's ZK proofs.
#[tokio::test]
async fn tampered_handshake_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (alice_identity, _peer_keys) = fixtures()?;
    let (alice_side, mut bob_side) = tokio::io::duplex(4096);

    let sender = tokio::spawn(async move {
        let mut stream: DuplexStream = alice_side;
        // Build a handshake blob from a throwaway initiator with a
        // corrupted ML-KEM ciphertext section.
        let throwaway = umbra_crypto::keys::IdentityBundle::generate();
        let (handshake, _root) = umbra_crypto::pqxdh::initiator_start(
            &throwaway.x25519,
            &umbra_crypto::keys::X25519PublicKey::from_bytes(&throwaway.x25519.public_bytes()),
            &umbra_crypto::keys::X25519PublicKey::from_bytes(&throwaway.spk.public_bytes()),
            &umbra_crypto::keys::MlKemPeerKey::from_bytes(&throwaway.kem.public_bytes())
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?,
        )?;
        let mut blob = handshake.encode();
        if let Some(last) = blob.last_mut() {
            *last ^= 0x01;
        }
        stream.write_all(&blob).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let result = receive_message(alice_identity, &mut bob_side).await;
    assert!(result.is_err(), "tampered handshake must be rejected");
    let _ = sender.await;
    Ok(())
}

/// Cover traffic placeholder: an OnionAddr fixture parses (transport-level
/// integration with the live Tor network is a production concern).
#[test]
fn onion_fixture_parses() -> Result<(), Box<dyn std::error::Error>> {
    let addr = OnionAddr::parse("5vzwalpq2cyjrhm5lvzhcjn6mbnwbv42xakxiqhunwpgz6hr32f7gxad")?;
    assert!(addr.to_string().ends_with(".onion"));
    Ok(())
}

/// Full SMP verification exchange over an established session and
/// hermetic duplex streams: equal secrets succeed on both sides.
#[tokio::test]
async fn smp_verification_over_session() -> Result<(), Box<dyn std::error::Error>> {
    use num_bigint::BigUint;
    use umbra_net::messenger::{smp_verify_initiator, smp_verify_responder};
    use umbra_protocol::session::Session;

    let bob_bundle = IdentityBundle::generate();
    let peer_ik =
        umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes());
    let peer_spk = umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes());
    let peer_kem = umbra_crypto::keys::MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())
        .map_err(Box::new)?;

    let (hs, blob) = Session::new()
        .begin_handshake(
            &peer_ik,
            &peer_spk,
            &bob_bundle.spk_signature,
            &bob_bundle.dsa.public_bytes(),
            &peer_kem,
        )
        .map_err(Box::new)?;
    let mut alice = hs.complete_handshake().map_err(Box::new)?;
    let mut bob = Session::with_identity(bob_bundle)
        .accept_handshake(&blob)
        .map_err(Box::new)?
        .complete_handshake_incoming()
        .map_err(Box::new)?;

    let secret = std::sync::Arc::new(BigUint::from_bytes_be(
        b"shared pairing password bytes 0123456789",
    ));
    let (mut a_side, mut b_side) = tokio::io::duplex(4096);

    let secret_for_alice = secret.clone();
    let alice_task = tokio::spawn(async move {
        smp_verify_initiator(&mut alice, &mut a_side, &secret_for_alice).await
    });
    let bob_result = smp_verify_responder(&mut bob, &mut b_side, &secret).await?;
    let alice_result = alice_task.await??;

    assert!(bob_result, "responder must accept equal secrets");
    assert!(alice_result, "initiator must accept equal secrets");
    Ok(())
}

/// SMP with DIFFERENT secrets rejects on both sides.
#[tokio::test]
async fn smp_verification_mismatch_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use num_bigint::BigUint;
    use umbra_net::messenger::{smp_verify_initiator, smp_verify_responder};
    use umbra_protocol::session::Session;

    let bob_bundle = IdentityBundle::generate();
    let peer_ik =
        umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes());
    let peer_spk = umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes());
    let peer_kem = umbra_crypto::keys::MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())
        .map_err(Box::new)?;

    let (hs, blob) = Session::new()
        .begin_handshake(
            &peer_ik,
            &peer_spk,
            &bob_bundle.spk_signature,
            &bob_bundle.dsa.public_bytes(),
            &peer_kem,
        )
        .map_err(Box::new)?;
    let mut alice = hs.complete_handshake().map_err(Box::new)?;
    let mut bob = Session::with_identity(bob_bundle)
        .accept_handshake(&blob)
        .map_err(Box::new)?
        .complete_handshake_incoming()
        .map_err(Box::new)?;

    let secret_a = BigUint::from_bytes_be(b"alice's password 0123456789abcdef");
    let secret_b = BigUint::from_bytes_be(b"bob's password 0123456789abcdef");
    let (mut a_side, mut b_side) = tokio::io::duplex(4096);

    let alice_task =
        tokio::spawn(async move { smp_verify_initiator(&mut alice, &mut a_side, &secret_a).await });
    let bob_result = smp_verify_responder(&mut bob, &mut b_side, &secret_b).await?;
    let alice_result = alice_task.await??;

    assert!(!bob_result, "responder must reject mismatched secrets");
    assert!(!alice_result, "initiator must reject mismatched secrets");
    Ok(())
}
