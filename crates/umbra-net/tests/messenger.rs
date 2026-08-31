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
