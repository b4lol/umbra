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

/// Computes the canonical identity fingerprint of a bundle.
fn fingerprint_of(bundle: &IdentityBundle) -> [u8; 32] {
    umbra_crypto::kdf::identity_fingerprint(
        &bundle.x25519.public_bytes(),
        &bundle.dsa.public_bytes(),
    )
}

/// Full SMP verification exchange over an established session and
/// hermetic duplex streams: equal secrets succeed on both sides.
#[tokio::test]
async fn smp_verification_over_session() -> Result<(), Box<dyn std::error::Error>> {
    use umbra_net::messenger::{smp_verify_initiator, smp_verify_responder};
    use umbra_protocol::session::Session;

    let alice_bundle = IdentityBundle::generate();
    let bob_bundle = IdentityBundle::generate();
    let alice_fp = fingerprint_of(&alice_bundle);
    let bob_fp = fingerprint_of(&bob_bundle);
    let peer_ik =
        umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes());
    let peer_spk = umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes());
    let peer_kem = umbra_crypto::keys::MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())
        .map_err(Box::new)?;

    let (hs, blob) = Session::with_identity(alice_bundle)
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

    let password = b"shared pairing password bytes 0123456789";
    let secret = std::sync::Arc::new(umbra_protocol::smp::bound_secret(
        password, &alice_fp, &bob_fp,
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

    let secret_a: [u8; 32] = core::array::from_fn(|i| i as u8);
    let secret_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(100));
    let (mut a_side, mut b_side) = tokio::io::duplex(4096);

    let alice_task =
        tokio::spawn(async move { smp_verify_initiator(&mut alice, &mut a_side, &secret_a).await });
    let bob_result = smp_verify_responder(&mut bob, &mut b_side, &secret_b).await?;
    let alice_result = alice_task.await??;

    assert!(!bob_result, "responder must reject mismatched secrets");
    assert!(!alice_result, "initiator must reject mismatched secrets");
    Ok(())
}

/// Fingerprint-bound SMP: an initiator who binds the REAL peer's
/// fingerprint cannot complete SMP with an impostor whose fingerprint
/// pair differs — even with the same password. This is the MITM
/// detection property of `smp::bound_secret`.
#[tokio::test]
async fn smp_bound_secret_rejects_impostor() -> Result<(), Box<dyn std::error::Error>> {
    use umbra_net::messenger::{smp_verify_initiator, smp_verify_responder};
    use umbra_protocol::session::Session;

    let alice_bundle = IdentityBundle::generate();
    let bob_bundle = IdentityBundle::generate();
    let impostor_bundle = IdentityBundle::generate();
    let alice_fp = fingerprint_of(&alice_bundle);
    let bob_fp = fingerprint_of(&bob_bundle);
    let impostor_fp = fingerprint_of(&impostor_bundle);
    let peer_ik =
        umbra_crypto::keys::X25519PublicKey::from_bytes(&impostor_bundle.x25519.public_bytes());
    let peer_spk =
        umbra_crypto::keys::X25519PublicKey::from_bytes(&impostor_bundle.spk.public_bytes());
    let peer_kem =
        umbra_crypto::keys::MlKemPeerKey::from_bytes(&impostor_bundle.kem.public_bytes())
            .map_err(Box::new)?;

    // Alice believes she is talking to Bob's recorded identity, but the
    // handshake is answered by the impostor's keys (blob substitution).
    let (hs, blob) = Session::with_identity(alice_bundle)
        .begin_handshake(
            &peer_ik,
            &peer_spk,
            &impostor_bundle.spk_signature,
            &impostor_bundle.dsa.public_bytes(),
            &peer_kem,
        )
        .map_err(Box::new)?;
    let mut alice = hs.complete_handshake().map_err(Box::new)?;
    let mut impostor = Session::with_identity(impostor_bundle)
        .accept_handshake(&blob)
        .map_err(Box::new)?
        .complete_handshake_incoming()
        .map_err(Box::new)?;

    // Same password, but Alice binds (alice, bob) while the impostor can
    // only bind (alice, impostor): the proofs must fail on both sides.
    // NOTE: this covers the NAIVE impostor; the stronger transcript-relay
    // adversary is covered by smp_relay_between_sessions_fails below.
    let password = b"identical pairing password 0123456789";
    let alice_secret = std::sync::Arc::new(umbra_protocol::smp::bound_secret(
        password, &alice_fp, &bob_fp,
    ));
    let impostor_secret = std::sync::Arc::new(umbra_protocol::smp::bound_secret(
        password,
        &alice_fp,
        &impostor_fp,
    ));
    let (mut a_side, mut b_side) = tokio::io::duplex(4096);

    let alice_task =
        tokio::spawn(
            async move { smp_verify_initiator(&mut alice, &mut a_side, &alice_secret).await },
        );
    let impostor_result =
        smp_verify_responder(&mut impostor, &mut b_side, &impostor_secret).await?;
    let alice_result = alice_task.await??;

    assert!(
        !impostor_result,
        "impostor must fail SMP with mismatched fingerprints"
    );
    assert!(!alice_result, "initiator must reject the impostor");
    Ok(())
}

/// Transcript-relay adversary, faithfully emulated: the attacker owns TWO
/// working sessions (Alice<->M over channel 1, M<->Bob over channel 2),
/// decrypts each SMP message out of one ratchet channel and re-injects it
/// into the other. Without per-session binding every ZKP verifies and
/// both honest sides accept although neither talks to the other; the
/// transcript-SSID mix must make both sides reject.
#[tokio::test]
async fn smp_relay_between_sessions_fails() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use umbra_net::messenger::{smp_verify_initiator, smp_verify_responder};
    use umbra_protocol::packet::SealedPacket;
    use umbra_protocol::session::{InboundPayload, Session};
    use umbra_protocol::types::PACKET_LEN;

    // --- identities and fingerprints ---
    let alice_bundle = IdentityBundle::generate();
    let bob_bundle = IdentityBundle::generate();
    let m_bundle = IdentityBundle::generate();
    let alice_fp = fingerprint_of(&alice_bundle);
    let bob_fp = fingerprint_of(&bob_bundle);

    // --- channel 1: Alice (initiator) <-> M1 (responder) ---
    let m_ik = umbra_crypto::keys::X25519PublicKey::from_bytes(&m_bundle.x25519.public_bytes());
    let m_spk = umbra_crypto::keys::X25519PublicKey::from_bytes(&m_bundle.spk.public_bytes());
    let m_kem = umbra_crypto::keys::MlKemPeerKey::from_bytes(&m_bundle.kem.public_bytes())
        .map_err(Box::new)?;
    let (hs1, blob1) = Session::with_identity(alice_bundle)
        .begin_handshake(
            &m_ik,
            &m_spk,
            &m_bundle.spk_signature,
            &m_bundle.dsa.public_bytes(),
            &m_kem,
        )
        .map_err(Box::new)?;
    let mut alice_session = hs1.complete_handshake().map_err(Box::new)?;
    let mut m1 = Session::with_identity(m_bundle)
        .accept_handshake(&blob1)
        .map_err(Box::new)?
        .complete_handshake_incoming()
        .map_err(Box::new)?;

    // --- channel 2: M2 (initiator) <-> Bob (responder) ---
    let bob_ik = umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.x25519.public_bytes());
    let bob_spk = umbra_crypto::keys::X25519PublicKey::from_bytes(&bob_bundle.spk.public_bytes());
    let bob_kem = umbra_crypto::keys::MlKemPeerKey::from_bytes(&bob_bundle.kem.public_bytes())
        .map_err(Box::new)?;
    let (hs2, blob2) = Session::new()
        .begin_handshake(
            &bob_ik,
            &bob_spk,
            &bob_bundle.spk_signature,
            &bob_bundle.dsa.public_bytes(),
            &bob_kem,
        )
        .map_err(Box::new)?;
    let mut m2 = hs2.complete_handshake().map_err(Box::new)?;
    let mut bob_session = Session::with_identity(bob_bundle)
        .accept_handshake(&blob2)
        .map_err(Box::new)?
        .complete_handshake_incoming()
        .map_err(Box::new)?;

    // The pairing material: M has seen both public payloads, but the
    // password itself is known only to Alice and Bob.
    let material = std::sync::Arc::new(umbra_protocol::smp::bound_secret(
        b"same pairing password 0123456789",
        &alice_fp,
        &bob_fp,
    ));

    // --- honest drivers on the outer ends of the two channels ---
    let (mut ch1_alice, mut ch1_m) = tokio::io::duplex(4096);
    let (mut ch2_m, mut ch2_bob) = tokio::io::duplex(4096);

    let material_for_alice = material.clone();
    let alice_task = tokio::spawn(async move {
        smp_verify_initiator(&mut alice_session, &mut ch1_alice, &material_for_alice).await
    });
    let bob_task = tokio::spawn(async move {
        smp_verify_responder(&mut bob_session, &mut ch2_bob, &material).await
    });

    // --- the relay: M forwards SMP payloads between the two channels ---
    async fn read_smp_from<S: tokio::io::AsyncRead + Unpin>(
        session: &mut Session<umbra_protocol::session::EstablishedSession>,
        stream: &mut S,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let mut frame = [0u8; PACKET_LEN];
            stream.read_exact(&mut frame).await?;
            let sealed = SealedPacket::from_bytes(&frame)?;
            match session.receive(&sealed)? {
                Some(InboundPayload::Smp(bytes)) => return Ok(bytes),
                Some(_) => continue,
                None => continue,
            }
        }
    }
    async fn inject_smp_to<S: tokio::io::AsyncWrite + Unpin>(
        session: &mut Session<umbra_protocol::session::EstablishedSession>,
        stream: &mut S,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for packet in session.send_smp(message)? {
            stream.write_all(packet.as_bytes()).await?;
        }
        stream.flush().await?;
        Ok(())
    }

    // SMP1: Alice -> Bob; SMP2: Bob -> Alice; SMP3: Alice -> Bob;
    // SMP4: Bob -> Alice — each carried across M's two sessions.
    macro_rules! step {
        ($e:expr, $what:expr) => {
            $e.await.map_err(|e| format!("{}: {e}", $what))?
        };
    }
    let msg1 = step!(read_smp_from(&mut m1, &mut ch1_m), "read msg1 from M1");
    step!(
        inject_smp_to(&mut m2, &mut ch2_m, &msg1),
        "inject msg1 to M2"
    );
    let msg2 = step!(read_smp_from(&mut m2, &mut ch2_m), "read msg2 from M2");
    step!(
        inject_smp_to(&mut m1, &mut ch1_m, &msg2),
        "inject msg2 to M1"
    );
    let msg3 = step!(read_smp_from(&mut m1, &mut ch1_m), "read msg3 from M1");
    step!(
        inject_smp_to(&mut m2, &mut ch2_m, &msg3),
        "inject msg3 to M2"
    );
    let msg4 = step!(read_smp_from(&mut m2, &mut ch2_m), "read msg4 from M2");
    step!(
        inject_smp_to(&mut m1, &mut ch1_m, &msg4),
        "inject msg4 to M1"
    );

    let bob_result = bob_task.await??;
    let alice_result = alice_task.await??;

    assert!(!bob_result, "relayed SMP must fail on the responder side");
    assert!(!alice_result, "relayed SMP must fail on the initiator side");
    Ok(())
}

/// The persistent Tor storage root (TODO A.2) is created on demand and
/// yields a valid client configuration pointing at it. Behavioral proof
/// of a stable `.onion` address needs a live bootstrap (not hermetic);
/// this pins the storage layout contract instead.
#[cfg(feature = "tor")]
#[test]
fn persistent_config_creates_storage_root() -> Result<(), Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("umbra-tor-persist-{}-{nanos}", std::process::id()));
    let config = umbra_net::tor::persistent_config(&base).map_err(Box::new)?;
    // Arti accepted the configuration; the directories exist with 0700.
    use std::os::unix::fs::PermissionsExt as _;
    assert!(base.join("state").is_dir());
    assert!(base.join("cache").is_dir());
    let state_mode = std::fs::metadata(base.join("state"))?.permissions().mode();
    assert_eq!(state_mode & 0o777, 0o700, "state dir must be 0700");
    let _ = config; // built value is the assertion (FromDirectories validates)
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}
