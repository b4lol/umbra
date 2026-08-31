//! Property-based test suite (TODO A.5, `proptest`).
//!
//! Hermetic: no network, no filesystem, deterministic seeds from proptest.

use proptest::prelude::*;
use zeroize::Zeroizing;

use umbra_crypto::aead::AeadCipher;
use umbra_crypto::kdf::RootKey;
use umbra_crypto::keys::{MlKemKeyPair, MlKemPeerKey, X25519KeyPair, X25519PublicKey};
use umbra_crypto::pqxdh::{initiator_start, responder_respond};
use umbra_crypto::ratchet::{DoubleRatchet, HEADER_LEN};

proptest! {
    /// AEAD seal/open roundtrip: any payload survives with the same key.
    #[test]
    fn aead_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let key = Zeroizing::new([7u8; 32]);
        let cipher = AeadCipher::new(key);
        let mut nonce = [0u8; 12];
        let ct = cipher.seal(b"aad", &msg, &mut nonce)?;
        let pt = cipher.open(&nonce, b"aad", &ct)?;
        prop_assert_eq!(pt, msg);
    }

    /// AEAD rejects tampered ciphertexts.
    #[test]
    fn aead_rejects_tamper(msg in proptest::collection::vec(any::<u8>(), 16..=512)) {
        let key = Zeroizing::new([9u8; 32]);
        let cipher = AeadCipher::new(key);
        let mut nonce = [0u8; 12];
        let mut ct = cipher.seal(b"aad", &msg, &mut nonce)?;
        if let Some(last) = ct.last_mut() {
            *last = last.wrapping_add(1);
        }
        prop_assert!(cipher.open(&nonce, b"aad", &ct).is_err());
    }

    /// Double Ratchet roundtrip across a DH ratchet step.
    #[test]
    fn ratchet_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..=256)) {
        let bob_spk = X25519KeyPair::generate();
        let root_a = RootKey::from_bytes([1u8; 32]);
        let root_b = RootKey::from_bytes([1u8; 32]);

        let mut alice = DoubleRatchet::init_alice(root_a, &X25519PublicKey::from_bytes(&bob_spk.public_bytes()))?;
        let mut bob = DoubleRatchet::init_bob(root_b, bob_spk);

        let m1 = alice.encrypt(&msg)?;
        prop_assert_eq!(bob.decrypt(&m1)?, msg.clone());

        // Bob replies: triggers a DH ratchet step on Alice's side.
        let m2 = bob.encrypt(b"pong")?;
        prop_assert_eq!(alice.decrypt(&m2)?, b"pong".to_vec());

        let m3 = alice.encrypt(&msg)?;
        prop_assert_eq!(bob.decrypt(&m3)?, msg.clone());
    }

    /// PQXDH both parties derive the identical root key.
    #[test]
    fn pqxdh_shared_root(seed in any::<u64>()) {
        // Deterministic, non-degenerate 32-byte scalar from the seed.
        let secret = umbra_crypto::kdf::derive_key("umbra test scalar", &seed.to_be_bytes());
        let alice_ik = X25519KeyPair::from_secret_bytes(&secret);
        let bob = MlKemKeyPair::generate();
        let bob_ik = X25519KeyPair::generate();
        let bob_spk = X25519KeyPair::generate();

        let peer_ik = X25519PublicKey::from_bytes(&bob_ik.public_bytes());
        let peer_spk = X25519PublicKey::from_bytes(&bob_spk.public_bytes());
        let peer_kem_public = bob.public_bytes();

        let peer_kem = MlKemPeerKey::from_bytes(&peer_kem_public)?;
        let (handshake, root_a) = initiator_start(&alice_ik, &peer_ik, &peer_spk, &peer_kem)?;
        let root_b = responder_respond(&bob_ik, &bob_spk, &bob, &handshake)?;
        prop_assert_eq!(root_a.as_bytes(), root_b.as_bytes());
    }

    /// Ratchet header roundtrips through the wire encoding helpers:
    /// DH public at 0..32, N (0-based) at 32..40, PN at 40..48.
    #[test]
    fn header_layout(
        peer_pk in proptest::collection::vec(any::<u8>(), 32),
        n in any::<u64>(),
        pn in any::<u64>(),
    ) {
        let mut header = [0u8; HEADER_LEN];
        let pk: [u8; 32] = peer_pk.try_into().unwrap_or([0u8; 32]);
        umbra_crypto::kdf::write_at(&mut header, 0, &pk)?;
        umbra_crypto::kdf::write_at(&mut header, 32, &n.to_be_bytes())?;
        umbra_crypto::kdf::write_at(&mut header, 40, &pn.to_be_bytes())?;
        let decoded: [u8; 32] = umbra_crypto::kdf::read_at(&header, 0)?;
        prop_assert_eq!(decoded.to_vec(), pk);
        let decoded_n = u64::from_be_bytes(umbra_crypto::kdf::read_at(&header, 32)?);
        let decoded_pn = u64::from_be_bytes(umbra_crypto::kdf::read_at(&header, 40)?);
        prop_assert_eq!(decoded_n, n);
        prop_assert_eq!(decoded_pn, pn);
    }

    /// Hostile ratchet headers (attacker-chosen N/PN, including u64::MAX)
    /// fail closed AND leave the receiver state untouched: a subsequent
    /// honest message still decrypts (transactional rollback).
    #[test]
    fn ratchet_hostile_header_rollback(n in any::<u64>(), pn in any::<u64>()) {
        let bob_spk = X25519KeyPair::generate();
        let mut alice = DoubleRatchet::init_alice(
            RootKey::from_bytes([6u8; 32]),
            &X25519PublicKey::from_bytes(&bob_spk.public_bytes()),
        )?;
        let mut bob = DoubleRatchet::init_bob(RootKey::from_bytes([6u8; 32]), bob_spk);

        let honest = alice.encrypt(b"honest")?;
        let mut hostile = alice.encrypt(b"hostile")?;
        hostile.header[32..40].copy_from_slice(&n.to_be_bytes());
        hostile.header[40..48].copy_from_slice(&pn.to_be_bytes());

        // The header is AEAD associated data: a mutated header fails
        // authentication and the ratchet state must survive intact.
        prop_assert!(bob.decrypt(&hostile).is_err());
        prop_assert_eq!(bob.decrypt(&honest)?, b"honest".to_vec());
    }
}

/// Identity fingerprints are deterministic and sensitive to each
/// component (X25519 IK and ML-DSA VK).
#[test]
fn identity_fingerprint_sensitivity() {
    use umbra_crypto::keys::IdentityBundle;
    let alice = IdentityBundle::generate();
    let bob = IdentityBundle::generate();
    let fp = |b: &IdentityBundle| {
        umbra_crypto::kdf::identity_fingerprint(&b.x25519.public_bytes(), &b.dsa.public_bytes())
    };
    assert_eq!(fp(&alice), fp(&alice));
    assert_ne!(fp(&alice), fp(&bob));

    // Same IK, different VK: the digest must change.
    let tampered = umbra_crypto::kdf::identity_fingerprint(
        &alice.x25519.public_bytes(),
        &bob.dsa.public_bytes(),
    );
    assert_ne!(fp(&alice), tampered);
}

/// Out-of-order delivery: later messages arriving first are stashed and
/// decrypt when their turn comes; the session stays usable.
#[test]
fn ratchet_out_of_order_delivery() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bob_spk = X25519KeyPair::generate();
    let mut alice = DoubleRatchet::init_alice(
        RootKey::from_bytes([2u8; 32]),
        &X25519PublicKey::from_bytes(&bob_spk.public_bytes()),
    )?;
    let mut bob = DoubleRatchet::init_bob(RootKey::from_bytes([2u8; 32]), bob_spk);

    let m1 = alice.encrypt(b"one")?;
    let m2 = alice.encrypt(b"two")?;
    let m3 = alice.encrypt(b"three")?;

    // 3, 1, 2 — reordered.
    assert_eq!(bob.decrypt(&m3)?, b"three".to_vec());
    assert_eq!(bob.decrypt(&m1)?, b"one".to_vec());
    assert_eq!(bob.decrypt(&m2)?, b"two".to_vec());

    // The session keeps working in order afterwards.
    let m4 = alice.encrypt(b"four")?;
    assert_eq!(bob.decrypt(&m4)?, b"four".to_vec());
    Ok(())
}

/// Replayed messages fail closed (single-use message keys, store miss).
#[test]
fn ratchet_replay_rejected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bob_spk = X25519KeyPair::generate();
    let mut alice = DoubleRatchet::init_alice(
        RootKey::from_bytes([3u8; 32]),
        &X25519PublicKey::from_bytes(&bob_spk.public_bytes()),
    )?;
    let mut bob = DoubleRatchet::init_bob(RootKey::from_bytes([3u8; 32]), bob_spk);

    let m1 = alice.encrypt(b"once")?;
    assert!(bob.decrypt(&m1).is_ok());
    assert!(
        bob.decrypt(&m1).is_err(),
        "a replayed message must be rejected"
    );
    Ok(())
}

/// A header gap larger than `MAX_SKIP_PER_CHAIN` is rejected up front
/// (hostile-input bound) instead of exhausting memory.
#[test]
fn ratchet_gap_bound_rejected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bob_spk = X25519KeyPair::generate();
    let mut alice = DoubleRatchet::init_alice(
        RootKey::from_bytes([4u8; 32]),
        &X25519PublicKey::from_bytes(&bob_spk.public_bytes()),
    )?;
    let mut bob = DoubleRatchet::init_bob(RootKey::from_bytes([4u8; 32]), bob_spk);

    let _ = alice.encrypt(b"zero")?;
    for _ in 0..umbra_crypto::ratchet::MAX_SKIP_PER_CHAIN {
        let _ = alice.encrypt(b"filler")?;
    }
    // Header N now claims an index beyond the skip bound.
    let far = alice.encrypt(b"far")?;
    assert!(
        bob.decrypt(&far).is_err(),
        "a gap beyond MAX_SKIP_PER_CHAIN must be rejected"
    );
    Ok(())
}

/// The skipped-key store is bounded: once `MAX_SKIPPED_KEYS` is exceeded
/// (filled across several rotations, each within the per-chain skip
/// bound), the oldest stashed key is evicted and its message becomes
/// undecryptable (documented trade-off) while newer stashed keys survive.
#[test]
fn ratchet_store_eviction() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use umbra_crypto::ratchet::MAX_SKIPPED_KEYS;

    let bob_spk = X25519KeyPair::generate();
    let mut alice = DoubleRatchet::init_alice(
        RootKey::from_bytes([5u8; 32]),
        &X25519PublicKey::from_bytes(&bob_spk.public_bytes()),
    )?;
    let mut bob = DoubleRatchet::init_bob(RootKey::from_bytes([5u8; 32]), bob_spk);

    // Chain 1: 129 messages; Bob receives ONLY the last one first, so
    // MAX_SKIP_PER_CHAIN (128) keys are stashed and the store fills.
    let mut chain1 = Vec::new();
    for _ in 0..(MAX_SKIPPED_KEYS.saturating_div(2).saturating_add(1)) {
        chain1.push(alice.encrypt(b"chain1")?);
    }
    let last1 = chain1.pop().ok_or("chain1 empty")?;
    bob.decrypt(&last1)?;

    // Chain 2: Bob replies (rotation), Alice sends 128 messages; Bob
    // receives only the last, stashing 127 more (store now at cap - 1).
    let reply = bob.encrypt(b"reply")?;
    alice.decrypt(&reply)?;
    let mut chain2 = Vec::new();
    for _ in 0..MAX_SKIPPED_KEYS.saturating_div(2) {
        chain2.push(alice.encrypt(b"chain2")?);
    }
    let last2 = chain2.pop().ok_or("chain2 empty")?;
    let chain2_first = chain2.remove(0);
    bob.decrypt(&last2)?;

    // Chain 3: another rotation, another 128-message gap. Stashing these
    // overflows the store and evicts the oldest (chain 1) entries.
    let reply2 = bob.encrypt(b"reply2")?;
    alice.decrypt(&reply2)?;
    let mut chain3 = Vec::new();
    for _ in 0..MAX_SKIPPED_KEYS.saturating_div(2) {
        chain3.push(alice.encrypt(b"chain3")?);
    }
    let last3 = chain3.pop().ok_or("chain3 empty")?;
    bob.decrypt(&last3)?;

    // An evicted chain-1 message can no longer be decrypted...
    let first1 = chain1.remove(0);
    assert!(
        bob.decrypt(&first1).is_err(),
        "an evicted skipped key must fail closed"
    );

    // ...but chain-2 keys survived the eviction (newer than chain 1).
    assert!(
        bob.decrypt(&chain2_first).is_ok(),
        "a surviving stashed key must still decrypt"
    );

    // The session is still fully usable after eviction and rollback.
    let tail = alice.encrypt(b"tail")?;
    assert_eq!(bob.decrypt(&tail)?, b"tail".to_vec());
    Ok(())
}
