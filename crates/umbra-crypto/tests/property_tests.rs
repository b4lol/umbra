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

    /// Ratchet header roundtrips through the wire encoding helpers.
    #[test]
    fn header_layout(peer_pk in proptest::collection::vec(any::<u8>(), 32)) {
        let mut header = [0u8; HEADER_LEN];
        let pk: [u8; 32] = peer_pk.try_into().unwrap_or([0u8; 32]);
        umbra_crypto::kdf::write_at(&mut header, 0, &pk)?;
        let decoded: [u8; 32] = umbra_crypto::kdf::read_at(&header, 0)?;
        prop_assert_eq!(decoded.to_vec(), pk);
    }
}
