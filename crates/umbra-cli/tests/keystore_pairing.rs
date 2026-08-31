//! Keystore + pairing tests (TODO A.3). Hermetic: tempdir files only.

use std::path::PathBuf;

use umbra_cli::keystore;
use umbra_cli::pairing;

/// Unique temp path for this test process.
fn temp_keystore(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("umbra-test-{}-{nanos}-{name}", std::process::id()))
}

/// Save/load roundtrip restores an equivalent identity (same public keys).
#[test]
fn keystore_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = temp_keystore("roundtrip");
    let bundle = umbra_crypto::keys::IdentityBundle::generate();
    let passphrase = b"correct horse battery staple";

    keystore::save_with_params(&path, passphrase, &bundle, 8192, 2, 1)?;
    let loaded = keystore::load_with_params(&path, passphrase, 8192, 2, 1)?;

    assert_eq!(loaded.x25519.public_bytes(), bundle.x25519.public_bytes());
    assert_eq!(loaded.spk.public_bytes(), bundle.spk.public_bytes());
    assert_eq!(loaded.kem.public_bytes(), bundle.kem.public_bytes());
    assert_eq!(loaded.dsa.public_bytes(), bundle.dsa.public_bytes());
    // SPK signature recomputed and still valid.
    umbra_crypto::keys::IdentityBundle::verify_spk_signature(&loaded.dsa.public_bytes(), &loaded)?;

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A wrong passphrase fails the AEAD verification (never panics, never
/// yields garbage keys).
#[test]
fn keystore_wrong_passphrase_rejected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = temp_keystore("wrongpw");
    let bundle = umbra_crypto::keys::IdentityBundle::generate();
    keystore::save_with_params(&path, b"right", &bundle, 8192, 2, 1)?;

    let result = keystore::load(&path, b"wrong");
    assert!(result.is_err());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A tampered keystore file fails AEAD verification.
#[test]
fn keystore_tamper_rejected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = temp_keystore("tamper");
    let bundle = umbra_crypto::keys::IdentityBundle::generate();
    keystore::save_with_params(&path, b"pw", &bundle, 8192, 2, 1)?;

    let mut raw = std::fs::read(&path)?;
    if let Some(last) = raw.last_mut() {
        *last ^= 0x01;
    }
    std::fs::write(&path, &raw)?;

    assert!(keystore::load(&path, b"pw").is_err());
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Pairing payload roundtrip + SPK self-signature verification.
#[test]
fn pairing_payload_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = umbra_crypto::keys::IdentityBundle::generate();
    let payload = pairing::payload_for(&bundle)?;
    let peer = pairing::parse_payload(&payload)?;
    assert_eq!(peer.ik_arr, bundle.x25519.public_bytes());
    assert_eq!(peer.spk_arr, bundle.spk.public_bytes());
    assert_eq!(peer.kem_arr, bundle.kem.public_bytes());
    assert_eq!(peer.dsa, bundle.dsa.public_bytes());
    Ok(())
}

/// A corrupted payload is rejected (base64 ok, signature broken).
#[test]
fn pairing_payload_corrupted_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = umbra_crypto::keys::IdentityBundle::generate();
    let mut payload = pairing::payload_for(&bundle)?;
    // Flip one character in the middle of the base64 string.
    let middle = payload.len() / 2;
    let flipped_byte = payload.as_bytes().get(middle).copied().unwrap_or(b'A') ^ 0x01;
    payload.replace_range(middle..=middle, &(flipped_byte as char).to_string());
    assert!(pairing::parse_payload(&payload).is_err());
    Ok(())
}

/// SAS is symmetric: both sides derive the same code from the same pair
/// of payloads, regardless of argument order.
#[test]
fn pairing_sas_symmetric() -> Result<(), Box<dyn std::error::Error>> {
    let a = umbra_crypto::keys::IdentityBundle::generate();
    let b = umbra_crypto::keys::IdentityBundle::generate();
    let payload_a = pairing::payload_for(&a)?;
    let payload_b = pairing::payload_for(&b)?;

    let sas_ab = pairing::pairing_sas(&payload_a, &payload_b);
    let sas_ba = pairing::pairing_sas(&payload_b, &payload_a);
    assert_eq!(sas_ab, sas_ba);
    assert!(sas_ab.value() < 1_000_000);
    Ok(())
}

/// Crypto-layer envelope roundtrip (isolates file I/O from the failure).
#[test]
fn envelope_roundtrip_direct() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use umbra_crypto::keystore;
    let salt = [7u8; 16];
    let key = keystore::derive_keystore_key_with_params(b"pw", &salt, 8192, 2, 1)?;
    let blob = keystore::seal_envelope(&key, b"payload")?;
    let opened = keystore::open_envelope(&key, &blob)?;
    let plain: &[u8] = opened.as_ref();
    assert_eq!(plain, b"payload");
    Ok(())
}

/// Peer record roundtrip: save → load → parse gives the same identity.
#[test]
fn peer_record_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use umbra_cli::peers;
    let dir = temp_keystore("peers");
    let bundle = umbra_crypto::keys::IdentityBundle::generate();
    let payload = umbra_cli::pairing::payload_for(&bundle)?;

    peers::save_peer(&dir, "colleague", &payload)?;
    let peer = peers::load_peer(&dir, "colleague")?;
    assert_eq!(peer.ik_arr, bundle.x25519.public_bytes());

    // Invalid names are rejected before touching the filesystem.
    assert!(peers::save_peer(&dir, "../evil", &payload).is_err());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// `serve` resolves the Tor storage root next to the keystore (TODO A.2
/// production call site); a parentless keystore path fails cleanly.
#[cfg(feature = "tor")]
#[test]
fn serve_tor_base_resolution() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let keystore = std::env::temp_dir()
        .join("umbra-serve-test")
        .join("umbra.enc");
    let base = umbra_cli::serve::tor_base_from_keystore(&keystore)?;
    assert_eq!(
        base,
        std::env::temp_dir().join("umbra-serve-test").join("tor")
    );
    let parentless = std::path::Path::new("umbra.enc");
    assert!(umbra_cli::serve::tor_base_from_keystore(parentless).is_err());
    Ok(())
}
