//! Proves the core OpenMLS API chain works as documented, in a single
//! process, with NO persistence (fresh in-memory storage/state for
//! both parties) — the narrowest possible proof before building
//! Umbra-specific plumbing on top. TODO B.2.
//!
//! Every API shape used here was verified against the actually-installed
//! `openmls` 0.9.0 / `openmls_libcrux_crypto` 0.4.0 source (see
//! `.superpowers/sdd/2026-09-07-pq-mls-group-encryption/task-1-report.md`
//! for the full verification notes), not merely assumed from docs.rs.

use openmls::prelude::*;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;

/// The X-Wing hybrid (X25519 + ML-KEM-768) ciphersuite. Confirmed against
/// the installed `openmls_traits` 0.6.0 source
/// (`openmls_traits::types::Ciphersuite`): this is the ONLY hybrid PQ
/// ciphersuite the libcrux crypto provider actually advertises in its
/// `supported_ciphersuites()` list (verified in
/// `openmls_libcrux_crypto-0.4.0/src/crypto.rs`), and it is gated behind
/// the `draft-ietf-mls-pq-ciphersuites` feature (on `openmls_traits` and
/// `openmls_libcrux_crypto` — deliberately NOT on `openmls` itself; see
/// the root Cargo.toml comment) — it does not exist at all without that
/// feature enabled.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// Builds a fresh libcrux-backed provider, a `BasicCredential` and a
/// `SignatureKeyPair` for a party identified by `identity`.
fn new_party(
    identity: &[u8],
) -> Result<(Provider, SignatureKeyPair, CredentialWithKey), Box<dyn std::error::Error + Send + Sync>>
{
    let provider = Provider::new()?;
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())?;
    let credential = BasicCredential::new(identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    Ok((provider, signer, credential_with_key))
}

#[test]
fn two_party_create_add_send_receive_round_trip()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1 & 2. Build a fresh `openmls_libcrux_crypto::Provider` (which
    // bundles its own `openmls_memory_storage::MemoryStorage` and
    // libcrux-backed crypto/rand implementation) plus a `BasicCredential`
    // + `SignatureKeyPair` for each party.
    let (alice_provider, alice_signer, alice_credential_with_key) = new_party(b"alice")?;
    let (bob_provider, bob_signer, bob_credential_with_key) = new_party(b"bob")?;

    // 3. Alice creates a group selecting the X-Wing ciphersuite.
    //
    // `openmls`'s own hardcoded default `Capabilities` ciphersuite list is
    // compiled without `openmls`'s "draft-ietf-mls-pq-ciphersuites"
    // feature (see the root Cargo.toml comment for why), so it would not
    // include the X-Wing ciphersuite. `Capabilities::for_provider` is
    // OpenMLS's own documented alternative: it advertises exactly the
    // ciphersuites the crypto provider reports via
    // `OpenMlsCrypto::supported_ciphersuites()`, which DOES include
    // X-Wing here because `openmls_libcrux_crypto`'s own
    // "draft-ietf-mls-pq-ciphersuites" feature is enabled.
    let alice_capabilities = Capabilities::for_provider(alice_provider.crypto());
    let group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(alice_capabilities)
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &group_create_config,
        alice_credential_with_key,
    )?;

    // 4. Bob builds a `KeyPackage` via the builder, advertising the same
    // provider-derived capabilities.
    let bob_capabilities = Capabilities::for_provider(bob_provider.crypto());
    let bob_key_package_bundle = KeyPackage::builder()
        .leaf_node_capabilities(bob_capabilities)
        .build(
            CIPHERSUITE,
            &bob_provider,
            &bob_signer,
            bob_credential_with_key,
        )?;
    let bob_key_package = bob_key_package_bundle.into_key_package();

    // 5. Alice adds Bob: (Commit, Welcome, Option<GroupInfo>). Merge
    // Alice's own pending commit so her group moves to the new epoch.
    let (_commit_msg_out, welcome_msg_out, _group_info) =
        alice_group.add_members(&alice_provider, &alice_signer, &[bob_key_package])?;
    alice_group.merge_pending_commit(&alice_provider)?;

    // 6. Bob processes the Welcome. Round-trip it through the real
    // `MlsMessageOut` -> `MlsMessageIn` wire representation (TLS codec)
    // rather than relying on any in-process shortcut, so this proves the
    // same path Bob would take receiving bytes over the network.
    let welcome_bytes = welcome_msg_out.tls_serialize_detached()?;
    let welcome_msg_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes)?;
    let welcome = match welcome_msg_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        other => return Err(format!("expected a Welcome message, got {other:?}").into()),
    };

    let group_join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged_welcome = StagedWelcome::new_from_welcome(
        &bob_provider,
        &group_join_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )?;
    let mut bob_group = staged_welcome.into_group(&bob_provider)?;

    // 7. Alice sends an application message.
    let app_msg_out = alice_group.create_message(&alice_provider, &alice_signer, b"hello group")?;

    // 8. Bob processes it (again via a real TLS-codec wire round trip) and
    // recovers the plaintext.
    let app_bytes = app_msg_out.tls_serialize_detached()?;
    let app_msg_in = MlsMessageIn::tls_deserialize_exact(app_bytes)?;
    let protocol_message = app_msg_in.try_into_protocol_message()?;
    let processed_message = bob_group.process_message(&bob_provider, protocol_message)?;

    let plaintext = match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            application_message.into_bytes()
        }
        other => return Err(format!("expected an ApplicationMessage, got {other:?}").into()),
    };

    assert_eq!(plaintext, b"hello group".to_vec());
    Ok(())
}
