//! Fan-out delivery of an MLS message (Commit/Welcome/application
//! frame) to every member of a [`GroupRoster`], over whichever raw
//! byte-stream transport each member is actually reachable on
//! (TODO B.2).
//!
//! # Correction to the original task brief
//!
//! The original brief pointed at `umbra_net::transport::Transport`
//! (`send(peer, &SealedPacket)` / `recv() -> SealedPacket`). That API
//! is tied to `umbra_protocol::packet::SealedPacket`, a FIXED-SIZE
//! `[u8; PACKET_LEN]` array produced only by the two-party Double
//! Ratchet's own `seal()` using live ratchet-session key state — it
//! cannot carry a variable-length, un-ratcheted MLS Commit/Welcome/
//! application-message frame. This module instead writes directly
//! onto a raw `AsyncWrite` byte stream, the same pattern
//! `crates/umbra-cli/src/tor_send.rs`/`mesh_send.rs` and this crate's
//! own `messenger.rs` use for their real sends (none of them go
//! through `Transport` either).
//!
//! # Wire format
//!
//! One connection carries exactly one delivery:
//!
//! ```text
//! [CONNECTION_TYPE_GROUP marker byte]
//! [group_id_len: u32 big-endian][group_id bytes]
//! [mls_message_len: u32 big-endian][mls_message bytes]
//! ```
//!
//! `mls_message bytes` is `message.tls_serialize_detached()`
//! (`MlsMessageOut` implements `tls_codec::Serialize` — verified
//! against installed `openmls-0.9.0/src/framing/message_out.rs`).
//! This length-prefixed frame is this task's own new convention: no
//! existing framing in this codebase covers an arbitrary-length raw
//! payload (`messenger.rs`'s own framing is a different,
//! ratchet-chunk-based scheme for the two-party path). The receive
//! side that parses this frame back out is Task 12's job.
//!
//! # Transport-agnosticism
//!
//! Real group members may be reachable over different transports
//! (Tor onion, Wi-Fi Direct mesh, Nym) within the same roster, and
//! this crate must never depend on `umbra-cli`, `arti-client`, or any
//! other transport-specific crate. So [`deliver_to_members`] takes a
//! caller-supplied `connect` closure that resolves one
//! [`PeerTransportAddress`] into an already-usable, boxed stream —
//! the real Tor/mesh/Nym connection logic is deferred entirely to
//! CLI-wiring tasks (8/10/11) that will supply the real closure. A
//! single generic stream type parameter would be wrong here: it would
//! force every member in one delivery call onto the identical
//! concrete stream type, but members can legitimately sit on
//! different transports.

use openmls::prelude::MlsMessageOut;
use openmls::prelude::tls_codec::Serialize as _;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use umbra_net::messenger::CONNECTION_TYPE_GROUP;

use crate::error::GroupError;
use crate::persistence::GroupRoster;

/// A member's transport address, as this crate's own transport-agnostic
/// design (informed by how `crates/umbra-cli/src/peers.rs`'s
/// `PeerIdentity` already stores `onion`/`mesh_addr`/`nym_addr` as
/// `Option<String>` fields). Resolving an Umbra peer name to one of
/// these is entirely the caller's job (`peer_lookup` below) — this
/// crate does not know how peer records are stored or which address a
/// caller should prefer when a peer has several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransportAddress {
    /// A Tor v3 `.onion` service address.
    Onion(String),
    /// A Wi-Fi Direct mesh address.
    Mesh(String),
    /// A Nym mixnet address.
    Nym(String),
}

/// Delivers `message` (an MLS Commit/Welcome/application frame) to
/// every member of `roster`, over whichever transport each member's
/// address resolves to.
///
/// For each `(peer_name, _leaf_index)` in `roster.members`:
///
/// 1. Resolve `peer_name` to a [`PeerTransportAddress`] via
///    `peer_lookup`. `None` is recorded as a per-member failure (no
///    address on file) and delivery moves on to the next member.
/// 2. Open a stream to that address via `connect`. A `connect` error
///    is likewise recorded as a per-member failure; delivery moves on.
/// 3. Write the [`CONNECTION_TYPE_GROUP`] marker byte, then the
///    length-prefixed `[group_id][mls_message]` frame (module docs).
///    A write failure is recorded as [`GroupError::Io`].
///
/// A failure delivering to one member never aborts delivery to the
/// rest of the roster — that is the entire reason this returns a
/// `Vec` of per-member results rather than a single `Result`.
pub async fn deliver_to_members<F, Fut>(
    roster: &GroupRoster,
    peer_lookup: impl Fn(&str) -> Option<PeerTransportAddress>,
    connect: F,
    group_id: &[u8],
    message: &MlsMessageOut,
) -> Vec<(String, Result<(), GroupError>)>
where
    F: Fn(&PeerTransportAddress) -> Fut,
    Fut: std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>,
{
    let mut results = Vec::with_capacity(roster.members.len());

    for (peer_name, _leaf_index) in &roster.members {
        let outcome = deliver_to_one(peer_name, &peer_lookup, &connect, group_id, message).await;
        results.push((peer_name.clone(), outcome));
    }

    results
}

/// Resolves, connects, and writes the frame for a single roster
/// member. Split out of [`deliver_to_members`] purely so the `?`
/// operator can short-circuit one member's own failure without any
/// hand-written early-`continue` bookkeeping in the loop above.
async fn deliver_to_one<F, Fut>(
    peer_name: &str,
    peer_lookup: &impl Fn(&str) -> Option<PeerTransportAddress>,
    connect: &F,
    group_id: &[u8],
    message: &MlsMessageOut,
) -> Result<(), GroupError>
where
    F: Fn(&PeerTransportAddress) -> Fut,
    Fut: std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>,
{
    let address = peer_lookup(peer_name).ok_or_else(|| {
        GroupError::Malformed(format!(
            "no transport address on file for peer {peer_name:?}"
        ))
    })?;

    let mut stream = connect(&address).await?;

    let mls_bytes = message
        .tls_serialize_detached()
        .map_err(GroupError::Codec)?;

    let group_id_len = u32::try_from(group_id.len())
        .map_err(|_| GroupError::Malformed("group id too large to frame (> u32::MAX)".into()))?;
    let mls_len = u32::try_from(mls_bytes.len())
        .map_err(|_| GroupError::Malformed("MLS message too large to frame (> u32::MAX)".into()))?;

    stream.write_all(&[CONNECTION_TYPE_GROUP]).await?;
    stream.write_all(&group_id_len.to_be_bytes()).await?;
    stream.write_all(group_id).await?;
    stream.write_all(&mls_len.to_be_bytes()).await?;
    stream.write_all(&mls_bytes).await?;
    stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use openmls::prelude::{
        Ciphersuite, CredentialWithKey, KeyPackage, LeafNodeIndex, MlsMessageOut,
    };
    use openmls_libcrux_crypto::CryptoProvider;
    use openmls_memory_storage::MemoryStorage;
    use tokio::io::{AsyncReadExt, DuplexStream};
    use tokio::sync::Mutex;

    use super::*;
    use crate::identity;
    use crate::persistence::RestoredProvider;

    /// Shorthand for a boxed, `Send`, `Send`-error result — this test
    /// module's own `?`-friendly error type, matching this crate's
    /// existing test-module house style (`identity.rs`/`persistence.rs`/
    /// `keypackage.rs`'s own `#[test]` functions all return this
    /// instead of `unwrap()`/`expect()`, which the workspace's
    /// `clippy::unwrap_used`/`expect_used` lints deny even in test code).
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// The future type returned by [`single_use_stream`]'s closure.
    /// Factored into its own alias purely to satisfy
    /// `clippy::type_complexity` (denied via `-D warnings`).
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    /// Builds a real `MlsMessageOut` (a `KeyPackage`'s own MLS message
    /// wrapper is the simplest way to get one without standing up a
    /// full group/commit) so the test exercises the crate's actual
    /// `tls_serialize_detached()` path rather than a fake payload.
    /// Reuses this crate's own `identity`/`persistence` helpers rather
    /// than hand-rolling an `OpenMlsProvider` impl.
    fn sample_mls_message() -> Result<MlsMessageOut, Box<dyn std::error::Error + Send + Sync>> {
        let identity = identity::generate_group_identity()?;
        let provider =
            RestoredProvider::from_parts(CryptoProvider::new()?, MemoryStorage::default());
        let credential_with_key = CredentialWithKey {
            credential: identity.credential.into(),
            signature_key: identity.signature_key_pair.public().into(),
        };
        let key_package_bundle = KeyPackage::builder().build(
            CIPHERSUITE,
            &provider,
            &identity.signature_key_pair,
            credential_with_key,
        )?;
        Ok(key_package_bundle.key_package().clone().into())
    }

    /// Builds a roster of `names.len()` members (test rosters here
    /// never exceed a handful of entries, so the `usize` -> `u32`
    /// leaf-index cast never truncates).
    fn sample_roster(names: &[&str]) -> GroupRoster {
        GroupRoster {
            members: names
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "test rosters have at most a handful of entries"
                    )]
                    let leaf_index = LeafNodeIndex::new(index as u32);
                    ((*name).to_string(), leaf_index)
                })
                .collect(),
        }
    }

    /// Looks up one named result out of a `deliver_to_members` result
    /// vec, without `Vec` indexing (denied by `clippy::indexing_slicing`)
    /// or `Option::unwrap()` (denied by `clippy::unwrap_used`).
    fn find_result<'a>(
        results: &'a [(String, Result<(), GroupError>)],
        name: &str,
    ) -> Result<&'a Result<(), GroupError>, Box<dyn std::error::Error + Send + Sync>> {
        results
            .iter()
            .find(|(peer_name, _)| peer_name == name)
            .map(|(_, outcome)| outcome)
            .ok_or_else(|| format!("no result for {name:?} in {results:?}").into())
    }

    /// Hands out one end of a `tokio::io::duplex` pair from an `Fn`
    /// closure: `connect` may only be `Fn` (not `FnMut`/`FnOnce`), but
    /// a `DuplexStream` is move-only, so the pair is wrapped in
    /// `Arc<Mutex<Option<_>>>` and taken out on first (and, in these
    /// tests, only) use.
    fn single_use_stream(stream: DuplexStream) -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
        let slot = Arc::new(Mutex::new(Some(stream)));
        move |_address: &PeerTransportAddress| {
            let slot = Arc::clone(&slot);
            Box::pin(async move {
                let taken = slot.lock().await.take().ok_or_else(|| {
                    GroupError::Malformed("connect() called more than once in this test".into())
                })?;
                Ok(Box::new(taken) as Box<dyn AsyncWrite + Unpin + Send>)
            })
        }
    }

    /// Reads back one `[marker][group_id_len][group_id][mls_len][mls_bytes]`
    /// frame from `stream` and asserts it matches `group_id`/`mls_bytes`.
    /// Shared by both tests below so the wire-format assertions live in
    /// one place.
    async fn assert_frame_matches<S>(mut stream: S, group_id: &[u8], mls_bytes: &[u8]) -> TestResult
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let marker = stream.read_u8().await?;
        assert_eq!(marker, CONNECTION_TYPE_GROUP);

        let group_id_len = stream.read_u32().await?;
        let mut read_group_id = vec![0u8; usize::try_from(group_id_len)?];
        stream.read_exact(&mut read_group_id).await?;
        assert_eq!(read_group_id, group_id);

        let mls_len = stream.read_u32().await?;
        let mut read_mls_bytes = vec![0u8; usize::try_from(mls_len)?];
        stream.read_exact(&mut read_mls_bytes).await?;
        assert_eq!(read_mls_bytes, mls_bytes);

        Ok(())
    }

    #[tokio::test]
    async fn delivers_a_frame_with_the_group_marker_and_correct_payload() -> TestResult {
        let (member_side, observer_side) = tokio::io::duplex(4096);
        let roster = sample_roster(&["alice"]);
        let group_id = b"group-42".to_vec();
        let message = sample_mls_message()?;
        let expected_mls_bytes = message.tls_serialize_detached()?;

        let connect = single_use_stream(member_side);
        let results = deliver_to_members(
            &roster,
            |name| {
                assert_eq!(name, "alice");
                Some(PeerTransportAddress::Onion("alice.onion".to_string()))
            },
            connect,
            &group_id,
            &message,
        )
        .await;

        assert_eq!(results.len(), 1);
        let alice_result = find_result(&results, "alice")?;
        assert!(
            alice_result.is_ok(),
            "delivery should succeed: {alice_result:?}"
        );

        assert_frame_matches(observer_side, &group_id, &expected_mls_bytes).await
    }

    #[tokio::test]
    async fn one_member_failure_does_not_abort_delivery_to_others() -> TestResult {
        let (member_side, observer_side) = tokio::io::duplex(4096);
        let roster = sample_roster(&["alice", "bob"]);
        let group_id = b"group-7".to_vec();
        let message = sample_mls_message()?;
        let expected_mls_bytes = message.tls_serialize_detached()?;

        // "bob" has no address on file (peer_lookup returns None) —
        // the simplest way to force a per-member failure without
        // standing up a real unreachable address.
        let connect = single_use_stream(member_side);
        let results = deliver_to_members(
            &roster,
            |name| match name {
                "alice" => Some(PeerTransportAddress::Mesh("alice-mesh".to_string())),
                _ => None,
            },
            connect,
            &group_id,
            &message,
        )
        .await;

        assert_eq!(results.len(), 2);

        let alice_result = find_result(&results, "alice")?;
        let bob_result = find_result(&results, "bob")?;
        assert!(
            alice_result.is_ok(),
            "alice should succeed: {alice_result:?}"
        );
        assert!(bob_result.is_err(), "bob should fail (no address on file)");

        // alice's frame still made it onto her duplex end.
        assert_frame_matches(observer_side, &group_id, &expected_mls_bytes).await
    }
}
