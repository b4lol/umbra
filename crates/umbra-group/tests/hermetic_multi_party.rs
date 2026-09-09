//! Full hermetic 3-party PQ-MLS group flow (TODO B.2): create, add two
//! members (confirming the Commit fans out to a previously-added member
//! on the SECOND add too, not just the Welcome path), send a group
//! message from the creator to both, and prove the reverse direction —
//! an added member independently sends a message the others (including
//! the creator) can decrypt. Delivery is wired entirely via
//! `tokio::io::duplex` pairs plus `connect`/`peer_lookup` closures (see
//! `crates/umbra-group/src/delivery.rs`'s own module docs for why this,
//! not a `Transport`/`LoopbackTransport`, is this crate's real delivery
//! seam) — no live network is involved at any point. This is this
//! increment's central acceptance proof.
//!
//! # A documented, ruled scope gap this test works around (not a bug)
//!
//! `inbound.rs`'s own module docs (see its "A freshly joined group has
//! no roster yet" section) rule that a peer who joins a group via a
//! `Welcome` gets an EMPTY [`persistence::GroupRoster`] persisted
//! alongside their group state — `GroupRoster` is Umbra's own
//! peer-name-to-leaf-index bookkeeping, never carried over MLS itself,
//! and populating it for a freshly joined member is explicitly left to
//! "whatever future mechanism bootstraps peer-name knowledge," ruled
//! out of scope for that task.
//!
//! That means a freshly joined member's own `send_group_message` would
//! fan out to an empty roster (nobody) until such a mechanism exists.
//! Proving the reverse-direction send this test's Step 7 requires (an
//! added member sending a message the others decrypt) therefore needs
//! that peer's roster to be populated first. Since the bootstrap
//! mechanism itself is a deliberately deferred design question (not an
//! "obvious correction" this test's job is to invent), this test
//! populates it directly using the same already-tested, public
//! `persistence::load_group_state`/`save_group_state` primitives
//! `add_member`/`inbound.rs` themselves use — simulating what that
//! future bootstrap would produce, without touching any production
//! file. No new production code was needed or added for this test.
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use openmls::prelude::OpenMlsProvider as _;
use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
use tokio::sync::Mutex;

use umbra_group::delivery::PeerTransportAddress;
use umbra_group::inbound::{self, InboundGroupEvent};
use umbra_group::persistence::{self, GroupRoster};
use umbra_group::{GroupError, add, create, keypackage, send};

/// Shorthand for a boxed, `Send`, `Send`-error result — matches this
/// crate's other test modules (`unwrap()`/`expect()` are denied even in
/// test code by this workspace's clippy lints).
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// The future type returned by [`addressed_streams`]'s closure —
/// factored into its own alias to satisfy `clippy::type_complexity`.
type ConnectFuture =
    Pin<Box<dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>> + Send>>;

/// Sets up a fresh temp dir under `std::env::temp_dir()`, unique per
/// test/label pair (mirrors this crate's existing test style, e.g.
/// `add.rs`/`send.rs`/`inbound.rs`'s own `temp_dir` helpers).
fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "umbra-group-hermetic-multi-party-{}-{label}",
        std::process::id()
    ))
}

/// A `connect` closure routing to whichever pre-built `DuplexStream`
/// half was registered for a given address — generalizes `add.rs`'s own
/// `dual_stream` test helper (fixed at exactly two recipients) to an
/// arbitrary number, which this 3-party test needs (a `Commit` fan-out
/// to N-1 previously-existing members, plus a `Welcome` to the new
/// member, in the same `add_member` call).
fn addressed_streams(
    pairs: Vec<(PeerTransportAddress, DuplexStream)>,
) -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
    let slots: Vec<(PeerTransportAddress, Arc<Mutex<Option<DuplexStream>>>)> = pairs
        .into_iter()
        .map(|(address, stream)| (address, Arc::new(Mutex::new(Some(stream)))))
        .collect();
    move |address: &PeerTransportAddress| {
        let address = address.clone();
        let slots = slots.clone();
        Box::pin(async move {
            let slot = slots
                .into_iter()
                .find(|(candidate, _)| candidate == &address)
                .map(|(_, slot)| slot)
                .ok_or_else(|| {
                    GroupError::Malformed(format!(
                        "unexpected connect() address in test: {address:?}"
                    ))
                })?;
            let taken = slot.lock().await.take().ok_or_else(|| {
                GroupError::Malformed(
                    "connect() called more than once for this address in test".into(),
                )
            })?;
            Ok(Box::new(taken) as Box<dyn AsyncWrite + Unpin + Send>)
        })
    }
}

/// Reads the `CONNECTION_TYPE_GROUP` marker byte off `stream`, then
/// everything after it (until the writer side closes, which
/// `deliver_to_one` triggers by dropping its stream handle once its
/// write completes) — exactly `process_inbound_group_frame`'s own
/// `frame_bytes` argument (marker already stripped). Mirrors
/// `add.rs`/`send.rs`/`inbound.rs`'s own `capture_frame`/
/// `assert_frame_matches` test helpers.
async fn capture_frame<S>(mut stream: S) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let marker = stream.read_u8().await?;
    assert_eq!(marker, umbra_net::messenger::CONNECTION_TYPE_GROUP);
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(buf)
}

/// Directly patches a group-state file's persisted [`GroupRoster`] to
/// `new_roster`, preserving the group's own MLS tree/epoch state exactly
/// as loaded (only the orthogonal Umbra-bookkeeping roster field
/// changes) — see this file's top-level module docs for why this test
/// needs to do this rather than the production code.
fn patch_roster(path: &Path, passphrase: &[u8], new_roster: &GroupRoster) -> TestResult {
    let (group, _old_roster, provider) = persistence::load_group_state(path, passphrase)?;
    persistence::save_group_state(path, passphrase, &group, provider.storage(), new_roster)?;
    Ok(())
}

#[tokio::test]
async fn three_party_create_add_send_receive_flow() -> TestResult {
    let alice_dir = temp_dir("alice");
    let bob_dir = temp_dir("bob");
    let carol_dir = temp_dir("carol");
    std::fs::create_dir_all(&alice_dir)?;
    std::fs::create_dir_all(&bob_dir)?;
    std::fs::create_dir_all(&carol_dir)?;
    let alice_pw = b"alice-hermetic-pw";
    let bob_pw = b"bob-hermetic-pw";
    let carol_pw = b"carol-hermetic-pw";

    // 1 & 2. Alice creates the group.
    create::create_group(&alice_dir, alice_pw, "cell")?;

    // 3. Bob and Carol each export a key package.
    let bob_kp = keypackage::export_keypackage(&bob_dir, bob_pw)?;
    let carol_kp = keypackage::export_keypackage(&carol_dir, carol_pw)?;

    let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
    let carol_addr = PeerTransportAddress::Mesh("carol-mesh".to_string());
    let alice_addr = PeerTransportAddress::Onion("alice.onion".to_string());

    // 4. Alice adds Bob. Alice's roster is empty at this point (a
    // freshly created group's own documented starting state — see
    // `create.rs`), so the Commit fan-out (to nobody) makes no
    // `connect()` call at all; only the Welcome to Bob does.
    let welcome_frame_for_bob = {
        let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![(bob_addr.clone(), bob_member_side)]);
        let peer_lookup = {
            let bob_addr = bob_addr.clone();
            move |name: &str| if name == "bob" { Some(bob_addr.clone()) } else { None }
        };

        add::add_member(&alice_dir, alice_pw, "cell", "bob", &bob_kp, peer_lookup, connect).await?;

        capture_frame(bob_observer_side).await?
    };

    let bob_joined = inbound::process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame_for_bob)?;
    let InboundGroupEvent::Joined { group_name: bob_group_name } = bob_joined else {
        return Err("expected Joined event for bob".into());
    };

    // 5. Alice adds Carol. Alice's roster now contains Bob (from step
    // 4), so THIS add's Commit fans out to Bob too — the specific path
    // this test must exercise beyond the Welcome-only case above.
    let (bob_commit_frame, welcome_frame_for_carol) = {
        let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
        let (carol_member_side, carol_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_member_side),
            (carol_addr.clone(), carol_member_side),
        ]);
        let peer_lookup = {
            let bob_addr = bob_addr.clone();
            let carol_addr = carol_addr.clone();
            move |name: &str| match name {
                "bob" => Some(bob_addr.clone()),
                "carol" => Some(carol_addr.clone()),
                _ => None,
            }
        };

        add::add_member(
            &alice_dir,
            alice_pw,
            "cell",
            "carol",
            &carol_kp,
            peer_lookup,
            connect,
        )
        .await?;

        (
            capture_frame(bob_observer_side).await?,
            capture_frame(carol_observer_side).await?,
        )
    };

    let bob_membership_updated =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_commit_frame)?;
    assert_eq!(
        bob_membership_updated,
        InboundGroupEvent::MembershipUpdated {
            group_name: bob_group_name.clone()
        },
        "bob's state must update correctly on the SECOND add too (Commit fan-out to an \
         existing member, not just a Welcome to a new one)"
    );

    let carol_joined = inbound::process_inbound_group_frame(&carol_dir, carol_pw, &welcome_frame_for_carol)?;
    let InboundGroupEvent::Joined { group_name: carol_group_name } = carol_joined else {
        return Err("expected Joined event for carol".into());
    };

    // Both Bob and Carol now independently see a 3-member group.
    let bob_group_path = bob_dir.join("groups").join(format!("{bob_group_name}.enc"));
    let carol_group_path = carol_dir.join("groups").join(format!("{carol_group_name}.enc"));
    let (bob_group_after_adds, _bob_roster, _bob_provider) =
        persistence::load_group_state(&bob_group_path, bob_pw)?;
    assert_eq!(bob_group_after_adds.members().count(), 3);
    let (carol_group_after_adds, _carol_roster, _carol_provider) =
        persistence::load_group_state(&carol_group_path, carol_pw)?;
    assert_eq!(carol_group_after_adds.members().count(), 3);

    // 6. Alice sends a group message; it fans out to both Bob and
    // Carol (Alice's own roster now holds both).
    let cell_plaintext = b"hello cell".to_vec();
    let (bob_app_frame, carol_app_frame) = {
        let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
        let (carol_member_side, carol_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_member_side),
            (carol_addr.clone(), carol_member_side),
        ]);
        let peer_lookup = {
            let bob_addr = bob_addr.clone();
            let carol_addr = carol_addr.clone();
            move |name: &str| match name {
                "bob" => Some(bob_addr.clone()),
                "carol" => Some(carol_addr.clone()),
                _ => None,
            }
        };

        send::send_group_message(&alice_dir, alice_pw, "cell", &cell_plaintext, peer_lookup, connect)
            .await?;

        (
            capture_frame(bob_observer_side).await?,
            capture_frame(carol_observer_side).await?,
        )
    };

    let bob_received = inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_app_frame)?;
    assert_eq!(
        bob_received,
        InboundGroupEvent::ApplicationMessage {
            group_name: bob_group_name.clone(),
            plaintext: cell_plaintext.clone(),
        }
    );
    let carol_received = inbound::process_inbound_group_frame(&carol_dir, carol_pw, &carol_app_frame)?;
    assert_eq!(
        carol_received,
        InboundGroupEvent::ApplicationMessage {
            group_name: carol_group_name.clone(),
            plaintext: cell_plaintext.clone(),
        }
    );

    // 7. Reverse direction: Bob independently sends a message that
    // Alice and Carol can both decrypt too — proving this isn't a
    // one-way artifact of Alice's own state.
    //
    // Bob's own persisted roster is empty (see this file's top-level
    // module docs), so it is patched here with the peer-name/leaf-index
    // mapping this test already knows, using only already-tested
    // persistence primitives (no production code changed).
    let (alice_group_for_leaf, alice_roster, _alice_provider) =
        persistence::load_group_state(&alice_dir.join("groups").join("cell.enc"), alice_pw)?;
    let alice_leaf = alice_group_for_leaf.own_leaf_index();
    let carol_leaf = alice_roster
        .leaf_index_for("carol")
        .ok_or("carol missing from alice's persisted roster")?;
    patch_roster(
        &bob_group_path,
        bob_pw,
        &GroupRoster {
            members: vec![("alice".to_string(), alice_leaf), ("carol".to_string(), carol_leaf)],
        },
    )?;

    let bob_plaintext = b"hello from bob".to_vec();
    let (alice_app_frame, carol_app_frame_from_bob) = {
        let (alice_member_side, alice_observer_side) = tokio::io::duplex(8192);
        let (carol_member_side, carol_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (alice_addr.clone(), alice_member_side),
            (carol_addr.clone(), carol_member_side),
        ]);
        let peer_lookup = {
            let alice_addr = alice_addr.clone();
            let carol_addr = carol_addr.clone();
            move |name: &str| match name {
                "alice" => Some(alice_addr.clone()),
                "carol" => Some(carol_addr.clone()),
                _ => None,
            }
        };

        send::send_group_message(
            &bob_dir,
            bob_pw,
            &bob_group_name,
            &bob_plaintext,
            peer_lookup,
            connect,
        )
        .await?;

        (
            capture_frame(alice_observer_side).await?,
            capture_frame(carol_observer_side).await?,
        )
    };

    let alice_received = inbound::process_inbound_group_frame(&alice_dir, alice_pw, &alice_app_frame)?;
    assert_eq!(
        alice_received,
        InboundGroupEvent::ApplicationMessage {
            group_name: "cell".to_string(),
            plaintext: bob_plaintext.clone(),
        }
    );
    let carol_received_from_bob =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &carol_app_frame_from_bob)?;
    assert_eq!(
        carol_received_from_bob,
        InboundGroupEvent::ApplicationMessage {
            group_name: carol_group_name,
            plaintext: bob_plaintext,
        }
    );

    std::fs::remove_dir_all(&alice_dir)?;
    std::fs::remove_dir_all(&bob_dir)?;
    std::fs::remove_dir_all(&carol_dir)?;
    Ok(())
}
