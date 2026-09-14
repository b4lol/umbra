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
//! # RosterSync (TODO B.2.1) replaces the old test-only workaround
//!
//! Earlier versions of this test directly patched a peer's persisted
//! `GroupRoster` on disk (`patch_roster`, since removed) to work
//! around `add_member` not yet broadcasting roster updates. That gap
//! is now closed for real: `add_member` sends a RosterSync application
//! message (`crate::roster_sync`) after every membership change, and
//! `process_inbound_group_frame` applies it on receipt. This test now
//! exercises ONLY the real mechanism — no roster is ever hand-patched.
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
use tokio::sync::Mutex;

use umbra_group::delivery::PeerTransportAddress;
use umbra_group::inbound::{self, InboundGroupEvent};
use umbra_group::persistence;
use umbra_group::{GroupError, add, create, keypackage, send};

/// Shorthand for a boxed, `Send`, `Send`-error result — matches this
/// crate's other test modules (`unwrap()`/`expect()` are denied even in
/// test code by this workspace's clippy lints).
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// The future type returned by [`addressed_streams`]'s closure —
/// factored into its own alias to satisfy `clippy::type_complexity`.
type ConnectFuture = Pin<
    Box<
        dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
            + Send,
    >,
>;

/// Sets up a fresh temp dir under `std::env::temp_dir()`, unique per
/// test/label pair (mirrors this crate's existing test style, e.g.
/// `add.rs`/`send.rs`/`inbound.rs`'s own `temp_dir` helpers).
fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "umbra-group-hermetic-multi-party-{}-{label}",
        std::process::id()
    ))
}

/// A `connect` closure routing to a per-address QUEUE of pre-built
/// `DuplexStream` halves — generalizes the old single-slot
/// `addressed_streams` helper now that `add_member` delivers an
/// additional RosterSync message per call, so a roster member can
/// receive more than one message (over separate connections) within a
/// single `add_member`/`send_group_message` invocation.
fn addressed_streams(
    pairs: Vec<(PeerTransportAddress, DuplexStream)>,
) -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
    let mut queues: Vec<(PeerTransportAddress, std::collections::VecDeque<DuplexStream>)> =
        Vec::new();
    for (address, stream) in pairs {
        match queues.iter_mut().find(|(candidate, _)| candidate == &address) {
            Some((_, queue)) => queue.push_back(stream),
            None => {
                queues.push((address, std::collections::VecDeque::from([stream])));
            }
        }
    }
    let state = Arc::new(Mutex::new(queues));
    move |address: &PeerTransportAddress| {
        let address = address.clone();
        let state = Arc::clone(&state);
        Box::pin(async move {
            let mut state = state.lock().await;
            let (_, queue) = state
                .iter_mut()
                .find(|(candidate, _)| candidate == &address)
                .ok_or_else(|| {
                    GroupError::Malformed(format!(
                        "unexpected connect() address in test: {address:?}"
                    ))
                })?;
            let stream = queue.pop_front().ok_or_else(|| {
                GroupError::Malformed(format!(
                    "connect() called more times than expected for {address:?} in test"
                ))
            })?;
            Ok(Box::new(stream) as Box<dyn AsyncWrite + Unpin + Send>)
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
async fn capture_frame<S>(
    mut stream: S,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let marker = stream.read_u8().await?;
    assert_eq!(marker, umbra_net::messenger::CONNECTION_TYPE_GROUP);
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(buf)
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

    // 1 & 2. Alice creates the group, seeding her own name into the
    // roster (TODO B.2.1) — without this, nobody she later adds could
    // ever route a reply back to her via RosterSync.
    create::create_group(&alice_dir, alice_pw, "cell", "alice")?;

    // 3. Bob and Carol each export a key package.
    let bob_kp = keypackage::export_keypackage(&bob_dir, bob_pw)?;
    let carol_kp = keypackage::export_keypackage(&carol_dir, carol_pw)?;

    let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
    let carol_addr = PeerTransportAddress::Mesh("carol-mesh".to_string());
    let alice_addr = PeerTransportAddress::Onion("alice.onion".to_string());

    // 4. Alice adds Bob. Alice's roster contains only herself at this
    // point (seeded at create time), so the Commit fan-out goes to
    // her alone... but `add_member` never delivers to the ACTOR's own
    // address (it fans the Commit out to `old_roster`, which here is
    // `[alice]` — `peer_lookup` below has no entry for "alice", so
    // that one delivery attempt harmlessly fails and is discarded, a
    // documented, accepted simplification — see the design spec's
    // §0). Bob receives the Welcome, then the RosterSync.
    let welcome_frame_for_bob = {
        let (bob_welcome_side, bob_welcome_observer) = tokio::io::duplex(8192);
        let (bob_roster_sync_side, bob_roster_sync_observer) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_welcome_side),
            (bob_addr.clone(), bob_roster_sync_side),
        ]);
        let peer_lookup = {
            let bob_addr = bob_addr.clone();
            move |name: &str| {
                if name == "bob" {
                    Some(bob_addr.clone())
                } else {
                    None
                }
            }
        };

        add::add_member(
            &alice_dir,
            alice_pw,
            "cell",
            "bob",
            &bob_kp,
            peer_lookup,
            connect,
        )
        .await?;

        let welcome = capture_frame(bob_welcome_observer).await?;
        let _roster_sync_from_first_add = capture_frame(bob_roster_sync_observer).await?;
        welcome
    };

    let bob_joined =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame_for_bob)?;
    let InboundGroupEvent::Joined {
        group_name: bob_group_name,
    } = bob_joined
    else {
        return Err("expected Joined event for bob".into());
    };

    // 5. Alice adds Carol. Alice's roster now contains Bob (from step
    // 4), so THIS add's Commit fans out to Bob too. Bob receives the
    // Commit then a RosterSync; Carol receives the Welcome then a
    // RosterSync.
    let (bob_commit_frame, bob_roster_sync_frame, welcome_frame_for_carol, carol_roster_sync_frame) = {
        let (bob_commit_side, bob_commit_observer) = tokio::io::duplex(8192);
        let (bob_roster_sync_side, bob_roster_sync_observer) = tokio::io::duplex(8192);
        let (carol_welcome_side, carol_welcome_observer) = tokio::io::duplex(8192);
        let (carol_roster_sync_side, carol_roster_sync_observer) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_commit_side),
            (bob_addr.clone(), bob_roster_sync_side),
            (carol_addr.clone(), carol_welcome_side),
            (carol_addr.clone(), carol_roster_sync_side),
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
            capture_frame(bob_commit_observer).await?,
            capture_frame(bob_roster_sync_observer).await?,
            capture_frame(carol_welcome_observer).await?,
            capture_frame(carol_roster_sync_observer).await?,
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

    // Bob applies the RosterSync that followed the Commit — this is
    // the REAL mechanism populating his roster with alice and carol,
    // replacing the old `patch_roster` workaround entirely.
    let bob_roster_synced =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_roster_sync_frame)?;
    let InboundGroupEvent::RosterSync {
        roster: bob_roster_after_second_add,
        ..
    } = bob_roster_synced
    else {
        return Err("expected a RosterSync event for bob".into());
    };
    assert!(bob_roster_after_second_add.leaf_index_for("alice").is_some());
    assert!(bob_roster_after_second_add.leaf_index_for("carol").is_some());

    let carol_joined =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &welcome_frame_for_carol)?;
    let InboundGroupEvent::Joined {
        group_name: carol_group_name,
    } = carol_joined
    else {
        return Err("expected Joined event for carol".into());
    };
    let carol_roster_synced =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &carol_roster_sync_frame)?;
    let InboundGroupEvent::RosterSync { .. } = carol_roster_synced else {
        return Err("expected a RosterSync event for carol".into());
    };

    // Both Bob and Carol now independently see a 3-member group.
    let bob_group_path = bob_dir.join("groups").join(format!("{bob_group_name}.enc"));
    let carol_group_path = carol_dir
        .join("groups")
        .join(format!("{carol_group_name}.enc"));
    let (bob_group_after_adds, _bob_roster, _bob_provider) =
        persistence::load_group_state(&bob_group_path, bob_pw)?;
    assert_eq!(bob_group_after_adds.members().count(), 3);
    let (carol_group_after_adds, _carol_roster, _carol_provider) =
        persistence::load_group_state(&carol_group_path, carol_pw)?;
    assert_eq!(carol_group_after_adds.members().count(), 3);

    // 6. Alice sends a group message; it fans out to both Bob and
    // Carol (Alice's own roster now holds both — from Bob's and
    // Carol's own adds, unchanged by RosterSync since Alice is the
    // sender of those, not a receiver).
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

        send::send_group_message(
            &alice_dir,
            alice_pw,
            "cell",
            &cell_plaintext,
            peer_lookup,
            connect,
        )
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
    let carol_received =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &carol_app_frame)?;
    assert_eq!(
        carol_received,
        InboundGroupEvent::ApplicationMessage {
            group_name: carol_group_name.clone(),
            plaintext: cell_plaintext.clone(),
        }
    );

    // 7. Reverse direction: Bob independently sends a message that
    // Alice and Carol can both decrypt too — proving this isn't a
    // one-way artifact of Alice's own state. Bob's roster (populated
    // via the REAL RosterSync mechanism in step 5, NOT `patch_roster`)
    // already contains alice and carol.
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

    let alice_received =
        inbound::process_inbound_group_frame(&alice_dir, alice_pw, &alice_app_frame)?;
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
