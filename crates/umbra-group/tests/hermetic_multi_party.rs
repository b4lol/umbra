//! Full hermetic 3-party PQ-MLS group flow (TODO B.2): create, add two
//! members (confirming the Commit fans out to a previously-added member
//! on the SECOND add too, not just the Welcome path), roster syncs
//! bootstrapping the joined members' rosters (TODO B.2.1), send a group
//! message from the creator to both, prove the reverse direction — an
//! added member independently sends a message the others (including the
//! creator) can decrypt — then remove a member (TODO B.2.2, proving the
//! removed member cannot decrypt post-removal traffic while the
//! remaining one can) and rotate a member's keys (TODO B.2.3, proving
//! the group still decrypts post-rotation). Delivery is wired entirely
//! via `tokio::io::duplex` pairs plus `connect`/`peer_lookup` closures
//! (see `crates/umbra-group/src/delivery.rs`'s own module docs for why
//! this, not a `Transport`/`LoopbackTransport`, is this crate's real
//! delivery seam) — no live network is involved at any point. This is
//! this increment's central acceptance proof.
//!
//! # No test-only roster patching anymore (TODO B.2.1 landed)
//!
//! This test previously patched a freshly joined member's empty
//! [`persistence::GroupRoster`] directly via the persistence primitives
//! (a documented, ruled workaround for the then-unimplemented roster
//! bootstrapping). The B.2.1 `RosterSync` mechanism is the real
//! mechanism: every `add_member`/`remove_member` now fans out a full
//! roster snapshot as a typed MLS application message, and this test
//! delivers those frames like any other — the reverse-direction send
//! below runs against rosters populated by PRODUCTION code only.
use std::collections::VecDeque;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
use tokio::sync::Mutex;

use umbra_group::delivery::PeerTransportAddress;
use umbra_group::inbound::{self, InboundGroupEvent};
use umbra_group::persistence;
use umbra_group::{GroupError, add, create, keypackage, remove, rotate, send};

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

/// A `connect` closure routing to pre-built `DuplexStream` halves
/// registered per address, MULTIPLE per address — a membership change
/// fans out more than one frame to the same member (e.g. an add's
/// Welcome AND its roster sync, as two separate connections; TODO
/// B.2.1). Frames are handed out in registration order.
fn addressed_streams(
    pairs: Vec<(PeerTransportAddress, DuplexStream)>,
) -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
    let mut ordered: Vec<(PeerTransportAddress, Vec<DuplexStream>)> = Vec::new();
    for (address, stream) in pairs {
        if let Some((_, queue)) = ordered
            .iter_mut()
            .find(|(candidate, _)| candidate == &address)
        {
            queue.push(stream);
        } else {
            ordered.push((address, vec![stream]));
        }
    }
    let slots: Vec<(PeerTransportAddress, Arc<Mutex<VecDeque<DuplexStream>>>)> = ordered
        .into_iter()
        .map(|(address, queue)| (address, Arc::new(Mutex::new(VecDeque::from(queue)))))
        .collect();
    move |address: &PeerTransportAddress| {
        let address = address.clone();
        let slots = slots.clone();
        Box::pin(async move {
            let queue = slots
                .into_iter()
                .find(|(candidate, _)| candidate == &address)
                .map(|(_, queue)| queue)
                .ok_or_else(|| {
                    GroupError::Malformed(format!(
                        "unexpected connect() address in test: {address:?}"
                    ))
                })?;
            let taken = queue.lock().await.pop_front().ok_or_else(|| {
                GroupError::Malformed(
                    "connect() called more times than registered for this address in test".into(),
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

/// Loads a peer's persisted roster for assertions.
fn load_roster(
    dir: &std::path::Path,
    group_name: &str,
    passphrase: &[u8],
) -> Result<umbra_group::persistence::GroupRoster, Box<dyn std::error::Error + Send + Sync>> {
    let path = dir.join("groups").join(format!("{group_name}.enc"));
    let (_group, roster, _provider) = persistence::load_group_state(&path, passphrase)?;
    Ok(roster)
}

#[tokio::test]
async fn three_party_create_add_sync_send_remove_rotate_flow() -> TestResult {
    let alice_dir = temp_dir("alice");
    let bob_dir = temp_dir("bob");
    let carol_dir = temp_dir("carol");
    std::fs::create_dir_all(&alice_dir)?;
    std::fs::create_dir_all(&bob_dir)?;
    std::fs::create_dir_all(&carol_dir)?;
    let alice_pw = b"alice-hermetic-pw";
    let bob_pw = b"bob-hermetic-pw";
    let carol_pw = b"carol-hermetic-pw";

    // 1 & 2. Alice creates the group, naming herself (TODO B.2.1: the
    // self entry her roster syncs will carry).
    create::create_group(&alice_dir, alice_pw, "cell", "alice")?;

    // 3. Bob and Carol each export a key package.
    let bob_kp = keypackage::export_keypackage(&bob_dir, bob_pw)?;
    let carol_kp = keypackage::export_keypackage(&carol_dir, carol_pw)?;

    let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
    let carol_addr = PeerTransportAddress::Mesh("carol-mesh".to_string());
    let alice_addr = PeerTransportAddress::Onion("alice.onion".to_string());

    // 4. Alice adds Bob. Alice's roster is empty at this point (a
    // freshly created group's own documented starting state — see
    // `create.rs`), so the Commit fan-out (to nobody) makes no
    // `connect()` call at all; Bob receives the Welcome AND the roster
    // sync that follows it (TODO B.2.1), as two separate connections.
    let (welcome_frame_for_bob, sync_frame_for_bob) = {
        let (bob_welcome_member, bob_welcome_observer) = tokio::io::duplex(8192);
        let (bob_sync_member, bob_sync_observer) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_welcome_member),
            (bob_addr.clone(), bob_sync_member),
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

        (
            capture_frame(bob_welcome_observer).await?,
            capture_frame(bob_sync_observer).await?,
        )
    };

    let bob_joined =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame_for_bob)?;
    let InboundGroupEvent::Joined {
        group_name: bob_group_name,
    } = bob_joined
    else {
        return Err("expected Joined event for bob".into());
    };

    // The freshly joined member's roster is empty UNTIL the sync
    // arrives (it is a separate frame, not part of the Welcome).
    let bob_roster_pre_sync = load_roster(&bob_dir, &bob_group_name, bob_pw)?;
    assert!(bob_roster_pre_sync.members.is_empty());

    let bob_synced = inbound::process_inbound_group_frame(&bob_dir, bob_pw, &sync_frame_for_bob)?;
    assert_eq!(
        bob_synced,
        InboundGroupEvent::RosterSynced {
            group_name: bob_group_name.clone()
        }
    );

    // TODO B.2.1 acceptance: bob's roster was populated by the REAL
    // mechanism — it names alice (and not bob himself), and bob learned
    // his own cell-wide name from the sync.
    let bob_roster = load_roster(&bob_dir, &bob_group_name, bob_pw)?;
    assert!(bob_roster.leaf_index_for("alice").is_some());
    assert!(bob_roster.leaf_index_for("bob").is_none());
    assert_eq!(bob_roster.self_name.as_deref(), Some("bob"));

    // 5. Alice adds Carol. Alice's roster now contains Bob (from step
    // 4), so THIS add's Commit fans out to Bob too — and the roster
    // sync goes to BOTH Bob and Carol.
    let (bob_commit_frame, bob_sync_frame_2, welcome_frame_for_carol, carol_sync_frame) = {
        let (bob_commit_member, bob_commit_observer) = tokio::io::duplex(8192);
        let (bob_sync_member, bob_sync_observer) = tokio::io::duplex(8192);
        let (carol_welcome_member, carol_welcome_observer) = tokio::io::duplex(8192);
        let (carol_sync_member, carol_sync_observer) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_commit_member),
            (bob_addr.clone(), bob_sync_member),
            (carol_addr.clone(), carol_welcome_member),
            (carol_addr.clone(), carol_sync_member),
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
            capture_frame(bob_sync_observer).await?,
            capture_frame(carol_welcome_observer).await?,
            capture_frame(carol_sync_observer).await?,
        )
    };

    // Bob processes the Commit BEFORE the sync (the sync is encrypted
    // under the new epoch the Commit moves him to).
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
    let bob_synced_2 = inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_sync_frame_2)?;
    assert_eq!(
        bob_synced_2,
        InboundGroupEvent::RosterSynced {
            group_name: bob_group_name.clone()
        }
    );

    let carol_joined =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &welcome_frame_for_carol)?;
    let InboundGroupEvent::Joined {
        group_name: carol_group_name,
    } = carol_joined
    else {
        return Err("expected Joined event for carol".into());
    };
    let carol_synced =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &carol_sync_frame)?;
    assert_eq!(
        carol_synced,
        InboundGroupEvent::RosterSynced {
            group_name: carol_group_name.clone()
        }
    );

    // Everyone's roster is now complete and consistent — populated
    // entirely by production code (the whole point of TODO B.2.1).
    let bob_roster = load_roster(&bob_dir, &bob_group_name, bob_pw)?;
    assert!(bob_roster.leaf_index_for("alice").is_some());
    assert!(bob_roster.leaf_index_for("carol").is_some());
    let carol_roster = load_roster(&carol_dir, &carol_group_name, carol_pw)?;
    assert!(carol_roster.leaf_index_for("alice").is_some());
    assert!(carol_roster.leaf_index_for("bob").is_some());
    assert_eq!(carol_roster.self_name.as_deref(), Some("carol"));

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
    // Alice and Carol can both decrypt too. NO test-side roster
    // patching anymore (TODO B.2.1 landed): Bob's roster was populated
    // by the roster syncs in steps 4-5.
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
            group_name: carol_group_name.clone(),
            plaintext: bob_plaintext,
        }
    );

    // 8. TODO B.2.2: Alice removes Carol. The Commit and the refreshed
    // roster sync fan out to the REMAINING members (Bob) only; Carol
    // deliberately receives nothing.
    let (bob_removal_commit_frame, bob_removal_sync_frame) = {
        let (bob_commit_member, bob_commit_observer) = tokio::io::duplex(8192);
        let (bob_sync_member, bob_sync_observer) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![
            (bob_addr.clone(), bob_commit_member),
            (bob_addr.clone(), bob_sync_member),
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

        remove::remove_member(&alice_dir, alice_pw, "cell", "carol", peer_lookup, connect).await?;

        (
            capture_frame(bob_commit_observer).await?,
            capture_frame(bob_sync_observer).await?,
        )
    };

    // Alice's own roster no longer names carol.
    let alice_roster = load_roster(&alice_dir, "cell", alice_pw)?;
    assert!(alice_roster.leaf_index_for("carol").is_none());
    assert!(alice_roster.leaf_index_for("bob").is_some());

    // Bob advances past the removal and adopts the refreshed roster.
    let bob_removal =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_removal_commit_frame)?;
    assert_eq!(
        bob_removal,
        InboundGroupEvent::MembershipUpdated {
            group_name: bob_group_name.clone()
        }
    );
    let bob_synced_3 =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_removal_sync_frame)?;
    assert_eq!(
        bob_synced_3,
        InboundGroupEvent::RosterSynced {
            group_name: bob_group_name.clone()
        }
    );
    let bob_roster_after_removal = load_roster(&bob_dir, &bob_group_name, bob_pw)?;
    assert!(bob_roster_after_removal.leaf_index_for("carol").is_none());
    assert!(bob_roster_after_removal.leaf_index_for("alice").is_some());

    // Bob now sees a 2-member group; Carol's stale state still shows 3
    // (she received nothing — she finds out by being unable to decrypt).
    let (bob_group_after_removal, _roster, _provider) =
        persistence::load_group_state(&bob_group_path, bob_pw)?;
    assert_eq!(bob_group_after_removal.members().count(), 2);

    // Post-removal forward secrecy: Alice sends a message (fanned out
    // to Bob only — carol is gone from the roster); the SAME ciphertext
    // is fed to Carol by hand (MLS group messages are one ciphertext
    // for the whole group, so this is exactly what eavesdropping the
    // delivery would give her). Bob decrypts it; Carol CANNOT — the
    // removal Commit advanced the epoch without her.
    let post_removal_plaintext = b"after carol left".to_vec();
    let bob_post_removal_frame = {
        let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![(bob_addr.clone(), bob_member_side)]);
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

        send::send_group_message(
            &alice_dir,
            alice_pw,
            "cell",
            &post_removal_plaintext,
            peer_lookup,
            connect,
        )
        .await?;

        capture_frame(bob_observer_side).await?
    };

    let bob_received_post_removal =
        inbound::process_inbound_group_frame(&bob_dir, bob_pw, &bob_post_removal_frame)?;
    assert_eq!(
        bob_received_post_removal,
        InboundGroupEvent::ApplicationMessage {
            group_name: bob_group_name.clone(),
            plaintext: post_removal_plaintext.clone(),
        },
        "the remaining member must still decrypt post-removal traffic"
    );
    let carol_post_removal =
        inbound::process_inbound_group_frame(&carol_dir, carol_pw, &bob_post_removal_frame);
    assert!(
        carol_post_removal.is_err(),
        "the removed member must NOT decrypt post-removal traffic (got {carol_post_removal:?})"
    );

    // 9. TODO B.2.3: Bob rotates his key material. The Commit fans out
    // to every other member of HIS roster (Alice only, post-removal);
    // no roster sync follows a rotation (membership is unchanged).
    let alice_rotation_commit_frame = {
        let (alice_member_side, alice_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![(alice_addr.clone(), alice_member_side)]);
        let peer_lookup = {
            let alice_addr = alice_addr.clone();
            move |name: &str| {
                if name == "alice" {
                    Some(alice_addr.clone())
                } else {
                    None
                }
            }
        };

        rotate::rotate_group_key(&bob_dir, bob_pw, &bob_group_name, peer_lookup, connect).await?;

        capture_frame(alice_observer_side).await?
    };

    let alice_rotation =
        inbound::process_inbound_group_frame(&alice_dir, alice_pw, &alice_rotation_commit_frame)?;
    assert_eq!(
        alice_rotation,
        InboundGroupEvent::MembershipUpdated {
            group_name: "cell".to_string()
        }
    );

    // Post-rotation the group still works: Bob sends, Alice decrypts.
    let post_rotation_plaintext = b"after bob rotated".to_vec();
    let alice_post_rotation_frame = {
        let (alice_member_side, alice_observer_side) = tokio::io::duplex(8192);
        let connect = addressed_streams(vec![(alice_addr.clone(), alice_member_side)]);
        let peer_lookup = {
            let alice_addr = alice_addr.clone();
            move |name: &str| {
                if name == "alice" {
                    Some(alice_addr.clone())
                } else {
                    None
                }
            }
        };

        send::send_group_message(
            &bob_dir,
            bob_pw,
            &bob_group_name,
            &post_rotation_plaintext,
            peer_lookup,
            connect,
        )
        .await?;

        capture_frame(alice_observer_side).await?
    };

    let alice_received_post_rotation =
        inbound::process_inbound_group_frame(&alice_dir, alice_pw, &alice_post_rotation_frame)?;
    assert_eq!(
        alice_received_post_rotation,
        InboundGroupEvent::ApplicationMessage {
            group_name: "cell".to_string(),
            plaintext: post_rotation_plaintext,
        },
        "the group must still decrypt post-rotation traffic"
    );

    std::fs::remove_dir_all(&alice_dir)?;
    std::fs::remove_dir_all(&bob_dir)?;
    std::fs::remove_dir_all(&carol_dir)?;
    Ok(())
}
