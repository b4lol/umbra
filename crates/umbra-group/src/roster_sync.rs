//! Typed application-level payloads for group messages, and the TODO
//! B.2.1 `RosterSync` mechanism built on them.
//!
//! # Typed application payloads
//!
//! Every MLS application message Umbra sends carries a one-byte type
//! tag as the first byte of its plaintext payload, so control traffic
//! rides the group's OWN AEAD channel instead of a side channel:
//!
//! ```text
//! [type_tag: u8][payload bytes]
//!   0x00 = user text (what `umbra group send` reads from stdin)
//!   0x01 = roster sync (this module)
//! ```
//!
//! This is an Umbra-internal framing INSIDE the MLS application
//! payload — MLS itself neither knows nor cares; the tag is
//! confidentiality- and integrity-protected like any other payload
//! byte. Unknown tags are rejected as [`GroupError::Malformed`] on
//! receipt (fail-closed, never silently reinterpreted as text).
//!
//! # RosterSync (TODO B.2.1)
//!
//! [`GroupRoster`] — Umbra's own peer-name ↔ leaf-index bookkeeping —
//! is never carried by MLS itself (Commits and Welcomes contain no
//! Umbra peer names). A member who joins via a `Welcome` therefore has
//! no local view of the other members' names, and without one their
//! own `umbra group send` would fan out to zero recipients (delivery
//! resolves peer names to transport addresses via the roster).
//! RosterSync closes that gap: immediately after an `add_member`
//! Commit+Welcome (and again after every `remove_member`), the member
//! who performed the change sends a FULL roster snapshot — every
//! member's `(peer name, leaf index)` pair, INCLUDING the sender's own
//! — as an ordinary application message to ALL members (the new member
//! included). Receivers adopt the snapshot in
//! [`crate::inbound::process_inbound_group_frame`].
//!
//! ## The sender's own name (a real design point, not implicit)
//!
//! A full snapshot must name EVERY member — including the sender — or
//! recipients would never learn how to address the sender back. But a
//! roster deliberately never lists the local member (nobody fan-out-
//! delivers to themselves), so the sender's own name is not in any
//! roster to copy from. It is supplied by the operator once, at
//! `umbra group create --self-name`, and propagated thereafter: a
//! member who joined via `Welcome` learns their own cell-wide name
//! from the first snapshot they adopt (the entry matching their own
//! leaf index), and carries it forward into any snapshot THEY later
//! originate. Cell-wide name consistency is an operational assumption
//! of the single-cell trust model (the names are labels the whole cell
//! agrees on); nothing authenticates a name beyond the group channel
//! itself.
//!
//! ## Trust and ordering
//!
//! The snapshot rides the group's own AEAD channel and (in production)
//! the sender's already-authenticated pairwise delivery; the sender
//! already controls membership (any member can add/remove — the
//! single-cell co-equal trust model, no ACL, deliberate). A malicious
//! or confused member could send a WRONG snapshot, but they could
//! already withhold or garbage their own deliveries; last-writer-wins
//! full snapshots are the ruled design, and
//! [`crate::persistence::GroupRoster::last_sync_epoch`] guards the one
//! failure mode with no operator visibility: a STALE snapshot
//! overtaking a newer one on the wire (MLS permits out-of-epoch
//! application-message decryption via skipped-key retention, so this
//! is reachable over an unordered transport like Tor).
//!
//! # Wire format of a roster-sync payload (after the `0x01` tag)
//!
//! ```text
//! [entry_count: u32 BE]
//! per entry: [name_len: u32 BE][name bytes (UTF-8)][leaf_index: u32 BE]
//! ```
//!
//! Length-prefixed big-endian framing matches this crate's own
//! `delivery.rs` wire-format style. All reads are bounds-checked; a
//! truncated, trailing-garbage, or non-UTF-8 payload is a clean
//! [`GroupError::Malformed`], never a panic. Entry count is validated
//! lazily by truncation: the payload itself is already bounded by the
//! caller (1 MiB at the `serve` inbound reader), so a huge claimed
//! count exhausts the input on the first missing entry rather than
//! pre-allocating.

use std::path::Path;

use openmls::prelude::{LeafNodeIndex, MlsGroup, OpenMlsProvider as _};

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::GroupIdentity;
use crate::persistence::{self, GroupRoster, RestoredProvider};

/// Type tag: a user-text application payload (what
/// [`crate::send::send_group_message`] encrypts).
pub const APP_TYPE_USER_TEXT: u8 = 0x00;

/// Type tag: a roster-sync application payload (this module).
pub const APP_TYPE_ROSTER_SYNC: u8 = 0x01;

/// A decoded, tag-stripped application payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationPayload {
    /// User text (tag `0x00`): the exact bytes the sender passed to
    /// `umbra group send`.
    UserText(Vec<u8>),
    /// A full roster snapshot (tag `0x01`): every member's `(peer
    /// name, leaf index)` pair INCLUDING the sender's own entry.
    RosterSync(Vec<(String, LeafNodeIndex)>),
}

/// Frames user text as a typed application payload (prepends the
/// `0x00` tag). The inverse of the [`ApplicationPayload::UserText`]
/// decode arm.
#[must_use]
pub fn encode_user_text(plaintext: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(plaintext.len().saturating_add(1));
    framed.push(APP_TYPE_USER_TEXT);
    framed.extend_from_slice(plaintext);
    framed
}

/// Encodes a full roster snapshot as a typed application payload
/// (module docs' wire format).
///
/// # Errors
///
/// Returns [`GroupError::Malformed`] if there are more than `u32::MAX`
/// entries or a name exceeds `u32::MAX` bytes (both unreachable at real
/// cell sizes).
pub fn encode_roster_sync(entries: &[(String, LeafNodeIndex)]) -> Result<Vec<u8>, GroupError> {
    let mut framed = Vec::new();
    framed.push(APP_TYPE_ROSTER_SYNC);
    let entry_count = u32::try_from(entries.len())
        .map_err(|_| GroupError::Malformed("roster too large to encode (> u32::MAX)".into()))?;
    framed.extend_from_slice(&entry_count.to_be_bytes());
    for (name, leaf_index) in entries {
        let name_len = u32::try_from(name.len()).map_err(|_| {
            GroupError::Malformed("roster entry name too long to encode (> u32::MAX)".into())
        })?;
        framed.extend_from_slice(&name_len.to_be_bytes());
        framed.extend_from_slice(name.as_bytes());
        framed.extend_from_slice(&leaf_index.u32().to_be_bytes());
    }
    Ok(framed)
}

/// Reads a big-endian `u32` off the front of `cursor`, advancing it.
fn read_u32(cursor: &mut &[u8]) -> Result<u32, GroupError> {
    // `read_at` is bounds-checked but surfaces a `CryptoError`; this
    // module's documented contract is that a truncated payload is a
    // clean `GroupError::Malformed` (module docs), so map it here.
    let bytes: [u8; 4] = umbra_crypto::kdf::read_at(cursor, 0)
        .map_err(|_| GroupError::Malformed("truncated roster sync payload".into()))?;
    *cursor = cursor
        .get(4..)
        .ok_or_else(|| GroupError::Malformed("truncated roster sync payload".into()))?;
    Ok(u32::from_be_bytes(bytes))
}

/// Takes `len` bytes off the front of `cursor`, advancing it.
fn take<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8], GroupError> {
    let head = cursor
        .get(..len)
        .ok_or_else(|| GroupError::Malformed("truncated roster sync payload".into()))?;
    *cursor = cursor
        .get(len..)
        .ok_or_else(|| GroupError::Malformed("truncated roster sync payload".into()))?;
    Ok(head)
}

/// Decodes the entry list of a roster-sync payload (after the tag).
fn decode_roster_entries(mut cursor: &[u8]) -> Result<Vec<(String, LeafNodeIndex)>, GroupError> {
    let entry_count = read_u32(&mut cursor)?;
    let mut entries = Vec::new();
    for _ in 0..entry_count {
        let name_len = usize::try_from(read_u32(&mut cursor)?).map_err(|_| {
            GroupError::Malformed("roster sync name length does not fit in usize".into())
        })?;
        let name_bytes = take(&mut cursor, name_len)?;
        let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| {
            GroupError::Malformed("roster sync entry name is not valid UTF-8".into())
        })?;
        let leaf_index = LeafNodeIndex::new(read_u32(&mut cursor)?);
        entries.push((name, leaf_index));
    }
    if !cursor.is_empty() {
        return Err(GroupError::Malformed(
            "trailing bytes after roster sync entry list".into(),
        ));
    }
    Ok(entries)
}

/// Splits a decrypted MLS application payload into its typed form
/// (module docs' tag table).
///
/// # Errors
///
/// Returns [`GroupError::Malformed`] for an empty payload (no tag), an
/// unknown tag, or a malformed roster-sync entry list.
pub fn decode_application_payload(payload: &[u8]) -> Result<ApplicationPayload, GroupError> {
    let (&tag, rest) = payload
        .split_first()
        .ok_or_else(|| GroupError::Malformed("empty application payload (no type tag)".into()))?;
    match tag {
        APP_TYPE_USER_TEXT => Ok(ApplicationPayload::UserText(rest.to_vec())),
        APP_TYPE_ROSTER_SYNC => Ok(ApplicationPayload::RosterSync(decode_roster_entries(rest)?)),
        other => Err(GroupError::Malformed(format!(
            "unknown application payload type tag 0x{other:02x}"
        ))),
    }
}

/// Builds the entry list a roster sync should carry for `group`:
/// `roster.members` (the OTHER members) plus the local member's own
/// `(self_name, own_leaf_index)` entry — recipients adopt everything
/// except their own entry, so the sender's entry is how they learn to
/// address the sender back (module docs, "The sender's own name").
///
/// If `roster.self_name` is `None` (this peer joined via a `Welcome`
/// and has not yet adopted a sync naming them), the snapshot simply
/// lacks a self entry — degraded but functional; see
/// [`GroupRoster::self_name`].
#[must_use]
pub fn snapshot_entries(roster: &GroupRoster, group: &MlsGroup) -> Vec<(String, LeafNodeIndex)> {
    let mut entries = roster.members.clone();
    if let Some(self_name) = &roster.self_name {
        entries.push((self_name.clone(), group.own_leaf_index()));
    }
    entries
}

/// Adopts a received roster snapshot into `roster`, guarding against
/// stale (out-of-order) snapshots: the snapshot REPLACES the member
/// list only if `message_epoch` is strictly newer than
/// [`GroupRoster::last_sync_epoch`] (module docs, "Trust and
/// ordering"). Returns whether the snapshot was adopted.
///
/// On adoption, the entry matching `own_leaf_index` is REMOVED from
/// the member list (a roster never lists the local member — nobody
/// fan-out-delivers to themselves) and its name becomes
/// [`GroupRoster::self_name`]: this is how a `Welcome`-joined member
/// learns the name the cell addresses them by. A snapshot that does
/// not name the receiver leaves any previously known `self_name`
/// untouched.
pub fn adopt_snapshot(
    roster: &mut GroupRoster,
    own_leaf_index: LeafNodeIndex,
    snapshot: Vec<(String, LeafNodeIndex)>,
    message_epoch: u64,
) -> bool {
    if roster
        .last_sync_epoch
        .is_some_and(|last| message_epoch <= last)
    {
        return false;
    }
    let mut members = Vec::with_capacity(snapshot.len());
    let mut own_name = None;
    for (name, leaf_index) in snapshot {
        if leaf_index == own_leaf_index {
            own_name = Some(name);
        } else {
            members.push((name, leaf_index));
        }
    }
    roster.members = members;
    if own_name.is_some() {
        roster.self_name = own_name;
    }
    roster.last_sync_epoch = Some(message_epoch);
    true
}

/// The local group-session context a roster-sync fan-out needs —
/// bundles what would otherwise be five sibling arguments (clippy's
/// `too_many_arguments` threshold is 7; the parameter list below plus
/// these five would exceed it).
pub(crate) struct GroupSessionContext<'a> {
    /// The group, already holding the POST-change state (the membership
    /// commit merged), so the sync is encrypted under the same new
    /// epoch the Welcome/Commit recipients just moved to.
    pub group: &'a mut MlsGroup,
    /// The restored OpenMLS provider (crypto + storage).
    pub provider: &'a RestoredProvider,
    /// This peer's group identity (signs the sync message).
    pub identity: &'a GroupIdentity,
    /// Path of the group's encrypted state file.
    pub group_state_path: &'a Path,
    /// The keystore passphrase (re-encrypts the state file).
    pub passphrase: &'a [u8],
}

/// Creates, persists, and fans out a roster-sync application message
/// carrying the full current roster (including the sender's own
/// entry) to every member of `roster` — the shared tail of
/// [`crate::add::add_member`] and [`crate::remove::remove_member`]
/// (TODO B.2.1/B.2.2).
///
/// The `create_message` ratchet advancement is persisted BEFORE any
/// delivery is attempted — the same ruled delivery-failure semantics
/// as `add.rs`/`send.rs` (a per-member delivery failure is swallowed
/// by [`delivery::deliver_to_members`]; a state-save failure IS an
/// error).
///
/// Note on ordering: the sync is necessarily a SEPARATE connection
/// from the Welcome a new member receives (`delivery.rs`'s format is
/// one frame per connection), so over an unordered transport it can
/// race the Welcome and fail with `GroupNotFound` on the receiver —
/// contained as an ordinary per-member delivery failure, and healed by
/// the next membership change's sync (the last-writer-wins full
/// snapshot makes every sync self-sufficient).
///
/// # Errors
///
/// Returns [`GroupError`] if the roster cannot be encoded, if
/// `MlsGroup::create_message` fails, or if the updated state cannot be
/// persisted. Per-member delivery failures never produce an `Err`.
pub(crate) async fn fan_out_roster_sync<F, Fut>(
    ctx: &mut GroupSessionContext<'_>,
    roster: &GroupRoster,
    peer_lookup: &impl Fn(&str) -> Option<PeerTransportAddress>,
    connect: &F,
) -> Result<(), GroupError>
where
    F: Fn(&PeerTransportAddress) -> Fut,
    Fut: std::future::Future<
            Output = Result<Box<dyn tokio::io::AsyncWrite + Unpin + Send>, GroupError>,
        >,
{
    let payload = encode_roster_sync(&snapshot_entries(roster, ctx.group))?;
    let message =
        ctx.group
            .create_message(ctx.provider, &ctx.identity.signature_key_pair, &payload)?;

    // Durable BEFORE delivery (ruled semantics, module docs).
    persistence::save_group_state(
        ctx.group_state_path,
        ctx.passphrase,
        ctx.group,
        ctx.provider.storage(),
        roster,
    )?;

    let group_id_bytes = ctx.group.group_id().to_vec();
    let _results =
        delivery::deliver_to_members(roster, peer_lookup, connect, &group_id_bytes, &message).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shorthand for a boxed, `Send`-error result — matches this
    /// crate's other test modules (`unwrap()`/`expect()` are denied
    /// even in test code by this workspace's clippy lints).
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// A few `(name, leaf)` entries for encode/decode tests.
    fn sample_entries() -> Vec<(String, LeafNodeIndex)> {
        vec![
            ("alice".to_string(), LeafNodeIndex::new(0)),
            ("bob".to_string(), LeafNodeIndex::new(1)),
            ("carol".to_string(), LeafNodeIndex::new(2)),
        ]
    }

    #[test]
    fn user_text_round_trips_and_strips_the_tag() -> TestResult {
        let framed = encode_user_text(b"hello cell");
        assert_eq!(framed.first(), Some(&APP_TYPE_USER_TEXT));
        let decoded = decode_application_payload(&framed)?;
        assert_eq!(
            decoded,
            ApplicationPayload::UserText(b"hello cell".to_vec())
        );
        Ok(())
    }

    #[test]
    fn roster_sync_round_trips_names_and_leaf_indices() -> TestResult {
        let entries = sample_entries();
        let framed = encode_roster_sync(&entries)?;
        assert_eq!(framed.first(), Some(&APP_TYPE_ROSTER_SYNC));
        let decoded = decode_application_payload(&framed)?;
        assert_eq!(decoded, ApplicationPayload::RosterSync(entries));
        Ok(())
    }

    #[test]
    fn roster_sync_with_non_ascii_and_empty_names_round_trips() -> TestResult {
        let entries = vec![
            (String::new(), LeafNodeIndex::new(0)),
            ("zoë-台".to_string(), LeafNodeIndex::new(u32::MAX)),
        ];
        let framed = encode_roster_sync(&entries)?;
        let decoded = decode_application_payload(&framed)?;
        assert_eq!(decoded, ApplicationPayload::RosterSync(entries));
        Ok(())
    }

    #[test]
    fn empty_payload_is_a_clean_error_not_a_panic() {
        let result = decode_application_payload(&[]);
        assert!(matches!(result, Err(GroupError::Malformed(_))));
    }

    #[test]
    fn unknown_tag_is_a_clean_error_not_a_panic() {
        let result = decode_application_payload(&[0x99, 0x00, 0x01]);
        assert!(matches!(result, Err(GroupError::Malformed(_))));
    }

    #[test]
    fn truncated_roster_sync_is_a_clean_error_not_a_panic() {
        for cut in 0..12usize {
            let framed = [APP_TYPE_ROSTER_SYNC]
                .into_iter()
                .chain([0, 0, 0, 2, 0, 0, 0, 3, b'b', b'o', b'b'])
                .take(cut)
                .collect::<Vec<u8>>();
            let result = decode_application_payload(&framed);
            assert!(
                matches!(result, Err(GroupError::Malformed(_))),
                "cut at {cut} should fail cleanly"
            );
        }
    }

    #[test]
    fn trailing_garbage_after_entries_is_a_clean_error() -> TestResult {
        let mut framed = encode_roster_sync(&sample_entries())?;
        framed.extend_from_slice(b"trailing");
        let result = decode_application_payload(&framed);
        assert!(matches!(result, Err(GroupError::Malformed(_))));
        Ok(())
    }

    #[test]
    fn adoption_replaces_members_and_learns_the_own_name() {
        let mut roster = GroupRoster::default();
        let adopted = adopt_snapshot(&mut roster, LeafNodeIndex::new(1), sample_entries(), 5);
        assert!(adopted);
        // Own entry (bob, leaf 1) is REMOVED from the member list and
        // becomes this peer's self_name.
        assert_eq!(
            roster.members,
            vec![
                ("alice".to_string(), LeafNodeIndex::new(0)),
                ("carol".to_string(), LeafNodeIndex::new(2)),
            ]
        );
        assert_eq!(roster.self_name.as_deref(), Some("bob"));
        assert_eq!(roster.last_sync_epoch, Some(5));
    }

    #[test]
    fn stale_snapshots_are_ignored() {
        let mut roster = GroupRoster::default();
        assert!(adopt_snapshot(
            &mut roster,
            LeafNodeIndex::new(1),
            sample_entries(),
            5
        ));
        let members_after_first = roster.members.clone();

        // Same epoch, and an OLDER epoch: both ignored.
        assert!(!adopt_snapshot(
            &mut roster,
            LeafNodeIndex::new(1),
            vec![],
            5
        ));
        assert!(!adopt_snapshot(
            &mut roster,
            LeafNodeIndex::new(1),
            vec![("mallory".to_string(), LeafNodeIndex::new(7))],
            3
        ));
        assert_eq!(roster.members, members_after_first);
        assert_eq!(roster.self_name.as_deref(), Some("bob"));
    }

    #[test]
    fn a_snapshot_not_naming_the_receiver_keeps_the_old_self_name() {
        let mut roster = GroupRoster {
            self_name: Some("bob".to_string()),
            ..GroupRoster::default()
        };
        let without_receiver = vec![
            ("alice".to_string(), LeafNodeIndex::new(0)),
            ("carol".to_string(), LeafNodeIndex::new(2)),
        ];
        assert!(adopt_snapshot(
            &mut roster,
            LeafNodeIndex::new(1),
            without_receiver,
            6
        ));
        assert_eq!(roster.self_name.as_deref(), Some("bob"));
        assert_eq!(roster.members.len(), 2);
    }
}
