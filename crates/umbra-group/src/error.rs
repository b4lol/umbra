//! Unified error type for `umbra-group` (PQ-MLS group/"cell" encryption,
//! TODO B.2).

use thiserror::Error;

/// Errors produced by `umbra-group`.
#[derive(Debug, Error)]
pub enum GroupError {
    /// AEAD/KDF failure from the underlying `umbra-crypto` keystore
    /// envelope: a wrong passphrase, tampered ciphertext, or a KDF
    /// parameter rejection.
    #[error(transparent)]
    Crypto(#[from] umbra_crypto::CryptoError),

    /// An I/O failure while reading or writing a keystore file.
    #[error("group keystore I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// The stored file is not a recognized Umbra group keystore (bad
    /// magic header) or its envelope is truncated/structurally malformed.
    #[error("malformed group keystore: {0}")]
    Malformed(String),

    /// OpenMLS signature-key-pair generation or reconstruction failed.
    #[error(transparent)]
    Signature(#[from] openmls::prelude::CryptoError),

    /// TLS-codec (de)serialization of a signature key pair failed.
    #[error(transparent)]
    Codec(#[from] openmls::prelude::tls_codec::Error),

    /// `serde_json` (de)serialization of a persisted group state
    /// (storage snapshot + roster) failed.
    #[error("group state (de)serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    /// An OpenMLS `MemoryStorage` operation failed while saving or
    /// loading a group's state.
    #[error(transparent)]
    Storage(#[from] openmls_memory_storage::MemoryStorageError),

    /// [`crate::persistence::load_group_state`] decrypted and
    /// deserialized a persisted blob successfully, but
    /// `MlsGroup::load` found no group matching the persisted group
    /// id in the restored storage. Also returned by
    /// [`crate::inbound::process_inbound_group_frame`] when an inbound
    /// Commit or application-message frame's group id does not match
    /// any locally known group under `<keystore_dir>/groups/`.
    #[error("no MLS group found in persisted storage for the stored group id")]
    GroupNotFound,

    /// `MlsGroup::new` itself failed while creating a new group (e.g.
    /// an unsupported ciphersuite/extension, or a storage error
    /// surfaced through OpenMLS's own group-creation path — distinct
    /// from [`Self::Storage`], which covers direct `MemoryStorage`
    /// operations performed by this crate's own persistence code).
    #[error(transparent)]
    GroupCreation(
        #[from] openmls::prelude::NewGroupError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// `KeyPackageBuilder::build` itself failed while creating a new
    /// key package (e.g. an unsupported ciphersuite, a signature-scheme
    /// mismatch, or a storage error surfaced through OpenMLS's own
    /// key-package-creation path — a plain, non-generic error enum,
    /// distinct from [`Self::GroupCreation`]'s generic
    /// `NewGroupError<StorageError>`).
    #[error(transparent)]
    KeyPackageCreation(#[from] openmls::prelude::KeyPackageNewError),

    /// Base64 decoding of an externally-supplied blob (e.g. an
    /// `Add`-command `KeyPackage` argument) failed. Distinct from
    /// [`Self::Codec`] (TLS-codec parsing of already-decoded bytes) —
    /// this covers the base64 *text* layer.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    /// `KeyPackageIn::validate` rejected an externally-supplied,
    /// untrusted key package (bad leaf-node signature, unsupported
    /// protocol version, or identical init/encryption keys — see
    /// `add.rs` for why this validation step is mandatory rather than
    /// using the unchecked `KeyPackageIn -> KeyPackage` conversion).
    #[error(transparent)]
    KeyPackageValidation(#[from] openmls::prelude::KeyPackageVerifyError),

    /// `MlsGroup::add_members` itself failed while committing a new
    /// member's addition (e.g. a pending commit already exists, or a
    /// storage error surfaced through OpenMLS's own commit-creation
    /// path).
    #[error(transparent)]
    MembershipAddition(
        #[from] openmls::prelude::AddMembersError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// `MlsGroup::merge_pending_commit` itself failed while merging a
    /// just-created Add commit into the group's own state.
    #[error(transparent)]
    CommitMerge(
        #[from]
        openmls::prelude::MergePendingCommitError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// [`crate::create::create_group`] refused to create a group
    /// because a group state file with that name already exists on
    /// disk. Since [`crate::persistence::save_group_state_with_params`]
    /// legitimately overwrites-in-place (required by
    /// [`crate::add::add_member`]'s own re-save on every membership
    /// change), `create_group` itself is the only call site that must
    /// still refuse to clobber a pre-existing group — this variant
    /// carries the message shown to the caller rather than a bare
    /// `std::io::Error` so it reads as a deliberate refusal, not an
    /// I/O accident.
    #[error("group already exists: {0}")]
    AlreadyExists(String),

    /// `MlsGroup::process_message` itself failed while processing an
    /// inbound Commit or application-message frame
    /// ([`crate::inbound::process_inbound_group_frame`]).
    #[error(transparent)]
    MessageProcessing(
        #[from] openmls::prelude::ProcessMessageError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// `MlsGroup::merge_staged_commit` itself failed while merging an
    /// inbound, already-processed Commit into the group's own state
    /// ([`crate::inbound::process_inbound_group_frame`]). Distinct from
    /// [`Self::CommitMerge`] ([`openmls::prelude::MergePendingCommitError`],
    /// used in `add.rs` for merging a LOCALLY authored commit's own
    /// pending commit) — this covers
    /// [`openmls::prelude::MergeCommitError`], produced when merging a
    /// staged (received-from-elsewhere) commit instead.
    #[error(transparent)]
    StagedCommitMerge(
        #[from] openmls::prelude::MergeCommitError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// `StagedWelcome::new_from_welcome`/`StagedWelcome::into_group`
    /// itself failed while processing an inbound Welcome message
    /// ([`crate::inbound::process_inbound_group_frame`]).
    #[error(transparent)]
    WelcomeProcessing(
        #[from] openmls::prelude::WelcomeError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// `MlsGroup::create_message` itself failed while encrypting an
    /// outbound application message ([`crate::send::send_group_message`]),
    /// e.g. this peer has been evicted from the group
    /// (`MlsGroupStateError::UseAfterEviction`) or a pending proposal
    /// blocks sending (`MlsGroupStateError::PendingProposal`). This is
    /// the plain, NON-generic `CreateMessageError` (no `StorageError`
    /// type parameter) — verified against the installed
    /// `openmls-0.9.0` source (`src/group/mls_group/errors.rs`) to be
    /// the applicable overload since this workspace does not enable the
    /// `virtual-clients-draft` feature (see `send.rs`'s own module
    /// docs for the full trace); the generic
    /// `CreateMessageError<StorageError>` form only exists behind that
    /// feature.
    #[error(transparent)]
    MessageCreation(#[from] openmls::prelude::CreateMessageError),

    /// `MlsGroup::remove_members` itself failed while committing a
    /// member's removal ([`crate::remove::remove_member`], TODO B.2.2)
    /// — e.g. an empty member list (`RemoveMembersError::EmptyInput`),
    /// a pending commit already exists, or a storage error surfaced
    /// through OpenMLS's own commit-creation path. Same generic-over-
    /// `StorageError` shape as [`Self::MembershipAddition`].
    #[error(transparent)]
    MembershipRemoval(
        #[from] openmls::prelude::RemoveMembersError<openmls_memory_storage::MemoryStorageError>,
    ),

    /// `MlsGroup::self_update` itself failed while building an on-demand
    /// key-rotation commit ([`crate::rotate::rotate_group_key`], TODO
    /// B.2.3) — e.g. a pending commit already exists, or a storage
    /// error surfaced through OpenMLS's own commit-creation path.
    #[error(transparent)]
    KeyRotation(
        #[from] openmls::prelude::SelfUpdateError<openmls_memory_storage::MemoryStorageError>,
    ),
}
