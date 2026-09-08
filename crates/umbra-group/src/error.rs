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
    /// id in the restored storage.
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
}
