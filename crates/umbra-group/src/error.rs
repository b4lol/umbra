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
}
