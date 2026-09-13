//! PKCS#11 hardware-security-key backend (TODO B.3): HMAC
//! challenge-response against a token-held, non-extractable secret key
//! — the cryptographic primitive a LATER increment will mix into the
//! keystore's existing Argon2id passphrase KDF (see
//! `docs/superpowers/specs/2026-09-13-hwkey-pkcs11-backend-design.md`).
//! This crate does none of that wiring yet: it only proves the PKCS#11
//! plumbing itself is correct, against a real token (SoftHSM2 in this
//! crate's own tests; any PKCS#11-compliant hardware key in principle).
//!
//! Deliberately its own crate, not folded into `umbra-crypto`: PKCS#11
//! support (the `cryptoki` dependency) is optional infrastructure most
//! Umbra builds never touch, and `umbra-crypto` is a dependency of
//! every crate in this workspace — the same isolation principle
//! `umbra-gui` already applies to its own GTK4/Libadwaita dependency
//! (though unlike GTK4, `cryptoki` needs no build-time system library
//! at all, so this crate needs no Cargo feature gate).

mod error;
pub use error::HwKeyError;

use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// Finds the first initialized token's slot. This crate does not yet
/// support choosing among multiple simultaneously-present tokens — a
/// later increment's concern, once real multi-token selection UX
/// exists.
fn first_token_slot(pkcs11: &Pkcs11) -> Result<Slot, HwKeyError> {
    pkcs11
        .get_slots_with_token()?
        .into_iter()
        .next()
        .ok_or(HwKeyError::NoTokenPresent)
}

/// Builds an [`AuthPin`] from raw PIN bytes.
///
/// PKCS#11 PINs are conventionally ASCII/UTF-8; a lossy conversion is
/// acceptable here since a mangled PIN simply fails login cleanly
/// rather than silently succeeding with the wrong secret.
fn auth_pin_from_bytes(pin: &[u8]) -> AuthPin {
    AuthPin::new(String::from_utf8_lossy(pin).into_owned().into())
}

/// Generates a non-extractable HMAC (generic-secret) key on the
/// already-logged-in `session`, labeled `label`.
fn generate_hmac_key_on_session(session: &Session, label: &str) -> Result<(), HwKeyError> {
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::ValueLen(32u64.into()),
    ];
    session.generate_key(&Mechanism::GenericSecretKeyGen, &template)?;
    Ok(())
}

/// Computes `HMAC-SHA256(token_key, challenge)` on the already-logged-in
/// `session`, using the key labeled `label`.
fn challenge_response_on_session(
    session: &Session,
    label: &str,
    challenge: &[u8],
) -> Result<[u8; 32], HwKeyError> {
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let handle: ObjectHandle = session
        .find_objects(&template)?
        .into_iter()
        .next()
        .ok_or_else(|| HwKeyError::KeyNotFound(label.to_string()))?;

    let signature = session.sign(&Mechanism::Sha256Hmac, handle, challenge)?;
    let output: [u8; 32] = signature
        .clone()
        .try_into()
        .map_err(|_| HwKeyError::UnexpectedSignatureLength(signature.len()))?;
    Ok(output)
}

/// Generates a non-extractable HMAC (generic-secret) key on the first
/// available PKCS#11 token, labeled `label`.
///
/// Idempotency is NOT handled here — calling this twice with the same
/// label creates two distinct key objects. A later increment's
/// concern, once real key-lifecycle UX exists (this increment is
/// backend plumbing only).
///
/// # Errors
///
/// Returns [`HwKeyError`] if the PKCS#11 module cannot be loaded, no
/// token is present, the PIN is rejected, or key generation fails.
pub fn generate_hmac_key(module_path: &Path, pin: &[u8], label: &str) -> Result<(), HwKeyError> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // Run the actual work in a nested scope so the `Session` (and its
    // automatic logout/close on drop) is gone before we finalize the
    // module below — PKCS#11 modules such as SoftHSM2 keep their
    // C_Initialize state keyed to the process, not to this particular
    // `Pkcs11` handle, so a later call to `generate_hmac_key` or
    // `challenge_response` in the SAME process would otherwise fail
    // with `CryptokiAlreadyInitialized`.
    let outcome = (|| -> Result<(), HwKeyError> {
        let slot = first_token_slot(&pkcs11)?;
        let session = pkcs11.open_rw_session(slot)?;
        let auth_pin = auth_pin_from_bytes(pin);
        session.login(UserType::User, Some(&auth_pin))?;
        generate_hmac_key_on_session(&session, label)
    })();

    let finalize_result = pkcs11.finalize().map_err(HwKeyError::from);
    outcome.and(finalize_result)
}

/// Computes `HMAC-SHA256(token_key, challenge)` using the token-held
/// key labeled `label`, returning the 32-byte output.
///
/// # Errors
///
/// Returns [`HwKeyError`] if the PKCS#11 module cannot be loaded, no
/// token is present, the PIN is rejected, the labeled key cannot be
/// found, or the sign operation fails.
pub fn challenge_response(
    module_path: &Path,
    pin: &[u8],
    label: &str,
    challenge: &[u8],
) -> Result<[u8; 32], HwKeyError> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // See the matching comment in `generate_hmac_key`: the session must
    // be dropped before this module is finalized below.
    let outcome = (|| -> Result<[u8; 32], HwKeyError> {
        let slot = first_token_slot(&pkcs11)?;
        let session = pkcs11.open_ro_session(slot)?;
        let auth_pin = auth_pin_from_bytes(pin);
        session.login(UserType::User, Some(&auth_pin))?;
        challenge_response_on_session(&session, label, challenge)
    })();

    match (outcome, pkcs11.finalize().map_err(HwKeyError::from)) {
        (Ok(response), Ok(())) => Ok(response),
        (Ok(_), Err(finalize_err)) => Err(finalize_err),
        (Err(outcome_err), _) => Err(outcome_err),
    }
}
