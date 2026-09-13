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
//!
//! See ADR-034 in `docs/DECISIONS.md` for this crate's own ADR-011
//! scoped deviation (loading a third-party PKCS#11 module).
//!
//! # Concurrency
//!
//! `C_Initialize`/`C_Finalize` are process-global PKCS#11 state, and
//! this crate's own explicit `finalize()` calls are the only thing
//! tearing that state down (`cryptoki` 0.12.0 has no `Drop` impl for
//! `Pkcs11`). [`generate_hmac_key`] and [`challenge_response`] both
//! serialize on a single process-wide mutex ([`PKCS11_LOCK`]) for their
//! entire call, so calling them from multiple threads is safe, but
//! concurrent calls block on each other rather than running in
//! parallel.

mod error;
pub use error::HwKeyError;

use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// Guards this crate's PKCS#11 operations: `C_Initialize`/`C_Finalize`
/// are process-global state (`cryptoki` 0.12.0 has no `Drop` impl for
/// `Pkcs11` — nothing tears this down except this crate's own explicit
/// `finalize()` calls), so two concurrent calls into this crate from
/// different threads could otherwise race: one thread's `finalize()`
/// tearing down the module while another is still mid-operation. This
/// mutex is held for an ENTIRE call to [`generate_hmac_key`] or
/// [`challenge_response`], from `Pkcs11::new` through `finalize()` —
/// serializing this crate's PKCS#11 usage process-wide is the
/// deliberately simple, provably-correct choice; a future increment
/// wiring this into a multithreaded consumer (`umbra-gui`'s GTK main
/// loop plus a worker thread for any blocking token operation) MUST
/// NOT bypass this lock by calling into `cryptoki` directly.
static PKCS11_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquires [`PKCS11_LOCK`], recovering from poisoning rather than
/// propagating a panic: this lock only guards call-ordering (nothing
/// enters an inconsistent SHARED state if a prior call panicked while
/// holding it — each call's own `Pkcs11`/`Session` are entirely local),
/// so one panicking caller must not permanently block every later
/// caller from using this crate.
fn lock_pkcs11() -> std::sync::MutexGuard<'static, ()> {
    match PKCS11_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

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
    let length = signature.len();
    let signature = zeroize::Zeroizing::new(signature);
    let output: [u8; 32] = signature
        .as_slice()
        .try_into()
        .map_err(|_| HwKeyError::UnexpectedSignatureLength(length))?;
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
///
/// # Concurrency
///
/// Serializes with every other call into this crate via a process-wide
/// lock — safe to call from multiple threads, but concurrent calls
/// block on each other rather than running in parallel (see
/// [`PKCS11_LOCK`]).
pub fn generate_hmac_key(module_path: &Path, pin: &[u8], label: &str) -> Result<(), HwKeyError> {
    let _guard = lock_pkcs11();
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
///
/// # Concurrency
///
/// Serializes with every other call into this crate via a process-wide
/// lock — safe to call from multiple threads, but concurrent calls
/// block on each other rather than running in parallel (see
/// [`PKCS11_LOCK`]).
pub fn challenge_response(
    module_path: &Path,
    pin: &[u8],
    label: &str,
    challenge: &[u8],
) -> Result<[u8; 32], HwKeyError> {
    let _guard = lock_pkcs11();
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
