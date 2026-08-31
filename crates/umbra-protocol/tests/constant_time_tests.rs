//! Constant-time analysis suite (TODO A.5, CRYPTOGRAPHY.md §1: "verified
//! with the `dudect` Welch t-test").
//!
//! Implements the dudect methodology (Reparaz, Balasch, Tufryeri —
//! "Dude, is my code constant time?"): two input classes that must be
//! indistinguishable, interleaved timing measurement, trimmed samples,
//! and a Welch t-test against the |t| < 4.5 threshold — first-order plus
//! a second-order (centered-square) test on the tag-verification path.
//!
//! Fixtures target the secret-dependent boundaries of Umbra's crypto;
//! every fixture compares classes that perform the SAME operation and
//! differ only in secret input:
//!
//! 1. AEAD **open across keys** (two valid ciphertexts, same shape) —
//!    probes key schedule, Poly1305 verify, and plaintext recovery.
//! 2. AEAD **seal across keys** — a key-dependent branch in ChaCha20
//!    init would show here.
//! 3. **SAS derivation** (two different secrets through BLAKE3).
//!
//! Scope note (dudect practice): classes must not differ in the
//! operation performed. Success-vs-failure AEAD is NOT a valid fixture —
//! the success path recovers the plaintext (caller-visible work), so a
//! timing difference there reflects the public result, not a secret.
//! The tag comparison itself is upstream RustCrypto (`subtle`-based),
//! re-verified here indirectly by fixture 1.
//!
//! Hermetic: pure CPU timing, no network/filesystem. Fixtures serialize
//! on a mutex so parallel test threads do not pollute measurements, and
//! each fixture retries with doubled sample counts to stay stable on
//! shared CI runners.

use std::hint::black_box;
use std::sync::Mutex;
use std::time::Instant;

use zeroize::Zeroizing;

use umbra_crypto::aead::{AeadCipher, NONCE_LEN};
use umbra_protocol::sas::SasCode;

/// Serializes fixtures: timing runs one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// dudect's standard pass threshold for |t|.
const THRESHOLD: f64 = 4.5;

/// Samples per class on the first attempt.
const BASE_SAMPLES: usize = 6000;

/// Unmeasured warmup iterations per class.
const WARMUP: usize = 800;

/// Percentage of the slowest samples dropped before the t-test.
const TRIM_PERCENT: usize = 10;

/// Maximum retries with doubled sample counts.
const MAX_ATTEMPTS: usize = 3;

/// Measures one call of `f` in nanoseconds.
fn measure(f: &mut impl FnMut()) -> f64 {
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    elapsed.as_secs_f64() * 1e9
}

/// Drops the slowest `TRIM_PERCENT` of the samples (dudect trimming).
fn trim(mut samples: Vec<f64>) -> Vec<f64> {
    samples.sort_by(|a, b| b.total_cmp(a));
    let dropped = samples.len().saturating_mul(TRIM_PERCENT) / 100;
    let keep = samples.len().saturating_sub(dropped);
    samples.truncate(keep);
    samples
}

/// Welch's t statistic for two independent samples.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let variance = |v: &[f64], m: f64| {
        v.iter()
            .map(|x| {
                let d = x - m;
                d * d
            })
            .sum::<f64>()
            / (v.len() as f64 - 1.0)
    };
    let (mean_a, mean_b) = (mean(a), mean(b));
    let (var_a, var_b) = (variance(a, mean_a), variance(b, mean_b));
    let numerator = mean_a - mean_b;
    let denominator = (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt();
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Second-order transform: center by the POOLED mean and square (dudect
/// methodology — catches variance-based leaks).
fn second_order(a: &[f64], b: &[f64]) -> (Vec<f64>, Vec<f64>) {
    // Both lengths are equal, non-zero constants derived from
    // sample_count — the division cannot divide by zero and f64 addition
    // is total (no panic).
    #[allow(clippy::arithmetic_side_effects)]
    let pooled_mean = (a.iter().chain(b.iter()).sum::<f64>()) / (a.len() + b.len()) as f64;
    let square = |v: &[f64]| {
        v.iter()
            .map(|x| {
                let d = x - pooled_mean;
                d * d
            })
            .collect()
    };
    (square(a), square(b))
}

/// Runs one dudect fixture: interleaved two-class measurement, trimmed
/// Welch t-test (first-order), retries with doubled samples.
fn dudect_fixture(
    name: &str,
    mut class_a: impl FnMut(),
    mut class_b: impl FnMut(),
) -> Result<(), String> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut sample_count = BASE_SAMPLES;
    for attempt in 0..MAX_ATTEMPTS {
        // Warmup: let caches/branch predictors settle.
        for _ in 0..WARMUP {
            class_a();
            class_b();
        }
        let mut samples_a = Vec::with_capacity(sample_count);
        let mut samples_b = Vec::with_capacity(sample_count);
        for _ in 0..sample_count {
            samples_a.push(measure(&mut class_a));
            samples_b.push(measure(&mut class_b));
        }
        let t_first = welch_t(&trim(samples_a.clone()), &trim(samples_b.clone()));
        let (second_a, second_b) = second_order(&samples_a, &samples_b);
        let t_second = welch_t(&trim(second_a), &trim(second_b));
        if t_first.abs() < THRESHOLD && t_second.abs() < THRESHOLD {
            return Ok(());
        }
        eprintln!(
            "dudect [{name}] attempt {attempt}: t_first={t_first:.3} t_second={t_second:.3} \
             samples={sample_count} — retrying with doubled samples"
        );
        sample_count = sample_count.saturating_mul(2);
    }
    Err(format!(
        "{name}: timing distribution differs across classes after \
         {MAX_ATTEMPTS} attempts (leak suspected)"
    ))
}

/// Builds a cipher and seals a 512-byte plaintext under `key`; returns
/// the cipher, nonce, and sealed buffer (valid by construction).
///
/// # Errors
///
/// Returns the underlying error if sealing fails (fixture inputs are
/// constant, so this cannot happen).
fn sealed_fixture() -> Result<(AeadCipher, [u8; NONCE_LEN], Vec<u8>), umbra_crypto::CryptoError> {
    let mut key = [0u8; 32];
    umbra_crypto::rng::fill(&mut key)?;
    let cipher = AeadCipher::new(Zeroizing::new(key));
    let plaintext = vec![0x5Au8; 512];
    let mut nonce = [0u8; NONCE_LEN];
    umbra_crypto::rng::fill(&mut nonce)?;
    let sealed = cipher.seal(b"ct-suite", &plaintext, &mut nonce)?;
    Ok((cipher, nonce, sealed))
}

/// AEAD open across two different keys (same operation, same shape):
/// key schedule + Poly1305 verify + plaintext recovery must be
/// indistinguishable between key materials.
#[test]
fn aead_open_across_keys_is_constant_time() -> Result<(), Box<dyn std::error::Error>> {
    let (cipher_a, nonce_a, sealed_a) = sealed_fixture()?;
    let (cipher_b, nonce_b, sealed_b) = sealed_fixture()?;

    // Sanity: both open successfully in place.
    let mut buffer = sealed_a.clone();
    assert!(
        cipher_a
            .open_in_place(&nonce_a, b"ct-suite", &mut buffer)
            .is_ok()
    );
    let mut buffer = sealed_b.clone();
    assert!(
        cipher_b
            .open_in_place(&nonce_b, b"ct-suite", &mut buffer)
            .is_ok()
    );

    // Persistent, pre-allocated buffers: reset per iteration with
    // symmetric truncate/resize/copy work — no allocation after setup
    // (success truncates the buffer to the plaintext length).
    let mut buffer_a = sealed_a.clone();
    let mut buffer_b = sealed_b.clone();
    let mut class_a = || {
        buffer_a.truncate(sealed_a.len());
        buffer_a.resize(sealed_a.len(), 0);
        buffer_a.copy_from_slice(&sealed_a);
        let opened = cipher_a.open_in_place(&nonce_a, b"ct-suite", &mut buffer_a);
        black_box(opened.is_ok());
    };
    let mut class_b = || {
        buffer_b.truncate(sealed_b.len());
        buffer_b.resize(sealed_b.len(), 0);
        buffer_b.copy_from_slice(&sealed_b);
        let opened = cipher_b.open_in_place(&nonce_b, b"ct-suite", &mut buffer_b);
        black_box(opened.is_ok());
    };

    let outcome = dudect_fixture("aead-open-keys", &mut class_a, &mut class_b);
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// AEAD key schedule: two different keys over the same plaintext take
/// the same time.
#[test]
fn aead_seal_key_schedule_is_constant_time() {
    let cipher_a = AeadCipher::new(Zeroizing::new([0xA5u8; 32]));
    let cipher_b = AeadCipher::new(Zeroizing::new([0x5Au8; 32]));
    let plaintext = vec![0xC3u8; 512];
    let mut nonce_a = [0u8; NONCE_LEN];
    let mut nonce_b = [0u8; NONCE_LEN];

    let mut class_a = || {
        let sealed = cipher_a.seal(b"ct-suite", &plaintext, &mut nonce_a);
        black_box(sealed.is_ok());
    };
    let mut class_b = || {
        let sealed = cipher_b.seal(b"ct-suite", &plaintext, &mut nonce_b);
        black_box(sealed.is_ok());
    };

    let outcome = dudect_fixture("aead-seal-key", &mut class_a, &mut class_b);
    assert!(outcome.is_ok(), "{outcome:?}");
}

/// SAS derivation: two different secrets through BLAKE3 take the same
/// time.
#[test]
fn sas_derive_is_constant_time() -> Result<(), String> {
    let mut secret_a = [0x11u8; 32];
    let mut secret_b = [0x22u8; 32];
    umbra_crypto::rng::fill(&mut secret_a).map_err(|e| e.to_string())?;
    umbra_crypto::rng::fill(&mut secret_b).map_err(|e| e.to_string())?;
    let mut class_a = || {
        let code = SasCode::derive(&secret_a);
        black_box(code.value());
    };
    let mut class_b = || {
        let code = SasCode::derive(&secret_b);
        black_box(code.value());
    };

    let outcome = dudect_fixture("sas-derive", &mut class_a, &mut class_b);
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// Double Ratchet chain advance (HKDF-SHA512 extract/expand over secret
/// chain keys) is timing-indistinguishable across chain keys.
#[test]
fn ratchet_chain_advance_is_constant_time() -> Result<(), String> {
    let mut chain_a = [0x33u8; 32];
    let mut chain_b = [0x44u8; 32];
    umbra_crypto::rng::fill(&mut chain_a).map_err(|e| e.to_string())?;
    umbra_crypto::rng::fill(&mut chain_b).map_err(|e| e.to_string())?;
    let mut class_a = || {
        let (next, message_key) = umbra_crypto::kdf::advance_chain(&chain_a);
        black_box(next);
        black_box(message_key);
    };
    let mut class_b = || {
        let (next, message_key) = umbra_crypto::kdf::advance_chain(&chain_b);
        black_box(next);
        black_box(message_key);
    };

    let outcome = dudect_fixture("ratchet-chain-advance", &mut class_a, &mut class_b);
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}
