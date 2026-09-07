//! Fuzz target: the media metadata sterilizer (CODE_MANIFESTO §8 — every
//! parser of attacker-controlled input must be fuzzed).
//!
//! Any input must be safely rejected (`MediaTooLarge`/`InvalidMedia`) or
//! produce a metadata-free PNG; a panic here is a sterilizer bug.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = umbra_protocol::media::sterilize(data);
});
