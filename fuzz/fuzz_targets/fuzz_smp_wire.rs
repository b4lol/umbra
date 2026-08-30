//! Fuzz target: SMP wire parsers (CODE_MANIFESTO §8).
//!
//! All four `from_bytes` entry points must reject hostile bytes with
//! typed errors — never panic, never allocate unboundedly (MPI cap 200 B,
//! fixed counts).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = umbra_protocol::smp::SmpMsg1::from_bytes(data);
    let _ = umbra_protocol::smp::SmpMsg2::from_bytes(data);
    let _ = umbra_protocol::smp::SmpMsg3::from_bytes(data);
    let _ = umbra_protocol::smp::SmpMsg4::from_bytes(data);
});
