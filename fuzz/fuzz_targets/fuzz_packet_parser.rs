//! Fuzz target: the 1024-byte packet parser (CONTRIBUTING §6,
//! `fuzz_packet_parser`).
//!
//! Any input slice must be safely rejected or parsed; a panic here is a
//! parser bug (CODE_MANIFESTO §9).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = umbra_protocol::packet::SealedPacket::from_bytes(data);
});
