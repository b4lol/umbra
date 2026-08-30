//! Fuzz target: the MEDIA_CHUNK reassembler (CODE_MANIFESTO §8).
//!
//! An adversarial peer can send arbitrary post-AEAD payloads; `push` and
//! `finish` must reject them with typed errors — never panic, never
//! allocate unboundedly (MAX_CHUNKS cap).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use umbra_protocol::media_chunk::MediaAssembler;
    let mut assembler = MediaAssembler::new();
    // Feed the input as a sequence of length-delimited payloads.
    let mut cursor = 0usize;
    while cursor < data.len() {
        let Some(len_byte) = data.get(cursor) else {
            break;
        };
        let len = (*len_byte as usize).saturating_mul(4); // up to 1020 bytes
        cursor = cursor.saturating_add(1);
        let Some(end) = cursor.checked_add(len) else {
            break;
        };
        let Some(payload) = data.get(cursor..end) else {
            break;
        };
        cursor = end;
        let _ = assembler.push(payload);
    }
    let _ = assembler.finish();
});
