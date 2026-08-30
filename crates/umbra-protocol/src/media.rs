//! Deterministic media metadata sterilizer (TODO A.3, ARCHITECTURE
//! "Deterministic Media Metadata Sanitizer", ADR-027 MVP scope).
//!
//! Strategy — **full pixel re-encode**: the input is decoded under hard
//! limits, reduced to raw RGBA8 pixels, and re-encoded as a fresh PNG
//! assembled only from the mandatory chunks (`IHDR`, `IDAT`, `IEND`). By
//! construction the output cannot carry EXIF/GPS/ICC/XMP or any other
//! ancillary metadata (README "Media metadata sterilizer"; TODO A.3
//! "EXIF, GPS, color-profile stripping and pixel re-encoding").
//!
//! Determinism: identical pixels yield identical output bytes — no
//! timestamps, no parallel scheduling in the encoder path.
//!
//! Decompression-bomb defense: the v2 Out-of-Process Media Sanitizer
//! (TARGETED_DEFENSES §1A) is not available in the MVP, so decoding runs
//! in-process behind strict dimension/allocation caps ([`MAX_DIMENSION_PX`],
//! [`MAX_PIXELS`], [`MAX_INPUT_BYTES`]). Scope notes:
//!
//! - `max_alloc` bounds the **destination** pixel buffer; decoder-internal
//!   scratch (GIF/WebP frame buffers, deflate windows, the `to_rgba8` copy)
//!   is not tracked by `image`'s non-strict contract, so the transient peak
//!   is roughly 4-5x the stated budget. An allocator-level peak cap and the
//!   subprocess isolation are tracked in TODO B (v2).
//! - Codecs are Safe Rust, but some decoders assert on hostile inputs
//!   (process abort, not memory corruption). The `fuzz_media_sterilizer`
//!   libFuzzer target hunts these continuously.
//!
//! Transport boundary: the sterilized PNG generally exceeds one packet's
//! 990-byte payload; MEDIA_CHUNK chunking is NOT wired yet (TODO A.3).

use std::io::Cursor;

use image::{ExtendedColorType, ImageEncoder, ImageReader, Limits, codecs::png::PngEncoder};

use crate::error::ProtocolError;

/// Hard cap on a single image dimension, in pixels.
pub const MAX_DIMENSION_PX: u32 = 2048;

/// Total pixel budget (`2048 x 2048 = 4 Mi px`, i.e. 16 MiB of RGBA8 in
/// memory at most).
pub const MAX_PIXELS: u64 = MAX_DIMENSION_PX as u64 * MAX_DIMENSION_PX as u64;

/// Hard cap on the encoded input size.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Sterilizes an encoded image: decode -> raw RGBA8 -> fresh metadata-free
/// PNG.
///
/// # Errors
///
/// Returns [`ProtocolError::MediaTooLarge`] when the input or the decoded
/// dimensions exceed the sterilizer limits, and
/// [`ProtocolError::InvalidMedia`] when the input cannot be decoded or the
/// re-encode fails.
pub fn sterilize(input: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ProtocolError::MediaTooLarge);
    }

    let mut reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|_e| ProtocolError::InvalidMedia)?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION_PX);
    limits.max_image_height = Some(MAX_DIMENSION_PX);
    limits.max_alloc = Some(MAX_PIXELS * 4);
    reader.limits(limits);
    let decoded = reader.decode().map_err(|err| match err {
        image::ImageError::Limits(_e) => ProtocolError::MediaTooLarge,
        _other => ProtocolError::InvalidMedia,
    })?;

    // The pixel matrix is the ONLY thing carried forward.
    let rgba = decoded.to_rgba8();
    let (width, height) = (rgba.width(), rgba.height());

    // RGBA8 size for the pixel budget above is bounded by MAX_PIXELS * 4;
    // the checked chain is defensive and cannot realistically fail.
    let output_capacity = (width as u64)
        .checked_mul(height as u64)
        .and_then(|pixels| pixels.checked_mul(4))
        .and_then(|bytes| bytes.checked_add(1024))
        .unwrap_or(0);
    let mut output = Vec::with_capacity(usize::try_from(output_capacity).unwrap_or(0));
    PngEncoder::new(&mut output)
        .write_image(rgba.as_raw(), width, height, ExtendedColorType::Rgba8)
        .map_err(|_e| ProtocolError::InvalidMedia)?;
    Ok(output)
}
