//! Media metadata sterilizer tests (TODO A.3).
//!
//! Hermetic: no network, no filesystem writes. Tests return `Result` and
//! honor the workspace lints (no panic!/unwrap/expect, no bare arithmetic,
//! no slice indexing).

use image::ImageEncoder;
use umbra_protocol::ProtocolError;
use umbra_protocol::media::{MAX_DIMENSION_PX, sterilize};

/// Builds a raw 8x8-style RGBA test image of `size x size` pixels.
fn test_pixels(size: u32) -> Vec<u8> {
    let count = (size as usize)
        .checked_mul(size as usize)
        .and_then(|px| px.checked_mul(4))
        .unwrap_or(0);
    (0..count).map(|i| (i % 251) as u8).collect()
}

/// Encodes raw RGBA8 pixels as a PNG via the `image` crate.
fn encode_png(pixels: &[u8], width: u32, height: u32) -> Result<Vec<u8>, image::ImageError> {
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out).write_image(
        pixels,
        width,
        height,
        image::ExtendedColorType::Rgba8,
    )?;
    Ok(out)
}

/// Reads a big-endian `u32` at `offset` without indexing.
fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    let quad: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_be_bytes(quad))
}

/// Lists the PNG chunk types present in an encoded PNG.
fn png_chunks(bytes: &[u8]) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cursor = 8usize; // skip the PNG signature
    while let Some(len) = read_u32_be(bytes, cursor) {
        let start = match cursor.checked_add(4) {
            Some(start) => start,
            None => break,
        };
        let end = match cursor.checked_add(8) {
            Some(end) => end,
            None => break,
        };
        let kind = bytes
            .get(start..end)
            .map(|slice| String::from_utf8_lossy(slice).to_string());
        match kind {
            Some(name) => chunks.push(name),
            None => break,
        }
        match cursor
            .checked_add(12)
            .and_then(|next| next.checked_add(len as usize))
        {
            Some(next) => cursor = next,
            None => break,
        }
    }
    chunks
}

/// Writes a PNG that carries ancillary metadata chunks (tEXt — the same
/// class of payload as EXIF/GPS/XMP).
fn png_with_metadata(
    pixels: &[u8],
    width: u32,
    height: u32,
) -> Result<Vec<u8>, png::EncodingError> {
    let mut buffer = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut buffer, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.add_text_chunk("Comment".to_string(), "GPS: 41.0082,28.9784".to_string())?;
        let mut writer = encoder.write_header()?;
        writer.write_image_data(pixels)?;
    } // the writer finalizes the chunk stream on drop
    Ok(buffer)
}

/// Sterilized output contains only mandatory PNG chunks.
#[test]
fn output_has_no_metadata_chunks() -> Result<(), Box<dyn std::error::Error>> {
    let dirty = png_with_metadata(&test_pixels(8), 8, 8)?;
    let clean = sterilize(&dirty)?;
    let chunks = png_chunks(&clean);
    assert!(chunks.contains(&"IHDR".to_string()));
    assert!(chunks.contains(&"IDAT".to_string()));
    assert!(chunks.contains(&"IEND".to_string()));
    for forbidden in [
        "tEXt", "iTXt", "zTXt", "eXIf", "iCCP", "gAMA", "cHRM", "sRGB", "sBIT", "pHYs", "tIME",
    ] {
        assert!(
            !chunks.contains(&forbidden.to_string()),
            "found {forbidden}"
        );
    }
    Ok(())
}

/// Sterilization is deterministic: identical pixels -> identical bytes.
#[test]
fn sterilize_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let dirty = png_with_metadata(&test_pixels(16), 16, 16)?;
    let first = sterilize(&dirty)?;
    let second = sterilize(&dirty)?;
    assert_eq!(first, second);
    Ok(())
}

/// Pixel content survives sterilization.
#[test]
fn pixels_survive() -> Result<(), Box<dyn std::error::Error>> {
    let pixels = test_pixels(8);
    let dirty = png_with_metadata(&pixels, 8, 8)?;
    let clean = sterilize(&dirty)?;
    let decoded = image::load_from_memory(&clean)?;
    assert_eq!(decoded.to_rgba8().as_raw(), &pixels);
    Ok(())
}

/// A clean image round-trips through sterilization unchanged in content.
#[test]
fn clean_input_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let pixels = test_pixels(8);
    let clean_input = encode_png(&pixels, 8, 8)?;
    let output = sterilize(&clean_input)?;
    let decoded = image::load_from_memory(&output)?;
    assert_eq!(decoded.to_rgba8().as_raw(), &pixels);
    Ok(())
}

/// Inputs exceeding the dimension limit are rejected (decompression-bomb
/// defense): width overflow...
#[test]
fn oversized_width_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let wide = MAX_DIMENSION_PX
        .checked_add(1)
        .and_then(|next| next.checked_mul(2))
        .ok_or("overflow building the oversized test image")?;
    let pixels = vec![0u8; (wide as usize).checked_mul(8).unwrap_or(0)];
    let bomb = encode_png(&pixels, wide, 2)?;
    assert!(matches!(
        sterilize(&bomb),
        Err(ProtocolError::MediaTooLarge)
    ));
    Ok(())
}

/// ...and height overflow.
#[test]
fn oversized_height_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let tall = MAX_DIMENSION_PX
        .checked_add(1)
        .and_then(|next| next.checked_mul(2))
        .ok_or("overflow building the oversized test image")?;
    let pixels = vec![0u8; (tall as usize).checked_mul(8).unwrap_or(0)];
    let bomb = encode_png(&pixels, 2, tall)?;
    assert!(matches!(
        sterilize(&bomb),
        Err(ProtocolError::MediaTooLarge)
    ));
    Ok(())
}

/// Inputs exceeding the encoded-size cap are rejected before parsing.
#[test]
fn oversized_input_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let oversized = vec![0u8; umbra_protocol::media::MAX_INPUT_BYTES.saturating_add(1)];
    assert!(matches!(
        sterilize(&oversized),
        Err(ProtocolError::MediaTooLarge)
    ));
    Ok(())
}

/// Non-image input is rejected with `InvalidMedia`.
#[test]
fn garbage_rejected() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        sterilize(b"this is not an image"),
        Err(ProtocolError::InvalidMedia)
    ));
    Ok(())
}
