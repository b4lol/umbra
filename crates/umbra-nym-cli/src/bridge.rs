//! Bridges Umbra's stream-based PQXDH messenger functions onto Nym's
//! single-message transport (TODO B.1 — Decision 2: no
//! stream-sequencing layer, one Nym message per direction).
//!
//! `send_text_stream` takes `S: AsyncWrite` ONLY; `receive_message`
//! takes `S: AsyncRead` ONLY — there is no bidirectional exchange over
//! one logical stream. Umbra's PQXDH design lets a sender complete and
//! transmit a full encrypted message using only the recipient's
//! asynchronously-known prekey bundle, with no live round trip
//! required, so `send_via_nym` is genuinely fire-and-forget: it drives
//! the sender side of the messenger over an in-memory
//! `tokio::io::duplex`, collects every byte the messenger wrote, and
//! hands that as exactly one Nym message to the transport.
//! `receive_via_nym` mirrors this on the other end: it waits for one
//! Nym message, feeds it into a fresh duplex, and drives the receiver
//! side of the messenger over it.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use umbra_crypto::keys::IdentityBundle;
use umbra_net::messenger::{receive_message, send_text_stream};
use umbra_net::{PeerPqxdhKeys, TransportError};

use crate::addr::NymPeerAddr;
use crate::transport::NymTransport;

/// Size of the in-memory duplex buffer bridging the messenger's stream
/// API to Nym's single-message API.
///
/// `send_via_nym` writes the ENTIRE stream produced by
/// `send_text_stream` into one end of the duplex before ever reading
/// from the other end (the read only starts after `shutdown`). If the
/// total bytes written exceeded the buffer size, that write would block
/// forever on a reader that isn't polling yet. So this must cover the
/// true worst case for a single call, not just a typical one:
///
/// - Handshake blob: `HANDSHAKE_BLOB_LEN` = 1152 B (`umbra_crypto::pqxdh`).
/// - Data frames: a plaintext at the messenger's own reassembly ceiling
///   (`MAX_TEXT_MESSAGE` = 64 KiB = 65,536 B, `umbra_net::messenger`) is
///   split into `CHUNK` = `MAX_PLAINTEXT` - 1 = 925 B pieces
///   (`umbra_crypto::ratchet::MAX_PLAINTEXT` = 926), i.e.
///   `ceil(65_536 / 925)` = 71 data frames, each one `PACKET_LEN` = 1024 B
///   (`umbra_protocol::types::PACKET_LEN`): 71 * 1024 = 72,704 B. (A
///   plaintext beyond `MAX_TEXT_MESSAGE` would be rejected by
///   `receive_message` on the far end anyway, so this is the bridge's
///   practical worst case, not an arbitrary bound.)
/// - Cover frames: up to `MAX_COVER_PER_SEND` = 64 frames total across
///   the whole burst (`umbra_net::messenger`), each `PACKET_LEN` = 1024 B:
///   64 * 1024 = 65,536 B.
/// - Termination frame: one more `PACKET_LEN` = 1024 B.
///
/// Worst case total: 1152 + 72,704 + 65,536 + 1024 = 140,416 B. 256 KiB
/// (262,144 B) is used here for round-number headroom (~1.87x) above
/// that figure.
const DUPLEX_BUF: usize = 256 * 1024;

/// Runs the PQXDH handshake + single-message send over an in-memory
/// duplex, then forwards the accumulated bytes as exactly one Nym
/// message to `to`.
///
/// # Errors
///
/// Returns [`TransportError`] on handshake failure or Nym send
/// failure.
pub async fn send_via_nym<T: NymTransport>(
    transport: &T,
    to: NymPeerAddr,
    peer: &PeerPqxdhKeys,
    plaintext: &[u8],
) -> Result<(), TransportError> {
    let (mut writer, mut reader) = tokio::io::duplex(DUPLEX_BUF);
    send_text_stream(&mut writer, peer, plaintext)
        .await
        .map(|_frames| ())?;
    writer
        .shutdown()
        .await
        .map_err(|e| TransportError::Nym(format!("duplex shutdown: {e}")))?;
    let mut framed = Vec::new();
    reader
        .read_to_end(&mut framed)
        .await
        .map_err(|e| TransportError::Nym(format!("duplex read: {e}")))?;
    transport.send(to, framed).await
}

/// Waits for exactly one Nym message from `transport`, then runs it
/// through `receive_message` over an in-memory duplex.
///
/// # Errors
///
/// Returns [`TransportError`] on Nym receive failure or handshake
/// processing failure.
pub async fn receive_via_nym<T: NymTransport>(
    transport: &mut T,
    identity: IdentityBundle,
) -> Result<Vec<u8>, TransportError> {
    let framed = transport.recv().await?;
    let (mut writer, mut reader) = tokio::io::duplex(DUPLEX_BUF);
    writer
        .write_all(&framed)
        .await
        .map_err(|e| TransportError::Nym(format!("duplex write: {e}")))?;
    writer
        .shutdown()
        .await
        .map_err(|e| TransportError::Nym(format!("duplex shutdown: {e}")))?;
    receive_message(identity, &mut reader).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FakeNymTransport;

    /// Builds a real `IdentityBundle` plus the `PeerPqxdhKeys` public
    /// view of it, exactly as `umbra-net`'s own
    /// `crates/umbra-net/tests/messenger.rs` fixture does, using only
    /// non-test-gated constructors (`IdentityBundle::generate` and
    /// `PeerPqxdhKeys::from_parts`).
    fn identity_and_peer_keys(
    ) -> Result<(IdentityBundle, PeerPqxdhKeys), Box<dyn std::error::Error + Send + Sync>> {
        let bundle = IdentityBundle::generate();
        let keys = PeerPqxdhKeys::from_parts(
            &bundle.x25519.public_bytes(),
            &bundle.spk.public_bytes(),
            bundle.spk_signature.clone(),
            bundle.dsa.public_bytes(),
            &bundle.kem.public_bytes(),
        )?;
        Ok((bundle, keys))
    }

    #[tokio::test]
    async fn round_trips_a_pqxdh_message_through_two_fakes(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = NymPeerAddr::parse(crate::addr::tests_support::SAMPLE_VALID_ADDRESS)?;
        let (b_identity, b_peer_keys) = identity_and_peer_keys()?;

        let transport_a = FakeNymTransport::new(addr.clone());
        let mut transport_b = FakeNymTransport::new(addr.clone());

        let plaintext = b"meet at midnight";
        send_via_nym(&transport_a, addr, &b_peer_keys, plaintext).await?;

        // The fake doesn't auto-route: pull what A "sent" and manually
        // deliver it into B's inbox.
        let sent = transport_a
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .ok_or("nothing was sent")?;
        transport_b.inbox.push_back(sent.1);

        let received = receive_via_nym(&mut transport_b, b_identity).await?;
        assert_eq!(received, plaintext.to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn receive_via_nym_surfaces_transport_errors(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = NymPeerAddr::parse(crate::addr::tests_support::SAMPLE_VALID_ADDRESS)?;
        let mut transport = FakeNymTransport::new(addr);
        let (identity, _peer_keys) = identity_and_peer_keys()?;
        assert!(receive_via_nym(&mut transport, identity).await.is_err());
        Ok(())
    }
}
