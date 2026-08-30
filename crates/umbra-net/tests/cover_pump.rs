//! Cover-traffic pump tests (TODO A.3, ADR-005).
//!
//! Hermetic: the pump runs against a LoopbackPair with an accelerated
//! scheduler; no network. Fixture builders return `Result` — no
//! panic!/unwrap anywhere (CODE_MANIFESTO §1).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;
use umbra_net::cover::{CoverPump, expected_ticks};
use umbra_net::transport::{LoopbackPair, Transport};
use umbra_net::{OnionAddr, TransportError};
use umbra_protocol::packet::{self, SealedPacket};
use umbra_protocol::types::PacketType;
use zeroize::Zeroizing;

/// Fixture onion address (valid 56-char base32).
fn peer() -> Result<OnionAddr, TransportError> {
    OnionAddr::parse("5vzwalpq2cyjrhm5lvzhcjn6mbnwbv42xakxiqhunwpgz6hr32f7gxad")
}

/// Builds one sealed DUMMY_COVER packet under a test key.
fn cover_packet(index: u32) -> Result<SealedPacket, umbra_protocol::ProtocolError> {
    packet::seal(
        PacketType::DummyCover,
        Zeroizing::new([5u8; 32]),
        &index.to_be_bytes(),
    )
}

/// The pump delivers cover packets on a Poisson schedule to the peer.
#[tokio::test]
async fn pump_delivers_cover_packets() -> Result<(), Box<dyn std::error::Error>> {
    let pair = LoopbackPair::new();
    let transport = Arc::new(pair.a);
    let received: Arc<Mutex<Vec<SealedPacket>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);

    // Drain loop on the receiving endpoint.
    tokio::spawn(async move {
        loop {
            if let Ok(packet) = pair.b.recv().await {
                sink.lock().await.push(packet);
            }
        }
    });

    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = Arc::clone(&counter);
    let scheduler = umbra_protocol::cover::PoissonScheduler::new(2000.0)?;
    let pump = CoverPump::spawn(Arc::clone(&transport), peer()?, scheduler, move || {
        let index = counter_clone.fetch_add(1, Ordering::Relaxed);
        async move { Ok(Some(cover_packet(index).map_err(TransportError::from)?)) }
    });

    // At 1000 Hz, 300 ms yields ~300 expected ticks; asserting on >= 1
    // keeps the hermetic test robust on loaded CI runners.
    tokio::time::sleep(Duration::from_millis(300)).await;
    pump.stop();

    tokio::time::sleep(Duration::from_millis(50)).await;
    let packets = received.lock().await;
    assert!(!packets.is_empty(), "pump delivered no cover packets");
    assert!(expected_ticks(1000.0, Duration::from_millis(300)) > 100.0);
    Ok(())
}

/// A source error (transport broken) stops the pump deterministically.
#[tokio::test]
async fn pump_stops_on_source_error() -> Result<(), Box<dyn std::error::Error>> {
    let pair = LoopbackPair::new();
    let transport = Arc::new(pair.a);
    let scheduler = umbra_protocol::cover::PoissonScheduler::new(2000.0)?;
    let pump = CoverPump::spawn(Arc::clone(&transport), peer()?, scheduler, || async move {
        Err(TransportError::ChannelClosed)
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(pump.finished(), "pump must stop after a source error");
    Ok(())
}

/// Sanity: every delivered packet carries the DUMMY_COVER opcode when
/// unsealed with the matching key.
#[tokio::test]
async fn delivered_packets_are_dummy_cover() -> Result<(), Box<dyn std::error::Error>> {
    let pair = LoopbackPair::new();
    let transport = Arc::new(pair.a);
    let received: Arc<Mutex<Vec<umbra_protocol::packet::UnsealedPacket>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);
    tokio::spawn(async move {
        loop {
            match pair.b.recv().await {
                Ok(sealed) => {
                    if let Ok(unsealed) = packet::unseal(&sealed, Zeroizing::new([5u8; 32])) {
                        sink.lock().await.push(unsealed);
                    }
                }
                Err(_e) => return,
            }
        }
    });

    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = Arc::clone(&counter);
    let scheduler = umbra_protocol::cover::PoissonScheduler::new(2000.0)?;
    let pump = CoverPump::spawn(Arc::clone(&transport), peer()?, scheduler, move || {
        let index = counter_clone.fetch_add(1, Ordering::Relaxed);
        async move { Ok(Some(cover_packet(index).map_err(TransportError::from)?)) }
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    pump.stop();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let packets = received.lock().await;
    assert!(!packets.is_empty());
    for unsealed in packets.iter() {
        assert_eq!(unsealed.packet_type, PacketType::DummyCover);
    }
    Ok(())
}

/// The Ok(None) source contract skips ticks without sending.
#[tokio::test]
async fn pump_skips_ticks_without_session() -> Result<(), Box<dyn std::error::Error>> {
    let pair = LoopbackPair::new();
    let transport = Arc::new(pair.a);
    let received: Arc<Mutex<Vec<SealedPacket>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);
    tokio::spawn(async move {
        loop {
            if let Ok(packet) = pair.b.recv().await {
                sink.lock().await.push(packet);
            }
        }
    });

    let scheduler = umbra_protocol::cover::PoissonScheduler::new(1000.0)?;
    let pump = CoverPump::spawn(Arc::clone(&transport), peer()?, scheduler, || async move {
        Ok(None)
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    pump.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let packets = received.lock().await;
    assert!(packets.is_empty(), "skipped ticks must not produce packets");
    Ok(())
}
