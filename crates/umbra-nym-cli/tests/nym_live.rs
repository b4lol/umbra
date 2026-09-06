//! Live-network proof that `nym-sdk` v1.21.6's confirmed API actually
//! works end to end against Nym's real, free Sandbox testnet (TODO
//! B.1). `#[ignore]`d — never runs under default `cargo test`; run
//! explicitly: `cargo test --manifest-path crates/umbra-nym-cli/Cargo.toml
//! --test nym_live -- --ignored --nocapture`.
//!
//! Honest scope: proves Sandbox connectivity and the send/receive API
//! shape only. See Task 15 for the full duplex-bridge/PQXDH proof.

use futures::StreamExt as _;
use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender};
use umbra_nym_cli::nym_network::sandbox_network_details;

#[tokio::test]
#[ignore = "requires live network access to Nym's Sandbox testnet"]
async fn self_send_round_trip_over_sandbox()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = MixnetClientBuilder::new_ephemeral()
        .network_details(sandbox_network_details())
        .build()?
        .connect_to_mixnet()
        .await?;

    let my_address = *client.nym_address();
    client
        .send_plain_message(my_address, b"umbra-nym-live-probe".to_vec())
        .await?;

    let received = tokio::time::timeout(std::time::Duration::from_secs(60), client.next())
        .await?
        .ok_or("mixnet client stream ended before delivering the message")?;
    assert_eq!(received.message, b"umbra-nym-live-probe");

    client.disconnect().await;
    Ok(())
}
