//! The `NymTransport` seam (TODO B.1): abstracts over a real
//! [`nym_sdk::mixnet::MixnetClient`] so the duplex-bridge logic
//! (Task 8) can be tested hermetically against [`FakeNymTransport`]
//! instead of a live network connection.

use umbra_net::TransportError;

use crate::addr::NymPeerAddr;

/// A Nym mixnet endpoint capable of sending to and receiving from
/// other Nym addresses, one message at a time.
pub trait NymTransport {
    fn address(&self) -> NymPeerAddr;

    fn send(
        &self,
        to: NymPeerAddr,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    fn recv(&mut self)
        -> impl std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send;
}

// Test-only: not gated per the original sketch's wording, but in
// practice `FakeNymTransport` has no consumer outside `#[cfg(test)]`
// code (this module's own tests today; Task 8's bridge tests later).
// Gating it here mirrors `addr::tests_support` and keeps the
// lint-clean state: an ungated `fake` module is unreachable dead code
// under a normal (non-test) build, which this crate's
// `missing_docs_in_private_items`/`dead_code` lint denials reject.
// `#[cfg(test)]` items remain visible to any other `#[cfg(test)]` code
// in the crate once compiled under `cargo test`, so
// `crate::transport::FakeNymTransport` stays importable from Task 8's
// bridge tests exactly as intended.
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::VecDeque;

    use super::NymTransport;
    use crate::addr::NymPeerAddr;
    use umbra_net::TransportError;

    /// An in-process `NymTransport` fake: test bodies push directly
    /// onto a peer's `inbox` to simulate delivery — `send` here does
    /// NOT auto-route between two fakes (see Task 8's tests for the
    /// two-fake wiring pattern). Instead, every call to `send` is
    /// recorded into `sent` so a test can retrieve the bytes that
    /// would have gone out and manually feed them into the recipient
    /// fake's `inbox`.
    pub(crate) struct FakeNymTransport {
        pub(crate) own_address: NymPeerAddr,
        pub(crate) inbox: VecDeque<Vec<u8>>,
        /// Every `(to, payload)` pair passed to `send`, in call order.
        /// A `Mutex` (not a `RefCell`) because `NymTransport::send`
        /// takes `&self` and its returned future must stay `Send`,
        /// which `RefCell`'s non-`Sync` guard would break.
        pub(crate) sent: std::sync::Mutex<Vec<(NymPeerAddr, Vec<u8>)>>,
    }

    impl FakeNymTransport {
        pub(crate) fn new(own_address: NymPeerAddr) -> Self {
            Self {
                own_address,
                inbox: VecDeque::new(),
                sent: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl NymTransport for FakeNymTransport {
        fn address(&self) -> NymPeerAddr {
            self.own_address.clone()
        }

        async fn send(&self, to: NymPeerAddr, payload: Vec<u8>) -> Result<(), TransportError> {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((to, payload));
            Ok(())
        }

        async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            self.inbox
                .pop_front()
                .ok_or_else(|| TransportError::Nym("fake transport: inbox empty".into()))
        }
    }
}

#[cfg(test)]
pub(crate) use fake::FakeNymTransport;

#[cfg(test)]
mod tests {
    use super::*;

    // Reuse the exact same real, SDK-generated address string Task 5
    // settled on for its own tests — do not invent a second one.
    // Returns `Result` (rather than `.expect()`-ing internally) so
    // callers propagate via `?`, per this crate's `expect_used = "deny"`
    // lint.
    fn sample_addr() -> Result<NymPeerAddr, TransportError> {
        NymPeerAddr::parse(crate::addr::tests_support::SAMPLE_VALID_ADDRESS)
    }

    #[tokio::test]
    async fn recv_returns_queued_message() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut transport = FakeNymTransport::new(sample_addr()?);
        transport.inbox.push_back(b"hello".to_vec());
        assert_eq!(transport.recv().await?, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn recv_errors_on_empty_inbox() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut transport = FakeNymTransport::new(sample_addr()?);
        assert!(transport.recv().await.is_err());
        Ok(())
    }
}
