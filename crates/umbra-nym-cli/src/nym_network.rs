//! Nym Sandbox network selection (TODO B.1, Nym Mixnet adapter).
//!
//! `NymNetworkDetails::new_from_env()` (defined in `nym-network-defaults`
//! v1.21.6, `src/network.rs`, `impl NymNetworkDetails::new_from_env`)
//! is **not** a file loader: it does not read a `NYM_ENV_PATH` variable
//! or parse any `.env`-style file itself. It reads a fixed set of
//! already-set *process* environment variables directly via
//! `std::env::var(...)` (see `nym_network_defaults::var_names` for the
//! exact key names — `NETWORK_NAME`, `BECH32_PREFIX`, `MIX_DENOM`,
//! `MIX_DENOM_DISPLAY`, `STAKE_DENOM`, `STAKE_DENOM_DISPLAY`,
//! `DENOMS_EXPONENT`, `NYXD`, `NYM_APIS`/`NYM_API`, `NYM_VPN_APIS`, the
//! `*_CONTRACT_ADDRESS` keys, etc.) and panics (`.expect(...)`) if a
//! required one is missing. Nym's own `sandbox.env` file (the one this
//! module vendors, in `fixtures/sandbox.env`) is meant to be sourced into
//! the process environment by the *caller* (e.g. shell `source` or a
//! `dotenv`-style loader) before calling `new_from_env()` — the SDK
//! itself never touches the filesystem for this. Verified by reading the
//! installed source of `nym-network-defaults` v1.21.6 at
//! `~/.cargo/registry/src/index.crates.io-*/nym-network-defaults-1.21.6/src/network.rs`
//! (`NymNetworkDetails::new_from_env`, `env_setup.rs::env_configured`,
//! and the `var_names` module referenced throughout) on 2026-09-06.
//!
//! Accordingly, `sandbox_network_details()` below sets each of those
//! process environment variables itself (parsed from the vendored,
//! pinned fixture) before calling `new_from_env()`, exactly once per
//! process (`std::sync::Once`) to avoid racing concurrent callers (e.g.
//! parallel `#[test]` functions) that both try to mutate process env.

use std::sync::Once;

use nym_sdk::mixnet::NymNetworkDetails;

/// Vendored, pinned Nym Sandbox testnet environment fixture. See
/// `fixtures/sandbox.env` for provenance and pin date.
const SANDBOX_ENV: &str = include_str!("fixtures/sandbox.env");

/// Guards one-time population of the process environment from
/// [`SANDBOX_ENV`], so repeated calls (e.g. from multiple tests) don't
/// race each other mutating global process state.
static SET_SANDBOX_ENV: Once = Once::new();

/// Returns Nym's Sandbox testnet network details, using the vendored,
/// pinned `sandbox.env` fixture.
///
/// # Panics
///
/// Panics (via `nym_sdk`'s own `NymNetworkDetails::new_from_env()`) if
/// the vendored fixture is missing a key that `new_from_env()` requires.
/// This should never happen for the pinned fixture committed alongside
/// this module.
#[must_use]
pub fn sandbox_network_details() -> NymNetworkDetails {
    SET_SANDBOX_ENV.call_once(|| {
        for line in SANDBOX_ENV.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                // `sandbox.env` quotes some values with double quotes
                // (`STATISTICS_SERVICE_DOMAIN_ADDRESS="..."`) and others
                // with single quotes (`NYM_APIS='[...]'`, shell-style, so
                // the embedded double quotes in the JSON survive). Strip
                // one matching layer of whichever quote character wraps
                // the whole value; `new_from_env()` expects the bare
                // value (e.g. raw JSON for `NYM_APIS`), not the quoted
                // literal.
                let value = strip_matching_quotes(value);
                // SAFETY-equivalent note: `set_var` is not `unsafe` in this
                // edition's std, but it does mutate global process state.
                // Guarded by `Once` above; this is the only writer.
                std::env::set_var(key, value);
            }
        }
    });
    NymNetworkDetails::new_from_env()
}

/// Strips one matching layer of wrapping quotes (`'...'` or `"..."`) from
/// `value`, if present on both ends. Returns `value` unchanged otherwise.
fn strip_matching_quotes(value: &str) -> &str {
    for quote in ['\'', '"'] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}
