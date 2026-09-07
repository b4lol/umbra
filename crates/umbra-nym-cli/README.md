# umbra-nym-cli

Umbra's Nym Mixnet transport adapter (TODO B.1, ADR-032) — the `umbra-nym`
binary. It reuses Umbra's existing PQXDH/Double-Ratchet session code
(`umbra_net::messenger::send_text_stream`/`receive_message`, unmodified)
and `umbra-cli`'s `pairing`/`peers`/`keystore`/`sandbox` modules, bridged
over Nym's mixnet via `nym-sdk`.

## This is a SEPARATE Cargo workspace — not a member of the main workspace

`crates/umbra-nym-cli` declares its own `[workspace]` and is **deliberately
not listed** in the root `Cargo.toml`'s `members`. The main workspace's
`cargo build --workspace` / `cargo test --workspace` **do not see this
crate at all** — they will not build, lint, or test it, and they will not
produce the `umbra-nym` binary. This is not an oversight: `nym-sdk`'s
mandatory bandwidth-fetcher dependency chain conflicts with the
already-shipped Tor feature's SQLite chain via Cargo's `links = "sqlite3"`
uniqueness rule, so the only way to keep both working is full Cargo-graph
isolation. See **ADR-032** in the top-level `DECISIONS.md` for the full
rationale (exact crate/version chains, the `blake3` pin move this required,
and why no ADR-011 C-language exception was needed).

Build and test this crate via its own manifest path, from the repository
root or from anywhere:

```bash
cargo build --manifest-path crates/umbra-nym-cli/Cargo.toml
cargo test  --manifest-path crates/umbra-nym-cli/Cargo.toml
cargo clippy --manifest-path crates/umbra-nym-cli/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path crates/umbra-nym-cli/Cargo.toml --check
```

(Equivalently: `cd crates/umbra-nym-cli && cargo build` etc. — it behaves
as an ordinary, independent Cargo workspace once you're inside it.)

## Commands

- `umbra-nym send-nym` — send one message over the Nym mixnet (Sandbox
  testnet by default; pass `--mainnet` to use Nym mainnet instead — see
  the Nym-mode honest-scope note in the top-level `THREAT_MODEL.md` before
  doing so).
- `umbra-nym serve-nym` — receive messages over the Nym mixnet.

Both subcommands reuse the main project's process-hardening conventions
(Seccomp/Landlock sandboxing, `mlockall` memory locking per ADR-025). See
the top-level `README.md` and `CLIENT_SECURITY.md` for what that hardening
requires of the host environment — it is not duplicated here. In
particular, both subcommands **fail closed** if `RLIMIT_MEMLOCK` is not
raised (e.g. systemd `LimitMEMLOCK=infinity` or an equivalent raised
ulimit); this is by-design fail-closed behavior, not a bug.

## Live network test

`tests/nym_live.rs` is a two-process (`send-nym` + `serve-nym`) interop
test against Nym's real Sandbox testnet. It is marked `#[ignore]` because
it requires live network access and a raised `RLIMIT_MEMLOCK` (see above);
run it explicitly with:

```bash
cargo test --manifest-path crates/umbra-nym-cli/Cargo.toml --test nym_live -- --ignored --nocapture
```

It is expected to be skipped (shown as `ignored`) in a plain `cargo test`
invocation — that's correct, matching the rest of the project's live-test
convention (e.g. `crates/umbra-net/tests/mesh_live.rs`).
