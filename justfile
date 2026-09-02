# Umbra verification chain (CONTRIBUTING.md §"Verification and Aggressive
# Security Scanning Commands"). All contributions must pass with zero errors
# and zero warnings.

default := "check"

# 1. Formatting, lints, hermetic tests.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --all-targets

# 2-3. Unsafe-usage, license, dependency, and RUSTSEC/CVE scanning.
scan:
    cargo geiger
    cargo deny check
    cargo audit

# 7. Logic and mutation testing.
mutants:
    cargo mutants --no-shuffle

# 6. Fuzzing mutation testing for parsers (cargo-fuzz; see fuzz/).
fuzz target="fuzz_packet_parser" seconds="60":
    cargo fuzz run {{target}} -- -max_total_time={{seconds}}

# 5. LIVE-NETWORK identity-persistence test (TODO A.2 residual): run on
# a machine with real Tor connectivity; NOT part of the hermetic CI set.
live-test:
    cargo test -p umbra-net --features tor --test serve_live -- --ignored --nocapture

# 4. LLVM memory sanitizers (nightly toolchain required).
asan:
    RUSTFLAGS="-Zsanitizer=address" cargo +nightly test \
        --workspace --all-targets --target x86_64-unknown-linux-gnu
