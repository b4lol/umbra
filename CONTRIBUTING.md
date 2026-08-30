# Umbra Contributing Guide

Thank you for wanting to contribute to the Umbra project!

Umbra is a zero-metadata, post-quantum-security-focused system developed for journalists, diplomats, and intelligence personnel. In the codebase, **no compromise is ever made** on the rules of stability, security, performance, safe Rust, and full documentation.

---

## 🛠️ Development Environment Setup

### 1. Requirements
- **Rust Toolchain:** The stable version pinned in `rust-toolchain.toml` (with the `rustfmt` and `clippy` components).
- **Helper Tools:**
  ```bash
  cargo install cargo-deny cargo-geiger cargo-audit just
  ```
- **Linux Dependencies (Wayland & GUI):**
  - **Fedora:** `sudo dnf5 install gtk4-devel libadwaita-devel`
  - **Debian / Ubuntu:** `sudo apt install libgtk-4-dev libadwaita-1-dev`

---

## 🛑 Binding Contribution Rules

1. **Safe Languages and the Safe Rust Requirement:**
   - Project source code may be written only in **Rust** and **Kotlin** (Android UI). C, C++, JavaScript/Electron, Python, and dynamic languages are strictly forbidden.
   - `#![forbid(unsafe_code)]` is active in the business-logic, crypto, network, and protocol crates.
   - `unsafe` is permitted only in isolated modules that directly touch physical hardware (`crates/umbra-hardware`), behind a `100% Safe API`, and with a `// SAFETY: ...` justification.
2. **Complete Documentation (`#![deny(missing_docs)]`):**
   - Every module (`//!`), function, struct, enum, and field (`///`) must be documented.
   - The reasons behind critical decisions in function bodies must be explained with inline comments (`// ...`).
3. **Resource Discipline and Zero Bloat (Anti-Bloat):**
   - Unnecessary `clone()` allocations, memory leaks, and disk residue are forbidden.
   - The RAM-only principle must be observed; no temporary files or logs may be written to disk.
4. **Hermetic and Deterministic Tests:**
   - All unit tests must run without depending on the external network or live system tools.

---

## 🧪 Verification and Aggressive Security Scanning Commands

All contributions must pass the following multi-layered verification chain with zero errors and zero warnings:

```bash
# 1. Code Formatting & Documentation Checks
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings -D missing_docs

# 2. Unsafe Code Scan (Isolated to Hardware Only)
cargo geiger

# 3. License, Dependency & RUSTSEC/CVE Vulnerability Scanning
cargo deny check
cargo audit

# 4. LLVM Memory Sanitizer Scans (ASan & UBSan)
RUSTFLAGS="-Zsanitizer=address" cargo test --target x86_64-unknown-linux-gnu

# 5. Cryptographic Constant-Time Analysis (Timing Leakage Analysis)
cargo test --test constant_time_tests -- --nocapture

# 6. Fuzzing Mutation Testing (for Parsers)
cargo fuzz run fuzz_packet_parser -- -max_total_time=60

# 7. Logic and Mutation Testing
cargo mutants --no-shuffle
cargo test --test property_tests

# 8. Hermetic Unit Tests
cargo test --all-targets
```

Or, briefly:
```bash
just check
just scan
just mutants
```

---

## 🔀 Pull Request (PR) Process

1. Create a new feature branch from the `main` branch (`git checkout -b feature/guvenlik-iyilestirmesi`).
2. Write your code and its accompanying hermetic tests.
3. Make sure you fully comply with the principles in [`CODE_MANIFESTO.md`](CODE_MANIFESTO.md) and the checklist in [`CODE_REVIEW.md`](CODE_REVIEW.md).
4. Verify that `just check`, `just scan`, and `just mutants` return zero errors.
5. Open a PR with a clear, well-reasoned commit message.
