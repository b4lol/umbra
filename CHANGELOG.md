# Umbra Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- **Wire-format revision (pre-release):** Double Ratchet header counters
  corrected — `N` (0-based chain index) at bytes 32..40, `PN` (previous
  chain length) at bytes 40..48; the previous encoding wrote them
  overlapping and nothing consumed them. Ratchet sessions now tolerate
  bounded out-of-order delivery via a skipped-key store (transactional
  rollback on failure); SMP carriage restarts reassembly on a fresh
  `index == 0` chunk, so abandoned transfers no longer wedge a session.

### Planned
- Post-Quantum TreeKEM (PQ-MLS) module for multi-cell communication (v2+).
- Linux Wayland GTK4/Libadwaita graphical interface (v2+) and the Ratatui TUI client (MVP).
- Android Jetpack Compose client and `FLAG_SECURE` hardware-lock integration (v2+).
- BLE & Wi-Fi Direct Mesh router for offline disaster and crisis environments (v2+).

### Changed
- **ADR-026:** C-based `pqcrypto-*` (PQClean) wrappers were rejected for post-quantum algorithms; the pure-Rust RustCrypto `ml-kem`, `ml-dsa`, and `slh-dsa` crates are now mandatory.
- **ADR-027:** Scope was split into MVP (v1.0) and v2+; `TODO.md` was restructured into Sections A/B.
- Absolute security claims in the documents ("100%", "unbreakable", "impossible") were replaced with measurable targets (e.g., constant-time behavior is verified with `dudect`; the Motion Wipe duration is defined as a target, not a guarantee).

---

## [0.1.0-alpha] - Unreleased (Planned)

### Planned
- Post-quantum hybrid handshake protocol (PQXDH: X25519 + ML-KEM-768 Kyber).
- Double Ratchet state machine providing Forward Secrecy and Post-Compromise Security.
- ChaCha20-Poly1305 AEAD and `subtle::ConstantTimeEq` timing protection.
- Fixed 1024-byte packet framer and Poisson artificial cover-traffic generator.
- Embedded Arti Tor v3 Hidden Service P2P network layer.
- Linux Seccomp-BPF syscall restriction, Landlock zero-disk sandbox, and `mlock` memory locking.
- FIDO2 / YubiKey hardware-key verification and Decoy Vault architecture.
- 100% Safe Rust, mandatory code documentation (`#![deny(missing_docs)]`), and anti-bloat rules.
