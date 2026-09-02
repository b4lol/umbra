# Umbra Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-alpha.2] — 2026-09-02

Interactive Tor flows landed; the three known alpha.1 limitations are
resolved (two in code, one live-verified).

### Added
- **`umbra serve`**: inbound onion-service daemon — identity seeds load
  once, bundle rebuilt per connection (no Argon2 per peer); Landlock
  zero-FS + [Tor tree rw, /etc ro] + Seccomp; concurrent per-stream
  PQXDH sessions behind a result queue; NDJSON `ready`/`text` events.
- **`umbra send --onion`**: outbound Tor flow — bounded 64 KiB stdin in
  locked RAM, shared Tor storage root, per-session ephemeral initiator,
  one PQXDH session with chunked ratchet messages, NDJSON `sent` event.
- **Burst-level cover traffic** (ADR-005): Poisson-driven DUMMY_COVER
  frames interleaved with real frames on every send path (p=0.5, hard
  cap 64/burst), wire-indistinguishable; receivers destroy cover
  silently (the pipe path previously REJECTED it — fixed).
- **Best-effort register scrub** (`umbra-hardware::hardening`): `asm!`
  zeroing caller-saved GPRs after PQXDH root derivation, skipped-key
  consumption and `GuardedBuffer::drop` (mitigates the upstream removal
  of `zero-call-used-regs`; residuals documented).
- **Live identity-persistence test** (`just live-test`, `#[ignore]`d):
  two consecutive bootstraps over one storage root publish the same
  `.onion` address — PASSED on the real Tor network (2026-09).
- Peer records carry an optional `onion <addr>` line (`pair --onion`);
  `--passphrase-file` reads the FIRST line per its documented contract.

### Fixed
- `/dev/tty` Landlock rule used directory rights invalid on character
  devices under HardRequirement (latent: any production harden() with a
  tty would fail) — now ReadFile+WriteFile+IoctlDev.
- Seccomp allowlist gained the filesystem-mutation syscalls Arti's
  atomic state/keystore writes need (post-sandbox persistence no longer
  fails closed) plus `socketpair`.
- `receive_message`: handshake-blob read is time-bounded (an idle peer
  could park a session forever); inbound reassembly bounded at 64 KiB
  (anonymous clients must not pin unbounded locked RAM).
- Release-docs claim sweep (README rewritten to the honest scope).

### Verification
- 117 test cases across 18 integration suites; hermetic CI unchanged
  (4 required checks). Live: `just live-test` passed on the real
  network; TODO A.2 address-stability claim is field-verified.

## [1.0.0-alpha.1] — 2026-08-31

Section A (MVP) scope of TODO.md: 39/40 tasks complete (one blocked upstream).
First tagged release: cryptographic core complete and CI-verified; interactive
product surface and live-network field testing deferred.

### Added
- PQXDH (X25519 + ML-KEM-768, ML-DSA-65-signed pre-keys) and a Signal-spec
  Double Ratchet with a bounded skipped-key store (out-of-order delivery),
  hostile-header bounds, replay fail-closed and transactional decrypt (§3.5).
- OTR v3 SMP engine with identity-fingerprint binding (`smp::bound_secret`)
  and per-session transcript-SSID mixing; `umbra fingerprint` command.
- Fixed 1024-byte packet framing, session-tag multiplexer, SMP carriage with
  reassembly restart, media metadata sterilizer, MEDIA_CHUNK assembler.
- Embedded Arti Tor v3 outbound + inbound onion services; persistent onion
  identity (`bootstrap_persistent`, 0700 storage root, native keystore);
  strict Vanguards-Lite pinning; inbound hs-pow with a bounded queue.
- Client hardening: Landlock zero-FS sandbox (+ narrow exception mechanism),
  Seccomp allowlist with the IPv4/UNIX-STREAM-only network kill-switch,
  mlockall/PR_SET_DUMPABLE/RLIMIT_CORE, GuardedBuffer, Argon2id keystore,
  pairing payloads + SAS, peer records, 60 s clipboard, masked D-Bus
  notifications, TUI skeleton, pipe transport (`send`/`recv`, NDJSON).
- Verification: 112 test cases across 17 integration suites plus per-crate
  unit tests, proptest, dudect-style constant-time suite, 4 fuzz targets,
  ASan nightly CI, weekly mutation testing.

### Changed
- Wire-format revisions (pre-release): Double Ratchet header counters
  corrected — `N` (0-based chain index) at bytes 32..40, `PN` (previous
  chain length) at bytes 40..48; the previous encoding wrote them
  overlapping and nothing consumed them. Ratchet sessions tolerate bounded
  out-of-order delivery (transactional rollback on failure); SMP carriage
  restarts reassembly on a fresh `index == 0` chunk, so abandoned transfers
  no longer wedge a session. Pipe framing documented in SPECIFICATION.md.
- Hardening order refined (ADR-025): memory locks apply BEFORE keystore
  reads; Landlock zero-FS + Seccomp apply after them.
- Claim-sweep: absolute anonymity statements in the release documents were
  replaced with scoped, measurable wording (docs outside this release
  section still contain inherited absolutes — the sweep continues).
- **ADR-026:** C-based `pqcrypto-*` (PQClean) wrappers were rejected for
  post-quantum algorithms; the pure-Rust RustCrypto `ml-kem`, `ml-dsa`, and
  `slh-dsa` crates are now mandatory.
- **ADR-027:** Scope was split into MVP (v1.0) and v2+; `TODO.md` was
  restructured into Sections A/B.
- Absolute security claims in the documents ("100%", "unbreakable",
  "impossible") were replaced with measurable targets (e.g., constant-time
  behavior is verified with `dudect`; the Motion Wipe duration is defined
  as a target, not a guarantee).

### Blocked
- CPU register zeroing (`zero-call-used-regs`): flag removed from rustc
  nightly 1.100.0 upstream; ADR-025 clause marked blocked (TODO A.4).

### Planned
- Post-Quantum TreeKEM (PQ-MLS) module for multi-cell communication (v2+).
- Linux Wayland GTK4/Libadwaita graphical interface (v2+) and the full
  interactive Ratatui TUI client (a skeleton shipped in 1.0.0-alpha.1).
- Android Jetpack Compose client and `FLAG_SECURE` hardware-lock
  integration (v2+).
- BLE & Wi-Fi Direct Mesh router for offline disaster and crisis
  environments (v2+).

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
