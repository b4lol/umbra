# Umbra Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Unmanaged pluggable-transport support** (TODO B.1, ADR-030):
  `umbra serve` / `send --onion` / `tui` accept `--pt-socks
  127.0.0.1:PORT` + repeatable `--bridge "…"` (or a `bridges` file next
  to the keystore, read pre-sandbox) and configure arti's unmanaged
  (loopback SOCKS5) transports — Umbra never spawns or links PT
  binaries; non-loopback endpoints and half-configured setups fail
  closed. PT protocol names are derived from the bridge lines.
- **`pt-proxy/` skeleton**: a standalone, loopback-only SOCKS5 proxy
  component in C under ADR-030's scoped, owner-granted language
  exception (process-isolated, hardening-flag build, ASan/UBSan gate
  target). The SOCKS5 front-end (RFC 1928, no-auth CONNECT, bounded
  parsing, exact reply codes, deadline-guarded upstream dial) is
  implemented and integration-tested (`pt-proxy/tests/socks5.sh`, also
  clean under ASan/UBSan).
- **`pt-proxy` obfs4 client handshake** (roadmap step 3): ntor variant
  + Elligator 2 representatives, implemented in C against the Go
  reference (lyrebird) as the wire authority — libsodium (system) for
  X25519/HMAC-SHA256/HKDF-SHA256/SHA-512/CSPRNG, vendored Monocypher
  4.0.3 for Elligator 2 only. Verified BYTE-EXACT against fixtures
  dumped from the Go reference (`make vectors`, normal + ASan/UBSan
  builds; regeneration recipe in `pt-proxy/tests/govectors/`).
- **`pt-proxy` obfs4 framing + packet layer + relay** (roadmap step 4):
  XSalsa20-Poly1305 frames with SipHash-2-4-DRBG length obfuscation
  (in-house streaming SipHash, cross-checked against libsodium's
  one-shot variant and the Go DRBG block sequence), nonce
  `prefix|counter-BE` from 1 with fatal wrap, the Bider
  length-countermeasure, the packet layer (payload / PRNG-seed /
  unknown types), and the poll-driven bidirectional relay wired into
  the SOCKS5 path — the proxy now carries real traffic (iat-mode 0).
  Verified byte-exact against Go framing fixtures (`make vectors`) and
  end-to-end against `tests/mockbridge.c`, a reference-faithful
  test-only obfs4 server (`make relay-test`: 1 KB / 5 KB / 100 KB echo
  round-trips + fail-closed mid-handshake cut, normal and ASan/UBSan
  builds).
- **`pt-proxy` iat-mode traffic shaping** (roadmap step 5): the length
  and inter-arrival-time distributions behind obfs4's iat-mode 0/1/2.
  Go `math/rand.Rand` helper semantics (Int63/Int31n/Float64/Perm)
  replicated over the obfs4 SipHash-2-4-OFB DRBG (`src/gorand.c`) and
  the uniform weighted-distribution tables via Vose's alias method
  (`src/probdist.c`), both pinned BIT-EXACT against fixtures dumped
  from lyrebird's `common/probdist` (`make vectors`). Per connection:
  distributions seed locally and RESET on the bridge's PRNG-seed packet
  (iat seed = SHA-256 of the length seed, Go parity); inter-chunk
  delays are scheduled via poll deadlines — never slept inline — with a
  bounded 4-slot pending queue that backpressures the SOCKS5 client;
  paranoid mode (2) chops every burst at sampled lengths and pads the
  tail up with Go padBurst semantics (resample on wrap; a sampled 0 is
  redrawn where Go panics). Mode-2 bursts are queued raw and encoded
  only at the head of the queue so payload frames and flush-time
  pad-ups advance the framing DRBG in wire order. Verified end-to-end
  in all three iat modes plus the fail-closed cut (`make relay-test`,
  normal and ASan/UBSan). Runtime gains a REQUIRED `--iat-mode 0|1|2`
  argument (missing/invalid fails at startup, before any accept).
  Honest shaping notes: distribution tables are byte-exact, individual
  samples are CSPRNG-drawn (as Go's csrand does), and delays quantize
  up to whole milliseconds.
- Hermetic tests: PT config validation + builder tests (umbra-net),
  CLI/bridges-file plumbing tests (umbra-cli).

### Fixed
- `pair --peer-payload` / `pairing-sas --own-payload` / `--peer-payload`
  no longer reject base64url payloads that legitimately START with '-'
  (clap took them for flags: "unexpected argument '-W'…"; ~1/64 of
  random payloads). `allow_hyphen_values` set + a parser regression
  test.
- Flaky CI hang in the `receive_reassembly_bounded` messenger test:
  the test awaited the sender task while the undrained duplex read half
  was still alive, deadlocking whenever scheduling left the sender
  parked on the full buffer. The test now closes the pipe before
  awaiting (150/150 full-parallel stress runs clean).

---

## [1.0.0-alpha.3] — 2026-09-03

The interactive Ratatui TUI client ships, and live-verifying its network
path caught a real alpha.2 defect: outbound `.onion` connects were
impossible (missing arti `onion-service-client` feature). Both
directions of the Tor transport are now live-verified.

### Added
- **Interactive Tor TUI client** (`umbra tui`, `tor` feature): live
  inbound onion feed and compose-and-send over Tor in one sandboxed
  process. The UI thread owns the terminal; a Tokio runtime runs
  bootstrap, the accept loop, and outbound sends in the background over
  channels. Tab cycles the peer selection; the log is bounded
  (400 lines); per-session plaintext copies move in `Zeroizing`
  buffers. Hardening order mirrors `serve` (ADR-025): memory locks
  before the keystore read, Landlock zero-FS + [Tor tree rw, /etc ro,
  /dev/tty] and Seccomp before the runtime starts.
- **Live TUI background-path test** (`crates/umbra-cli/tests/tui_live.rs`,
  `#[ignore]`d): self-send through the client's own onion service —
  PASSED on the real Tor network (2026-09), closing the outbound
  live-verification gap below.

### Fixed
- **Outbound onion connections were impossible on the live network:**
  `arti-client` was compiled with `onion-service-service` (hosting) but
  WITHOUT `onion-service-client` (connecting to `.onion`), so every
  `send --onion` / TUI send failed at connect time with "feature
  onion-service-client not compiled in". The alpha.2 outbound flow had
  never been live-tested; the gap is now closed in code and verified by
  the self-send live test.

### Changed
- **`umbra tui` now requires `--keystore`** and takes `--nickname`
  (default `umbra-tui`) for its persistent inbound onion identity; the
  command and the `tui` module are gated behind the `tor` feature.
- `serve`: the address wait and the accept loop are extracted as the
  shared `wait_for_address` / `inbound_loop` helpers (reused by the
  TUI); seeds are `Arc`-shared. NDJSON behaviour unchanged.
- `tor_send`: the send core is extracted as `send_over` (bounded
  120 s connect, one PQXDH session) so the TUI reuses it; the CLI flow
  is unchanged.
- `peers`: new `list_names` (sorted record names; a missing directory
  is an empty list) for pre-sandbox peer loading.

### Verification
- 122 test cases across 19 integration suites; hermetic CI unchanged
  (4 required checks). Live: `tui_live` self-send PASSED on the real
  Tor network (2026-09); the alpha.2 `just live-test` identity-persistence
  result stands.

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
