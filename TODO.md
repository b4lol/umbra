# Umbra Task and TODO List

This list contains the technical tasks planned for the step-by-step implementation of the project.

> **Scope Note (ADR-027):** Tasks are divided into two sections by delivery priority.
> - **Section A — MVP (v1.0):** Core cryptography, the Arti P2P network, protocol masking, the Linux TUI, and basic security/test infrastructure. v1.0 is released with exactly this scope.
> - **Section B — v2 and Later:** Android client, GTK4 GUI, mesh/mixnet, PQ-MLS, active deception, and hardware side-channel defenses. These items are not cancelled; they are planned for after v1.0.

---

# Section A — MVP (v1.0) Scope

## A.1 Rust Workspace & Core Cryptography (`umbra-crypto`)

- [x] Creating the Cargo Workspace (`crates/umbra-crypto`, `crates/umbra-net`, `crates/umbra-protocol`, `crates/umbra-cli`, `crates/umbra-gui`, `crates/umbra-ffi`).
- [x] Classical Diffie-Hellman key-pair management with `x25519-dalek`.
- [x] Pure-Rust (RustCrypto) `ml-kem` (ML-KEM-768) and `ml-dsa` (ML-DSA-65) integration (ADR-026; C-based `pqcrypto-*` wrappers are not used).
- [x] Implementation of the hybrid PQXDH handshake protocol.
- [x] Double Ratchet state machine and KDF chains.
- [x] `ChaCha20-Poly1305` AEAD encryption and `subtle::ConstantTimeEq` timing protection.
- [x] Secure memory hygiene with `zeroize` and guard pages. *(GuardedBuffer: PROT_NONE guards + mlock + MADV_DONTDUMP/DONTFORK/WIPEONFORK/UNMERGEABLE + zeroize-on-drop)*
- [x] Zero-copy in-place identity generation — RESOLVED BY DESIGN (ADR-029): safe Rust cannot control return-slot placement, and `unsafe` placement hacks would violate the ADR-011/ADR-012 language policy for zero measurable gain. The compensating controls are exactly the ADR-025 layers (mlockall, PR_SET_DUMPABLE=0, RLIMIT_CORE=0, MADV_DONTDUMP; secrets are Zeroizing-on-drop). Residual documented in CRYPTOGRAPHY.md.
- [x] Double Ratchet recovery: bounded skipped-key store for out-of-order delivery (128/chain, 256 total, FIFO eviction + rotation pruning, header gap bound, replay fail-closed, transactional rollback per Signal §3.5). *(Recovery after an unrecoverable loss = establishing a new session; no automatic in-band resync protocol.)*

## A.2 Network & Transport (`umbra-net`)

- [x] Pure-Rust Tor v3 outbound P2P: embedded Arti client bootstrap (time-bounded) + anonymized streams to peer `.onion` services (`tor` feature).
- [x] Inbound Tor v3 Hidden Service hosting (`tor-hsservice`): rendezvous accept loop (head-of-line protected), fixed-size packet pump, ephemeral identity keystore.
- [x] Pairing-tied identity-key persistence (MECHANISM): `TorTransport::bootstrap_persistent(base)` roots the Arti state dir (native keystore under `base/state/keystore`, dirs 0700) so the `.onion` address is stable per nickname — by construction of Arti's keystore; NOT yet exercised against the live network, and no production call site wires it yet. Landlock reconciliation ships as `restrict_filesystem_with_exceptions` (narrowed grant: regular files/dirs only; no Execute/Make*/IoctlDev on the Tor tree) — API-only until a Tor-hosting flow exists.
- [x] Per-transport inbound hardening: hs-pow enabled on the inbound onion service (`enable_pow(true)` via the `hs-pow-full` feature; load-triggered with dynamic difficulty — never "always") with a BOUNDED rendezvous queue (512 ≈ 2 MB instead of the 8192 ≈ 32 MB default, which `mlockall` would pin into non-swappable RAM). The shared config builder is hermetically tested (build acceptance proves `hs-pow-full` is compiled in); PoW behavior against the live network is not exercised. *(Persistent peer streams remain a v2 item — one fresh circuit per stream is the v1 anonymity posture.)*
- [x] Strict Vanguards-Lite circuit policy: BOTH config paths (ephemeral + persistent) pin `VanguardMode::Lite` EXPLICITLY, so the mode cannot be weakened by consensus (pool sizes/lifetimes REMAIN consensus parameters). Scope note (arti 0.45): one shared config drives ALL circuits — client and service alike run Lite (`G -> L2 -> M`, L2-only pinning); per-service Full is upstream arti #1382. Hermetic test asserts the pinned mode.

## A.3 Protocol & Metadata Masking (`umbra-protocol`)

- [x] 1024-byte fixed-block packet framing (`Packetizer`) and cryptographic random padding.
- [x] Poisson-distributed artificial cover-traffic generator (`PoissonTimer`). *(scheduler + `umbra-net::cover` pump; must be started with the session)*
- [x] Media Metadata Sterilizer (EXIF, GPS, color-profile stripping and pixel re-encoding). *(full pixel re-encode to metadata-free PNG; fuzzed)*
- [x] MEDIA_CHUNK framing/chunking for sterilized media (who chunks, EFK keying per SPECIFICATION.md `0x06`). *(split/assembler with MAX_CHUNKS/MAX_MEDIA_BYTES caps; fuzzed)*
- [x] Socialist Millionaire Protocol (SMP) and SAS code verification engine. *(OTR v3 SMP engine, all 4 messages + ZKPs; SAS 6-digit codes)*
- [x] Session-layer SMP carriage: tag multiplexer + multi-packet chunking over DATA_MESSAGE (SMP2 ≈ 1.5 KB > 990 B) + messenger driver (smp_verify_initiator/responder over any stream).
- [x] Peer record store: named peers with self-authenticating pairing payloads + `umbra pair` SAS command.
- [x] Pairing-authenticated identity binding: peer payloads (incl. ML-DSA VK) are recorded out of band in the peer store; `umbra fingerprint` exposes the canonical IK+VK digest for comparison; `smp::bound_secret` derives the SMP secret from the password plus the canonically-sorted fingerprint pair, so key-substituting MITMs fail SMP. *(Interactive per-message SMP remains part of the session driver; pipe-mode recv still runs no SMP by design.)*

## A.4 Linux Security & TUI (`umbra-cli`)

- [x] Linux `seccomp-bpf` syscall filtering (seccompiler allowlist, fail-closed EPERM) and `Landlock` zero-filesystem-access sandboxing (+ `/dev/tty` read/write/ioctl exception for the TUI — crossterm raw mode).
- [x] Security-focused, low-resource Terminal TUI (`ratatui`). *(state-machine skeleton; runs fully under the Landlock+Seccomp sandbox)*
- [x] Clipboard manager with a 60-second auto-destruct. *(in-process manager: `Zeroizing` RAM buffer + TTL wipe, tested against a memory backend; the Wayland system-clipboard backend is v2 scope)*
- [x] Linux D-Bus masked generic notification adapter (`org.freedesktop.Notifications`). *(zbus backend implemented, unwired to any production flow; masking logic tested against a memory backend — the D-Bus path itself is untested)*
- [x] **Memory Leak Locks:** `mlockall`, `prctl(PR_SET_DUMPABLE, 0)` and `MADV_DONTDUMP`/`MADV_DONTFORK` integration. *(plus `setrlimit(RLIMIT_CORE, 0)` and `MADV_UNMERGEABLE`; Landlock zero-FS sandbox in the CLI)*
- [ ] **CPU Register Zeroing:** BLOCKED UPSTREAM — rustc removed `zero-call-used-regs` (nightly 1.100.0; never stabilized, no `-C`/`-Z` form survives; clang's `-fzero-call-used-regs` LLVM feature has no rustc front-door). Track rust-lang/rust for a re-landing; revisit `-Cllvm-args` workarounds before v1.0. (ADR-025 wording needs updating to match.)
- [x] **DNS & IPv6 Blocking:** kernel-level kill-switch implemented in-process: Seccomp argument rules allow only IPv4/UNIX STREAM sockets — IPv6 and UDP (DNS :53) return EPERM (`sandbox_seccomp.rs::ipv6_and_udp_sockets_are_blocked`); host-layer nftables reference ruleset documented in CLIENT_SECURITY §4.C (process-scoped ADR-019 allowance note preserved).
- [x] **SESSION_TERMINATE (opcode 0x09):** emit on panic-button/teardown and handle on receipt (mutual ephemeral-key reset; authenticated packet, no ratchet message, local state zeroized).

## A.5 Quality, Test & Security Verification Infrastructure

- [x] **Continuous Fuzzing Harness:** libFuzzer targets via `cargo-fuzz` for the packet parser, media sterilizer, SMP wire format and media assembler; CI smoke runs two targets per push.
- [x] **LLVM Memory Sanitizer Integration:** AddressSanitizer (ASan) test stage in CI on the nightly toolchain. *(UBSan is partially covered by debug overflow checks; a dedicated stage is deferred to v2 hardening)*
- [x] **Constant-Time Analysis Suite:** dudect-style pooled-mean Welch t-test suite (`constant_time_tests.rs`) over AEAD/ratchet/KDF hot paths.
- [x] **Typestate Pattern Library:** `Session<Unauthenticated>` $\to$ `Session<HandshakeInProgress>` $\to$ `Session<EstablishedSession>`; illegal transitions unrepresentable.
- [x] **Newtype Wrappers:** `SequenceNumber`, `EpochId`, `RatchetStep` and friends strongly typed in `umbra-protocol::newtypes`.
- [x] **Property-Based Test Suite:** proptest invertibility suite and ratchet recovery suite (out-of-order, replay, hostile headers, store bounds).
- [x] **Mutation Testing Pipeline:** weekly `cargo-mutants` run in CI (`mutation.yml`).
- [x] **Standard Pipeline Support:** `umbra send --peer NAME` reads stdin, establishes a PQXDH session against the stored peer record and emits length-prefixed handshake blob + 1024-byte sealed frames + SESSION_TERMINATE on stdout; `umbra recv` consumes the framing and writes plaintext to stdout. Binary or `--json` NDJSON (base64url `data` fields). Sandbox applies after keystore/peer-record loads.
- [x] **Rule of Silence Audit:** `cli_silence.rs` asserts clean `stdout` on success and failure, diagnostics on `stderr` with the `umbra: ` prefix.
- [x] **JSON/NDJSON Parseable Streams:** `umbra --json` NDJSON output; pipe transport events are jq/awk-compatible.

---

# Section B — v2 and Later (Deferred Scope)

## B.1 Advanced Network, Censorship Resistance & Mesh (`umbra-net`)

- [ ] Pluggable Transports (Obfs4 and Snowflake WebRTC) integration for censored networks.
- [ ] Offline Mesh Protocol (BLE & Wi-Fi Direct DTN) for internet-less crisis environments.
- [ ] Nym Mixnet / Loopix delayed packet-mixing adapter.

## B.2 Asynchronous Group Encryption (`umbra-crypto`)

- [ ] PQ-MLS TreeKEM asynchronous group encryption engine for multiple cells (since no production-proven reference implementation exists yet, a research/prototyping phase is planned separately).

## B.3 Linux GUI & Advanced Client Security (`umbra-gui`)

- [ ] Wayland-only enforcement (`WAYLAND_DISPLAY` requirement).
- [ ] Modern Desktop GUI (`gtk4` + `libadwaita`).
- [ ] FIDO2 / YubiKey (PKCS#11 / NFC / USB) hardware-key verification.
- [ ] Dynamic visual masking: Scratch-to-Reveal (Anti-Shoulder Surfing).
- [ ] Decoy Vault: opening a fake profile with the Duress PIN and destroying data in the background.

## B.4 Android Client (`android/`)

- [ ] Building the Rust core for Kotlin/Compose with `uniffi`.
- [ ] Mandatory application of the `FLAG_SECURE` window flag to all screens.
- [ ] **Anti-FlagSecure-Bypass:** 60Hz/120Hz Temporal Pixel Interleaving drawing engine (its effectiveness and usability impact will be verified with real-device tests).
- [ ] **Accessibility Shielding:** Drawing directly with the Native Skia Canvas instead of standard UI text components (Empty AccessibilityNodeInfo).
- [ ] **Hardware DRM Surface:** GPU/TEE-encrypted `FLAG_HW_SECURE` buffers for images and videos.
- [ ] **Native Anti-Hook & Anti-Root:** A Rust-level `ptrace(PTRACE_TRACEME)` and `/proc/self/maps` library-injection sentinel.
- [ ] **60-Second Clipboard Destruction:** 60-second timeout and the `ClipDescription.EXTRA_IS_SENSITIVE = true` history block.
- [ ] **Zero-Knowledge Masked Notifications:** Zero-Knowledge Wakeup Ping and fake system notifications (`VISIBILITY_SECRET`).
- [ ] Android StrongBox / Keystore TEE biometric key protection.
- [ ] Accelerometer-based sudden-motion / snatch protection (`Motion Wipe`; the wipe time is a millisecond-scale target, not a guarantee — see ADR-009).
- [ ] Offline QR Code scanner and BLE Mesh background service.

## B.5 OS-Specific Deep Optimizations (`umbra-hardware` / `umbra-net`)

- [ ] **GrapheneOS `hardened_malloc` Integration:** `#[global_allocator]` on Linux and static linking of `libhardened_malloc.a` in the Android NDK.
- [ ] **Linux `io_uring` Async I/O:** Integration of zero-copy ring buffers in packet routing.
- [ ] **Linux Kernel Memory Flags:** Applying `MADV_DONTDUMP`, `MADV_DONTFORK`, `MADV_WIPEONFORK` to sensitive pages.
- [ ] **Linux x86_64 SIMD Vectorization:** Pure-Rust AVX2 and AVX-512 hardware acceleration for Kyber NTT and ChaCha20 (ADR-026; no C/assembly is used).
- [ ] **Wayland Direct Render:** Zero-latency 120Hz/144Hz UI drawing via `wl_shm` and DMA-BUF.
- [ ] **Android Zero-Copy JNI:** Eliminating Rust-Kotlin memory copies with `DirectByteBuffer`.
- [ ] **Android ARM64 NEON & Crypto SIMD:** Battery-efficient quantum cryptography with NEON vector instructions on aarch64.
- [ ] **Tickless Low-Power Poisson Timer:** A Doze-Mode-compatible, battery-friendly smart wake-up mechanism.

## B.6 Active Cyber Deception, Honeypots & Ghost Mode Infrastructure

- [ ] **Canary Memory Pages:** Fake X25519/Kyber key buffers and a `Silent Suicide` trigger upon access.
- [ ] **Cryptographic Tar-Pit:** A generator of exponential PoW difficulty and CPU-consumption traps for fake packets.
- [ ] **Hallucinated Fake Chat Module:** A Markov/LLM-free text simulator producing ordinary family/daily-life messages at the moment of a forensic dump.
- [ ] **Ghost Mode:** An isolated shadow mode that generates fake control flows and deceptive fake packets when a debugger is detected.

## B.7 Hardware & Side-Channel Tests

- [ ] **Hardware Port & IOMMU Tests:** Writing rule-verification tests for Linux `USBGuard` and Android USB Data Lockout.
- [ ] **Microarchitectural Protection:** Tests for `PR_SET_SPECULATION_CTRL` and cache-line eviction (`clflushopt`).
