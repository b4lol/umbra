# Umbra Task and TODO List

This list contains the technical tasks planned for the step-by-step implementation of the project.

> **Scope Note (ADR-027):** Tasks are divided into two sections by delivery priority.
> - **Section A — MVP (v1.0):** Core cryptography, the Arti P2P network, protocol masking, the Linux TUI, and basic security/test infrastructure. v1.0 is released with exactly this scope.
> - **Section B — v2 and Later:** Android client, GTK4 GUI, mesh/mixnet, PQ-MLS, active deception, and hardware side-channel defenses. These items are not cancelled; they are planned for after v1.0.

---

# Section A — MVP (v1.0) Scope

## A.1 Rust Workspace & Core Cryptography (`umbra-crypto`)

- [ ] Creating the Cargo Workspace (`crates/umbra-crypto`, `crates/umbra-net`, `crates/umbra-protocol`, `crates/umbra-cli`, `crates/umbra-gui`, `crates/umbra-ffi`).
- [ ] Classical Diffie-Hellman key-pair management with `x25519-dalek`.
- [ ] Pure-Rust (RustCrypto) `ml-kem` (ML-KEM-768) and `ml-dsa` (ML-DSA-65) integration (ADR-026; C-based `pqcrypto-*` wrappers are not used).
- [ ] Implementation of the hybrid PQXDH handshake protocol.
- [ ] Double Ratchet state machine and KDF chains.
- [ ] `ChaCha20-Poly1305` AEAD encryption and `subtle::ConstantTimeEq` timing protection.
- [ ] Secure memory hygiene with `zeroize` and guard pages.

## A.2 Network & Transport (`umbra-net`)

- [ ] Pure-Rust Tor v3 Hidden Service (`.onion`) P2P communication with `arti-client`.

## A.3 Protocol & Metadata Masking (`umbra-protocol`)

- [ ] 1024-byte fixed-block packet framing (`Packetizer`) and cryptographic random padding.
- [ ] Poisson-distributed artificial cover-traffic generator (`PoissonTimer`).
- [ ] Media Metadata Sterilizer (EXIF, GPS, color-profile stripping and pixel re-encoding).
- [ ] Socialist Millionaire Protocol (SMP) and SAS code verification engine.

## A.4 Linux Security & TUI (`umbra-cli`)

- [ ] Linux `seccomp-bpf` syscall filtering and `Landlock` zero-filesystem-access sandboxing.
- [ ] Security-focused, low-resource Terminal TUI (`ratatui`).
- [ ] Clipboard manager with a 60-second auto-destruct.
- [ ] Linux D-Bus masked generic notification adapter (`org.freedesktop.Notifications`).
- [ ] **Memory Leak Locks:** `mlockall`, `prctl(PR_SET_DUMPABLE, 0)` and `MADV_DONTDUMP`/`MADV_DONTFORK` integration.
- [ ] **CPU Register Zeroing:** Adding the LLVM `-Z zero-call-used-regs=all` rule to the build configuration.
- [ ] **DNS & IPv6 Blocking:** Verification of the absolute kernel/nftables-level `DROP` of UDP 53 and IPv6.

## A.5 Quality, Test & Security Verification Infrastructure

- [ ] **Continuous Fuzzing Harness:** Setting up libFuzzer tests with `cargo-fuzz` for the 1024-byte packet parser and the PQXDH handshake state machine.
- [ ] **LLVM Memory Sanitizer Integration:** Adding AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) test stages to the CI pipeline.
- [ ] **Constant-Time Analysis Suite:** Automating timing-leak scanning of cryptographic functions with the `dudect`-based Welch t-test.
- [ ] **Typestate Pattern Library:** Enforcing packet states (`Unauthenticated` $\to$ `HandshakeInProgress` $\to$ `EstablishedSession`) at the type level.
- [ ] **Newtype Wrappers:** Strongly typing all critical IDs and counters such as `SequenceNumber`, `EpochId`, `RatchetStep`.
- [ ] **Property-Based Test Suite:** Writing cryptographic invertibility and Double Ratchet sequence-unbrokenness tests with `proptest`.
- [ ] **Mutation Testing Pipeline:** Auditing the catch rate of logical-operator mutations with `cargo mutants` in CI.
- [ ] **Standard Pipeline Support:** Making the `umbra send` and `umbra recv` commands fully process `stdin`/`stdout` byte streams.
- [ ] **Rule of Silence Audit:** Testing that successful CLI commands print no banners to `stdout` and that logs go to `stderr`.
- [ ] **JSON/NDJSON Parseable Streams:** Output support compatible with standard Unix tools (`jq`, `awk`) via the `umbra --json` flag.

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
