# Umbra Code Review Standards

This document defines the mandatory quality, security, stability, and performance rules for every contribution, PR, and code change made to the **Umbra** project.

---

## ⚡ The Non-Negotiable Triad

### 1. 🔒 Security Review
- [ ] **Memory Wiping:** All structures containing cryptographic keys, temporary secrets, or messages implement `Zeroize` and `ZeroizeOnDrop`.
- [ ] **Constant-Time Comparisons:** `subtle::ConstantTimeEq` is used for token, MAC, or key comparisons, preventing timing attacks.
- [ ] **Zero Metadata Rule:** All packets sent over the network strictly conform to the 1024-byte fixed-block structure and are woven into the Poisson artificial cover traffic flow.
- [ ] **OS and Screen Isolation:** For Android, `FLAG_SECURE`, 60Hz/120Hz Temporal Pixel Interleaving, a custom Skia canvas (empty accessibility tree), a hardware DRM Surface, and pure-Rust `/proc/self/maps` anti-hook checks are implemented.
- [ ] **Clipboard and Notification Security:** 60-second automatic wiping, the `EXTRA_IS_SENSITIVE` clipboard-history block, the Zero-Knowledge wake ping, and Masked Generic Notifications (`VISIBILITY_SECRET`) are implemented.
- [ ] **Linux Isolation:** `Wayland`-only (`WAYLAND_DISPLAY` mandatory), `mlock`, Seccomp-BPF, and Landlock sandbox checks are fully implemented.
- [ ] **Dependency Security:** Every newly added dependency has passed the vulnerability and license audit (`cargo audit` / `cargo deny`).

### 2. 🛡️ Stability and Error Handling Review
- [ ] **Zero Panics:** Production code contains no `unwrap()`, `expect()`, or unchecked `panic!`.
- [ ] **Complete Error Types:** All errors are wrapped in explicit `thiserror`-based enum variants; no error is silenced (`let _ = ...` is forbidden).
- [ ] **Hermetic Tests:** Deterministic unit tests are written for crypto, packetization, and state machines; the tests do not depend on a live network or system.
- [ ] **Async Safety:** Deadlock and race condition risks in Tokio tasks are eliminated.

### 3. ⚡ Performance and OS Optimization Review
- [ ] **Zero Allocation:** In critical loops, needless `clone()`, `String`, and `Vec` allocations are avoided; references and slices (`&str`, `&[u8]`) are preferred.
- [ ] **Zero-Copy JNI / I/O:** `DirectByteBuffer` is used on Android and `io_uring`/`epoll` buffers on Linux; unnecessary `memcpy` steps are eliminated.
- [ ] **SIMD and Hardware Acceleration:** x86_64 AVX2/AVX-512 and ARM64 NEON vector instructions are verified for quantum matrix and symmetric encryption operations.
- [ ] **Kernel Memory Flags (`madvise`):** `MADV_DONTDUMP`, `MADV_DONTFORK`, and `MADV_WIPEONFORK` flags are applied to sensitive memory pages.
- [ ] **Battery and Doze Mode Efficiency:** Tor circuits and the Poisson scheduler are built with tickless asynchronous timers so that mobile battery is not drained.

### 4. 🪶 Anti-Bloat & Resource Review
- [ ] **Zero Memory Bloat:** The memory footprint has been profiled (Heaptrack/Valgrind); no structure consuming unnecessary memory at idle or under load has been added.
- [ ] **Zero Storage Clutter:** No temporary files, huge logs, or uncleaned database caches are written to disk; the default RAM-only rule is followed to the letter.
- [ ] **No Heavy Overhead:** Electron, unnecessary WebView layers, or bloated libraries that pull in hundreds of unneeded dependencies have not been introduced into the project.
- [ ] **Binary Discipline:** The compiled binary size is kept to a minimum with `strip`, `LTO`, and `opt-level = "z"` optimizations.

### 5. 🛑 Language Policy and Dependency Review
- [ ] **Allowed Safe Languages:** Changes include only **Rust** (core/crypto/Linux) and **Kotlin** (Android UI).
- [ ] **Zero C/C++ Rule:** No C/C++ source files or unsafe FFI modules directly linking C libraries have been introduced into the project; pure Rust libraries (`rustls`, `arti`) are used.
- [ ] **Zero JavaScript / Electron / Dynamic Scripting:** Web-based frameworks, npm modules, Python, and dynamic scripts are completely blocked.
- [ ] **Safe Rust Requirement (`#![forbid(unsafe_code)]`):** `#![forbid(unsafe_code)]` is active in the core, crypto, network, and protocol crates. Business logic contains no `unsafe`.
- [ ] **Hardware-Level-Only Unsafe Exception:** `unsafe` blocks appear only in isolated modules that directly touch physical hardware (`mlock`, TPM/TEE, YubiKey, TRNG).
- [ ] **`// SAFETY:` Documentation Requirement:** Every hardware-level `unsafe` block is preceded by a `// SAFETY: ...` docstring explaining the invariants (`-D clippy::undocumented_unsafe_blocks`).
- [ ] **Dependency Security Scanning (`cargo-geiger`):** Dependencies' `unsafe` usage has been scanned with `cargo geiger` and `cargo deny`, and libraries carrying memory risk have been rejected.

### 6. 📝 Mandatory Comments and Documentation Review
- [ ] **`#![deny(missing_docs)]` Compliance:** All public and private modules (`//!`), functions, structs, enums, and fields (`///`) are fully documented.
- [ ] **Explanatory Inline Comments (`// ...`):** Complex cryptographic formulas, state transitions, and timing mechanisms in function bodies have clear comments explaining *why* they were done that way.
- [ ] **Standard and RFC References:** The relevant NIST/RFC specification references (e.g. `// RFC 8439`, `// FIPS 203`) are added as comments to cryptographic and protocol algorithms.
- [ ] **Zero Uncommented Code:** No function or logical block in the PR has been left without explanation or rationale.

### 7. 🔍 Vulnerability, Fuzzing & Side-Channel Scanning Review
- [ ] **Static Vulnerability Scanning:** `cargo audit` and `cargo deny` have been run; no known vulnerabilities exist in the RUSTSEC/CVE databases.
- [ ] **LLVM Memory Sanitizer Verification:** New code has been compiled with the `AddressSanitizer` (ASan) and `UndefinedBehaviorSanitizer` (UBSan) flags and passes the tests with zero memory errors.
- [ ] **Fuzzing Mutation Testing:** Parser functions have been tested with `cargo-fuzz` (libFuzzer) against at least 10 million random mutation inputs, achieving zero crashes/panics.
- [ ] **Constant-Time and Side-Channel Scanning:** New crypto functions have been put through `dudect` statistical timing analysis ($p < 10^{-5}$) and Valgrind/Cachegrind cache-leak scanning.

### 8. 🧠 Logic, Invariants & Type Design Review
- [ ] **Typestate Pattern:** Invalid intermediate states are blocked at compile time; the type system makes it impossible to send unencrypted data to a socket.
- [ ] **Newtype Pattern:** Semantic types (`SequenceNumber`, `EpochId`) are used instead of primitive integers; meaningless comparisons are prevented.
- [ ] **Checked Arithmetic:** `checked_add`, `saturating_sub`, or `overflowing_add` are used instead of bare `+`/`-` operators.
- [ ] **Property-Based Testing:** `proptest` tests have been added and mathematical invariants are verified.
- [ ] **Mutation Testing Verification:** `cargo mutants` has been run; incomplete tests that fail to catch logical mutations have been eliminated.

### 9. 🐧 Unix Philosophy and Composability Review
- [ ] **Single Responsibility:** Every newly added module and CLI command serves a single purpose.
- [ ] **Pipeline Support (`Pipes`):** CLI commands can take input from `stdin` and produce pipeable data on `stdout`.
- [ ] **Rule of Silence (`Rule of Silence`):** Successful operations print no noise/banners to `stdout`; error and status logs are written to `stderr`.
- [ ] **Discrete Process Isolation:** The engine, UI, and media parser are cleanly separated by Unix process boundaries and sockets.

### 10. 📜 Code Craftsmanship Manifesto Review
- [ ] **Manifesto Compliance:** Changes strictly follow the 10 core principles in [`CODE_MANIFESTO.md`](CODE_MANIFESTO.md).
- [ ] **Compiler Flags:** The `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, and `-Z zero-call-used-regs=all` settings are preserved.
- [ ] **Global Allocator:** All memory allocations go through the GrapheneOS `hardened_malloc` global allocator.
- [ ] **Contributor Pledge:** The developer, mindful that the code protects users' lives and privacy, has committed to never compromising quality for the sake of convenience.
