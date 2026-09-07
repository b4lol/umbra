# Umbra — Project Summary and Scope

## 📌 Mission

**Umbra** aims to provide an independent, decentralized communication system DESIGNED to maximize anonymity and minimize metadata (design goals, not measured properties) with post-quantum security, for human-rights defenders, investigative journalists, diplomatic delegations, and intelligence professionals — even under the harshest digital surveillance and censorship regimes.

---

## 🎯 Target Audience and Threat Scenarios

1. **Investigative Journalists & Sources:**
   - *Risk:* Source exposure, tracking via phone number/IP, correlation of messaging times.
   - *Solution:* Zero personal-data registration, Tor v3 Onion-based IP hiding, and concealment of the very moment of communication through fixed-size artificial traffic.
2. **Diplomats and Senior Government Officials:**
   - *Risk:* Foreign intelligence services recording network traffic to decrypt it later with quantum computers (*"Harvest Now, Decrypt Later"*).
   - *Solution:* NIST-standard **ML-KEM (Kyber-768)** hybrid Post-Quantum Encryption (PQ-E2EE).
3. **Field Operatives and Intelligence Personnel:**
   - *Risk:* Physical seizure of the device, RAM dumping, screenshot capture by spyware.
   - *Solution:* RAM-only (diskless) mode, memory locking with `mlock`, the panic-wipe button, and the `FLAG_SECURE` screen block.

---

## 📊 Project Metadata

- **Project Name:** Umbra
- **License:** GPL-3.0-or-later (fully open source and open to independent audit)
- **Core Language:** Rust (2021 Edition)
- **Client Platforms:**
  - **Linux:** x86_64 and aarch64 (Wayland desktop GTK4 and headless Terminal TUI)
  - **Android:** Android 10+ (Jetpack Compose + Rust Core via UniFFI)

---

## 🧱 Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Core Engine** | Rust (`tokio`, `arti`, `zeroize`) | Memory safety, superior performance, cross-platform compilation |
| **Network / Transport** | Arti (the Tor Project's pure-Rust engine) | Embedded Tor v3 Onion P2P communication without any external C library |
| **Cryptography** | `ml-kem`, `ml-dsa` (pure-Rust RustCrypto), `x25519-dalek`, `chacha20poly1305` | NIST-approved post-quantum algorithms and industry-standard E2EE |
| **Linux UI** | GTK4 + Libadwaita & Ratatui (TUI) | Modern Wayland GNOME interface and a low-resource terminal interface |
| **Android UI** | Kotlin + Jetpack Compose + UniFFI | Native Android performance and hardware-backed security (`FLAG_SECURE`) |

---

## 🛑 Programming Language Policy (Strict Language Policy)

In the Umbra project, memory safety, type safety, and deterministic resource management are non-negotiable rules:

### ✅ Allowed Memory-Safe Languages
- **Rust (100% Safe Rust by Default & Isolated Unsafe Only for Hardware):**
  - **Core & Protocol Guarantee (`#![forbid(unsafe_code)]`):** `#![forbid(unsafe_code)]` is mandatory across all cryptography, state machines, the P2P Tor network layer, message parsing, and UI layers. All Umbra-OWNED Rust source carries memory safety at compile time (Safe Rust; the isolated `unsafe` exception is audited per ADR-012). Transitive C via the Tor stack (`ring`, bundled SQLite) is a recorded deviation (ADR-028).
  - **Single and Strict Exception (Direct Hardware Communication Only):** `unsafe` is allowed **only and exclusively in isolated modules that communicate directly with physical hardware and OS kernel/hardware interfaces** (`umbra-hardware` / `mlock` page locking, TPM/Secure Enclave chips, FIDO2/YubiKey USB-NFC raw hardware drivers, hardware TRNG).
  - **Hardware Unsafe Rules:**
    1. All `unsafe` calls are fully encapsulated (`encapsulated`) behind a 100% Safe wrapper API. No `unsafe` function may ever leak to the outside world.
    2. Every `unsafe` block must carry `// SAFETY: ...` documentation explaining the invariants for the compiler and auditors (`-D clippy::undocumented_unsafe_blocks`).
- **Kotlin (Android UI Only):**
  - Used only for the Android Jetpack Compose UI and Android OS service integration.
  - Binds directly to the Rust core through `UniFFI` with type safety and without C-ABI.

### ❌ Strictly Banned Languages
- **C and C++ (STRICTLY BANNED):**
  - Banned with zero tolerance due to manual memory management (`malloc`/`free`, raw pointers), buffer overflows, use-after-free, memory corruption, and undefined-behavior risks.
  - Umbra-owned C/C++ is banned; pure-Rust equivalents (`rustls`, `arti`) are mandatory for directly depended-on libraries. Transitive C inside the pure-Rust Tor stack (`ring`, bundled SQLite) is the single recorded deviation (ADR-028).
- **JavaScript / TypeScript / Node.js / Electron (STRICTLY BANNED):**
  - Banned due to V8 JIT engine vulnerabilities, massive dependency trees (npm supply-chain attacks), prototype pollution, and excessive RAM consumption.
- **Python / Ruby / PHP / Dynamic Scripting Languages (STRICTLY BANNED):**
  - Banned due to runtime ambiguity, weak type checking, unchecked memory, and leak risks.
- **Go (BANNED for Crypto and Core):**
  - Unusable in the core because garbage-collector pauses prevent `zeroize` memory wiping from being instantaneous and deterministic (risk of sensitive keys lingering in RAM).

---

## ⚡ The Non-Negotiable Core Doctrine

1. **🔒 Security:**
   - Cryptographic standards and zero-metadata principles cannot be stretched.
   - Every third-party library undergoes strict security and license review before being added.
   - `zeroize` and constant-time comparisons are mandatory in all encryption and key operations.

2. **🛡️ Stability:**
   - In mission-critical environments a single crash (panic/crash), data corruption, or async deadlock is unacceptable.
   - `unwrap()` and `expect()` are forbidden; all errors are handled through `thiserror`-based explicit types.
   - All parsing and network functions are secured with hermetic unit tests.

3. **⚡ Performance:**
   - Rust's zero-cost abstractions and async I/O architecture (`tokio`) target the lowest CPU usage and processing latency.
   - Tor circuits and the Poisson artificial packet flow run with high efficiency so they needlessly consume neither the device battery nor network resources.
   - Instant, deterministic response times are provided without garbage-collector (GC) latency.

4. **🪶 Prohibition of Excessive RAM, Storage, and Heavy Load (Anti-Bloat & Minimal Footprint):**
   - **Zero RAM Waste:** Memory bloat is absolutely unacceptable. Electron, needless web-based layers, or bloated frameworks consuming hundreds of megabytes are forbidden. Process RAM usage is bounded by hard memory caps.
   - **Zero Storage Clutter:** Massive log files, uncleanable residues, or unnecessary bloated databases must not be created on disk. Binary size is kept small with the most aggressive build optimizations (`LTO`, `strip`).
   - **Zero Heavy Load and Needless Background Consumption:** Unnecessary background services, inefficient polling loops, and bloated C/C++ external library dependencies are strictly rejected. Every byte and every CPU cycle must be mission-focused.

5. **📝 Mandatory Explanatory Comment and Documentation Doctrine:**
   - **`#![deny(missing_docs)]` Compiler Rule:** `#![deny(missing_docs)]` is mandatory in all crates. A single undocumented module (`//!`), function, struct, enum, or field (`///`) produces a compile error.
   - **Explanatory Comments for Every Piece of Code (`// ...`):** Not just *what* the code does but especially *why* it was designed that way (cryptographic rationale, memory-safety boundaries, Tor flow rules, RFC and NIST standard references) must be explained with detailed comments in every function and critical code block. Even a single uncommented line is not accepted.

6. **🔍 Mandate for Aggressive Software and Hardware Vulnerability Scanning on Every Change:**
   - **Software & Static Level:** Whenever new code or a feature is added, `cargo audit` (RUSTSEC/CVE), `cargo deny` (supply chain/license), `cargo geiger` (`unsafe` audit), and `cargo clippy -D warnings` run with zero tolerance.
   - **Dynamic Fuzzing & Sanitizers:** All protocol and media parsers are subjected to aggressive mutation testing with LLVM AddressSanitizer (ASan), MemorySanitizer (MSan), UndefinedBehaviorSanitizer (UBSan), and `cargo-fuzz` (libFuzzer).
   - **Hardware & Side-Channel Scanning:** Cryptographic functions are scanned with `dudect` (timing-leak analysis) and Valgrind/Cachegrind (cache side-channel simulation). If a single vulnerability or leak is detected, the code must absolutely not be merged.

7. **🧠 Doctrine for Preventing Logic Bugs and Invalid States (Logic Flaw & Invariant Prevention):**
   - **Type-Driven State Design (Typestate Pattern):** Invalid states are made impossible at compile time (*Make Illegal States Unrepresentable*). Unencrypted data cannot be handed to the network socket (`Plaintext` $\to$ `Ciphertext<1024>`), a session object (`AuthenticatedSession`) cannot be produced before the handshake completes, and boolean flag combinations are forbidden.
   - **Semantic Newtypes (Newtype Pattern):** `SequenceNumber(u64)`, `SessionEpoch(u32)` are used instead of primitive `u64`/`u32`; accidentally adding/comparing two different IDs is blocked by the compiler.
   - **Checked Arithmetic (Checked/Saturating Arithmetic):** Against overflow and logic bugs, `checked_add`, `saturating_sub` are mandatory instead of bare `+`, `-` operators.
   - **Property-Based Testing:** With `proptest`, all possible state combinations are verified through mathematical invariants.
   - **Mandatory Mutation Testing (`cargo-mutants`):** When logical operators in code lines are inverted (`>` $\to$ `<`, `==` $\to$ `!=`), the tests must fail immediately; incomplete tests that fail to catch mutations are rejected.

8. **🐧 Uncompromising Unix Philosophy Doctrine:**
   - **Do One Thing and Do It Well:** Every module, command-line tool, and service focuses solely on its single responsibility; monolithic bloat and needless functional sprawl are strictly rejected.
   - **Pipeline Compatibility and Composability (Composability via Pipes):** All CLI tools work directly with Unix pipes (`|`) (`cat message.txt | umbra send <dest>` or `umbra recv --json | jq .`).
   - **Rule of Silence (Silence is Golden):** Successful operations print no decorative logs or banners to `stdout`; only the requested data flows. Status logs and errors are routed to the `stderr` channel.
   - **Discrete Process Isolation (Rule of Separation):** The UI (GUI/TUI), Engine, and Media Sanitizer layers are cleanly separated from one another by Unix Domain Sockets (`AF_UNIX`) and process boundaries.
