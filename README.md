# Umbra (Shadow)

**Zero-Trust, Zero-Metadata, Post-Quantum Anonymous Communication System**

`Umbra` is an end-to-end encrypted communication protocol and client designed for journalists, government officials, and intelligence professionals operating in the highest-threat environments; it is serverless (centralized-server-free), built on zero-metadata principles, and leaves no IP or identity trace.

---

## 🛡️ Core Features

- **Serverless P2P:** No central server, relay, or registration database exists. Communication takes place directly between devices over Tor v3 Onion services.
- **Zero-PII Identity:** No phone number, e-mail, username, or SIM card is required. Identity is a cryptographic key pair generated entirely on-device.
- **Full IP Isolation (Tor Onion v3):** All connections are routed through the embedded **Arti** (pure-Rust Tor) engine. The IP addresses of both sender and receiver are completely hidden from the network and from each other.
- **Post-Quantum Hybrid Encryption (PQ-E2EE):** Against the future decryption threat of quantum computers (*"Harvest Now, Decrypt Later"*), the **X25519 + ML-KEM (Kyber-768)** hybrid handshake and the **Double Ratchet** protocol are used.
- **Traffic-Analysis and Metadata Protection:**
  - Fixed-size (1024 byte) packet framing (*Fixed-size Padding*).
  - Poisson-distributed artificial/cover traffic (*Cover Traffic*).
  - The timing, frequency, and data size of communication are masked against ISP/nation-state-level observers.
- **View-Once Media by Default:**
  - All photos are encrypted with single-use $EFK$ keys; the moment the dialog is closed or the finger is lifted, they are wiped from RAM (`zeroize`) and the key is destroyed. Re-opening is impossible.
- **Advanced Screenshot and Recording Prevention:**
  - **Android:** `FLAG_SECURE` + 60/120Hz Temporal Pixel Interleaving + Android 14+ `ScreenCaptureCallback` (*Emergency Media Eviction*) + Custom Skia Canvas (Empty Accessibility Tree) + Hardware DRM/TEE Surface.
  - **Linux:** **Wayland** only (X11 strictly forbidden) + outright rejection of PipeWire/Portal screen-capture requests.
- **60-Second Ephemeral Clipboard:**
  - Data copied to the clipboard is wiped with `zeroize` and removed from the clipboard after 60 seconds; on Android, `EXTRA_IS_SENSITIVE` blocks clipboard history.
- **Zero-Knowledge Unreadable Notifications:**
  - Silent wake-up over Tor (Zero-Knowledge Ping); the OS is NEVER given the actual message text or sender identity; only generic masked system notifications (e.g., *"System Update"*) are delivered.
- **Universal Automatic Cryptographic Destruction in 24 Hours (Crypto-Shredding):**
  - Without exception, all messages, photos, videos, voice recordings, and documents are automatically destroyed after **24 Hours (1 Day)**.
  - NIST SP 800-88 3-pass overwrite (`0xFF`, `0x00`, random) + $EFK$ key destruction + clock-tampering protection via Tor Consensus Time (Anti-Clock Tampering).
- **Memory-Level Security (GrapheneOS `hardened_malloc` & RAM-Only):**
  - **GrapheneOS `hardened_malloc`** is used as the global memory allocator on both Linux and Android (`PROT_NONE` guard pages, out-of-line metadata, slab quarantine, `zero_on_free`).
  - Messages are never written to disk by default; they are kept only in RAM locked with `mlock`.
  - With `zeroize`, keys and messages are securely erased from memory the instant processing finishes.
  - Emergency Panic Button (*Duress Wipe*) and Decoy Vault (*Decoy Vault*).
- **Target Platforms:** **Linux** (Desktop / TUI) and **Android** only.

---

## 🏛️ Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      UI Layer                               │
│   Linux: GTK4/Libadwaita / TUI  │  Android: Jetpack Compose │
└──────────────────────────────┬──────────────────────────────┘
                               │ UniFFI / Rust FFI
┌──────────────────────────────▼──────────────────────────────┐
│                    Umbra Core Engine (Rust)                 │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Cryptography Layer                                    │  │
│  │ • PQXDH (X25519 + ML-KEM/Kyber-768)                   │  │
│  │ • Double Ratchet & ChaCha20-Poly1305                  │  │
│  │ • Deniable Authentication & Secure Memory (zeroize)   │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Metadata & Traffic Masking                            │  │
│  │ • 1024-byte Fixed-Block Packet Framing                │  │
│  │ • Poisson-Distributed Artificial/Cover Traffic        │  │
│  │ • Out-of-band QR Pairing (SAS/SMP Verification)       │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Network & Anonymity Layer                             │  │
│  │ • Arti (Embedded Pure-Rust Tor v3 Hidden Services)    │  │
│  │ • P2P Streaming & NAT-Free Socket Management          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📚 Documentation Index

| Document | Description |
|---|---|
| [`PROJECT.md`](PROJECT.md) | Project mission, vision, target-audience analysis, language policy, and technical scope. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System architecture, data-flow diagrams, sandbox layer, and module designs. |
| [`SPECIFICATION.md`](SPECIFICATION.md) | 1024-byte binary packet format, byte offsets, state machine, and FFI interface specification. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Nation-state-level threat model, Pegasus analysis, and defense mechanisms. |
| [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) | PQXDH, ML-KEM-768, ML-DSA-65, Double Ratchet, PQ-MLS TreeKEM, and deniable authentication. |
| [`NETWORK_PROTOCOL.md`](NETWORK_PROTOCOL.md) | Fixed packet structure, Tor v3 P2P communication protocol, Pluggable Transports, and Off-Grid Mesh mode. |
| [`CLIENT_SECURITY.md`](CLIENT_SECURITY.md) | Android (`FLAG_SECURE`, TEE) and Linux (Wayland, `mlock`, Seccomp, Landlock, Decoy Vault) security hardening. |
| [`HARDWARE_SECURITY.md`](HARDWARE_SECURITY.md) | Baseband IOMMU isolation, USBGuard / Port Lockout, Cold-Boot Anti-Tamper, and CC EAL6+ FIDO2 hardware binding. |
| [`TARGETED_DEFENSES.md`](TARGETED_DEFENSES.md) | Pinpoint defenses against zero-click (Pegasus), side-channel (EM/cache), Rowhammer, Sybil, WTF-PAD, and memory-injection attacks. |
| [`OS_OPTIMIZATIONS.md`](OS_OPTIMIZATIONS.md) | Deep optimization specification for Linux (`io_uring`, `madvise`, AVX-512/AVX2) and Android (Zero-Copy JNI, ARM64 NEON, Doze Mode, StrongBox). |
| [`ROADMAP.md`](ROADMAP.md) | Development phases, releases, and the strategic roadmap. |
| [`TODO.md`](TODO.md) | Step-by-step implementation task checklist. |
| [`DECISIONS.md`](DECISIONS.md) | Architecture Decision Records (all foundational decisions from ADR-001 to ADR-025). |
| [`ZERO_DATA_LEAKS.md`](ZERO_DATA_LEAKS.md) | Zero data leakage and absolute anti-exfiltration defense specification. |
| [`CODE_MANIFESTO.md`](CODE_MANIFESTO.md) | Manifesto on code writing, code quality, and engineering excellence. |
| [`CODE_REVIEW.md`](CODE_REVIEW.md) | Security, Safe Rust, anti-bloat, and mandatory-comment standards for code reviews. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Developer guide, build environment, and contribution rules. |
| [`SECURITY.md`](SECURITY.md) | Security policy and responsible vulnerability disclosure guidelines. |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history and change records. |
| [`GLOSSARY.md`](GLOSSARY.md) | Glossary of all technical, cryptographic, network, and security terms. |

---

## 🚀 Core Development Doctrine (Non-Negotiable Principles)

1. **Security, Stability, and Performance Are Never Compromised:**
   - **Security:** No convenience or user-experience (UX) trade-off may ever lower the cryptographic bar, memory hygiene, or the zero-metadata rule.
   - **Stability:** In mission-critical environments a single panic/crash, memory leak, or hang is unacceptable. The codebase is built with 100% error handling and hermetic tests.
   - **Performance & Zero Bloat:** Zero-cost abstractions, asynchronous I/O, minimal memory footprint, and zero garbage-collector (GC) pauses are essential.
2. **Prohibition of Excessive RAM, Storage, and Heavy Load (Anti-Bloat & Resource Discipline):**
   - **Minimal RAM Footprint:** Bloaty frameworks that consume megabytes of memory (Electron etc.), needless dynamic allocations (`clone()`), and memory leaks are strictly forbidden. Deterministic, ultra-low RAM usage both idle and under load is essential.
   - **Zero Storage Clutter:** Massive temporary files, bloated databases, uncleanable caches, or needless logs must not be created on disk. Binary size is aggressively optimized (`strip`, `LTO`).
   - **Zero Overhead:** Unnecessary background services, polling loops, and heavy external dependencies that burn CPU cycles and battery are rejected.
3. **Safe Programming Languages and the Safe Rust Doctrine (Safe Rust with Isolated Hardware Unsafe):**
   - **Safe Rust Mandate (`#![forbid(unsafe_code)]`):** The core engine, cryptography, P2P network layer, protocol, and Linux clients must be written in `100% Safe Rust` (`#![forbid(unsafe_code)]`).
   - **Single Isolated Exception (Direct Hardware Communication Only):** `unsafe` is permitted only in isolated modules that touch physical hardware/the kernel (`mlock` memory locking, TPM/Secure Enclave, FIDO2/YubiKey USB-NFC, hardware TRNG), only when encapsulated behind a `100% Safe API` and documented with `// SAFETY:`.
   - **Android UI:** Only the type-safe, memory-safe **Kotlin** (Jetpack Compose).
   - **Strictly Forbidden:** C and C++ (due to buffer overflows, Use-After-Free, memory corruption); JavaScript/Electron (due to V8 vulnerabilities, npm supply-chain risks, and RAM bloat); Python and dynamic languages are banned with zero tolerance.
4. **Never Trust (Zero-Trust):** The network, the OS's other services, and intermediate nodes are considered compromised at all times.
5. **Metadata Is Data:** Who talks to whom and when is as critical as message content; it is fully masked.
6. **No Footprint:** When the app is closed or the emergency code is entered, no data recoverable by forensic analysis remains on the device.
7. **Mandatory Explanatory Comments for All Code (`#![deny(missing_docs)]`):** Every module, function, struct, enum, and logical block in the project must carry complete explanatory comments and docstrings. Comment-free, unexplained code is not accepted.
8. **Mandatory Aggressive Vulnerability Scanning on Every Code Change:** Every new line of code must pass `cargo-audit`, `cargo-deny`, `cargo-geiger`, the LLVM Sanitizers (`ASan`/`MSan`/`UBSan`), `cargo-fuzz` mutation tests, and `dudect` constant-time/side-channel analysis with zero errors.
9. **Doctrine for Preventing Logic Bugs and Invalid States:** With the Typestate Pattern (*Make Illegal States Unrepresentable*), Newtype wrappers, `checked_add`/`saturating_sub` arithmetic, `proptest` property-based tests, and `cargo-mutants` mutation tests, logic errors are eliminated mathematically and at the type level.
10. **Uncompromising Unix Philosophy Doctrine:** "Do one thing and do it well", pipability (`stdin`/`stdout`/`stderr`), the Rule of Silence (*zero noise*), parseable JSON streams, and process isolation are applied without compromise.
