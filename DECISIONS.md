# Umbra Architecture Decision Records (Architecture Decision Records - ADR)

This document explains the rationale behind the foundational technical and architectural decisions made in the development of the **Umbra** project.

---

## ADR-001: Pure-Rust "Arti" Instead of an External Tor Daemon

- **Status:** Accepted
- **Rationale:** Using the traditional C-language `tor` daemon would require external process management, root privileges, or complex IPC (Inter-Process Communication) mechanisms on Android and Linux.
- **Decision:** The Tor Project's pure-Rust `arti-client` will be embedded directly into the binary and compiled.
- **Addendum (2026-08, TODO A.2):** enabling `hs-pow-full` on `tor-hsservice` transitively enables the `__is_experimental` API unification on tor-hsservice/tor-hscrypto/tor-netdoc/tor-cell and pulls `equix`/`arrayvec`/`num-traits` (pure Rust — no new C surface beyond the recorded deviations above).
- **Addendum (2026-09, TUI live verification):** the outbound flows (`send --onion`, the TUI send path) additionally require arti-client's `onion-service-client` feature (`tor-hsclient` + `tor-hscrypto`, pure Rust — no new C surface beyond the recorded deviations). alpha.2 shipped WITHOUT it, so live outbound connects were refused at runtime; caught and fixed by the `tui_live` self-send test.
- **Consequence:** A portable, monolithic Tor client free of C memory errors is obtained, with no external system dependency at all.

---

## ADR-002: Post-Quantum Hybrid KEM (X25519 + ML-KEM-768)

- **Status:** Accepted
- **Rationale:** Although quantum computers are not yet widespread, state intelligence services are storing encrypted traffic aiming to break it in the future (*"Harvest Now, Decrypt Later"*). Moving to post-quantum algorithms alone carries risk on its own, because of the possible unknown mathematical weaknesses of the new algorithms.
- **Decision:** The proven, battle-tested X25519 ECDH and the NIST-standard ML-KEM-768 (Kyber) have been combined as a hybrid. The session key is derived from the shared secret of both.
- **Consequence:** Double assurance is provided against both existing classical cryptanalysis attacks and future quantum computers.

---

## ADR-003: Diskless (RAM-Only) Operation Mode by Default

- **Status:** Accepted
- **Rationale:** On NAND Flash and SSD disks, deleted data remains in blocks due to "Wear Leveling" and can be recovered by forensic analysis. Even encrypted databases like SQLCipher expose past messages when the key is compromised.
- **Decision:** Messages are, by default, never written to disk by Umbra processes (v1.0 Linux scope): they live in locked RAM (`mlockall`) and are destroyed with `zeroize` when the session ends. Residual: transport state (Arti guard/cache files) is intentionally persistent — see the README honest-scope table.
- **Consequence:** Even if the device is physically seized, forensic experts cannot reach any fragment of a message through the flash disk.

---

## ADR-004: Wayland-Only Support on Linux (Rejecting X11)

- **Status:** Accepted
- **Rationale:** The X11 architecture is inherently insecure; any ordinary background process running on the desktop can record the entire screen with `XGrabKey` or `XGetImage`, or steal keystrokes.
- **Decision:** The window manager is checked when the Linux client starts; if the system is X11, the app is not launched and the user is directed to a Wayland session.
- **Consequence:** Inter-process shoulder surfing and unauthorized screen-recording attacks are blocked at the OS level.

---

## ADR-005: 1024-Byte Fixed Size and Poisson Traffic Masking

- **Status:** Accepted
- **Rationale:** Even when end-to-end encrypted, packet sizes (for example, a 42-byte "OK" reply versus an 800-byte long message) and packet send times (metadata) give adversaries very serious intelligence through traffic analysis.
- **Decision:** All packets are fixed to exactly 1024 bytes with cryptographic padding, and dummy packets are pushed onto the wire with Poisson timing even when the queue is empty.
- **Consequence:** An observer on the network cannot analyze when users talk, message sizes, or correspondence frequency.
- **Note (v0.1.0-alpha, size masking):** MEDIA_CHUNK transfers pad media to the next power-of-two bucket (`umbra-protocol::media_chunk`), so an observer learns at most a 2x size bucket, not the exact length. Classifier-level fingerprinting additionally requires WTF-PAD (v2+, TARGETED_DEFENSES §3A).

---

## ADR-006: Stability, Security, Performance, and Resource Discipline Doctrine

- **Status:** Accepted (Foundational Principle / Inviolable Doctrine)
- **Rationale:** The lives and data integrity of journalists, diplomats, and intelligence officers are entrusted to this system. A vulnerability is life-threatening; a crash/hang leads to mission failure; poor performance, excessive RAM consumption, or disk clutter endanger the operation through battery drain, latency, or forensic leakage.
- **Decision:**
  - No "ease of use" (UX convenience) or feature-addition request may ever compromise security.
  - `unwrap()`, `expect()`, `unsafe` blocks (except documented `mlock` FFI), and swallowed errors in Rust code are strictly forbidden.
  - **Prohibition of Excessive RAM and Storage Consumption:** Electron, needless WebView layers, or heavy dependencies are strictly forbidden. Process RAM usage is bounded by strict caps; needless residue/logs must not be left on disk.
  - Resource consumption is always optimized with asynchronous execution and zero-cost abstractions.
- **Consequence:** The codebase is built to be deterministic, highly resilient, minimal-leak, lightweight, and high-performing; these goals are tracked with CI measurements (memory caps, leak tests, benchmarks).
- **Recorded deviation (cover pump):** `umbra-net::cover` swallows transient cover-packet send failures (`let _ = send`) — cover traffic must not reveal link health to an observer. Data-path errors are never swallowed.

---

## ADR-007: Strict Kernel Isolation with Linux Seccomp-BPF and Landlock

- **Status:** Accepted
- **Rationale:** Zero-day (0-day) spyware (Pegasus derivatives) has the ability to read in-process memory and manipulate the filesystem.
- **Decision:** At process startup, all unnecessary system calls (`execve`, `ptrace`, etc.) are blocked with `seccomp`, and all read/write access to the filesystem is closed off with `Landlock`.
- **Consequence:** Even if an unknown vulnerability exists in the codebase, the adversary cannot make a system call or reach files on disk.
- **Refinement (2026-08, TODO A.2):** the zero-FS ruleset gains exactly two sanctioned exception kinds: the controlling terminal `/dev/tty` (ReadFile+WriteFile+IoctlDev — crossterm raw mode needs termios ioctls and, with redirected stdin, an O_RDWR reopen) and the caller-supplied Tor storage directory for onion-service flows (narrowed grant: regular files/dirs only, no Execute/Make*/IoctlDev). Everything else stays denied; the handled set remains full V5 so no right becomes globally unrestricted.
---


## ADR-008: Anti-Censorship Pluggable Transports and Offline Mesh Mode

- **Status:** Accepted
- **Rationale:** Authoritarian regimes can block the Tor network with DPI or shut down the internet backbone entirely at moments of crisis (Blackout).
- **Decision:**
  - Obfs4 and Snowflake (WebRTC masking) will be integrated against DPI censorship.
  - During internet outages, the encrypted Off-Grid Mesh mode operating device-to-device over BLE and Wi-Fi Direct will engage.
- **Consequence:** Communication is sustained without interruption even in environments without internet or under heavy censorship.

---

## ADR-009: Hardware Security Key (FIDO2 / YubiKey) and Sudden-Motion Sentinel

> **Scope:** v2 per ADR-027 (tracked in TODO.md Section B); the FIDO2 gate and Motion Wipe are NOT implemented in v1.0.

- **Status:** Accepted
- **Rationale:** During physical dominance or a snatch-and-grab forcible taking of the phone, the device may remain unlocked.
- **Decision:**
  - Keys cannot be loaded into memory unless the optional FIDO2 / YubiKey (CC EAL6+) hardware key is plugged in.
  - On sudden accelerometer spikes or unauthorized USB insertion, RAM is zeroed as soon as possible (`Motion Wipe`). The target is millisecond scale; however, a fixed duration cannot be guaranteed due to sensor latency and timer resolution, and this boundary is measured with tests.
- **Consequence:** Even if the device is physically stolen, the adversary finds only locked/wiped memory.

---

## ADR-010: Deniable Fake Profile with the Decoy Vault

- **Status:** Accepted
- **Rationale:** The user can be compelled to give up the password under torture or coercion (*Rubber-Hose Cryptanalysis*).
- **Decision:** A secondary "Duress PIN" is defined. When this PIN is entered, fake, realistic conversations are shown while the real data is permanently deleted in the background. The goal is the impossibility of proving the real profile's existence (*plausible deniability*); the strength of this goal is verified through design review and expert assessment.
- **Consequence:** The user's physical safety is preserved and the other side is prevented from becoming suspicious.

---

## ADR-011: Safe Programming Language Policy and the Absolute Ban on C/C++/JS/Dynamic Languages

- **Status:** Accepted (Foundational Rule / Mandatory Invariant)
- **Rationale:**
  - Historically, over 70% of software vulnerabilities (per Microsoft and Chromium security reports) stem from memory-management errors in C and C++ (Buffer Overflow, Use-After-Free, Memory Corruption).
  - JavaScript / TypeScript / Node.js and Electron are unsuitable for mission-critical security architectures due to V8 JIT vulnerabilities, prototype pollution, the massive npm supply-chain (Supply Chain) attack surface, and excessive memory consumption.
  - Dynamic languages such as Python / Ruby carry runtime type ambiguity and unchecked memory.
  - Go's automatic garbage collector (GC) prevents `zeroize` memory wiping from being instantaneous.
- **Decision:**
  - **Allowed Safe Languages:** Only **Rust** for the system core, cryptography, network layer, and Linux clients; only **Kotlin** for the Android UI.
  - **Strictly Banned:** C, C++, JavaScript/TypeScript, Electron, Python, Ruby, PHP, and other dynamic languages entering the project directly or indirectly is strictly prohibited.
  - External C libraries (`OpenSSL`, `libcurl`, the C `tor`, etc.) are rejected outright; pure-Rust equivalents (`rustls`, `arti`) are mandatory.
- **Consequence:** Safe Rust provides memory safety at compile time for all non-`umbra-hardware` code; the classic memory-corruption and JIT vectors are removed from that surface (residual: the isolated `unsafe` in `umbra-hardware`, audited per ADR-012).

---

## ADR-012: Safe Rust Mandate and the Hardware-Level Isolated Unsafe Exception

- **Status:** Accepted (Absolute and Binding / Inviolable Rule)
- **Rationale:** Uncontrolled use of `unsafe` blocks in general logic can import the memory-safety risks of C/C++ into the project. However, OS-kernel FFI calls are unavoidable for talking directly to physical hardware (RAM pages `mlock`, TPM/TEE Secure Enclave, FIDO2/YubiKey USB-NFC, hardware TRNG).
- **Decision:**
  - **General Rule:** Root-level `#![forbid(unsafe_code)]` is mandatory in the core engine, cryptography, protocol, and network crates. Not a single `unsafe` may exist in business logic.
  - **Hardware Exception:** `unsafe` is allowed **only and exclusively in isolated hardware driver modules that communicate directly with physical hardware**.
  - **Mandatory Safety Criteria:**
    1. Every `unsafe` block will be fully encapsulated behind a 100% Safe public API.
    2. Every `unsafe` block will document the compiler invariants with a `// SAFETY:` explanation (`-D clippy::undocumented_unsafe_blocks`).
    3. `unsafe` usage in external dependencies will be scanned with `cargo-geiger` and `cargo-deny`.
- **Consequence:** While over 99% of the codebase is protected by Safe Rust at compile time, hardware-level critical operations are managed safely with full auditability and transparency.

---

## ADR-013: Mandatory Explanatory Comments and the `#![deny(missing_docs)]` Doctrine

- **Status:** Accepted (Absolute and Binding / Mandatory Invariant)
- **Rationale:** In high-grade intelligence and security applications, "cryptic", unexplained code with unclear rationale carries the risk of a potential backdoor (Backdoor) or an overlooked vulnerability. Independent auditors and developers must fully understand the security purpose of every line.
- **Decision:**
  - **`#![deny(missing_docs)]` Compiler Rule:** `#![deny(missing_docs)]` and `#![warn(clippy::missing_docs_in_private_items)]` are enforced in all crates. No undocumented function, struct, or module can compile.
  - **In-Code Explanatory Comment Mandate:** Not only `///` docstrings; within every function, critical steps, cryptographic formulas, RFC/NIST references, and memory-management decisions must be explained with explanatory inline comments (`// ...`) in Turkish/English.
  - Writing uncommented, unexplained code will be rejected in CI pipelines.
- **Consequence:** The codebase gains a highly transparent, easily auditable structure with high educational value and clear reliability expectations.

---

## ADR-014: OS-Specific Deep Optimizations and SIMD Acceleration

- **Status:** Accepted
- **Rationale:** Post-quantum cryptography (ML-KEM/Kyber) and the continuous Poisson cover-traffic flow can cause excessive CPU, memory bandwidth, and mobile battery consumption in unoptimized environments.
- **Decision:**
  - **Linux Optimization:** `io_uring` zero-copy async I/O, `MADV_DONTDUMP`/`MADV_DONTFORK` memory locks, x86_64 AVX-512/AVX2 vector acceleration, and direct Wayland rendering will be used.
  - **Android Optimization:** ARM64 NEON & Crypto extensions, the `DirectByteBuffer` zero-copy JNI bridge, the StrongBox Keymaster hardware chip, and a tickless smart Doze Mode timer will be applied.
  - **Binary Optimization:** `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, and `strip = true` will deliver minimal binary size and zero garbage-collector pauses.
- **Consequence:** The system reaches the highest cryptographic speed on both desktop and mobile with minimal energy and memory consumption.

---

## ADR-015: View-Once Media by Default, Screen-Recording Block, and Universal Cryptographic Destruction in 24 Hours (Crypto-Shredding)

- **Status:** Accepted
- **Rationale:** In case devices are eventually seized, the accumulation of past chat and media records on the device creates a massive intelligence risk. Also, users' screen-recording or second photo-opening attempts can lead to source exposure.
- **Decision:**
  - **View-Once Photos by Default:** All photos are encrypted with single-use $EFK$ keys; the moment the dialog is closed, they are wiped from RAM and the key is destroyed.
  - **Advanced Screen-Recording Block:** When screen capture is detected with the Android 14+ `ScreenCaptureCallback`, open media is deleted instantly (`Emergency Media Eviction`) and the image is blacked out on virtual-display/mirroring connections. On Linux, all capture protocols other than Wayland are rejected.
  - **Universal Irreversible Destruction in 24 Hours:** Without exception, all messages, photos, videos, voice recordings, and files are permanently destroyed after **24 Hours (1 Day)** by destroying the $EFK$ keys via Tor Consensus Time and `CLOCK_MONOTONIC_RAW` (`Crypto-Shredding`) and by NIST SP 800-88 3-pass overwriting.
- **Consequence:** Even if the device is seized, no data, message, or media older than 24 hours should be recoverable — ASSUMING the AEAD holds and every $EFK$ key copy is destroyed (crypto-shredding).

---

## ADR-016: Multi-Layer Screen and Hardware DRM Protection Against the Android `FLAG_SECURE` Bypass

- **Status:** Accepted
- **Rationale:** Android's standard `FLAG_SECURE` flag can be easily bypassed with root (Magisk/KernelSU), LSPosed `DisableFlagSecure` modules, Frida dynamic hooking, and `AccessibilityService` exploits. Trusting OS flags is insufficient against state-sponsored adversaries.
- **Decision:**
  - **60Hz/120Hz Temporal Pixel Interleaving:** Texts and images will be split into 2 complementary half-frames and painted to the screen at a frequency the human eye will merge but a screenshot will capture as meaningless noise in a single frame.
  - **Custom Skia Native Canvas:** Standard Android text components will be abandoned; texts will be drawn directly with pixels, and screen-reader spyware will be blocked by leaving the `AccessibilityNodeInfo` tree completely empty.
  - **Hardware DRM/TEE GPU Surface:** Media images will be processed in hardware-encrypted `SurfaceHolder.SURFACE_TYPE_HARDWARE` / `FLAG_HW_SECURE` buffers.
  - **Pure-Rust Anti-Hook Detection:** The microsecond LSPosed/Frida injection is detected via `ptrace(PTRACE_TRACEME)` and `/proc/self/maps` inspection, RAM will be zeroed and the process terminated.
- **Consequence:** Even if `FLAG_SECURE` is bypassed, the readability of the resulting screenshot is significantly degraded and collection of UI texts through the accessibility tree is blocked. The effectiveness of these mechanisms (especially the impact of temporal pixel interleaving on real screen-capture hardware and usability) will be verified with real-device tests in the v2+ phase.

---

## ADR-017: Targeted Vulnerability Prevention and Pinpoint Defense Architecture

- **Status:** Accepted *(the §Zero-Click Media Isolation subprocess variant is v2+ scope per ADR-027; the MVP ships the in-process deterministic sterilizer in `umbra-protocol::media`)*
- **Rationale:** Generic security controls (input validation, standard encryption) fall short against Pegasus, NSO Group, state-level DPI, and side-channel (Side-channel) attacks. Low-cost pinpoint architectural defenses specific to each attack vector are required.
- **Decision:**
  - **Zero-Click Media Isolation:** Image parsing will be moved out of the main process to a single-use subprocess with a 2 MB RAM limit, locked with `Landlock` and `Seccomp`.
  - **Encrypted-in-RAM Rings:** Data will be kept encrypted in RAM with AES-NI, decrypted only in the CPU L1 cache, and evicted instantly with `clflushopt`.
  - **Masked Kyber & Dual SIMD Verification:** Polynomial masking and dual-channel parallel execution will be applied against side-channel and Rowhammer attacks.
  - **WTF-PAD & Vanguards-Lite:** Markov adaptive padding and the 3-layer pinned Guard topology will engage against traffic-analysis and Guard-discovery attacks.
- **Consequence:** Advanced intelligence and zero-day exploitation vectors are significantly hindered at the hardware and logic levels at low performance cost; the effectiveness target of each defense is measured with its own test suite.

---

## ADR-018: 1-Minute Automatic Clipboard Destruction and Zero-Knowledge Masked Notification Architecture

- **Status:** Accepted
- **Rationale:** Sensitive keys or texts copied to the clipboard can leak into keyboard history or to spyware. Standard notification systems, meanwhile, expose message contents and sender information to the OS and to spyware apps granted `NotificationListenerService`.
- **Decision:**
  - **1-Minute Clipboard Destruction:** All data transferred to the system clipboard will be wiped and cleaned by being zeroed with `0x00` under a 60-second asynchronous counter. On Android, clipboard history will be blocked with `EXTRA_IS_SENSITIVE = true`. By default, data will be kept in an isolated in-app buffer.
  - **Zero-Knowledge Notifications:** Wake-up signals arriving over the network will carry no text; only masked generic texts (e.g., *"System Update Completed"*) will be delivered to the OS (Android `NotificationManager` / Linux D-Bus). The actual message will be drawn from secure RAM only when the user opens the app with biometric verification.
- **Consequence:** Clipboard leaks are bounded to 60 seconds and archiving is blocked; notification-listening spyware obtains zero data about real communication.

---

## ADR-019: Full-Stack Hardware, Kernel, and Network Anti-Leak Architecture

- **Status:** Accepted
- **Rationale:** Providing security only at the application layer can leave the system defenseless against cellular Baseband DMA attacks, BadUSB/Thunderbolt memory dumps, DNS/IPv6 leaks, and kernel-level privilege escalation (LPE) vulnerabilities.
- **Decision:**
  - **Hardware Isolation:** The cellular modem's direct memory access will be blocked with IOMMU/SMMU; external port attacks will be blocked with Linux `USBGuard` and Android `USB Data Lockout`.
  - **Kernel-Level Kill-Switch:** With `nftables` / Android `VpnService`, ALL TCP/UDP/IPv6 packets outside Tor will be `DROP`ped at the hardware level.
  - **Kernel Hardening:** The `kptr_restrict = 2`, `yama.ptrace_scope = 3`, and `dmesg_restrict = 1` kernel parameters will be enforced.
- **Consequence:** The leak surface and DMA attack surface are minimized across the entire stack from hardware to the UI; forensic resistance is significantly increased and verified with leak tests.

---

## ADR-020: Mandatory Aggressive Multi-Layer Vulnerability Scanning on Every Code Change

- **Status:** Accepted (Absolute and Binding / Mandatory Invariant)
- **Rationale:** A single overlooked integer overflow, timing leak, or insecure dependency update can bring down the entire post-quantum and zero-trust architecture. Vulnerability scanning must not be a periodic check; it must be a binding gate (Gatekeeper) for every commit and PR.
- **Decision:**
  - **Static & AST Scanning:** `cargo audit` (RUSTSEC/CVE), `cargo deny` (License/Bans), and `cargo geiger` (`unsafe` code audit) are mandatory on every code addition.
  - **Dynamic Fuzzing & Memory Sanitizers:** All network and protocol parsers must pass mutation tests with LLVM AddressSanitizer (ASan), MemorySanitizer (MSan), UndefinedBehaviorSanitizer (UBSan), and `cargo-fuzz` (libFuzzer).
  - **Hardware & Side-Channel Scanning:** Cryptographic functions will be subjected to constant-time (timing leakage) analysis with `dudect` and to cache-access leak simulation with Cachegrind.
- **Consequence:** Memory risks, timing leaks, and vulnerable dependencies are scanned and measured at the CI gates on every commit; a single detected finding blocks the merge.

---

## ADR-021: Prevention of Logic Errors and Invalid States Through Type-Driven Design and Mutation Testing

- **Status:** Accepted (Absolute and Binding / Mandatory Invariant)
- **Rationale:** Even with memory safety achieved, business logic, state-machine inconsistencies, or protocol ordering errors (Logic Bugs / Flaws) can lead to critical security vulnerabilities. Logic errors must be made impossible not at runtime but at compile time via the type system and mathematical tests.
- **Decision:**
  - **Typestate Pattern:** All invalid intermediate states will be made impossible at compile time (*Make Illegal States Unrepresentable*). Unencrypted data (`Plaintext`) cannot be sent directly to the network; a `Session` object cannot be created without authentication.
  - **Newtype Protection:** Semantic types (`SequenceNumber`, `EpochId`) will be used instead of primitive integers.
  - **Checked Arithmetic:** `checked_add`, `saturating_sub` are enforced instead of bare `+`, `-` operators.
  - **Property-Based & Mutation Tests:** Mathematical invariants will be verified with `proptest`; tests that fail to catch logical-operator mutations with `cargo-mutants` will be rejected.
- **Consequence:** Human-caused logic errors at the protocol and business-logic level are minimized with the type system and test layers; the residual risk is measured with the mutation-test score and property-based test coverage.

---

## ADR-022: Compliance with the Uncompromising Unix Philosophy, Pipability, and Composability

- **Status:** Accepted
- **Rationale:** Monolithic, closed CLI tools and subsystems block integration with automation scripts (scripts) and other Unix tools (`jq`, `grep`, `tar`, `awk`); they damage the system's transparency and auditability.
- **Decision:**
  - **Do One Thing Well:** Every module and CLI command will have a single responsibility.
  - **Pipes & Streams:** Full data piping support over `stdin`/`stdout` will be provided (`cat payload | umbra send <peer>` / `umbra recv --json | jq .`).
  - **Rule of Silence:** Successful operations will print no needless banners or decorative text to `stdout`; logs will flow only to `stderr`.
  - **Process Separation:** The UI, engine, and media sanitizer will be isolated with Unix Domain Sockets and separate process boundaries.
- **Consequence:** The Umbra CLI and engine become both a powerful standalone application and a deterministic pipeline component that composes flawlessly with Unix system tools.

---

## ADR-023: GrapheneOS `hardened_malloc` Memory Allocator Integration (Linux & Android)

- **Status:** Accepted
- **Rationale:** Standard system memory allocators (`glibc malloc`, `jemalloc`, Android `scudo`) do not provide sufficient deterministic protection against heap overflow (*Heap Overflow*), Use-After-Free (UAF), Double-Free, and heap metadata corruption.
- **Decision:**
  - **Global Allocator (Rust & Linux):** The GrapheneOS `hardened_malloc` library will be used as `#[global_allocator]` in the Rust core.
  - **Android JNI Integration:** In the Android native binary (`libumbra_native.so`), `libhardened_malloc.a` will be statically linked to harden the JNI and Rust heap space.
  - **Protection Mechanisms:** `PROT_NONE` guard pages, out-of-line metadata, automatic zeroing on free (`zero_on_free`), and the UAF-preventing quarantine queue will be enforced.
- **Consequence:** On both Linux and Android platforms, the probability of success of heap-based memory exploits is significantly reduced through hardware/page-level protections.

---

## ADR-024: Active Cyber Deception, Honeypot Traps, and Ghost Mode Architecture

- **Status:** Accepted
- **Rationale:** No software can theoretically be 100% flawless and unhackable. When advanced adversaries (Pegasus/Zero-Click) infiltrate the process or hook memory, the system must not be left defenseless; active cyber deception mechanisms that mislead, occupy, and paralyze the adversary are required.
- **Decision:**
  - **Canary Honeypots:** Fake key pages will be kept in memory; the moment they are touched, the real keys will be destroyed and fake packets fed to the adversary (*Silent Suicide*).
  - **Cryptographic Tar-Pit (Tar-Pit):** When fake key packets are attempted to be decrypted, infinite PoW/mathematical traps that drain the adversary's processor resources will engage.
  - **Hallucinated Fake Messages:** When a forced memory dump is taken, convincing fake everyday chats will be simulated.
  - **Ghost Mode:** When anti-debug is detected, the process will neither crash nor raise an alarm; it will keep the reverse engineer busy for days by producing fake control flows and fake responses.
- **Consequence:** Even at the moment of a breach or intrusion, the adversary's access to real data is significantly hindered; the adversary faces misleading disinformation and drained processor resources.

---

## ADR-025: Zero Data Leakage and Multi-Layer Anti-Exfiltration Architecture

- **Status:** Accepted (Absolute and Binding / Mandatory Invariant)
- **Rationale:** No matter how strong the encryption; there is a risk of data leaking via the swap space, core dumps, CPU register residues, DNS/IPv6/WebRTC leaks, DMA ports, and cache side channels. Leak channels must be closed completely at the hardware and kernel level.
- **Decision:**
  - **Memory Locks:** `mlockall`, `prctl(PR_SET_DUMPABLE, 0)`, `MADV_DONTDUMP`, `MADV_DONTFORK`, `MADV_UNMERGEABLE`, and the compiler flag `-Z zero-call-used-regs=all` will be enforced. *(2026-08 revision note: the register-zeroing flag was removed from rustc upstream (nightly 1.100.0) without stabilization — MITIGATED via a best-effort explicit `asm!` register scrub in `umbra-hardware::hardening` at sensitive boundaries (PQXDH root derivation, skipped-key consumption, `GuardedBuffer::drop`); residuals documented in TODO A.4. The memory-lock clauses are enforced.)*
  - **Network Leak Block:** ALL TCP/UDP/IPv6 traffic other than the local Arti Tor SOCKS5 will be `DROP`ped in the kernel; system DNS will be bypassed entirely.
  - **Hardware Isolation:** Baseband DMA will be segregated with IOMMU/SMMU; data ports will be blacked out with Linux `USBGuard` and Android `USB Data Lockout`.
  - **Microarchitectural Protection:** `PR_SET_SPECULATION_CTRL` and `clflushopt` cache eviction will be applied.
  - **Hardening Order (refinement):** Memory locks (`mlockall`, `PR_SET_DUMPABLE`, `RLIMIT_CORE`) apply BEFORE any keystore or peer-record read so identity secrets are born inside the locked, non-dumpable region; the Landlock zero-FS sandbox and the Seccomp allowlist apply immediately AFTER those reads complete (keystore and peer files are the only FS accesses a session command ever makes).
- **Consequence:** The data and metadata leak surface is minimized at every layer; the residual leak risk is measured with leak-test suites and continuously monitored through CI.

---

## ADR-026: Switch to Pure-Rust Post-Quantum Crates (Resolving the `pqcrypto-*` Contradiction)

- **Status:** Accepted (Extension / Correction of ADR-011)
- **Rationale:** ADR-011 strictly bans C and C++ code from entering the project, directly or indirectly. However, the `pqcrypto-kyber`, `pqcrypto-dilithium`, and `pqcrypto-sphincsplus` crates referenced in earlier specifications wrap the PQClean project's C and assembly implementations. This directly contradicts the language policy; it also adds a C compiler dependency to the build chain and an additional memory-unsafe code surface that must be audited.
- **Decision:**
  - For ML-KEM-768, RustCrypto's pure-Rust **`ml-kem`** crate will be used; for ML-DSA-65, **`ml-dsa`**; and for SLH-DSA, the **`slh-dsa`** crate. The `pqcrypto-*` family is rejected as a dependency.
  - NIST FIPS 203/204/205 compliance of these crates will be verified with Known-Answer Test (KAT) vectors, and their constant-time behavior with `dudect` analysis.
  - The AVX2/NEON acceleration need will be met with pure-Rust vector code (`std::simd` or approved pure-Rust SIMD crates); C/assembly optimizations will not be used.
- **Consequence:** An end-to-end Safe Rust cryptographic stack fully compliant with the language policy is obtained, and the C build-chain dependency disappears. Affected documents: `CRYPTOGRAPHY.md`, `TODO.md`, `PROJECT.md`.

---

## ADR-027: MVP Prioritization and Deferral of the v2+ Scope

- **Status:** Accepted- **Rationale:** The total scope (Android client, GTK4 GUI, BLE/Wi-Fi Direct mesh, Pluggable Transports, the Nym mixnet adapter, PQ-MLS TreeKEM, the active cyber deception layer, hardware side-channel defenses, and OS deep optimizations) is multi-year work on a single development line; some items, such as PQ-MLS, do not yet have a production-proven reference implementation. Making all of it a v1.0 requirement risks deliverability. Additionally, absolute security claims in the documents such as "100%", "unbreakable", and "impossible" are unmeasurable and indefensible in an independent audit.
- **Decision:**
  - **MVP (v1.0) Scope:** Core cryptography (PQXDH + Double Ratchet), Tor v3 onion P2P over Arti, 1024-byte fixed packet framing + Poisson cover traffic, SAS/SMP verification, the media metadata sterilizer, the Linux TUI, basic memory/kernel hardening (Seccomp, Landlock, `mlock`, kill-switch), and the test/fuzz/CI infrastructure.
  - **v2 and Later:** The Android client, GTK4 GUI, advanced client defenses such as FIDO2/Decoy Vault, the BLE/Wi-Fi Direct mesh, Obfs4/Snowflake, the Nym adapter, PQ-MLS TreeKEM, the active deception layer, hardware side-channel defenses, and OS deep optimizations. These items are not cancelled; they are tracked in `TODO.md` Section B.
  - **Measurability Rule:** Security claims are written with measurable targets instead of absolute statements (e.g., "constant-time behavior is verified with `dudect`", "the Motion Wipe target is millisecond scale, not a guarantee").
- **Consequence:** A deliverable and auditable v1.0 definition is obtained; deferred items are not lost and are explicitly tracked as the v2+ scope. Affected documents: `TODO.md`, `ROADMAP.md`, `TARGETED_DEFENSES.md`.

---

## ADR-028: Accepted C-Bearing Transitive Dependencies of the Tor Stack (Deviation from ADR-011)

- **Status:** Accepted (Documented Deviation / Exception to ADR-011)
- **Rationale:** ADR-011 bans C and C++ from the project's own code and direct dependencies. The embedded Arti Tor stack (ADR-001) is nonetheless unavoidable for censorship-resistant transport, and its TLS and storage layers transitively require C-bearing components that have no pure-Rust replacement in the current ecosystem: `ring` (audited C/assembly crypto provider required to select a rustls 0.23 `CryptoProvider`) and the bundled C SQLite via `cc` (arti `static` feature). Rejecting them would mean shelling out to an external C `tor` daemon — strictly worse under ADR-001.
- **Decision:**
  - C-bearing dependencies are permitted **only** as transitive dependencies of the feature-gated `tor` transport in `crates/umbra-net`; no Umbra crate may link them directly for its own cryptography or storage.
  - Umbra's own cryptography stays 100% pure-Rust RustCrypto (ADR-026 unchanged); the `crates/umbra-hardware` FFI exception (ADR-012) is unchanged.
  - `ring` is selected explicitly (single CryptoProvider) to keep the choice auditable.
  - Same-deviation scope: `seccompiler` (Landlock/Seccomp sandbox frontend, pure Rust with internal `unsafe` BPF emission) is accepted under this ADR as a transitive exception; Umbra-owned crates remain `#![forbid(unsafe_code)]`.
  - This deviation is revisited on every Tor-stack dependency bump; if a pure-Rust provider (e.g., a RustCrypto TLS backend) becomes viable, the deviation is retired.
- **Consequence:** The "no C" policy is scoped to Umbra-owned code paths with an audited, minimal, feature-gated transitive exception; CI license/audit scanning (cargo-deny, cargo-audit) continues to cover the C-bearing components.

---

## ADR-029: Identity Generation Return-Slot Transit Is a Documented Residual (Resolves TODO A.1 "Zero-Copy Identity Generation")

- **Status:** Accepted (Design decision; residual documented, not eliminated)
- **Context:** TODO A.1 asked to eliminate the copy made when `IdentityBundle::generate()` returns its value, because the return-slot bytes transit the stack before reaching their final home (keystore serialization or in-memory session state).
- **Decision:**
  - Safe Rust provides no control over return-slot placement or move elision; a value of this size is memcpy'd through stack space by the ABI.
  - Guaranteeing zero transit would require `unsafe` placement tricks (out-of-place allocation via raw pointers), which (a) violate the language policy of confining `unsafe` to `umbra-hardware` (ADR-011/ADR-012), (b) add correctness risk to key-generation code, and (c) yield no measurable reduction in leak surface given the ADR-025 layers below.
  - The compensating controls are therefore the accepted mitigation set: `mlockall` (no swap), `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0` (no core images), `MADV_DONTDUMP` on guarded buffers, and `zeroize`-on-drop for all key material. Stack-transit bytes are wiped only by page reuse — accepted because the process never writes them to disk and cannot be introspected without ptrace-class access, which the seccomp allowlist denies (ADR-007; ADR-019 documents the ptrace-scope layer).
- **Consequence:** TODO A.1's "zero-copy identity generation" is closed as a documented residual. Any future placement-return stabilization in Rust (`&out` parameters, placement protocols) may be revisited for v2.
