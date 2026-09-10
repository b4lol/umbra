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

---

## ADR-030: External Pluggable Transport Proxies — the Unmanaged (SOCKS5) Model, with a Scoped C Exception for a Future Standalone Proxy

- **Status:** Accepted (TODO B.1; includes a scoped, owner-granted exception to ADR-011)
- **Rationale:** Authoritarian DPI blocks the Tor network itself; pluggable transports (obfs4-class) disguise the guard/bridge connection. Arti 0.45 supports two PT models: *managed* (Arti spawns an external binary — impossible under Umbra's Seccomp no-`execve` allowlist and Landlock zero-FS sandbox, and banned by ADR-011) and *unmanaged* (an OS-managed proxy exposes a loopback SOCKS5 endpoint; Arti merely connects to it). The unmanaged model slots into Umbra's existing guarantees with zero sandbox changes: a loopback TCP connection is already permitted by the Seccomp IPv4-STREAM rule, and no filesystem access is involved.
- **Decision:**
  - Umbra supports PTs **exclusively** through unmanaged, loopback-only SOCKS5 endpoints (`TransportConfigBuilder::proxy_addr`, non-loopback rejected fail-closed) plus user-supplied bridge lines. Umbra never spawns, links, loads, or audits PT code; the proxy's lifecycle belongs to the OS/administrator.
  - The `managed-pts` arti feature (binary spawning) and any in-process FFI binding of PT code are **rejected**: the former violates the sandbox, the latter would import `unsafe`/C into the process image that `#![forbid(unsafe_code)]` (ADR-012) reserves for `umbra-hardware`.
  - **Scoped C exception (owner-granted, 2026-09):** a future standalone PT-proxy component (its own repository directory, build, isolation, and audit gate — e.g. an obfs4 client written in C) MAY be written in C as a recorded deviation from ADR-011, because no maintained pure-Rust or C PT client library exists (reference implementations are Go; the Rust `obfs4` crate is unaudited 0.1.x self-labeled not production-ready). The exception covers ONLY that separate component, running as an OS-managed process; nothing non-Rust is ever linked into or spawned by an Umbra binary. Snowflake remains **blocked** (no Rust or C client exists).
  - PT support is meaningless without bridge addresses; bridge lines are user-supplied operational secrets and are read pre-sandbox like peer records (ADR-025 ordering).
- **Consequence:** Censorship resistance becomes possible without weakening the process-sandbox or language doctrines; the C surface, if it ever lands, is confined to a separate, separately-audited process that Umbra talks to over loopback SOCKS5. Live censorship-path testing requires a real bridge and is tracked separately from the hermetic CI gates.
- **Addendum (2026-09, obfs4 handshake increment):** the scoped C exception now covers two third-party C crypto libraries, chosen BECAUSE they are the audited, constant-time upstreams the Go reference itself relies on:
  - **libsodium** (ISC, system package): X25519 ECDH, HMAC-SHA256, HKDF-SHA256, SHA-512, CSPRNG, constant-time compare, `sodium_memzero`.
  - **Monocypher 4.0.3** (CC0/BSD-2, vendored under `components/pt-proxy/vendor/monocypher/` with the tarball SHA-256 recorded in the README): Elligator 2 and the "dirty" X25519 basepoint multiplication ONLY. This is not optional decoration — the deployed obfs4 wire format requires dirty public keys, and Go's own `x25519ell2` is explicitly derived from Monocypher, so the vendored copy is what makes byte-exact interop possible. Vendored files build with a relaxed warning set (no `-Wconversion`/`-Werror`; documented in the Makefile) but keep all exploit mitigations and sanitizer gates; our own `src/` keeps the full hardening set.
  - Correctness is anchored to the Go reference by byte-exact test vectors dumped from lyrebird (`components/pt-proxy/tests/vectors_fixtures.h`, regeneration recipe in `components/pt-proxy/tests/govectors/`); `make vectors` is a merge gate alongside the ASan/UBSan build.

---

## ADR-031: Mesh-Mode Seccomp Profile — A Scoped Widening of the IPv6/UDP Kill-Switch

- **Status:** Accepted (TODO B.1)
- **Rationale:** The default Seccomp kill-switch (`restrict_syscalls`, ADR-019/TODO A.4) allows `socket()` only for `(AF_INET, SOCK_STREAM)` and `(AF_UNIX, SOCK_STREAM)` — IPv6 and any `SOCK_DGRAM` are EPERM'd at the kernel level, by design, for every hardened command. The Wi-Fi Direct mesh transport (spec: ADR-031 in DECISIONS.md) needs BOTH: `(AF_INET6, SOCK_STREAM)` for the P2P link (IPv6 link-local addressing, chosen specifically because it needs no DHCP daemon — `execve` is banned) and `(AF_UNIX, SOCK_DGRAM)` for `wpa_supplicant`'s control-interface protocol.
- **Decision:** Rather than loosen the default kill-switch for every command, `send --mesh` and `serve-mesh` install a SEPARATE profile (`restrict_syscalls_mesh`) that adds exactly those two narrow `(domain, type)` rules on top of the unchanged base allowlist. Every other hardened command (`send` without `--mesh`, `recv`, `serve --onion`, `tui`) keeps calling `restrict_syscalls` and is completely unaffected — verified by `crates/umbra-cli/tests/sandbox_seccomp.rs`'s existing `ipv6_and_udp_sockets_are_blocked` test staying green, unmodified.
- **Consequence:** Mesh mode is strictly opt-in at the process level — a command that never requests it never gains any additional socket surface. The mesh profile itself is still a fail-closed allowlist (unlisted syscalls EPERM), not a general loosening: `crates/umbra-cli/tests/sandbox_seccomp_mesh.rs` proves IPv6 `SOCK_DGRAM`/`SOCK_RAW` and IPv4 `SOCK_DGRAM` (UDP/DNS) remain blocked even under the mesh profile.

---

## ADR-032: `umbra-nym-cli` as a Fully Separate Cargo Workspace, the `blake3` 1.8.3 Pin, and a Scoped Seccomp Widening for Nym

- **Status:** Accepted (TODO B.1)
- **Rationale (workspace isolation):** `nym-sdk` 1.21.6 pulls in `nym-bandwidth-fetcher` 1.21.6 as a mandatory, non-optional dependency, which in turn pulls `sqlx-sqlite` 0.8.6 → `libsqlite3-sys` `^0.30.1`. The already-shipped `tor` feature (ADR-028) pulls `arti-client` → `tor-dirmgr` → `rusqlite` → `libsqlite3-sys` 0.37.0. Both paths set the `links = "sqlite3"` key, and Cargo's `links` uniqueness rule permits only ONE version of a `links`-key crate in a given dependency graph. This was not a theoretical concern: a first attempt to add `nym-sdk` directly as a dependency of `umbra-net` failed to resolve, with Cargo reporting the `links` conflict directly. No version of `nym-sdk` 1.21.x and no version of arti's Tor stack current at time of writing share a compatible `libsqlite3-sys` range, and neither upstream project treats its SQLite dependency as swappable.
- **Decision:**
  - `crates/umbra-nym-cli` (binary `umbra-nym`) is its own standalone Cargo workspace — it declares its own `[workspace]` in its `Cargo.toml` and is **never** added to the root `Cargo.toml`'s `members` list. This gives it a fully independent dependency graph and lockfile, so its `libsqlite3-sys` 0.30.1 never has to coexist with the main workspace's 0.37.0 in a single resolve.
  - This was verified empirically before being adopted as the fix: throwaway probe crates (since deleted) confirmed that a standalone workspace resolves cleanly end-to-end, before any real `umbra-nym-cli` source was written.
  - `umbra-nym-cli` reuses `umbra-cli`'s existing `pairing`/`peers`/`keystore`/`sandbox` modules directly as a library path-dependency (`umbra-cli` as a `[dependencies]` path entry) — no extraction into a shared crate and no duplication of that logic was necessary or done.
  - **Consequence of the split:** there is no single `umbra` binary offering `--nym` alongside `--onion`/`--mesh`. An operator who wants Nym transport builds and runs the separate `umbra-nym` binary, built via its own manifest path (see `crates/umbra-nym-cli/README.md`). This is a permanent architectural constraint, not a temporary gap — it is retired only if a future `nym-sdk` release drops the SQLite-backed bandwidth fetcher or the Tor stack drops its C SQLite dependency (see ADR-028's own revisit clause).
- **Rationale (`blake3` pin move, 1.8.7 → 1.8.3):** `nym-crypto` 1.21.6 requires `blake3 >=1.7,<1.8.4`. `umbra-crypto`'s `blake3.workspace = true` resolves against the ROOT workspace's pin regardless of which consumer wants it, so satisfying `nym-crypto`'s upper bound (in `umbra-nym-cli`'s independent graph, which does not even share a lockfile with the root — but the root pin itself was moved down to keep both graphs on a mutually defensible, currently-supported line rather than diverge silently) meant moving the root pin from `blake3 = "1.8.7"` to `blake3 = "1.8.3"`.
- **Decision:** Before landing the downgrade, its security-changelog implications were checked directly rather than assumed safe: `blake3` 1.8.7 had dropped its `arrayref` dependency specifically in response to RUSTSEC-2026-0260, a confirmed crates.io supply-chain compromise of `arrayref` 0.3.10 (deleted from the registry roughly 86 minutes after publication). Downgrading to `blake3` 1.8.3 reintroduces `arrayref` as a dependency, but the resolver locks it to `arrayref` 0.3.9 — inside the advisory's own declared-safe boundary (`unaffected = ["<=0.3.9"]`). This was independently confirmed two ways: `cargo audit` reports zero vulnerabilities against the resulting lockfile, and direct inspection of the crates.io index confirms version 0.3.10 is fully absent from the registry (not merely yanked). No other `blake3` 1.8.4–1.8.7 changelog entry was found to be security- or correctness-relevant to `umbra-crypto`'s actual usage (`keyed_hash`/`derive_key` only; the `traits-preview` feature is not enabled).
- **Consequence:** The main workspace's `blake3` pin is one version lower than the latest release, tracked as a standing constraint of the Nym integration rather than a stale-dependency oversight; it is revisited whenever `nym-crypto` widens its `blake3` bound.
- **No ADR-011 exception required:** unlike ADR-028 (Tor's transitive `ring`/SQLite) and ADR-030 (pt-proxy's obfs4 C component), this integration's full crypto dependency chain was verified to be pure Rust: `nym-crypto`, `libcrux-curve25519`, and `libcrux-psq` come from Cryspen's formally-verified (hacspec/F*-derived) `libcrux`, and `nym-bls12_381-fork` is a fork of zkcrypto's pure-Rust `bls12_381` (not the C-based `blst`). No deviation from ADR-011 is recorded for this plan.
- **Rationale (Seccomp widening for `umbra-nym-cli`):** the default hardened profile's socket allowlist (`(AF_INET, SOCK_STREAM)` and `(AF_UNIX, SOCK_STREAM)`) was sufficient for the entire mixnet connection with no widening at all — `nym-sdk`'s gateway/mixnode connections are plain TCP. What DID need widening, discovered empirically against Nym's real Sandbox testnet rather than assumed up front, was the base non-socket syscall list: `nym-client-core-surb-storage`'s directory setup calls raw `mkdir(2)`, SQLite's unix VFS calls raw `unlink(2)` when clearing WAL/journal sidecar files, and `nym-pemstore` calls raw `chmod(2)` after writing identity key files.
- **Decision:** `umbra-nym-cli` installs `restrict_syscalls_nym()`, which adds exactly three syscalls — `SYS_mkdir`, `SYS_unlink`, `SYS_chmod` (the raw, non-`*at` variants) — on top of `umbra-cli`'s shared base allowlist, and reuses the SAME two socket rules as the main workspace's default `restrict_syscalls()` (no `AF_INET6`/`SOCK_DGRAM` widening, unlike ADR-031's mesh profile). To avoid maintaining a second copy of the base list, `umbra-cli`'s `allowed_syscalls()`, `install_filter`, and `socket_rule` were bumped from private to `pub` — a purely additive visibility change with zero behavior change to `restrict_syscalls()` or `restrict_syscalls_mesh()` — so `umbra-nym-cli` calls the shared base list directly instead of duplicating it.
- **Consequence:** The Nym profile is its own separate, narrowly-scoped fail-closed allowlist, isolated to the separate `umbra-nym` binary; every command in the main `umbra` binary is completely unaffected by its existence.
- **Residual: `umbra-nym-cli`'s own independent lockfile carries its own unresolved advisories.** Because this crate has a fully separate `Cargo.lock` (the whole point of this ADR's isolation), it also needs its own, separate `cargo audit` pass — the main workspace's audit (Task 1 of this plan) never touches it. Run directly against `crates/umbra-nym-cli/Cargo.lock`, `cargo audit` reports 4 hard vulnerabilities, all transitive from `nym-sdk`'s own pinned dependency tree, none touching the `blake3`/`arrayref` pair addressed above: `h2` 0.3.27 (RUSTSEC-2026-0258, unbounded empty DATA frames / DoS), and `rustls-webpki` 0.101.7 (RUSTSEC-2026-0098, RUSTSEC-2026-0099, RUSTSEC-2026-0104, certificate-validation bugs) — plus 4 unmaintained-crate warnings (`bincode`, `derivative`, `proc-macro-error2`, `rustls-pemfile`). Separately, `rsa` 0.9.10 is present in the same tree and carries RUSTSEC-2023-0071 (the "Marvin Attack" timing side-channel, no upstream fix exists for any `rsa` version); this specific advisory's entry does not surface as a flagged line in a plain `cargo audit` run against this lockfile (its RustSec record carries no version-range data for the tool's matcher to key on), but it is a real, well-known, ecosystem-wide, currently-unpatchable issue applicable to any consumer of the `rsa` crate, this one included. None of this is a defect introduced by Umbra's own code: these are `nym-sdk`'s own transitive dependency choices, and no clean fix is available within this project's scope (patching `h2`/`rustls-webpki` independently would mean fighting `nym-sdk`'s own pinned tree; `rsa`'s advisory has no patched version to move to at all). Tracked as an upstream-dependency residual to revisit at `nym-sdk`'s next version bump, not something this plan attempts to "fix" directly.

---

## ADR-033: `umbra-group` (PQ-MLS Group "Cell" Encryption) — Single Workspace, Whole-Blob Persistence, the Connection-Type Marker, and the Partial-PQ Ciphersuite Caveat

- **Status:** Accepted (TODO B.2)
- **Rationale (no separate Cargo workspace needed):** ADR-032 put `umbra-nym-cli` in its own standalone workspace because `nym-sdk`'s bandwidth-fetcher chain *mandatorily* pulls a native SQLite (`libsqlite3-sys` via `sqlx-sqlite`), which collides via Cargo's `links = "sqlite3"` uniqueness rule with the Tor stack's own `libsqlite3-sys` version (ADR-028). `openmls` 0.9.0 presents the same shape of risk — it ships an optional `sqlite-provider` feature (`openmls_sqlite_storage` → `rusqlite`) — but unlike `nym-sdk`'s bandwidth fetcher, that feature is genuinely optional: the crate also ships a pure in-memory `libcrux-provider` path (`openmls_libcrux_crypto` + `openmls_memory_storage`), and `umbra-group`'s root `Cargo.toml` entry sets `default-features = false, features = ["libcrux-provider"]`, so `sqlite-provider` is never enabled and `rusqlite`/`libsqlite3-sys` never enter `umbra-group`'s dependency graph at all (confirmed: `cargo tree -p umbra-group -e normal` contains no `-sys` crate, no `ring`, no `rusqlite`). A second, subtler trap was found and avoided during Task 1: enabling openmls's *own* `draft-ietf-mls-pq-ciphersuites` feature (needed to unlock the X-Wing ciphersuite) resolves through a Cargo "weak dependency feature" edge (`openmls_sqlite_storage?/draft-ietf-mls-pq-ciphersuites`) that forces the resolver to version-select `openmls_sqlite_storage` just to validate the feature forward — even with `sqlite-provider` itself off — which reproduces the exact `libsqlite3-sys` version conflict against the Tor stack. The fix was to enable that same feature on `openmls_libcrux_crypto` directly instead (whose own feature definition forwards it to `openmls_traits`/`openmls_memory_storage` via ordinary, non-weak `pkg/feature` edges with no SQLite reference at all), letting Cargo's feature unification apply it to the same `openmls_traits` instance `openmls` itself uses. With both traps avoided, `umbra-group` lives in the root workspace as an ordinary member, with no lockfile-isolation tax and no separate-binary UX cost.
- **Rationale (whole-`MlsGroup`-blob persistence, not a hand-implemented `StorageProvider`):** the original task plan assumed `MlsGroup` implements `Serialize`/`Deserialize` directly; verified false under this workspace's feature set (those impls are gated behind `migration-import`/`test-utils`, neither enabled). The only real persistence seam OpenMLS exposes is its `openmls_traits::storage::StorageProvider` trait, and `MlsGroup::load` reconstructs a group by issuing seven-plus separate typed lookups against that trait (`group_epoch_secrets`, `own_leaf_index`, `message_secrets`, `resumption_psk_store`, `mls_group_join_config`, `own_leaf_nodes`, `group_state`), not by deserializing a single blob. Hand-implementing that 80-plus-method trait ourselves (the shape a "do it properly" persistence layer would take) was rejected as disproportionate engineering for what this feature needs. Instead, `crates/umbra-group/src/persistence.rs` exploits a specific, verified fact about the already-used in-memory backend: `openmls_memory_storage::MemoryStorage` is `pub struct MemoryStorage { pub values: RwLock<HashMap<Vec<u8>, Vec<u8>>> }` — one public field, no `#[non_exhaustive]` — so `save_group_state` locks it, clones the map out, and serializes it (with the group's MLS `GroupId` and Umbra's own `GroupRoster`) into one small AEAD-encrypted wrapper (`PersistedState`); `load_group_state` deserializes that wrapper, rebuilds a fresh `MemoryStorage` from the map, and (since `openmls_libcrux_crypto::Provider`'s own constructors always pair a fresh crypto backend with a fresh, empty storage — no constructor accepts caller-supplied storage) assembles a minimal `RestoredProvider` around the restored storage and a freshly instantiated, stateless `CryptoProvider`. This works only because `MemoryStorage`'s map layout happens to be a serialization-friendly implementation detail of the backend OpenMLS ships today, not a documented public contract — a future OpenMLS release is free to change it, at which point this persistence layer would need to be revisited (accepted trade-off: implementing all 80-plus `StorageProvider` methods correctly, including the SQLite backend's own on-disk schema, was judged far more implementation and audit risk than depending on one already-verified struct shape).
- **Rationale (the connection-type marker byte — first wire-protocol change since inception):** `umbra-net::messenger`'s two-party wire format has, until this increment, always begun a stream with the raw PQXDH handshake blob — there was never a concept of "what kind of connection is this" because there was only ever one kind. Adding group traffic onto the SAME transport primitives (raw TCP/Tor/mesh streams, `serve.rs`'s single inbound loop) required a way for a receiver to distinguish an incoming PQXDH handshake from an incoming PQ-MLS frame before either payload is parsed. The change (commit `dee1726`) is deliberately the smallest possible one: `send_text_stream` now writes a single leading marker byte (`CONNECTION_TYPE_PQXDH = 0x00`) before the handshake blob it always sent; a new `peek_connection_type` reads that one byte and returns an enum (`PqxdhHandshake` for `0x00`, `GroupFrame` for the new `CONNECTION_TYPE_GROUP = 0x01`, `TransportError::Unsupported` for anything else); `receive_message` itself is unchanged and still expects the marker to already be consumed by the caller. Every existing receiver (`serve.rs`'s `inbound_loop`, `mesh_serve.rs`, `umbra-nym-cli`'s `receive_via_nym`) was updated to call `peek_connection_type` first. This is a breaking wire-format change in principle, but scoped so narrowly (one prefix byte, one new reserved value, all four receivers updated in the same commit) that the existing PQXDH regression suite plus a new marker-specific test (`crates/umbra-net/tests/messenger.rs`) cover it directly — a peer running pre-marker code and a peer running post-marker code are NOT wire-compatible, which is acceptable because Umbra has no released/deployed version with external users to stay compatible with yet.
- **Rationale (partial-PQ ciphersuite — a real caveat, not a hidden gap):** `umbra-group` uses `Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` — X-Wing (the IETF-draft hybrid combining X25519 and ML-KEM-768) for the KEM/HPKE side of TreeKEM, but classical **Ed25519** for leaf-node and message signatures. This is the entire post-quantum-adjacent surface OpenMLS 0.9.0 ships: `draft-ietf-mls-pq-ciphersuites` currently defines hybrid KEM ciphersuites only, because the wider MLS ecosystem has no standardized post-quantum *signature* ciphersuite yet (no ML-DSA/SLH-DSA MLS ciphersuite exists in the draft as implemented here). Concretely, this means: an adversary who both harvests today's group traffic **and** later breaks classical ECDLP (a future large quantum computer) could forge leaf-node credentials and MLS handshake messages retroactively, even though the message *content* stays protected by the hybrid KEM's PQ leg. This is the same asymmetric posture ADR-002's PQXDH hybrid avoids for two-party sessions (which pairs ML-KEM with ML-DSA-class assurance via `umbra-crypto`'s own layer, not MLS's); `umbra-group`'s posture is weaker specifically because it delegates entirely to what OpenMLS's ciphersuite catalog offers rather than layering Umbra's own PQ signature scheme underneath MLS framing (which was judged out of scope for this increment — it would mean re-deriving MLS's authentication properties independently of OpenMLS, essentially forking the protocol).
  - **Migration plan:** re-evaluate `umbra-group`'s ciphersuite selection whenever `openmls`/`draft-ietf-mls-pq-ciphersuites` ships a full post-quantum ciphersuite (KEM **and** signature, e.g. an ML-DSA-based leaf/message-signing scheme). Until then, this is a documented, honest residual — not a defect discovered post-hoc, but a known limitation accepted because no better option exists in the ecosystem's current MLS tooling.
- **No ADR-011 exception required:** unlike ADR-028 (Tor's transitive `ring`/SQLite) and ADR-030 (pt-proxy's obfs4 C component), `umbra-group`'s full dependency chain was verified to be pure Rust. `cargo tree -p umbra-group -e normal` shows no C-bearing `-sys` crate anywhere in the graph: `openmls`, `openmls_basic_credential`, `openmls_memory_storage`, and `openmls_libcrux_crypto` all resolve to pure-Rust implementations, with the actual KEM/AEAD/hash primitives coming from Cryspen's formally-verified (hacspec/F*-derived) `libcrux` family (`libcrux-curve25519`, `libcrux-chacha20poly1305`, `libcrux-sha3`, `libcrux-hacl-rs`, etc.) — the same audited-pure-Rust provenance ADR-032 already relied on for `nym-crypto`'s use of `libcrux`. No deviation from ADR-011 is recorded for this increment.
- **Consequence:** `umbra-group` ships as an ordinary root-workspace member with no lockfile isolation, no `StorageProvider` reimplementation, a minimal and fully regression-tested wire-protocol addition, an honestly documented partial-PQ ciphersuite gap tracked for future migration, and zero ADR-011 exceptions. Affected documents: `CRYPTOGRAPHY.md` §3, `THREAT_MODEL.md`, `TODO.md` B.2, `CHANGELOG.md`.
