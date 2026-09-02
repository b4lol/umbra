# Umbra Glossary

This document defines the cryptographic, networking, operating-system, and operational-security concepts used in the **Umbra** architecture and documentation.

---

## 🔐 Cryptography and Key Management

- **ML-KEM (Module-Lattice Key Encapsulation Mechanism):** The NIST FIPS 203 post-quantum key encapsulation algorithm based on lattice mathematics (formerly CRYSTALS-Kyber-768).
- **ML-DSA (Module-Lattice Digital Signature Algorithm):** The NIST FIPS 204 quantum-resistant digital signature algorithm (formerly CRYSTALS-Dilithium).
- **PQXDH (Post-Quantum Extended Triple Diffie-Hellman):** The session-establishment protocol that hybridly combines the classical X25519 elliptic-curve key exchange with the ML-KEM-768 post-quantum key encapsulation.
- **Double Ratchet:** The key schedule that renews its root and chain keys with every message exchange, providing Forward Secrecy and Post-Compromise Security.
- **ChaCha20-Poly1305 AEAD:** The high-performance encryption algorithm (RFC 8439) that provides a 256-bit symmetric stream cipher and a message authentication tag (MAC).
- **Argon2id:** The memory-hard password derivation function (RFC 9106) that resists ASIC- and GPU-based brute-force attacks.
- **Deniable Authentication:** The cryptographic method by which a message is verified to the recipient as coming from the sender, while being designed so that it cannot constitute legal proof against third parties.
- **SMP (Socialist Millionaire Protocol):** The protocol by which two parties verify, with zero knowledge and without disclosing it to each other, that they share the same secret passphrase.

---

## 🌐 Networking and Anonymity

- **Arti:** The pure-Rust Tor client library developed from scratch by the Tor Project to replace the old C-language Tor daemon.
- **Tor v3 Onion Service:** The hidden-service protocol that requires no IP address, operates with 56-character `.onion` addresses, is end-to-end encrypted, and hides both parties' IP addresses.
- **Poisson-Distributed Cover Traffic:** The mechanism that defeats timing-analysis attacks by pumping 1024-byte dummy packets into the network according to a Poisson probability distribution even when the user is not actively writing.
- **Pluggable Transports:** The carriers (Obfs4 / Snowflake) that mask Tor traffic against Deep Packet Inspection (DPI) as ordinary WebRTC video conferencing or random noise.
- **Off-Grid Mesh:** The encrypted local network in which, in crisis environments where internet and GSM infrastructure are cut off, devices establish direct P2P links over BLE and Wi-Fi Direct.

---

## 🛡️ Device, Memory, and Operating System Security

- **`FLAG_SECURE`:** The Android window security flag that prevents screenshots, screen recording, and the recent-apps preview.
- **Wayland:** The modern Linux display server protocol that closes X11's screen-snooping and keystroke-logging gaps and enforces strict window isolation between processes.
- **`mlock`:** The POSIX system call that tells the Linux kernel that a memory page must never be written to disk (swap space).
- **`zeroize`:** The security function that zeroes (`0x00`) memory regions holding sensitive keys or messages when they go out of scope, preventing compiler optimizations from eliding the wipe.
- **Seccomp-BPF:** The kernel-level filtering mechanism that restricts the system calls a Linux process may use.
- **Landlock LSM:** The modern Linux security module that completely locks down a process's access to the filesystem.
- **Decoy Vault:** The defense mechanism in which entering a secondary PIN under physical coercion opens a harmless fake profile while the real data is destroyed in the background.
- **Scratch-to-Reveal:** The dynamic masking interface that keeps messages blurred to prevent shoulder surfing and reveals the words only while a finger is held on the screen.
- **View-Once Media:** The media protection in which, the moment the dialog closes or the finger is lifted after the user opens a photo, the $EFK$ key is destroyed and wiped out of RAM, making a second opening infeasible by design (v2 media-engine design goal).
- **Crypto-Shredding:** The technique whereby, when the 24-hour retention period expires, the data is not sought out and deleted; instead, the unique $EFK$ key that encrypted it is destroyed, turning the data into noise that is undecryptable assuming the AEAD holds and every key copy is destroyed.
- **Anti-Clock Tampering:** Time verification via Tor Consensus Time and the `CLOCK_MONOTONIC_RAW` differential, used to prevent the user from rolling the device clock back to extend the 24-hour retention period.
- **Emergency Media Eviction:** The wiping of all open media and messages from memory within microseconds when a screen-capture attempt is detected via the Android 14+ `ScreenCaptureCallback`.
- **Temporal Pixel Interleaving:** The `FLAG_SECURE` bypass protection that renders text and images as two complementary half-frames at 60Hz/120Hz, so the human eye sees them while a screenshot captures only meaningless noise in a single frame.
- **Accessibility Shielding:** The method that renders text directly as pixels on the native Skia canvas, leaving the Android `AccessibilityNodeInfo` tree completely empty and preventing spyware from copying on-screen text.
- **Hardware Protected DRM Surface:** The protection that renders media in hardware- and TEE (TrustZone)-level encrypted GPU buffers (`FLAG_HW_SECURE`), turning even a rooted system's `SurfaceFlinger` memory dump into a black screen.
- **Out-of-Process Media Sanitizer:** The architecture that, against Pegasus zero-click exploits, parses images in a single-use subprocess capped at 2MB of RAM and locked down with `Landlock` and `Seccomp`, shielding the main process.
- **Encrypted-in-RAM Buffers:** The memory protection that never leaves data as plaintext in RAM, encrypting it with AES-NI, processing it only in the CPU L1/L2 cache, and evicting it with `clflushopt`.
- **Masked Kyber:** The cryptographic method that processes post-quantum polynomials split apart with random masks against side-channel EM and cache-timing attacks.
- **WTF-PAD (Adaptive Padding):** The intelligent cover-traffic protocol that shapes packet intervals to a WebRTC/video profile with Markov chains in order to deceive ISP and DPI classifiers.
- **Strict Vanguards-Lite:** The circuit topology that pins Tor guard nodes across 3 layers, blocking Sybil and guard-discovery attacks.
- **Ephemeral Clipboard:** The mechanism whereby copied sensitive data is crushed with `0x00` after 60 seconds, removing it from the clipboard and preventing it from being saved to the clipboard history via Android `EXTRA_IS_SENSITIVE`.
- **Zero-Knowledge Masked Notification:** The architecture that feeds the operating system (NotificationManager/D-Bus) generic fake text (e.g. 'System Update') instead of the actual message text or identity, blocking spyware and lockscreen snoopers from reading notifications.
- **IOMMU / SMMU DMA Isolation:** The kernel-level protection that blocks, at the hardware level, unauthorized DMA access by the cellular baseband modem or external peripherals to the main application processor's RAM.
- **USBGuard / USB Data Lockout:** The protective shield that hardware-disables the data port while the device is locked or when unauthorized BadUSB/Cellebrite hardware is plugged in.
- **Kernel-Level Hardware Kill-Switch:** The zero-leak rule that instantly `DROP`s, in the kernel, all TCP/UDP/IPv6 packets other than Tor v3 via `nftables` / Android `VpnService`.
- **Dual-Hardware Token Binding:** The cryptographic lock that simultaneously binds session login and key derivation to an external CC EAL6+ FIDO2 hardware key (YubiKey) in addition to the device's internal Secure Element (TEE) chip.
- **LLVM Sanitizers (ASan / MSan / UBSan):** The aggressive security instrumentation injected into the code at compile time that catches memory overflows, uninitialized memory reads, and undefined behavior at runtime.
- **Coverage-Guided Fuzzing (`cargo-fuzz`):** The automated vulnerability-hunting technique that generates millions of mutated inputs to force out every branch and corner case of the protocol parsers.
- **`dudect` (Constant-Time Timing Leakage Analysis):** The analysis tool that catches nanosecond-scale timing and side-channel leaks by comparing the execution times of two different input sets with the Welch t-test statistic.
- **Typestate Pattern:** The design pattern that eliminates MODELED invalid state transitions at compile time through the type system (*Make Illegal States Unrepresentable*); residual logic-error risk is measured via mutation testing (ADR-021).
- **Newtype Pattern:** The zero-cost abstraction technique that wraps primitive types to catch wrong-type matches and logic errors at compile time.
- **Mutation Testing (`cargo-mutants`):** The method that deliberately alters the source code's logical operators, measures whether the tests catch it, and eliminates incomplete test logic.
- **Property-Based Testing (`proptest`):** The testing approach that verifies the code's mathematical invariants with thousands of automatically generated random inputs.
- **Unix Philosophy:** The software development doctrine built on modularity, single responsibility (*Do One Thing Well*), pipeable byte streams, and composability.
- **Rule of Silence:** The principle that a successfully running program prints no unnecessary decoration or banners to the `stdout` channel and produces only the requested data.
- **Composability:** The ability of software to be chained with other system tools (`jq`, `grep`, `tar`) through standard Unix pipes (`|`).
- **`hardened_malloc` (GrapheneOS):** The security-hardened global memory allocator that uses `PROT_NONE` guard pages, out-of-line metadata, and slab quarantine to prevent heap overflows, Use-After-Free (UAF), and metadata corruption.
- **Slab Quarantine:** The security queue in which freed memory blocks are held back rather than being immediately reallocated, in order to prevent UAF attacks.
- **Out-of-Line Metadata:** The architecture in which memory-management headers are stored not next to the allocated data blocks but in isolated, protected, separate memory pages.
- **Active Cyber Deception:** The counter-defense approach that, when an attacker has breached the system or hooked memory, redirects them to fake honeypots, consuming their resources and misleading them.
- **Canary Honeypot Keyring:** The decoy key buffer that sits in memory as if valid but, the moment it is accessed, destroys the real keys and feeds fake packets to the attacker.
- **Cryptographic Tar-Pit:** The endless mathematical PoW and computation trap designed to grind down the processor resources of an attacker trying to solve the fake packets.
- **Ghost Mode:** The operating mode in which, when a debugger or hook is detected, the application sabotages reverse engineering by producing fake control flows and misleading success responses instead of crashing.
- **Zero Data Leakage:** The multi-layered architectural state that aims to minimize the egress of data and metadata through memory, swap, core dumps, DNS, IPv6, ports, or side channels, and that is measured with leak tests.
- **Anti-Exfiltration:** The body of mechanisms that locks down, at the hardware and kernel level, the exfiltration of data off the device by malicious software or analysis tools.
- **Register Zeroing (`zero-call-used-regs`):** The compiler technique of zeroing all registers on function returns so that sensitive keys do not linger in CPU registers.
- **Microarchitectural Jitter:** The injection of random artificial cycles into the CPU execution pipeline to disrupt power and electromagnetic side-channel attacks.
- **Code Craftsmanship:** The engineering philosophy that insists software must not merely work; it must possess mathematical correctness, complete documentation, zero panics, and the highest aesthetic/quality standards.
- **Exhaustive Pattern Matching:** The Rust check that prevents runtime undefined behavior by mandating that every possible enum variant be handled at compile time.
