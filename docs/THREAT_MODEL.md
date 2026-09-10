# Umbra Threat Model and Security Analysis (Ultra-Hardened Threat Model)

This document describes the adversary profiles that **Umbra** is designed to withstand, its security boundaries, advanced threat scenarios, and multi-layered defense strategies.

---

## 1. Comprehensive Threat Matrix

| Threat Scenario | Adversary Capability | Umbra's Mitigation |
|---|---|---|
| **Global Passive Adversary (Nation-State / NSA / Five Eyes)** | Nationwide fiber-optic line tapping, timing correlation, "Harvest Now, Decrypt Later". | **Arti Tor v3 + Nym Mixnet**, **ML-KEM-768 / Kyber**, **1024-byte fixed blocks**, and **Poisson artificial cover traffic**. |
| **Zero-Click Spyware (Pegasus / NSO Zero-Click)** | Background memory reading, exploitation of operating system vulnerabilities. | **Linux Seccomp-BPF & Landlock Sandbox** (zero filesystem access, forbidden `ptrace`/`execve`), `mlock`, and Guard Pages. |
| **DPI-Based Internet Censorship (China GFW / Iran)** | Detection and blocking of the Tor protocol and encrypted VPNs via Deep Packet Inspection (DPI). | **Pluggable Transports (Obfs4 / Snowflake WebRTC Masking)** to make traffic appear as ordinary video conferencing or random noise. |
| **Physical Seizure & Forensics (NAND Dump / Cold Boot)** | Seizing the device, freezing-based memory readout (Cold Boot), JTAG/chip dumps. | **RAM-Only Operation** (zero writes to disk), instant `zeroize`, swap prevention via `mlock`, **Motion-Triggered Emergency Wipe (Motion Wipe)**. |
| **Physical Threat, Torture / Coercion (Rubber-Hose Cryptanalysis)** | Forcing the user to hand over the password. | **Decoy Vault**: Entering the Duress PIN opens fake, harmless chats while the real keys are silently destroyed in the background. |
| **Communication Infrastructure Shutdown (Internet Blackout / Crisis)** | Cell towers being switched off, the internet backbone being unplugged. | Sealed Encrypted Envelopes transferred device-to-device via **Off-Grid Mesh Mode (Off-Grid BLE & Wi-Fi Direct DTN)**. |
| **Screen Surveillance (Shoulder Surfing / Hidden Camera)** | Looking at the user's screen from behind, or video recording with a hidden camera. | **`FLAG_SECURE`** on Android, **Mandatory Wayland** on Linux, and **Dynamic Masking (Scratch-to-Reveal)**. |
| **`FLAG_SECURE` Bypass & Root/Hook Attacks (LSPosed, Frida, Accessibility Spyware)** | Using `DisableFlagSecure` modules with root privileges, copying on-screen text via `AccessibilityService`, `SurfaceFlinger` dumps. | **60Hz/120Hz Temporal Pixel Interleaving**, **Custom Skia Native Canvas (Empty Accessibility Tree)**, **Hardware DRM/TEE GPU Surface**, and **Pure Rust `/proc/self/maps` & `ptrace(PTRACE_TRACEME)` anti-hook detection**. |
| **Clipboard Snooping & History Archiving (GBoard History)** | Copied sensitive messages and keys being left on the clipboard or recorded into keyboard history. | **60-Second Asynchronous Auto-Destruction (zeroize)**, Android `EXTRA_IS_SENSITIVE = true` (blocks history recording), and an **In-App Isolated Clipboard**. |
| **Operating System Notification Listening (NotificationListener Spyware / Lockscreen Leak)** | Spyware or lockscreen previews reading the notification text and sender. | **Zero-Knowledge Silent Wake (Zero-Knowledge Ping)**, **Masked Generic Notifications (e.g., 'System Update')**, and `VISIBILITY_SECRET`. |
| **Baseband Modem & Cellular DMA Exploitation (Stingray / IMSI-Catcher)** | Unauthorized DMA access from the cellular chip to the AP's main memory, and base station tracking. | **Strict IOMMU / SMMU Isolation**, a cellular metadata block, and data transmission over Tor-only/Mesh. |
| **BadUSB & Direct Port Memory Leakage (Thunderbolt DMA / Cellebrite)** | Dumping memory through the port with malicious USB/PCIe hardware or forensics devices. | **Linux USBGuard**, Android **USB Data Lockout** (data port blanked while locked), and `disable_early_pci_dma`. |
| **DNS, IPv6, and WebRTC Network Leaks** | Background connections leaking the real IP address or DNS queries outside Tor. | **Kernel-Level Hardware Kill-Switch (`nftables` / Android VpnService DROP ALL)**; all packets outside Tor are dropped in hardware. |
| **Post-Exploitation Memory Reading & Hooking (Post-Exploitation / Spyware Infiltration)** | The adversary breaching the process with a zero-day or hooking memory. | **Active Cyber Deception:** Canary Honeypot Keyrings (*Canary Keyrings* $\to$ *Silent Wipe*), Cryptographic Tar-Pit (*Tar-Pit Infinite Loop*), Hallucinatory Fake Messages, and *Ghost Mode*. |

**Mesh-mode honest scope:** unlike the Tor transport, Wi-Fi Direct mesh mode has NO onion routing — anyone within radio range can observe the P2P device address in use and the fact that two Umbra devices are communicating. It is a last-resort AVAILABILITY mechanism for a total infrastructure blackout, not a metadata-protected transport; do not conflate its guarantees with Tor mode's.

**Nym-mode honest scope:** Nym mixnet mode depends on a real, third-party-operated network (independent mixnode and gateway operators), whose node population is smaller and newer than Tor's decade-plus relay set — the anonymity set is correspondingly smaller and less battle-tested. The Sandbox testnet, which is the default and the only environment this project has verified against, does NOT carry mainnet's anonymity-set guarantees: it is a smaller, purpose-built test network. Umbra's own privacy claims for this transport only fully apply once an operator deliberately opts into mainnet (`--mainnet`) with real bandwidth credentials — acquiring and managing those credentials is entirely outside this project's scope. Separately, Nym support ships as its own standalone binary (`umbra-nym`), never as a flag on the main `umbra` binary (see ADR-032) — there is no risk of a user accidentally enabling it.

**Group-mode (PQ-MLS "cell") honest scope:** the single-cell group-encryption increment (TODO B.2, ADR-033) inherits Tor-mode's transport-level metadata protection (each fan-out delivery is an ordinary two-party stream to one member) but adds its own protocol-level residuals, tracked explicitly rather than silently:
- **Partial post-quantum coverage:** the `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` ciphersuite protects group content with a hybrid (X25519 + ML-KEM-768) KEM, but leaf-node and message *signatures* remain classical Ed25519 — OpenMLS has no standardized post-quantum signature ciphersuite yet. A future break of classical ECDLP could retroactively forge group handshake authentication even though harvested content stays KEM-protected. Migration is planned once OpenMLS ships a full PQ ciphersuite (ADR-033).
- **No member removal or key rotation:** a compromised or departed member's key material is never revoked from a cell; forward secrecy is exercised only on the add path.
- **No sub-groups; unvalidated at scale:** one flat member list per cell, validated only at small (3-party) scale — large-group behavior is untested.
- **Mesh/Nym transports cannot carry group traffic:** group frames are Tor-only. `mesh_serve.rs` explicitly rejects an inbound `CONNECTION_TYPE_GROUP` marker ("mesh transport: group frames are not yet handled"), and `umbra-nym-cli` has no group-inbound handling at all — a cell member relying on mesh or Nym transport for their two-party sessions gets no group functionality over those same transports.
- **Roster-bootstrapping gap for newly joined members (a real, unmitigated availability/functionality gap, not a confidentiality break):** `GroupRoster` — Umbra's own peer-name↔leaf-index bookkeeping, never carried by MLS itself — is populated only by the local view of whoever creates a cell or adds a member. A device that joins a cell via an inbound `Welcome` persists an **empty** roster (see `crates/umbra-group/src/inbound.rs`'s module docs: "populating it is left to whatever future mechanism bootstraps peer-name knowledge for a newly joined group; out of scope here"). That member can receive and decrypt group traffic normally, but their own `umbra group send` silently fans out to zero peers, because fan-out delivery resolves recipients from the roster. This is a genuine functional gap with no numbered follow-up task in the current plan — a future protocol extension or out-of-band exchange is required to close it, and until then a newly joined member is a passive listener only.

---

## 2. Advanced STRIDE Analysis

```
  S - Spoofing:
      ↳ Mitigation: With the out-of-band dynamic QR code, the SAS code, and the Socialist Millionaire Protocol (SMP), MITM attacks are detected — provided the out-of-band verification actually happens. (Engine scope: SMP proves shared-secret knowledge; `smp::bound_secret` binds the pairing fingerprints and the session driver mixes the per-handshake transcript SSID, so relays and key substitution fail the proofs — but the password/comparison remains the root of trust, and the pipe layer runs no SMP.)

  T - Tampering:
      ↳ Mitigation: ChaCha20-Poly1305 AEAD + BLAKE3 integrity verification.

  R - Repudiation (Non-Repudiation Threat):
      ↳ Mitigation: "Deniable Authentication" provided by OTR-style MAC key disclosure.

  I - Information Disclosure (Metadata Disclosure):
      ↳ Mitigation: Tor v3 Onion, zero PII, 1024-byte fixed blocks, artificial Poisson traffic, Media Metadata Sterilizer.

  D - Denial of Service:
      ↳ Mitigation: With the P2P architecture, Pluggable Transports, and the Off-Grid Mesh mode, central server dependency is zero.

  E - Elevation of Privilege (Spyware):
      ↳ Mitigation: Seccomp-BPF syscall restriction, the Landlock disk lock, and Rust memory safety.
```

---

## 3. Unbreakability and Security Boundaries

1. **The Human Factor:** If the user surrenders the real password and does not use the Decoy PIN, encrypted data may be exposed; therefore education and automatic Panic Buttons are of vital importance.
2. **Hardware Trojans:** Against hardware backdoors at the CPU or Baseband level, open hardware platforms and FIDO2 / YubiKey hardware keys are recommended.
