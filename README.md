# Umbra (Shadow)

**Zero-Trust, Zero-Metadata, Post-Quantum Anonymous Communication System**

`Umbra` is an end-to-end encrypted communication protocol and client designed for journalists, government officials, and intelligence professionals operating in high-threat environments. It is serverless (no central server) and built on zero-metadata principles. Under its Tor transport the goal is no IP or identity trace — burst-level cover traffic is wired and both directions of the Tor flows are live-verified, while idle-gap cover is still pending (see the honest-scope table), so treat every absolute anonymity claim as a design goal, not a measured property.

> **Release status — `v1.0.0-alpha.3`:** the Section A (MVP) scope of [TODO.md](TODO.md) is implemented and CI-verified; onion-identity persistence AND a full outbound+inbound self-send round trip are LIVE-VERIFIED on the real Tor network (`just live-test`, `tui_live`). This is an **alpha**: the cryptographic core is complete and continuously tested, while parts of the interactive product surface (GUI, Android) are not yet done. Every claim in this README is scoped to what is on disk; the honest-scope notes are authoritative over any marketing language inherited from the specification documents.

---

## ✅ What is implemented (v1.0.0-alpha.3)

### Cryptography (`umbra-crypto`, `umbra-protocol`)
- **PQXDH handshake** — X25519 + ML-KEM-768 (RustCrypto `ml-kem`, pure Rust, FIPS 203) with ML-DSA-65-signed pre-keys (FIPS 204); non-contributory DH rejected.
- **Double Ratchet** — Signal-spec, with a bounded **skipped-key store** (out-of-order delivery decrypts; replay/evicted messages fail closed) and **transactional decrypt** (spec §3.5: a failed authentication rolls back all state changes).
- **ChaCha20-Poly1305 AEAD** with `subtle` constant-time verification; single-use message keys with deterministically derived nonces.
- **OTR v3 Socialist Millionaire Protocol** (faithful transcription; all 4 messages + ZKPs), with **identity-fingerprint binding** (`smp::bound_secret`) and **per-session transcript SSID mixing** — a wire MITM relaying SMP messages between two sessions fails the proofs on both sides. Residual: the password (or the out-of-band fingerprint comparison) remains the root of trust — anyone holding it passes SMP by design.
- **Session typestate** (`Unauthenticated → HandshakeInProgress → EstablishedSession`) makes illegal transitions unrepresentable; newtype counters, checked arithmetic everywhere.
- **Fixed 1024-byte packet framing** with cryptographic padding; `MEDIA_CHUNK` split/assembler with hostile-input caps; session-tag multiplexer (text / SMP / terminate).
- **SESSION_TERMINATE (0x09)** — mutual ephemeral-key reset, authenticated, zeroized locally.

### Network (`umbra-net`, `tor` feature)
- **Embedded Arti** (pure-Rust Tor) v3 outbound + inbound onion services, head-of-line-protected inbound with bounded concurrency and idle timeouts.
- **Persistent onion identity** (`bootstrap_persistent`): Arti native keystore under a `0700` storage root keeps the `.onion` address stable per nickname.
- **Strict Vanguards-Lite** circuit pinning on both config paths (mode pinned explicitly; consensus cannot weaken it), **hs-pow** enabled inbound with a memory-bounded rendezvous queue.
- **Burst-level cover traffic** (ADR-005): Poisson-driven `DUMMY_COVER` frames interleaved with real frames on every send path (pipe + Tor), wire-indistinguishable; receiver destroys them silently. Idle-gap cover is v2.

### Client security (`umbra-cli`, `umbra-hardware`)
- **Landlock zero-FS sandbox** with exactly two sanctioned exceptions (the `/dev/tty` terminal — read/write/ioctl for crossterm raw mode, silently dropped on headless systems; the caller-supplied Tor storage dir with a narrowed regular-files grant). The zero-FS default and the exception mechanism are verified hermetically.
- **Seccomp-BPF allowlist** (fail-closed EPERM, thread-inherited) including a **network kill-switch**: `socket(2)` is granted only for IPv4/UNIX STREAM — IPv6 and UDP (DNS :53) fail at the kernel level.
- **Memory locks**: `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, guard-page `GuardedBuffer` (`PROT_NONE` + `MADV_DONTDUMP/DONTFORK/WIPEONFORK`), `zeroize` everywhere.
- **Keystore** (Argon2id m=2¹⁸/t=4/p=4 + ChaCha20-Poly1305 envelope), seed-based identity, pairing payloads with **SAS codes**, named peer records.
- **Pipe transport**: `umbra send --peer NAME | umbra recv` (binary or `--json` NDJSON), sandbox applied after keystore loads.
- 60-second clipboard manager (in-process; system-backend integration is v2), D-Bus masked notifications (implemented, unwired; the D-Bus path is untested), interactive Tor TUI client (Ratatui: live inbound onion feed, compose-and-send, Tab-cycled peer selection).

### Verification infrastructure
- **122 test cases** across 19 integration suites plus per-crate unit tests, hermetic by policy; **proptest** (invertibility, ratchet recovery), **dudect-style constant-time suite**, **cargo-fuzz** (4 targets), **ASan nightly CI**, weekly **cargo-mutants**, `cargo-deny`/`cargo-audit` on every push.
- CI (4 required checks): fmt+clippy+tests (workspace `-D warnings`), deny+audit, fuzz smoke, ASan (nightly).

---

## ⚠️ Honest scope — what v1.0.0-alpha.3 does NOT have

| Feature | Status |
|---|---|
| GUI (GTK4), Wayland enforcement | Deferred (Section B) |
| Android client (`FLAG_SECURE`, TEE, Skia canvas) | Deferred (Section B) |
| View-once media engine, 24 h crypto-shredding | Deferred (Section B; media *metadata sterilizer* IS implemented) |
| `hardened_malloc` integration | Deferred (Section B) |
| Persistent onion identity in production flows | LIVE-VERIFIED (`just live-test`, 2026-09: two consecutive bootstraps over one storage root published the same `.onion` address). Tor transport state persists under the Tor tree — messages stay RAM-only, transport state does not |
| CPU register zeroing (`zero-call-used-regs`) | Best-effort `asm!` scrub of caller-saved registers at sensitive boundaries (`umbra-hardware::hardening`); the upstream rustc flag remains removed, vector registers are a documented residual |
| Live-network field testing of the Tor paths | DONE (2026-09): inbound identity persistence (`just live-test`) and an outbound+inbound self-send round trip (`tui_live`) both PASSED on the real network — the latter caught the missing `onion-service-client` feature that made alpha.2 outbound connects impossible |
| SMP in the product surface | Library-only (drivers + tests); no CLI command runs SMP yet — the pipe layer runs none |
| Pluggable transports (obfs4-class) | Unmanaged-proxy support LANDED (ADR-030): `--pt-socks` + `--bridge` on serve/send/tui configure arti for a loopback SOCKS5 PT proxy; Umbra never spawns/links PT code. The PT proxy itself is external (a standalone C skeleton lives in `pt-proxy/`, obfs4 NOT yet implemented); live censorship-path testing pending. Snowflake: blocked (no Rust/C client) |
| PQ-MLS TreeKEM, mixnets | v2 (Section B) |

The authoritative status list is [TODO.md](TODO.md); claim arbitration lives in [DECISIONS.md](DECISIONS.md) (ADR-001…ADR-030).

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              CLI / TUI Layer (umbra-cli, clap 4)             │
│   init · pair · fingerprint · send/recv (pipe) · sandbox     │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Umbra Core Engine (Rust)                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ umbra-protocol: 1024 B packets · session typestate     │  │
│  │  · SMP carriage · media chunking · newtype counters    │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ umbra-crypto: PQXDH (X25519+ML-KEM-768) · Double       │  │
│  │  Ratchet · ChaCha20-Poly1305 · ML-DSA-65 · zeroize ·   │  │
│  │  GuardedBuffer · keystore envelope                     │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ umbra-net (tor): embedded Arti v3 · onion service ·    │  │
│  │  Vanguards-Lite · hs-pow · cover pump · messenger      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ umbra-hardware: mlockall/prctl · Landlock+Seccomp ·    │  │
│  │  guarded pages (the single unsafe-isolated crate)      │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick start

Requirements: Linux, Rust **1.97.1** (pinned via `rust-toolchain.toml`), a kernel with **Landlock ABI 5 (Linux 6.10+)** — the ruleset uses HardRequirement, so older kernels are refused, not degraded — and `RLIMIT_MEMLOCK` raised (systemd `LimitMEMLOCK=infinity` or equivalent): the hardened session commands (`send`, `recv`, `tui`, `serve`, `fingerprint` without `--peer`) **fail closed** under the default limit by design (`init`, `keygen`, `export-pairing`, `pair` do not harden yet; `serve` additionally wants `LimitMEMLOCK=infinity` — it locks the whole Arti runtime heap).

```sh
git clone https://github.com/b4lol/umbra && cd umbra
just check                 # fmt + clippy (-D warnings) + full test suite

# a real passphrase file (FIRST LINE is the passphrase; 0600 recommended)
printf '%s\n' '<YOUR-LONG-RANDOM-PASSPHRASE>' > ~/.umbra-pass && chmod 600 ~/.umbra-pass

# create an identity keystore (Argon2id envelope)
cargo run -p umbra-cli -- init --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass

# export your pairing payload; verify SAS out of band; store the peer
# (peer records live in peers/ NEXT TO the keystore)
cargo run -p umbra-cli -- export-pairing --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass
cargo run -p umbra-cli -- pair --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass \
    --peer-name alice --peer-payload <their-base64url-payload>
cargo run -p umbra-cli -- fingerprint --peer alice   # compare out of band

# Tor transport (built with --features tor):
cargo run -p umbra-cli --features tor -- serve --nickname myname --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass
# ... then the peer stores the published address: pair --onion <addr>
echo "hello" | cargo run -p umbra-cli --features tor -- send --peer alice --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass
echo "hello" | cargo run -p umbra-cli -- send --peer alice --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass > wire.bin
cargo run -p umbra-cli -- recv --keystore ~/.umbra/umbra.enc --passphrase-file ~/.umbra-pass < wire.bin
```

All commands honor the **Rule of Silence** (data on `stdout`, diagnostics prefixed `umbra: ` on `stderr`). `--json` NDJSON output is honored by `keygen`, `send` and `recv`.

---

## 📚 Documentation Index

| Document | Description |
|---|---|
| [`PROJECT.md`](PROJECT.md) | Project mission, vision, target-audience analysis, language policy, and technical scope. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System architecture, data-flow diagrams, sandbox layer, and module designs. |
| [`SPECIFICATION.md`](SPECIFICATION.md) | 1024-byte binary packet format, byte offsets, state machine, pipe transport, and FFI interface specification. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Nation-state-level threat model, Pegasus analysis, and defense mechanisms. |
| [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) | PQXDH, Double Ratchet delivery semantics, SMP binding, and the primitives table. |
| [`NETWORK_PROTOCOL.md`](NETWORK_PROTOCOL.md) | Fixed packet structure, Tor v3 P2P communication protocol, and transport notes. |
| [`CLIENT_SECURITY.md`](CLIENT_SECURITY.md) | Linux process isolation: Landlock, Seccomp kill-switch, mlock, register-zeroing status. |
| [`TARGETED_DEFENSES.md`](TARGETED_DEFENSES.md) | Defenses against zero-click, side-channel, and metadata-analysis attacks. |
| [`TODO.md`](TODO.md) | Step-by-step implementation checklist (the authoritative scope list). |
| [`DECISIONS.md`](DECISIONS.md) | Architecture Decision Records (ADR-001…ADR-029). |
| [`ZERO_DATA_LEAKS.md`](ZERO_DATA_LEAKS.md) | Zero data leakage and anti-exfiltration defense specification. |
| [`CODE_MANIFESTO.md`](CODE_MANIFESTO.md) | Manifesto on code quality and engineering doctrine. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Developer guide, build environment, and contribution rules. |
| [`SECURITY.md`](SECURITY.md) | Security policy and responsible vulnerability disclosure. |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history and change records. |
| [`GLOSSARY.md`](GLOSSARY.md) | Glossary of technical, cryptographic, network, and security terms. |

---

## 🚀 Core Development Doctrine (Non-Negotiable Principles)

1. **Security, Stability, and Performance Are Never Compromised** — no UX trade-off may lower the cryptographic bar; a single panic/hang is unacceptable (`#![deny(unwrap_used, expect_used, panic, todo, …)]` workspace-wide); zero-cost abstractions only.
2. **Anti-Bloat & Resource Discipline** — bounded memory everywhere (hostile-input caps in every parser), no caches/logs on disk, `strip`+`LTO` release profile.
3. **Safe Rust with Isolated Hardware Unsafe** — `unsafe` exists only in `umbra-hardware` behind 100% safe APIs with `// SAFETY:` documentation; C/C++ are banned (one recorded deviation: `ring` via the Tor stack, ADR-028).
4. **Never Trust (Zero-Trust)** — the network, the OS, and intermediate nodes are considered compromised at all times.
5. **Metadata Is Data** — who talks to whom and when is masked as aggressively as content.
6. **No Footprint** — messages never touch disk; every claim in every document is honest-scope audited (ADR-027 two-section delivery, honest residuals).
7. **Mandatory Documentation** — `#![deny(missing_docs, missing_docs_in_private_items)]` workspace-wide; undocumented code is not accepted.
8. **Aggressive Verification on Every Change** — cargo-audit/deny (CI), ASan nightly, fuzz smoke, mutation testing, dudect constant-time analysis (CI-enforced); `cargo geiger` via `just scan`, with the `// SAFETY:` lint CI-enforced.
9. **Illegal States Unrepresentable** — typestate session machine, newtype counters, checked arithmetic, proptest + cargo-mutants.

---

## 📄 License

GPL-3.0-or-later — see [LICENSE](LICENSE).
