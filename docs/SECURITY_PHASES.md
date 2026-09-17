# Umbra — Full Security Lifecycle, in Phases

A single-page index over the project's full security posture for v1.0.0-alpha.3+,
cross-referencing every phase to its authoritative source document and its `DECISIONS.md`
ADR(s). This document does not restate policy — each phase links to the document that
actually defines it, and states LANDED / PARTIAL / PLANNED status as of this writing
(2026-09-17). Where a phase describes work already covered elsewhere in this repo, that
existing document remains the single source of truth; this page exists to make the whole
lifecycle visible from one place and to give upcoming hardening work (Phase 12) a home.

---

## Phase 0 — Philosophy and Non-Negotiable Commitments
**Status: LANDED.** Source: `SECURITY.md`, root `README.md`.

The five commitments (Zero-PII, Post-Quantum, Zero-Metadata, RAM-Only & Anti-Forensics,
Safe Rust + Isolation) and the workspace-wide `#![deny(unwrap_used, expect_used, panic,
todo)]` doctrine. ADRs: [ADR-003](DECISIONS.md#adr-003-diskless-ram-only-operation-mode-by-default)
(RAM-only), [ADR-006](DECISIONS.md#adr-006-stability-security-performance-and-resource-discipline-doctrine)
(discipline doctrine), [ADR-011](DECISIONS.md#adr-011-safe-programming-language-policy-and-the-absolute-ban-on-cc%2B%2Bjsdynamic-languages)
(no C/C++/JS), [ADR-012](DECISIONS.md#adr-012-safe-rust-mandate-and-the-hardware-level-isolated-unsafe-exception)
(Safe Rust mandate, `unsafe` confined to `umbra-hardware`).

## Phase 1 — Threat Modeling
**Status: LANDED.** Source: `THREAT_MODEL.md`, `TARGETED_DEFENSES.md`.

Adversary model (Global Passive Adversary, zero-click-capable actors, malicious Tor
relays/introduction points) and the honestly-scoped list of what is NOT defended against
(cold-boot RAM dump post-physical-seizure, CPU register residue beyond best-effort scrub,
idle-gap cover traffic deferred to v2). No single dedicated ADR — this phase is the
document itself; individual defenses it describes each cite their own ADR.

## Phase 2 — Cryptography Design
**Status: LANDED.** Source: `CRYPTOGRAPHY.md`.

PQXDH handshake (X25519 + ML-KEM-768/FIPS 203 + ML-DSA-65-signed pre-keys, non-contributory
DH rejected), Signal-spec Double Ratchet (bounded skipped-key store, transactional
decrypt), ChaCha20-Poly1305 AEAD with `subtle` constant-time verification, OTR v3 SMP +
identity-fingerprint binding, fixed 1024-byte framing, dudect + proptest verification.
ADRs: [ADR-002](DECISIONS.md#adr-002-post-quantum-hybrid-kem-x25519--ml-kem-768) (hybrid
KEM), [ADR-026](DECISIONS.md#adr-026-switch-to-pure-rust-post-quantum-crates-resolving-the-pqcrypto--contradiction)
(pure-Rust PQ crates, no `pqcrypto-*`).

## Phase 3 — Network Protocol and Tor
**Status: LANDED** (outbound and inbound both live-verified on the real Tor network).
Source: `NETWORK_PROTOCOL.md`.

Embedded Arti (pure Rust) outbound + inbound onion service, `bootstrap_persistent`
identity stability, strict Vanguards-Lite pinning, inbound hs-pow with a bounded
rendezvous queue, Poisson burst-level cover traffic (idle-gap deferred to v2, TODO
B.1-adjacent), unmanaged pluggable-transport support. ADRs:
[ADR-001](DECISIONS.md#adr-001-pure-rust-arti-instead-of-an-external-tor-daemon) (pure-Rust
Arti), [ADR-005](DECISIONS.md#adr-005-1024-byte-fixed-size-and-poisson-traffic-masking)
(framing + cover), [ADR-008](DECISIONS.md#adr-008-anti-censorship-pluggable-transports-and-offline-mesh-mode)
(PT/mesh), [ADR-028](DECISIONS.md#adr-028-accepted-c-bearing-transitive-dependencies-of-the-tor-stack-deviation-from-adr-011)
(accepted C-bearing Tor transitive deps), [ADR-030](DECISIONS.md#adr-030-external-pluggable-transport-proxies--the-unmanaged-socks5-model-with-a-scoped-c-exception-for-a-future-standalone-proxy)
(PT proxy model), [ADR-031](DECISIONS.md#adr-031-mesh-mode-seccomp-profile--a-scoped-widening-of-the-ipv6udp-kill-switch)
(mesh Seccomp widening).

## Phase 4 — Client and OS Security
**Status: LANDED.** Source: `CLIENT_SECURITY.md`, `OS_OPTIMIZATIONS.md`,
`HARDWARE_SECURITY.md`.

Landlock zero-FS sandbox (narrow, per-flow exceptions only), Seccomp-BPF allowlist with
the IPv4/UNIX-STREAM-only kill-switch, `mlockall`/`PR_SET_DUMPABLE=0`/`RLIMIT_CORE=0`/
`GuardedBuffer`, Argon2id keystore (m=2^18, t=4, p=4). ADRs:
[ADR-004](DECISIONS.md#adr-004-wayland-only-support-on-linux-rejecting-x11) (Wayland-only),
[ADR-007](DECISIONS.md#adr-007-strict-kernel-isolation-with-linux-seccomp-bpf-and-landlock)
(Seccomp/Landlock), [ADR-009](DECISIONS.md#adr-009-hardware-security-key-fido2--yubikey-and-sudden-motion-sentinel)
(hardware key), [ADR-010](DECISIONS.md#adr-010-deniable-fake-profile-with-the-decoy-vault)
(Decoy Vault), [ADR-014](DECISIONS.md#adr-014-os-specific-deep-optimizations-and-simd-acceleration)
(OS-specific optimizations, mostly still TODO B.9 (renumbered from B.5, 2026-09-17)).

## Phase 5 — Zero Data Leakage
**Status: LANDED** (core paths); D-Bus notification path implemented but untested
against a real bus. Source: `ZERO_DATA_LEAKS.md`.

RAM-only messages, 60-second in-process clipboard manager, masked D-Bus notifications
(implemented, unwired to a production flow), core dump / swap / fork / hibernation paths
closed. ADR: [ADR-025](DECISIONS.md#adr-025-zero-data-leakage-and-multi-layer-anti-exfiltration-architecture),
also [ADR-018](DECISIONS.md#adr-018-1-minute-automatic-clipboard-destruction-and-zero-knowledge-masked-notification-architecture)
(clipboard/notifications), [ADR-019](DECISIONS.md#adr-019-full-stack-hardware-kernel-and-network-anti-leak-architecture)
(full-stack anti-leak).

## Phase 6 — Code Quality and Verification
**Status: LANDED**, with formal-methods verification tracked as new work (see TODO
B.7, added alongside this document; renumbered from B.8 on 2026-09-17). Source: `CODE_MANIFESTO.md`, `CODE_REVIEW.md`.

Typestate session states, newtypes + checked arithmetic everywhere, 122+ hermetic test
cases across 19+ suites, proptest, 4 fuzz targets with CI smoke, nightly ASan, weekly
`cargo-mutants`, `#![deny(missing_docs, missing_docs_in_private_items)]`. ADRs:
[ADR-012](DECISIONS.md#adr-012-safe-rust-mandate-and-the-hardware-level-isolated-unsafe-exception),
[ADR-013](DECISIONS.md#adr-013-mandatory-explanatory-comments-and-the-denymissing_docs-doctrine)
(doc doctrine), [ADR-020](DECISIONS.md#adr-020-mandatory-aggressive-multi-layer-vulnerability-scanning-on-every-code-change)
(scanning), [ADR-021](DECISIONS.md#adr-021-prevention-of-logic-errors-and-invalid-states-through-type-driven-design-and-mutation-testing)
(typestate/mutation testing).

**New work proposed and tracked (TODO B.7, renumbered from B.8):** Kani model-checking for panic-freedom and
bounded-store proofs, and TLA+ specifications for protocol liveness/safety — neither
exists in this repo yet.

## Phase 7 — Secret Leakage Prevention
**Status: LANDED.** Source: `SECURITY.md` § "Secret Leakage Prevention and Response".

Full-git-history gitleaks scan on every push/PR (pinned SHA256 binary, log redaction),
weekly scheduled re-scan, GitHub push protection, local `just secrets` pre-push
equivalent. No dedicated ADR (a CI/process control, not an architectural decision);
landed as a `CHANGELOG.md` "Unreleased" entry.

## Phase 8 — Vulnerability Disclosure and Incident Response
**Status: LANDED (process, not code).** Source: `SECURITY.md` § "Reporting a
Vulnerability".

PGP-encrypted private disclosure only, no public issues, 24-hour response target,
coordinated disclosure until a patch ships. No dedicated ADR — an operational procedure.

## Phase 9 — Targeted Defenses
**Status: LANDED** (v1.0 subset); most of `TARGETED_DEFENSES.md` is explicitly v2+
scope. Source: `TARGETED_DEFENSES.md`.

Zero-click surface reduction (Landlock + Seccomp + pipe transport), side-channel defense
(constant-time suite, fixed framing, Poisson cover), metadata-analysis resistance
(burst cover, session-tag multiplexer, Vanguards-Lite), Pegasus-class mitigation
(`mlockall` + `GuardedBuffer` + `PR_SET_DUMPABLE=0` + register scrub). ADR:
[ADR-017](DECISIONS.md#adr-017-targeted-vulnerability-prevention-and-pinpoint-defense-architecture).

## Phase 10 — Limitations and Honest Scope
**Status: LANDED (as a living document).** Source: `LIMITATIONS_PLAN.md`, `TODO.md`.

The explicit "not yet in alpha.3" table (GUI messaging, Android, view-once/24h
crypto-shredding, `hardened_malloc`, CPU register zeroing beyond best-effort, SMP CLI
surface, PQ-MLS TreeKEM, idle-gap cover) — all tracked as open `TODO.md` Section B items,
none silently dropped. ADR: [ADR-027](DECISIONS.md#adr-027-mvp-prioritization-and-deferral-of-the-v2-scope).

## Phase 11 — Release and Publication Security
**Status: LANDED.** Source: root `README.md`/`CONTRIBUTING.md`, `.github/workflows/`.

`just check` (fmt + clippy `-D warnings` + full test suite), 4 required CI checks
(fmt+clippy+tests, deny+audit, fuzz smoke, nightly ASan), `cargo-deny`/`cargo-audit` on
every push, `strip`+LTO release profile, PGP-signed tags. ADR:
[ADR-020](DECISIONS.md#adr-020-mandatory-aggressive-multi-layer-vulnerability-scanning-on-every-code-change)
(the scanning half); release mechanics themselves have no dedicated ADR.

## Phase 12 — Active Resilience Testing
**Status: PLANNED — new work, tracked as TODO B.7 (renumbered from B.8, 2026-09-17).** No source document yet; this
phase does not exist anywhere else in the repo before this page.

Testing the project's OWN local testnet, not production infrastructure:
- A local 30-node Chutney Tor network as the target, not the public Tor network.
- Adversarial-node scenarios: 1000 out-of-order Double Ratchet messages against the
  bounded skipped-key store (does it fail closed once full, as designed, or does it
  degrade some other way under real adversarial pacing rather than a synthetic unit
  test?); an attempt to flood the memory-bounded inbound rendezvous queue.
- Kani: a machine-checked proof that no hostile input to the wire-format parsers can
  panic (extending the existing hermetic "garbage input" test style with an actual
  proof over the whole input space, not just chosen examples).
- TLA+: a machine-checked proof that a broken Tor circuit never silently falls back to
  a clearnet connection (a liveness/safety property this project currently only argues
  for in prose, in `THREAT_MODEL.md` and the Seccomp network kill-switch's own design).

This phase has no ADR yet — one should be written (`ADR-035` is the next free number, see
`DECISIONS.md`) if and when this work actually lands, following this project's own
convention of writing the ADR alongside the landing, not speculatively ahead of it.

---

## Not covered by this index

Formal per-phase `just` recipes and CI checks were suggested as a possible follow-up
when this document was drafted. Not created here: most phases above already have their
own verification wired into the existing `just check`/CI pipeline (Phase 11), and
splitting that into twelve parallel phase-specific recipes would fragment a pipeline
that currently has one clear entry point — a real cost against a benefit that has not
been asked for concretely. If a specific phase's verification genuinely needs its own
separate, differently-scheduled check (the way fuzzing and mutation testing already
do), that is worth doing for that one phase specifically, not as a blanket rule across
all twelve.
