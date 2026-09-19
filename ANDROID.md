# Umbra Android Client — Architecture (TODO B.4)

**Status:** Architecture decided; nothing in this document is implemented
yet (TODO B.4 is v2+ scope per ADR-027, and B.3 — the Linux GUI — is this
project's current priority per its own roadmap ordering; B.4 begins after
B.3 closes).

**Purpose:** This document is the single architectural reference for the
Android client. Several of its foundations were already decided before this
document existed — `docs/DECISIONS.md`'s ADR-011/012/014/016/018/019/023,
`docs/SPECIFICATION.md` §3, and the existing `crates/umbra-ffi` stub crate
all commit to specific choices. This document does not re-litigate those;
it cites them, reconciles the few places their wording leaves a gap, and
makes the decisions genuinely still open: the formal-verification target
list, in-app process/privilege separation, concrete build-system wiring,
and the phased delivery order. Every section below states what was chosen,
what it does, and why — per the project owner's explicit request.

## 1. What's already decided (context, not new decisions)

- **Language policy (ADR-011, binding):** Rust for all core logic; Kotlin
  for the Android UI. No exceptions — this rules out Flutter/React
  Native/Java-only approaches outright.
- **Unsafe-code policy (ADR-012, binding):** `#![forbid(unsafe_code)]` in
  every Umbra-owned crate except `umbra-hardware`. Android must not open a
  second exception; see §3 for how the FFI boundary honors this.
- **FFI shape (`docs/SPECIFICATION.md` §3, `crates/umbra-ffi`):** UniFFI
  bridging a `UmbraCoreController` trait to Kotlin. The trait already
  exists (`crates/umbra-ffi/src/controller.rs`) as a `StubController`
  returning `CoreControllerError::Unsupported` for every method — this
  document's job is to say how that stub becomes real, not whether to use
  UniFFI at all.
- **UI framework (`crates/umbra-ffi/src/lib.rs` doc comment,
  `docs/SPECIFICATION.md` §3):** Jetpack Compose.
- **Hardware key storage (ADR-014):** StrongBox Keymaster is already named
  as the target; ADR-023 already commits `libhardened_malloc.a` as the
  static allocator for the native binary.
- **Screen/clipboard/notification hardening (ADR-016, ADR-018):** Custom
  Skia Canvas text rendering, `FLAG_SECURE` layering, 60-second clipboard
  destruction, and zero-knowledge notifications are already specified at
  the mechanism level; this document places them relative to the UI
  framework (§4) rather than re-deriving them.
- **v1.0 MVP boundary (ADR-027):** Android is v2+ scope, deferred behind
  the Linux CLI/GUI. This document does not change that ordering.

## 2. Core reuse strategy

**Decision:** The Android client reuses the ENTIRE existing Rust
workspace — `umbra-crypto`, `umbra-protocol`, `umbra-group`, `umbra-net`
— unmodified, cross-compiled for Android targets. No cryptographic,
protocol, or group-encryption logic is reimplemented in Kotlin, ever.

**Why:** ADR-011 already restricts "system core, cryptography, network
layer" to Rust; the only question this document resolves is whether
Android gets its OWN Rust implementation or reuses the one Linux already
has. Reuse wins on every axis that matters here:
- **Security:** one audited PQXDH/Double-Ratchet/PQ-MLS implementation
  instead of two, halving the surface a vulnerability report or an audit
  has to cover, and eliminating the risk of the two implementations
  silently drifting apart on a subtle protocol detail (padding, nonce
  reuse, ratchet-state handling).
- **Minimalism:** zero duplicated logic; the Android-specific code is
  confined to what is GENUINELY platform-specific (UI, Keystore, process
  model, notifications) rather than to a second crypto stack.
- **Performance:** the existing crates are already tuned (ADR-014's
  binary-optimization profile — `lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`, `strip = true` — applies unchanged to the Android
  `cdylib` target; ADR-002/026's pure-Rust ML-KEM/ML-DSA get NEON
  acceleration for free once compiled for `aarch64-linux-android`,
  without a second hand-tuned implementation).

The one exception is transport: `umbra-net`'s Tor/Arti stack is reused
as-is (ADR-001's rationale — no external daemon, no root — applies to
Android even more strongly than to Linux), but BLE Mesh (a TODO B.4 item)
is genuinely Android-specific I/O with no existing Rust counterpart in this
workspace; see §9's phased plan for where that lands.

## 3. FFI boundary: UniFFI, and what it takes to honor ADR-012 across it

**Decision:** UniFFI generates the Kotlin bindings from
`crates/umbra-ffi`'s `UmbraCoreController` trait, packaged as a `cdylib`
(`libumbra_native.so`, matching ADR-023's existing naming). No hand-written
JNI in this project's own code, ever.

**Why:** The alternative — hand-rolled JNI via `jni-rs` or raw
`jni_sys` — pushes reference-counting, exception-translation, and
type-marshalling logic into code a human writes and can get wrong; that
class of bug (a leaked global reference, a wrong JNI signature string, a
missed `DeleteLocalRef` under load) is exactly the kind of memory/lifetime
error ADR-011/012 exist to keep out of this codebase. UniFFI generates
that glue from the trait definition and audits it as shared, widely-used
infrastructure rather than bespoke per-project code — the same "adopt
audited infrastructure over hand-rolled equivalents" reasoning ADR-026
already used to reject `pqcrypto-*`'s C bindings in favor of pure-Rust
crates.

**Honoring `#![forbid(unsafe_code)]` across the boundary:** `umbra-ffi`
itself stays `#![forbid(unsafe_code)]` (already true today). UniFFI's own
generated Rust-side glue and its `uniffi` crate dependency are NOT
Umbra-owned code — this is the same category ADR-028 already accepted for
`ring`/C-SQLite inside the Arti stack: a third-party dependency may carry
`unsafe`/FFI internals that Umbra's own code never touches directly and
never has to review line-by-line, as long as nothing NEW gets written
inside an Umbra crate. `umbra-hardware` remains the only Umbra-owned
`unsafe` exception; Android adds none.

**Concrete surface work (not yet built):** `StubController` today only
covers identity init, pairing, one-shot send, and panic-wipe — it predates
TODO A.3 (peers)/B.2 (group encryption)/B.3 (hardware keys, Decoy Vault).
Before Android can do anything the Linux CLI already does, the trait needs
new methods mirroring `umbra-cli`'s already-landed surface: peer
list/pairing (mirrors the Linux GUI's Phase 1 work landing in parallel with
this document), group create/add/remove/rotate (`umbra-group`), and
Decoy-Vault-aware unlock. This is mechanical trait extension, not a new
architectural decision — each method follows `IdentityKeys`'s existing
pattern of exposing only public material or opaque success/error results
across the boundary, never raw key bytes beyond what `IdentityKeys`
already documents as public.

## 4. UI framework: Compose, with Custom Canvas for anything sensitive

**Decision:** Jetpack Compose is the application framework (navigation,
layout, standard chrome: buttons, settings, dialogs, lists). Any screen or
element that renders SENSITIVE content — message text, identity
fingerprints, SAS codes, keys, Decoy-Vault contents — is drawn with a
Compose `Canvas` composable issuing raw Skia draw calls, never a standard
`Text`/`BasicText` composable.

**Why this isn't a contradiction:** `docs/SPECIFICATION.md` §3 commits to
Compose; ADR-016 commits to "Custom Skia Native Canvas... standard Android
text components will be abandoned" for the FLAG_SECURE-bypass defense.
Read literally these look opposed, but Compose's `Canvas` composable IS a
direct Skia drawing surface embedded inside the Compose tree — using it for
sensitive text satisfies ADR-016's actual requirement (an empty
`AccessibilityNodeInfo` subtree, no OS text-layout object a screen-reader
spyware or `AccessibilityService` exploit can read) while still living
inside Compose's navigation/state/layout system for everything else.
Non-sensitive chrome gets standard Compose components (accessibility
SHOULD work normally there — the threat this defense targets is content
exfiltration, not general app usability). ADR-016's own temporal pixel
interleaving and pure-Rust anti-hook detection layer underneath this
canvas; that mechanism is unchanged by this document and is a UI-code
concern, not an architecture decision.

**Minimalism consequence:** Compose's own dependency footprint
(`androidx.compose.*`) is accepted as the cost of a maintained, actively
security-patched framework over a hand-rolled View-based UI toolkit —
rejecting a full custom UI engine on minimalism grounds would trade a
well-audited dependency for a much larger from-scratch attack surface,
which is the wrong minimalism trade here. What stays minimal is everything
this document controls: no unnecessary Compose libraries beyond
`compose-ui`/`compose-foundation`/`compose-material3` (skip
`compose-navigation`'s full graph-based router in favor of a small manual
`when`-on-`sealed class` screen-state switch, matching this project's
existing "hand-roll the small thing rather than pull a library for it"
practice — e.g. the CLI's own hand-written argument dispatch over a bigger
framework).

## 5. Process/privilege separation on Android

**Decision:** ONE process for v1 of the Android client (no separate
`:engine` process). Revisit only if a concrete threat (not yet identified)
requires it.

**Why:** The Linux GUI's Engine/UI split (`umbra-engine`, TODO B.3.1) exists
because a single Linux process has essentially no OS-enforced isolation
between "the code that renders attacker-controlled Wayland/GTK content"
and "the code that holds identity key material" — Landlock/Seccomp had to
be built BY this project to create that boundary. Android already provides
a materially different starting point: every app runs in its own UID-based
sandbox (SELinux + per-app UID) enforced by the OS itself, and the
`android:process` manifest attribute CAN split an app into multiple
processes, but doing so:
- adds a real engineering cost (Binder IPC marshalling instead of a direct
  Rust function call across the UniFFI boundary, a second process to crash-
  and re-launch cleanly on key-material teardown, a second attack surface
  for Binder-specific vulnerabilities Android itself has had CVEs for), and
- buys comparatively little: the specific threat the Linux split defends
  against — a compromised GTK/Wayland renderer reading raw identity keys
  out of the SAME process's heap — has a weaker Android analogue, since
  Compose/Skia rendering a malicious peer's message content is a narrower,
  more contained attack surface than a full desktop windowing protocol
  stack, and Android's per-app sandbox already stops that compromised
  process from reaching OTHER apps' data even without an in-app split.

This is a judgment call, not a certainty — if TODO B.6/B.7's hardware/
side-channel or formal-verification work later identifies a concrete
in-process key-exposure path Compose rendering can trigger, revisit this
with a `:engine`-process design mirroring `umbra-engine`'s. Until then, a
second process is unjustified complexity relative to a threat that hasn't
been demonstrated on this platform. What DOES carry over unconditionally:
key material still lives only in `Zeroizing`-wrapped Rust memory (never a
Kotlin/JVM-heap `String` or `ByteArray`, which the JVM GC can relocate/copy
and cannot zero deterministically — the same GC argument ADR-011 already
used to ban Go from this project applies equally to holding secrets on the
Kotlin side of the boundary), and `libhardened_malloc.a` (ADR-023) still
hardens that Rust heap.

## 6. Key storage: StrongBox/Keystore as an additional unlock factor

**Decision:** Android Keystore (StrongBox-backed where the device has it,
falling back to TEE-backed Keystore where it doesn't) protects a
hardware-bound secret that gets mixed into the SAME Argon2id-derived
keystore key `umbra-crypto::keystore` already computes from the user's
passphrase — an additional factor, not a replacement scheme.

**Why:** `umbra-crypto::keystore`'s existing envelope
(`derive_keystore_key`: Argon2id, `docs/CRYPTOGRAPHY.md` §1 parameters,
`ChaCha20-Poly1305` AEAD) is already the project's one keystore-encryption
design, and ADR-009's own hardware-key work (FIDO2 on Linux) already
commits to mixing a hardware-derived secret INTO that same KDF rather than
building a parallel encryption scheme — "a LATER increment will mix into
the keystore's existing Argon2id passphrase KDF" (`umbra-hwkey`'s own
module doc). Android's Keystore plays the identical role FIDO2 plays on
Linux: a secret that cannot be extracted from the device (StrongBox keys
are non-exportable by hardware design; TEE-backed ones nearly so), so an
attacker with only the encrypted keystore FILE (e.g., an offline device
image) cannot brute-force it without also possessing the physical device's
Keystore-protected key. This keeps ONE consistent multi-factor-unlock
mental model across platforms — passphrase always required, hardware
factor mixed in where the platform has one — rather than Android getting
its own bespoke scheme.

**Mechanically:** `umbra-hwkey`'s existing PKCS#11 backend does NOT extend
to Android — Android Keystore has no PKCS#11 interface; it's a Kotlin/Java
API (`android.security.keystore.KeyGenParameterSpec`,
`setIsStrongBoxBacked(true)`) with an NDK C API (`NDK Keystore`, itself
JNI-adjacent). Given §3's "no hand-written JNI" rule, the Keystore
operation (generate-if-absent, then sign or derive a fixed challenge,
mirroring `umbra_hwkey::challenge_response`'s existing HMAC
challenge-response shape) runs on the KOTLIN side and crosses the FFI
boundary as a UniFFI **callback interface** (a Kotlin object implementing
a Rust-defined trait, which UniFFI supports natively) — the Rust core
calls `HardwareKeyProvider::challenge_response(challenge: &[u8]) -> Vec<u8>`
without knowing or caring that the implementation is Android Keystore on
one platform and a PKCS#11 module on another. This is new trait surface in
`umbra-ffi`, not a new architectural mechanism: it's the same "public
result crosses the boundary, secret material never does" shape
`IdentityKeys` already establishes.

## 7. Formal verification target list

**Decision:** Kani (Rust's bounded model checker), extending TODO B.7's
already-planned adoption rather than introducing a second, competing
verification tool. Kani proofs are written ONCE, in the shared Rust
crates, and verify Android's copy of the logic for free (same binary, same
proof) — this is a second reason (beyond §2's) that reusing the shared
Rust core rather than a parallel Kotlin implementation matters: Kotlin
logic cannot be Kani-verified at all.

**Why Kani specifically:** TODO B.7 already names Kani as this project's
first formal-verification target (wire-format parser panic-freedom); Prusti
and Creusot are real alternatives but neither is yet used anywhere in this
codebase, and introducing a second tool for Android alone (rather than
extending the one this project already committed to) would fragment the
verification story for no benefit — the properties below don't need a
different tool's strengths.

**Concrete targets** (naming real modules in today's tree, `crates/`
paths):
1. **`umbra-protocol::packet`, `::media_chunk`, `::smp`, `::sas`** — wire
   parsers. This is TODO B.7's own first candidate (panic-freedom over the
   whole bounded input space); Android inherits it automatically once it
   lands, since it's the same crate.
2. **`umbra-crypto::ratchet`** — Double Ratchet state transitions: prove
   the state machine never reaches an "encrypt with a used/skipped key" or
   "advance without a valid DH ratchet step" state — a `#[kani::proof]`
   harness exercising the ratchet's own transition function over a bounded
   sequence of send/receive calls, checking the type-state invariants
   ADR-021 already requires (`Session` cannot exist unauthenticated) hold
   under EVERY reachable sequence, not just the ones hand-picked tests
   cover.
3. **`umbra-crypto::kdf`, `::aead`** — key-derivation and AEAD wrapper
   invariants: output length correctness, that a derived key never equals
   its own input (a cheap but real sanity property), and — where Kani's
   model-checking approach reaches it — panic-freedom over malformed
   ciphertext/tag lengths at the AEAD boundary.
4. **`umbra-group::roster_sync`, `::rotate`, `::remove`** — PQ-MLS group
   state-machine properties: a removed member's key package can never be
   reachable from a POST-removal epoch's derived state (the property a
   group-messaging vulnerability class — "removed member still decrypts" —
   would violate); Kani proves this over the bounded state space these
   modules define, a strictly stronger claim than the existing
   `hermetic_multi_party`-style integration tests make.
5. **Constant-time comparison paths** — anywhere a MAC/tag/fingerprint
   comparison happens (`umbra_crypto::signing`, pairing's own SAS
   comparison), Kani is the wrong tool (it proves logical properties, not
   timing) — this stays `dudect`'s job per ADR-020, unchanged by this
   document. Listed here only to be explicit that "formal verification" in
   this doc means Kani's model-checking, not a timing-side-channel claim.

Each proof is a `#[cfg(kani)] #[kani::proof]` harness inside the crate it
verifies (matching Kani's own standard placement convention), gated so it
never compiles into a shipped binary (Android or Linux) — pure CI-time
verification, zero runtime or binary-size cost, consistent with §9's
minimalism goal.

## 8. Build system integration

**Decision:** `cargo-ndk` drives the Rust cross-compilation from Gradle via
a Gradle task that shells out to `cargo ndk` before the Kotlin compile
step (not a hand-rolled `ndk-build`/CMake integration).

**Concrete wiring:**
- Targets: `aarch64-linux-android` (primary; the overwhelming majority of
  real devices) and `x86_64-linux-android` (emulator only) as v1 targets;
  `armv7-linux-androideabi` deliberately excluded — matches this project's
  minimalism doctrine (no 32-bit ARM devices are a realistic target for a
  security-focused client whose threat model already assumes recent,
  patchable hardware for StrongBox/TEE anyway) and shrinks the `.apk`'s
  bundled `.so` count by a third versus a 3-ABI build.
- NDK version: pinned explicitly in the Gradle config (not "latest"), same
  reproducibility reasoning `Cargo.lock` pinning already applies elsewhere
  in this workspace.
- Output: `libumbra_native.so` per target ABI, packaged as Gradle
  `jniLibs`; UniFFI's Kotlin bindings are generated at build time via
  `uniffi-bindgen`'s Gradle plugin (not checked in, matching this project's
  existing practice of generating rather than committing derived
  artifacts).
- `Cargo.toml` profile: the Android `cdylib` target inherits ADR-014's
  existing release profile (`lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`, `strip = true`) unchanged — no Android-specific
  profile fork.

## 9. Minimal dependency footprint

Deliberately excluded, with a smaller adequate alternative chosen instead:
- **Dagger/Hilt** (dependency injection) → plain constructor injection; the
  app's dependency graph (one `UmbraCoreController` instance, a handful of
  Compose ViewModels) is small enough that a DI framework buys nothing over
  passing references explicitly, and removes an annotation-processor build-
  time and APK-size cost.
- **Retrofit/OkHttp** → not needed at all; all network I/O already goes
  through `umbra-net`'s Arti-based Tor stack in Rust, so the Kotlin side
  never makes its own network calls (any bug in a second, Kotlin-side HTTP
  stack would be a completely wasted attack surface this app has no reason
  to carry).
- **Room/SQLite-backed persistence** → not needed for message data (ADR-003
  diskless-by-default, ADR-015 24-hour crypto-shredding: message state is
  RAM-resident and expires, not a durable relational store); Android
  `DataStore` (a small key-value store, not a full ORM) is enough for the
  little durable app-preference state that exists (theme, last-used
  identity file reference) and nothing security-relevant ever lives there.
- **A second logging framework (Timber, etc.)** → `android.util.Log` calls
  gated behind a debug-build flag, mirroring ADR-022's "Rule of Silence"
  (no decorative output) applied to Android; nothing security-sensitive is
  ever logged, full stop.

## 10. Phased delivery outline

Matches this project's established practice of ordered, incrementally
shippable phases (mirrors the Linux GUI's own phased delivery). Each phase
produces something independently buildable/testable; none of this is an
implementation plan yet — that gets written per-phase when B.4 actually
starts.

1. **Phase 0 — FFI surface completion.** Extend `umbra-ffi`'s
   `UmbraCoreController` trait (§3) to cover peers/pairing and
   Decoy-Vault-aware unlock, matching what `umbra-cli`/the Linux GUI
   already support. No Android code yet — this phase is pure Rust,
   testable without a device or emulator. (Correction, landed with
   `docs/superpowers/plans/2026-09-19-android-phase0-ffi-unlock-pairing.md`:
   group-encryption trait methods were dropped from this phase's scope
   — no phase in this outline actually builds a group-chat UI on
   Android, so building that FFI surface now would be speculative,
   the same YAGNI gap the Linux GUI's own messaging design avoided by
   listing group chat as an explicit non-goal. Add group-encryption
   trait methods to whichever future phase actually needs them.)
2. **Phase 1 — Minimal Compose shell + cargo-ndk build wiring (§8).**
   Identity creation, pairing (QR display/scan), one-shot Tor-only
   send/receive — the Android equivalent of the Linux GUI's own Phase 1
   scope. Standard Compose components throughout (§4's Custom-Canvas
   requirement is NOT yet load-bearing here, since no real message content
   renders until Phase 2).
3. **Phase 2 — Custom Canvas sensitive-content rendering (§4) + Keystore
   unlock factor (§6).** Real message rendering behind the Canvas
   composable; StrongBox/Keystore mixed into keystore unlock.
4. **Phase 3 — Screen/clipboard/notification hardening (ADR-016, ADR-018).**
   Temporal pixel interleaving, anti-hook detection, clipboard destruction,
   zero-knowledge notifications — the items TODO B.4 already lists, each
   verified with the real-device testing ADR-016 itself calls for.
5. **Phase 4 — Kani proofs extended to Android-reused modules (§7).**
   Assuming TODO B.7's Linux-side Kani adoption has landed by this point;
   if not, this phase starts B.7's work rather than duplicating it.
6. **Phase 5 — BLE Mesh + offline QR (TODO B.4's remaining items).**
   Genuinely Android-specific I/O with no Rust-workspace counterpart today;
   scoped last since it has no dependency on anything above it.

## 11. Open questions / explicitly deferred

- **iOS:** never discussed anywhere in this project's docs; out of scope
  for this document and not assumed by any decision above (though §2's
  core-reuse strategy would transfer cleanly if iOS is ever pursued —
  UniFFI also targets Swift).
- **Mesh/Nym GUI parity:** the Linux GUI's own mesh/Nym transport wiring is
  itself still pending (tracked separately in `docs/TODO.md`); Android's
  BLE Mesh (Phase 5 above) is a DIFFERENT transport from Wi-Fi
  Direct/Nym and isn't blocked on that Linux work, but full transport
  parity across both clients is a longer-term convergence this document
  doesn't schedule.
- **`:engine` process split (§5):** explicitly revisitable, not closed —
  flagged for reconsideration if TODO B.6/B.7 work surfaces a concrete
  in-process threat.
- **Exact StrongBox availability fallback UX** (what the app tells a user
  on a device with no StrongBox, only TEE, or neither) is a UI-design
  question, not an architecture one — deferred to Phase 2's own
  implementation plan.
