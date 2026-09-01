# Umbra — Known-Limitations Remediation Plan (revised)

Revision of the 2026-08-31 proposal after fact-checking against the
codebase at `ed9dfad+` (v1.0.0-alpha.1 + serve/send-onion rounds).
Status lines cite the authoritative `TODO.md` / `DECISIONS.md` entries.

**Corrected execution order: 2 → 1 → 3-residual** (item 3's mechanism
already shipped; see below).

---

## Item 1 — CPU register zeroing (upstream flag removed)

**Status: BLOCKED upstream (TODO A.4, ADR-025 revision note).**

**Fact-check corrections to the original proposal:**
- Safe Rust **cannot** scrub the register file: there is no mechanism to
  address registers from safe code, and a post-hoc memset cannot recall
  values the ABI already placed in registers. The "saf Rust scrub.rs"
  premise is technically impossible — the only real mechanism is
  `core::arch::asm!` (an `unsafe` construct) or C.
- Only **caller-saved** registers may be zeroed (`rax rcx rdx rsi rdi
  r8-r11` on x86_64). Zeroing callee-saved registers (`rbx rbp r12-r15`)
  from a callee corrupts the caller — `-fzero-call-used-regs=used-gpr`
  has the same constraint.
- A "register dump test" in the dudect suite is not feasible: register
  state cannot be observed from a Rust test. Verification is by
  construction (the asm clobber list) plus reading the generated
  disassembly; this must be documented as unverifiable-by-test.

**Agreed implementation (best-effort mitigation, honestly labeled):**
- New module `crates/umbra-hardware/src/hardening.rs`:
  `scrub_volatile_registers()` — `#[inline(never)]`, `core::arch::asm!`
  with an explicit clobber list zeroing the caller-saved GPR set,
  x86_64 first (aarch64 follows the same pattern), documented `//
  SAFETY:` block stating the best-effort semantics.
- Call sites (added dependency edge `umbra-crypto → umbra-hardware`,
  a leaf crate — no cycle):
  - `pqxdh.rs` after `kem.decapsulate(...)` and the final HKDF;
  - `ratchet.rs` after skipped-key store consumption/eviction;
  - `GuardedBuffer::drop` (already in `umbra-hardware`).
- Residuals (documented, not hidden): the compiler may have spilled
  secrets to the stack (covered by `mlockall` + non-dumpable, not by the
  scrub); callee-saved register copies are out of reach; no automated
  register-state test exists.
- TODO A.4 wording: `Mitigated via best-effort explicit register scrub
  (umbra-hardware::hardening), pending rustc stabilization` — the row
  stays in the README honest-scope table with that wording.
- Optional C shim (`-fzero-call-used-regs=used-gpr`): **rejected** for
  v1.0 — ADR-011 bans C; `ring` is the single recorded deviation
  (ADR-028) and adding a second one needs its own ADR for marginal gain.

---

## Item 2 — Cover-traffic pump not wired into interactive flows

**Status: real and open.** `CoverPump` (`umbra-net::cover`) and
`Session::cover_packet()` exist and are tested; **no flow calls them**.

**Fact-check corrections:**
- The wire format is already indistinguishable by construction: every
  packet (real or `DUMMY_COVER`) is a fixed 1024-byte sealed packet; the
  cover marker lives inside the ratchet-encrypted payload only.
- `serve`'s `receive_message` already destroys cover silently
  (`None => {}` in the payload match). **`pipeline.rs` recv does NOT**:
  it maps `None` to an error ("unexpected partial SMP chunk"), so pipe
  recv would reject cover frames. That must be fixed as part of this
  item.
- Timing histogram tests are flaky by nature; the hermetic
  indistinguishability test must be format/size-based, not wall-clock.

**Agreed implementation (v1.0 scope — burst-level cover):**
- `pipeline::send_stream` and `tor_send::run`: after each real frame,
  emit a `cover_packet()` with probability/schedule driven by the
  existing `PoissonScheduler` (rate bounded by `Bounded(64)` queue
  semantics — hard cap `MAX_COVER_PER_MESSAGE`, hostile-input style
  bound). Cover frames consume ratchet keys; the receiver's skipped-key
  store already tolerates the resulting chain positions.
- `pipeline::recv_stream`: treat `None` (cover) as "destroyed silently,
  continue" — matching `serve`.
- Serve idle-gap cover (timer-driven dummies between real messages)
  requires a cancellable frame reader (cancel-safety: `read_exact`
  cannot be dropped mid-frame without desync) — **deferred to v2** with
  an explicit honest-scope note; burst-level cover hides count/size
  within a session, idle gaps remain visible.
- Hermetic tests: (a) `cover_frames_are_indistinguishable` — sealed
  bytes of real vs cover packets are the same length/format and both
  parse through `Session::receive` (real → Text, cover → `None`);
  (b) scheduler rate test on the Poisson schedule itself; (c) pipe
  roundtrip with interleaved cover frames.
- Docs: README honest-scope row for cover traffic gets REMOVED once
  landed; serve idle-gap stays as a v2 note in `umbra-net::messenger`
  and THREAT_MODEL.

---

## Item 3 — Persistent onion identity

**Status of the original proposal: STALE — the mechanism AND the
production call site already shipped** (serve round + outbound round):

- `TorTransport::bootstrap_persistent(base)` roots the Arti state dir;
  the native keystore under `<base>/state/keystore` keeps the onion
  identity; dirs are created `0700`.
- Production call sites: `umbra serve` (`serve.rs`:
  `bootstrap_persistent` + `spawn_inbound`) and `umbra send --onion`
  (`tor_send.rs` shares the same tree for guard-state reuse).
- Landlock reconciliation: `restrict_filesystem_with_exceptions` grants
  read+write on the Tor tree (narrowed: regular files/dirs only) and
  read-only `/etc`; wired in both flows.
- The proposed `~/.local/share/umbra/onion/` path is replaced by
  `<keystore parent>/tor/` — same-dir co-location so one Landlock
  exception covers the flow's own data (recorded in the ADR-007
  refinement note).

**Remaining work (the only real gap): live-network verification** — two
consecutive `umbra serve` runs publishing the SAME `.onion` address.
This cannot be hermetic (needs the live Tor network, minutes of
bootstrap). Agreed shape: a `#[ignore]`d integration test
(`serve::live_identity_persistence`) behind `--ignored`, run manually /
in a periodic nightly-with-network job, NOT in the required CI set.
Until then the README row keeps its "not live-verified" caveat — it is
NOT removed by this plan.

---

## Order and exit criteria

| Step | Item | Outcome |
|---|---|---|
| 1 | Cover pump wiring (burst-level) | README honest-scope row REMOVED; pipe recv accepts cover; new hermetic tests |
| 2 | Register scrub (asm, best-effort) | TODO A.4 → "Mitigated via best-effort scrub"; honest-scope row reworded (not removed) |
| 3 | Live identity verification | `#[ignore]` live test; README row keeps the caveat until it passes on the real network |

`just check` must stay green after every step; the two feature-gated
clippy runs (`--features tor` for umbra-cli and umbra-net) are part of
the verification loop.
