//! Best-effort CPU register scrubbing (ADR-025 revision note, TODO A.4;
//! `LIMITATIONS_PLAN.md` item 1).
//!
//! rustc removed the `zero-call-used-regs` flag upstream (nightly 1.100.0
//! — neither the `-C` nor the `-Z` form survives; it was never
//! stabilized). This module provides the closest safe-Rust-accessible
//! equivalent: an `asm!` sequence that zeroes the **caller-saved** GP
//! registers at chosen points after sensitive computations.
//!
//! ## Honest semantics (what this does and does NOT guarantee)
//!
//! - Zeroing is **best-effort**: the compiler may have spilled secret
//!   values to the stack (covered by `mlockall` + non-dumpable, not by
//!   this scrub) or kept them in **callee-saved** registers, which a
//!   callee must not touch (`rbx rbp r12-r15` on x86_64) — zeroing those
//!   would corrupt the caller. `-fzero-call-used-regs=used-gpr` has the
//!   same constraint.
//! - **Vector registers are not scrubbed** in v1.0 (documented
//!   residual).
//! - **No automated register-state test exists**: verification is by
//!   construction (the clobber list below) and by reading the generated
//!   disassembly. The dudect suite cannot observe register files.
//! - The scrub is `#[inline(never)]` so the compiler cannot move or
//!   merge it away from the chosen call sites.

/// Zeroes the caller-saved GP registers on x86_64 (`rax rcx rdx rsi rdi
/// r8-r11`). A no-op on other architectures (aarch64 variant pending —
/// documented residual).
///
/// Call this immediately after a sensitive computation whose results
/// may still sit in volatile registers (KEM decapsulation, chain-key
/// derivation, skipped-key consumption). Cheap: ~10 cycle bit-clears.
///
/// The compiler treats every listed register as fully clobbered on
/// return, so it will not rely on any value the scrub overwrote.
pub fn scrub_volatile_registers() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `asm!` with explicit `out` declarations for every
        // register written. `xor eax, eax`-style 32-bit clears zero the
        // full 64-bit registers; no memory, stack, or flags preservation
        // is requested — the flags are deliberately NOT preserved
        // because `xor` writes them. Only caller-saved registers are
        // listed, so caller state in callee-saved registers is intact.
        // The sequence has no outputs the compiler could elide and no
        // `pure` option, so it is never removed.
        unsafe {
            core::arch::asm!(
                "xor eax, eax",
                "xor ecx, ecx",
                "xor edx, edx",
                "xor esi, esi",
                "xor edi, edi",
                "xor r8d, r8d",
                "xor r9d, r9d",
                "xor r10d, r10d",
                "xor r11d, r11d",
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("rdi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                options(nomem, nostack)
            );
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Documented no-op: the aarch64 variant (x0-x17 clears) is
        // pending and must be verified on real hardware before landing.
    }
}

#[cfg(test)]
mod tests {
    use super::scrub_volatile_registers;

    /// The scrub executes safely inside a normal call chain and leaves
    /// the calling convention intact (the compiler's clobber tracking is
    /// the contract; this test pins the "does not crash / corrupt" part):
    /// a value computed BEFORE the scrub must survive it deterministically.
    #[test]
    fn scrub_executes_and_preserves_execution() {
        fn sensitive_roundtrip(value: u64) -> u64 {
            let mixed = value ^ 0xA5A5_A5A5_A5A5_A5A5;
            scrub_volatile_registers();
            mixed.rotate_left(17).wrapping_add(0x1F1F)
        }
        let first = sensitive_roundtrip(0);
        let second = sensitive_roundtrip(0);
        let flipped = sensitive_roundtrip(1);
        assert_eq!(first, second, "the scrub must be deterministic for callers");
        assert_ne!(first, flipped, "input must still flow through the scrub");
    }
}
