//! Guard-page-protected, RAM-locked key storage (TODO A.1, ADR-025,
//! HARDWARE_SECURITY.md §4).
//!
//! [`GuardedBuffer`] places a value on its own anonymous, `mlock`ed page
//! surrounded by `PROT_NONE` guard pages:
//!
//! ```text
//! [ guard: PROT_NONE ][ data: RW, mlock, MADV_DONTDUMP ][ guard: PROT_NONE ]
//! ```
//!
//! An overflow/underflow dereference faults immediately instead of silently
//! reading adjacent heap objects, `mlock` keeps the page out of swap, and
//! `MADV_DONTDUMP`/`MADV_DONTFORK`/`MADV_WIPEONFORK` keep it out of core
//! dumps and child processes. The value is zeroized and the mapping torn
//! down on drop.
//!
//! Access is closure-based so no reference to the guarded page can outlive
//! the borrow held by the guard object itself.
//!
//! Kernel floor: Linux >= 4.14 (`MADV_WIPEONFORK` semantics) with KSM
//! support for `MADV_UNMERGEABLE`. Every advisory is mandatory (ADR-025:
//! "zorunlu kılınacaktır"); a kernel that refuses any of them fails the
//! allocation closed instead of silently weakening the guarantee.

use std::fmt;

use libc::{
    _SC_PAGESIZE, MADV_DONTDUMP, MADV_DONTFORK, MADV_UNMERGEABLE, MADV_WIPEONFORK, MAP_ANONYMOUS,
    MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, madvise, mlock, mmap, mprotect, munlock, munmap,
    sysconf,
};
use std::io::Error;
use zeroize::Zeroize;

use crate::HardwareError;

/// Computes the three-region layout for a value of `size` bytes.
///
/// Returns `(data_len, total)` in bytes; the data region is at least one
/// page and page-aligned, and the total spans three equal regions
/// (guard / data / guard).
fn layout_for(size: usize, page: usize) -> Result<(usize, usize), HardwareError> {
    // A zero-sized value still occupies one full data page.
    let effective = size.max(1);
    let data_len = effective
        .checked_next_multiple_of(page)
        .ok_or(HardwareError::InvalidLayout)?;
    let total = data_len
        .checked_mul(3)
        .ok_or(HardwareError::InvalidLayout)?;
    Ok((data_len, total))
}

/// A value guarded by `PROT_NONE` pages, locked in RAM and zeroized on drop.
pub struct GuardedBuffer<T> {
    /// Base of the whole mapping (guards + data).
    base: *mut u8,
    /// Total mapping length.
    total: usize,
    /// Offset of the data region within the mapping.
    data_offset: usize,
    /// Length of the data region.
    data_len: usize,
    /// Marker: we own a `T` in the data region.
    _value: std::marker::PhantomData<T>,
}

// SAFETY: the guarded page is owned exclusively by this buffer; sending it
// to another thread moves that exclusive ownership. Access goes through
// `&self`/`&mut self` closures, so the usual aliasing rules apply.
unsafe impl<T: Send> Send for GuardedBuffer<T> {}
// SAFETY: `&GuardedBuffer<T>` only ever hands out `&T` through `with`
// (which two threads may call concurrently — sound because both only share
// `&T`, requiring `T: Sync` exactly like a plain `&T`), and `&mut self`
// methods exclude any concurrent access, mirroring owned-value semantics.
unsafe impl<T: Sync> Sync for GuardedBuffer<T> {}

impl<T> GuardedBuffer<T> {
    /// Moves `value` into a fresh guarded, RAM-locked page.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::InvalidLayout`] if `T`'s alignment exceeds
    /// the system page size, and [`HardwareError::Syscall`] if
    /// `mmap`/`mprotect`/`mlock`/`madvise` fails.
    pub fn new(value: T) -> Result<Self, HardwareError> {
        let page = Self::page_size()?;
        if std::mem::align_of::<T>() > page {
            return Err(HardwareError::InvalidLayout);
        }
        let (data_len, total) = layout_for(std::mem::size_of::<T>(), page)?;
        let data_offset = data_len;

        // SAFETY: anonymous private mapping of a computed, non-zero length;
        // the returned pointer is page-aligned by the kernel.
        let base = unsafe {
            mmap(
                std::ptr::null_mut(),
                total,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(HardwareError::Syscall {
                name: "mmap",
                source: Error::last_os_error(),
            });
        }
        let base = base.cast::<u8>();

        // SAFETY: `data_offset` equals the guard-region length, so
        // `data..data+data_len` stays inside the `total`-byte mapping.
        let data = unsafe { base.add(data_offset) };
        // SAFETY: `data..data+data_len` lies inside the mapping and is
        // currently PROT_NONE; flipping it to RW cannot affect the guards.
        if unsafe { mprotect(data.cast(), data_len, PROT_READ | PROT_WRITE) } != 0 {
            let err = Error::last_os_error();
            // SAFETY: unmapping the whole region we just created; no other
            // reference exists yet.
            unsafe { Self::unmap(base, total) };
            return Err(HardwareError::Syscall {
                name: "mprotect",
                source: err,
            });
        }

        // SAFETY: data region length is at least one page and page-aligned.
        if unsafe { mlock(data.cast(), data_len) } != 0 {
            let err = Error::last_os_error();
            // SAFETY: see above; the mapping is exclusively ours.
            unsafe { Self::unmap(base, total) };
            return Err(HardwareError::Syscall {
                name: "mlock",
                source: err,
            });
        }

        for (name, advice) in [
            ("madvise(DONTDUMP)", MADV_DONTDUMP),
            ("madvise(DONTFORK)", MADV_DONTFORK),
            ("madvise(WIPEONFORK)", MADV_WIPEONFORK),
            ("madvise(UNMERGEABLE)", MADV_UNMERGEABLE),
        ] {
            // All four advisories are mandatory (ADR-025); a refusal fails
            // the allocation closed — see the module docs for the floor.
            // SAFETY: valid mapped range owned by this buffer.
            if unsafe { madvise(data.cast(), data_len, advice) } != 0 {
                let err = Error::last_os_error();
                // SAFETY: exclusively-owned mapping; value not yet moved in.
                unsafe {
                    munlock(data.cast(), data_len);
                    Self::unmap(base, total);
                }
                return Err(HardwareError::Syscall { name, source: err });
            }
        }

        // SAFETY: `data` is valid for `size_of::<T>()` bytes (data_len >=
        // size_of::<T>()), page-aligned (checked against align_of::<T>()
        // above), and no prior value exists there; this moves `value` into
        // the guarded page and takes sole ownership.
        unsafe { data.cast::<T>().write(value) };

        Ok(Self {
            base,
            total,
            data_offset,
            data_len,
            _value: std::marker::PhantomData,
        })
    }

    /// Runs `f` with a shared reference to the guarded value.
    ///
    /// The reference is confined to the closure; the guard pages themselves
    /// are never de-armed for the lifetime of the buffer, and exclusive
    /// mutation is only reachable through [`Self::with_mut`].
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        // SAFETY: while the closure runs, no other access to the value can
        // be created (`with_mut` takes `&mut self`, excluded by `&self`);
        // the pointer is valid, initialized, and aligned.
        let value = unsafe { &*self.data_ptr() };
        f(value)
    }

    /// Runs `f` with an exclusive reference to the guarded value.
    pub fn with_mut<R>(&mut self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: `&mut self` guarantees exclusive access; the pointer is
        // valid, initialized, and aligned for `T`.
        let value = unsafe { &mut *self.data_ptr() };
        f(value)
    }

    /// Byte pointer to the guarded value.
    fn data_ptr(&self) -> *mut T {
        // SAFETY: offset stays within the mapping; alignment is page-based
        // (>= align_of::<T>() for all practical T; enforced below for exotic
        // alignments at construction time via `layout_for`).
        unsafe { self.base.add(self.data_offset).cast::<T>() }
    }

    /// System page size.
    fn page_size() -> Result<usize, HardwareError> {
        // SAFETY: `_SC_PAGESIZE` is a constant query; no side effects.
        let page = unsafe { sysconf(_SC_PAGESIZE) };
        if page <= 0 {
            return Err(HardwareError::Syscall {
                name: "sysconf(_SC_PAGESIZE)",
                source: Error::last_os_error(),
            });
        }
        Ok(page as usize)
    }

    /// Tears down the mapping without zeroizing (used on error paths).
    ///
    /// # Safety
    ///
    /// `base` must be the base of an exclusively-owned mapping of `total`
    /// bytes that contains no initialized value needing destruction.
    unsafe fn unmap(base: *mut u8, total: usize) {
        // SAFETY: caller guarantees exclusive ownership of a live mapping
        // of exactly `total` bytes rooted at `base`.
        unsafe {
            let _ = munmap(base.cast(), total);
        }
    }
}

impl<T> Drop for GuardedBuffer<T> {
    fn drop(&mut self) {
        // SAFETY: `&mut self` is exclusive; the data region is valid and
        // contains exactly one initialized `T`.
        let value = unsafe { &mut *self.data_ptr() };
        // SAFETY: dropping in place is required by ownership; the raw bytes
        // are then wiped with the `zeroize` crate's volatile-safe wipe
        // (CODE_MANIFESTO §7), and only afterwards unlocked and unmapped.
        unsafe {
            std::ptr::drop_in_place(value);
            let bytes = std::slice::from_raw_parts_mut(
                self.data_ptr().cast::<u8>(),
                std::mem::size_of::<T>(),
            );
            bytes.zeroize();
            munlock(self.base.add(self.data_offset).cast(), self.data_len);
            Self::unmap(self.base, self.total);
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for GuardedBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print guarded contents.
        f.debug_struct("GuardedBuffer").finish_non_exhaustive()
    }
}
