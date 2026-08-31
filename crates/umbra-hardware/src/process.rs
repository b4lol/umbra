//! Process-level memory hardening (TODO A.4, ADR-025): `mlockall`,
//! core-dump suppression, and related kernel locks behind a 100% Safe API.
//!
//! These are OS-kernel FFI calls; per ADR-012 they live in
//! `umbra-hardware` — the sole crate permitted `unsafe` — fully
//! encapsulated behind safe functions with `// SAFETY:` justifications.

use std::io::Error;

use libc::{MCL_CURRENT, MCL_FUTURE, PR_SET_DUMPABLE, RLIMIT_CORE, rlimit, setrlimit};

use crate::HardwareError;

/// Locks all process memory (current and future) against swapping.
///
/// RAM-only doctrine (ADR-003): pages must never reach swap. Must be called
/// before sensitive allocations for the `MCL_FUTURE` guarantee to cover them.
///
/// # Errors
///
/// Returns [`HardwareError::Syscall`] if the kernel refuses (for example,
/// `RLIMIT_MEMLOCK` exhausted).
pub fn lock_all_memory() -> Result<(), HardwareError> {
    // SAFETY: `mlockall` is a process-wide, stateless syscall; the flags
    // argument is a valid combination of MCL_CURRENT | MCL_FUTURE and the
    // call touches no user memory.
    let rc = unsafe { libc::mlockall(MCL_CURRENT | MCL_FUTURE) };
    if rc != 0 {
        return Err(HardwareError::Syscall {
            name: "mlockall",
            source: Error::last_os_error(),
        });
    }
    Ok(())
}

/// Marks the process non-dumpable (`PR_SET_DUMPABLE, 0`).
///
/// Blocks `ptrace`-based core/heap dumps by unprivileged peers and clears
/// the dumpable flag consulted by core-dump generation (ADR-025).
///
/// # Errors
///
/// Returns [`HardwareError::Syscall`] on failure.
pub fn disable_core_dumps() -> Result<(), HardwareError> {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes only scalar arguments and
    // modifies only this process's dumpable flag.
    let rc = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        return Err(HardwareError::Syscall {
            name: "prctl(PR_SET_DUMPABLE)",
            source: Error::last_os_error(),
        });
    }
    Ok(())
}

/// Caps the core-dump file size at zero (`RLIMIT_CORE = 0`).
///
/// Belt-and-braces with [`disable_core_dumps`]: even if the dumpable flag
/// were reset by a privileged helper, the kernel would refuse to write a
/// core file (ZERO_DATA_LEAKS "Memory Locks" mandates both).
///
/// # Errors
///
/// Returns [`HardwareError::Syscall`] on failure.
pub fn limit_core_dumps() -> Result<(), HardwareError> {
    // SAFETY: `setrlimit` takes a scalar resource selector and a plain
    // struct by reference; both are fully initialized stack values and the
    // call affects only this process.
    let rc = unsafe {
        let limits = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        setrlimit(RLIMIT_CORE, &limits)
    };
    if rc != 0 {
        return Err(HardwareError::Syscall {
            name: "setrlimit(RLIMIT_CORE)",
            source: Error::last_os_error(),
        });
    }
    Ok(())
}

/// Applies the full process-hardening set for a session.
///
/// Order matters: core dumps are disabled first (flag, then rlimit) so no
/// snapshot can be taken between operations; `mlockall` comes last and its
/// `MCL_FUTURE` part covers every later allocation.
///
/// # Errors
///
/// See [`disable_core_dumps`], [`limit_core_dumps`], [`lock_all_memory`].
pub fn harden_process() -> Result<(), HardwareError> {
    disable_core_dumps()?;
    limit_core_dumps()?;
    lock_all_memory()
}

/// Returns the parent process id (test hook for seccomp EPERM probes).
///
/// # Errors
///
/// Returns [`HardwareError::Syscall`] if the syscall fails (for example,
/// EPERM under a seccomp filter — the property this hook exists to test).
#[doc(hidden)]
pub fn get_parent_pid() -> Result<i64, HardwareError> {
    // SAFETY: `getppid` is a stateless, argument-free syscall.
    let rc = unsafe { libc::getppid() };
    if rc == -1 {
        return Err(HardwareError::Syscall {
            name: "getppid",
            source: Error::last_os_error(),
        });
    }
    Ok(rc as i64)
}

/// Performs a raw `socket(2)` and, on success, immediately closes the
/// descriptor (test hook for the seccomp kill-switch probes; the
/// production sandbox never opens sockets through this path).
///
/// # Errors
///
/// Returns [`HardwareError::Syscall`] if the syscall fails (for example,
/// EPERM under the socket argument filter — the property this hook
/// exists to test).
#[doc(hidden)]
pub fn probe_socket(domain: i32, sock_type: i32) -> Result<i32, HardwareError> {
    // SAFETY: `socket(2)` has no side effects beyond the returned
    // descriptor.
    let fd = unsafe { libc::socket(domain, sock_type, 0) };
    if fd < 0 {
        return Err(HardwareError::Syscall {
            name: "socket",
            source: Error::last_os_error(),
        });
    }
    // SAFETY: `fd` was created above, is owned by this function, and is
    // not aliased.
    let closed = unsafe { libc::close(fd) };
    if closed == -1 {
        return Err(HardwareError::Syscall {
            name: "close",
            source: Error::last_os_error(),
        });
    }
    Ok(fd)
}
