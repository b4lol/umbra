//! Process sandboxing for the Linux client (TODO A.4, ADR-007):
//! Landlock LSM with a zero-access filesystem ruleset (plus a targeted
//! read+write `/dev/tty` exception so the TUI can draw) and a Seccomp-BPF
//! allowlist that returns `EPERM` for every non-listed syscall
//! (fail-closed, non-killing so violations surface as errors instead of
//! dead processes). The allowlist includes the network syscall family:
//! the embedded Arti client opens its own relay TCP connections after
//! `harden()` runs (ADR-001), and Landlock does not touch networking.

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};

use crate::cli::CliError;

/// Restricts the process to **zero filesystem access** (CLIENT_SECURITY:
/// "Landlock zero file system access"; ADR-007).
///
/// All filesystem `AccessFs` rights are handled but no `path_beneath` rule
/// is added, so every path becomes inaccessible. Already-open file
/// descriptors (stdin/stdout/TTY) keep working: Landlock restricts new
/// path operations only.
///
/// Fail-closed by design: `CompatLevel::HardRequirement` makes the ruleset
/// error out unless the running kernel enforces the full request — an
/// old kernel degrades the CLI to refusing to start rather than running
/// with a weaker sandbox.
///
/// # Errors
///
/// Returns [`CliError::Sandbox`] if the ruleset cannot be created or is
/// not fully enforced by the kernel.
pub fn restrict_filesystem() -> Result<landlock::RestrictionStatus, CliError> {
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V5))?
        .create()?;
    // Targeted exception: the TUI must be able to open its controlling
    // terminal under the zero-FS sandbox. Everything else stays denied.
    let created = match PathFd::new("/dev/tty") {
        Ok(tty) => created
            .add_rule(PathBeneath::new(tty, AccessFs::from_read(ABI::V5)))
            .map_err(CliError::Sandbox)?,
        Err(_e) => created,
    };
    let status = created.restrict_self()?;
    Ok(status)
}

/// The syscall allowlist for sandboxed session commands (x86_64 numbers
/// via the `libc` SYS_* constants; the profile is fail-closed: every
/// non-listed syscall returns `EPERM` instead of killing the process, so
/// violations surface as ordinary errors — ADR-006 forbids silent death).
///
/// Covers: memory management (mmap/mprotect/mlock family for the guarded
/// buffers), threading/futexes (Tokio), timers (Poisson scheduler),
/// eventfds/epoll (Arti + crossterm), terminal ioctls, getrandom, and
/// process exit paths. Filesystem syscalls remain listed because Landlock
/// already denies the content access; defence in depth keeps the process
/// functional while both layers gate.
#[must_use]
fn allowed_syscalls() -> Vec<i64> {
    const SYSCALLS: &[i64] = &[
        // Memory management.
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_mlock,
        libc::SYS_mlock2,
        libc::SYS_mlockall,
        libc::SYS_munlock,
        libc::SYS_munlockall,
        libc::SYS_mincore,
        // Process lifecycle and signals.
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_sched_yield,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_restart_syscall,
        // Synchronization.
        libc::SYS_futex,
        // Randomness and time.
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        // I/O multiplexing and descriptors.
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_pipe2,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        // Networking (embedded Arti client: Tor relay TCP + DNS-over-TCP
        // through the network; Landlock does NOT touch networking).
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        // Thread creation (Tokio workers spawned AFTER installation
        // inherit this filter across clone — see the module docs).
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_sched_getaffinity,
        libc::SYS_rt_sigpending,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        // Minimal filesystem surface (content access is denied by
        // Landlock; these keep std's early initialization alive).
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_getdents64,
    ];
    SYSCALLS.to_vec()
}

/// Applies the Seccomp-BPF allowlist to the calling thread.
///
/// Fail-closed via `Errno(EPERM)` on the mismatch action (not
/// `KillThread`): a violation degrades into an error the caller sees,
/// never a silently dead process.
///
/// Thread model: seccomp filters are INHERITED across `clone`, so
/// installing the filter before any worker thread is spawned covers the
/// whole process. `harden()` therefore MUST run before Tokio runtime
/// creation and Arti bootstrap — it does (main.rs is synchronous, the
/// runtime is created inside the command handlers after `harden()`).
/// Moving `harden()` behind runtime creation would leave workers
/// unfiltered and is a documented footgun.
///
/// # Errors
///
/// Returns [`CliError::Sandbox`] if the filter cannot be built or
/// installed.
pub fn restrict_syscalls() -> Result<(), CliError> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule, TargetArch, apply_filter};

    #[cfg(target_arch = "x86_64")]
    let arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = TargetArch::aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(()); // No table for this architecture: degrade open.

    let rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> = allowed_syscalls()
        .into_iter()
        .map(|number| (number, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        // Mismatch: every unlisted syscall gets EPERM (fail-closed).
        SeccompAction::Errno(libc::EPERM as u32),
        // Match: allow.
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| CliError::Seccomp(e.to_string()))?;
    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| CliError::Seccomp(e.to_string()))?;
    apply_filter(&program).map_err(|e| CliError::Seccomp(e.to_string()))?;
    Ok(())
}

/// Test hook: applies the allowlist to the calling thread (hermetic test
/// support; production callers use `restrict_syscalls`).
///
/// # Errors
///
/// See [`restrict_syscalls`].
#[doc(hidden)]
pub fn restrict_syscalls_for_tests() -> Result<(), crate::cli::CliError> {
    restrict_syscalls()
}

/// Test hook: fills a buffer from the OS entropy source.
///
/// # Errors
///
/// Returns an error if the OS entropy source fails.
#[doc(hidden)]
pub fn fill_random_for_tests(dest: &mut [u8]) -> Result<(), umbra_crypto::CryptoError> {
    umbra_crypto::rng::fill(dest)
}
