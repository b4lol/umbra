//! Nym-specific sandbox profile (TODO B.1). Filesystem needs are already
//! served by `umbra_cli::sandbox::restrict_filesystem_with_exceptions`
//! directly (already general-purpose, reused as-is — no wrapper needed).
//! This module adds ONLY the Seccomp profile.
//!
//! Sized from an OBSERVED real connection attempt against Nym's live
//! Sandbox testnet (Task 12), not assumed up front. The socket-family
//! part of the profile needed NO widening at all: `(AF_INET, SOCK_STREAM)`
//! and `(AF_UNIX, SOCK_STREAM)` — the exact same two rules the main
//! workspace's default `restrict_syscalls()` installs — were sufficient
//! for a full `NymClient::connect` round trip. The real gap was three
//! EXTRA BASE SYSCALLS: `nym-sdk`'s SQLite storage backend
//! (`nym-client-core-surb-storage`'s `StorageManager::init`) calls the
//! raw, non-`*at` `mkdir(2)` via `std::fs::create_dir_all` and the raw
//! `unlink(2)` via SQLite's unix VFS (`unixDelete` deleting a
//! not-yet-existing journal/WAL file), and `nym-pemstore`'s
//! `write_pem_file` (identity key persistence) finishes with
//! `std::fs::set_permissions`, which calls the raw `chmod(2)`. Arti's own
//! storage layer — what the upstream base list was originally sized for —
//! apparently never needed any of the three, using only the `*at` family
//! (`mkdirat`/`unlinkat`/`fchmodat`, all already on the list) instead. See
//! Task 12's report for the exact denial observed at each step.
//!
//! `umbra_cli::sandbox::install_filter` cannot express this: it hardcodes
//! `umbra-cli`'s own private base syscall list with no extension point,
//! only a caller-supplied `socket()` rule set (by design — see that
//! function's own docs). Since the gap here is extra BASE syscalls, not
//! a wider socket rule, this module cannot reuse `install_filter` and
//! instead builds its own filter, reusing `umbra_cli::sandbox::socket_rule`
//! for the socket() conditions (the one piece that *is* reusable as-is).
//! [`allowed_syscalls_nym`] below is a deliberate, documented copy of
//! `umbra_cli::sandbox`'s private `allowed_syscalls()` (verified against
//! `crates/umbra-cli/src/sandbox.rs` on 2026-09-06) plus the three
//! additions — keep it in sync if that upstream list ever changes.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch, apply_filter,
};
use umbra_cli::sandbox::socket_rule;

/// The syscall allowlist for the Nym profile: `umbra_cli::sandbox`'s
/// private base list (see the module docs above for the exact upstream
/// function/date verified) plus `SYS_mkdir`, `SYS_unlink` and
/// `SYS_chmod` — the three raw syscalls Task 12's empirical probe against
/// Nym's Sandbox testnet found missing.
#[must_use]
fn allowed_syscalls_nym() -> Vec<i64> {
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
        // Networking. NOTE: SYS_socket is NOT in this list — it is
        // installed with ARGUMENT rules in `restrict_syscalls_nym` that
        // allow only IPv4/UNIX STREAM sockets, exactly like the main
        // workspace's default profile (ADR-019-style kill-switch).
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
        // inherit this filter across clone).
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_sched_getaffinity,
        libc::SYS_rt_sigpending,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        // Minimal filesystem surface (content access is denied by
        // Landlock; these keep std's early initialization alive) plus the
        // mutation calls the Nym storage/keystore path needs.
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_fstat,
        libc::SYS_readlinkat,
        libc::SYS_fsync,
        libc::SYS_ftruncate,
        libc::SYS_pwrite64,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_utimensat,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        // AF_UNIX stream sockets (landlock-granted; used by the runtime
        // stack and resolver plumbing).
        libc::SYS_socketpair,
        // TASK 12 ADDITIONS (empirically observed, see module docs):
        // `nym-sdk`'s SQLite storage backend calls raw `mkdir`/`unlink`
        // directly, and `nym-pemstore`'s identity-key persistence calls
        // raw `chmod` directly — none of which Arti's own storage layer
        // needed (it only uses the `*at` family, already listed above).
        libc::SYS_mkdir,
        libc::SYS_unlink,
        libc::SYS_chmod,
    ];
    SYSCALLS.to_vec()
}

/// Builds and installs a Seccomp-BPF filter from
/// [`allowed_syscalls_nym`] plus a caller-supplied `socket()` rule set.
/// Same fail-closed, non-killing `Errno(EPERM)` design as
/// `umbra_cli::sandbox::install_filter` — duplicated here (rather than
/// reused) only because that function has no hook for extra base
/// syscalls; see the module docs for why that hook is needed.
fn install_filter_nym(
    socket_rules: Vec<SeccompRule>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_arch = "x86_64")]
    let arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = TargetArch::aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = allowed_syscalls_nym()
        .into_iter()
        .map(|number| (number, Vec::new()))
        .collect();
    rules.insert(libc::SYS_socket, socket_rules);
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

/// Applies the Nym Seccomp-BPF allowlist to the calling thread.
///
/// The SAME socket kill-switch as the main workspace's default
/// `restrict_syscalls()` — only `(AF_INET, SOCK_STREAM)` and
/// `(AF_UNIX, SOCK_STREAM)` — widened by exactly three base syscalls
/// (`mkdir`, `unlink`, `chmod`) that Task 12's live Sandbox-testnet probe
/// found `nym-sdk`'s storage backend and `nym-pemstore`'s key persistence
/// need. IPv6 and UDP (including DNS `:53`) stay blocked: a full mixnet
/// connection round trip never touched either.
///
/// Thread model: identical to `restrict_syscalls` — seccomp filters are
/// inherited across `clone`, so this MUST run before the Tokio runtime
/// (and its worker threads) is created.
///
/// # Errors
///
/// Returns an error if the filter cannot be built or installed (Seccomp
/// backend failure), or if a socket rule cannot be constructed.
pub fn restrict_syscalls_nym() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    install_filter_nym(vec![
        socket_rule(libc::AF_INET, libc::SOCK_STREAM)?,
        socket_rule(libc::AF_UNIX, libc::SOCK_STREAM)?,
    ])
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::restrict_syscalls_nym;

    /// Unique temp directory for this test process.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!(
            "umbra-nym-sandbox-test-{}-{nanos}-{name}",
            std::process::id()
        ))
    }

    /// Regression test for Task 12's three additions PLUS a proof that
    /// the socket kill-switch stays exactly as narrow as the default
    /// profile's (no accidental widening). Hermetic: no live network,
    /// mirrors the main workspace's `ipv6_and_udp_sockets_are_blocked`
    /// structure. In-process: the filter applies to the spawned thread
    /// only, so the test runner is unaffected.
    #[test]
    fn nym_profile_allows_raw_mkdir_unlink_chmod_and_default_sockets_only()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle = std::thread::spawn(
            || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                restrict_syscalls_nym()?;

                // The three additions: exercised via std's SAFE wrappers,
                // which is exactly how nym-sdk/nym-pemstore trip the raw
                // (non-`*at`) syscalls in production.
                let dir = temp_dir("mkdir");
                std::fs::create_dir_all(&dir)?;
                // A second call on an ALREADY-EXISTING directory is the
                // exact shape nym-sdk's storage init hits (config_dir
                // pre-created by the caller) — this is what raw `mkdir`
                // being blocked broke before this profile existed.
                std::fs::create_dir_all(&dir)?;

                let file = dir.join("probe.txt");
                std::fs::write(&file, b"probe")?;
                let mut perms = std::fs::metadata(&file)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&file, perms)?;
                std::fs::remove_file(&file)?;

                // Socket kill-switch: identical to the default profile —
                // NOT a blanket opendoor.
                let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
                drop(listener);
                assert!(
                    std::net::UdpSocket::bind("127.0.0.1:0").is_err(),
                    "SOCK_DGRAM (e.g. DNS :53) must still be blocked"
                );
                assert!(
                    std::net::TcpListener::bind("[::1]:0").is_err(),
                    "AF_INET6 must still be blocked"
                );

                Ok(())
            },
        );
        match handle.join() {
            Ok(result) => result,
            Err(_panic) => Err("worker thread panicked".into()),
        }
    }
}
