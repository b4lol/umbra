//! Seccomp allowlist tests (TODO A.4). In-process: the filter applies to
//! the spawned thread only, so the test runner is unaffected; violations
//! return EPERM instead of killing (fail-closed, non-killing profile).

use umbra_cli::sandbox::restrict_syscalls_for_tests;

/// Under the filter, allowlisted syscalls succeed...
#[test]
fn allowlisted_syscalls_still_work() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handle = std::thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        restrict_syscalls_for_tests()?;
        // getrandom is allowlisted.
        let mut buf = [0u8; 16];
        umbra_cli::sandbox::fill_random_for_tests(&mut buf)?;
        assert!(buf.iter().any(|b| *b != 0));
        Ok(())
    });
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;
    Ok(())
}

/// The filter installs without error on a worker thread (the runner
/// thread stays unfiltered).
#[test]
fn filter_installs_cleanly() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handle = std::thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        restrict_syscalls_for_tests()?;
        Ok(())
    });
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;
    Ok(())
}

/// A NON-listed syscall (getppid) returns EPERM under the filter — the
/// fail-closed Errno action regression test. getppid is absent from
/// `allowed_syscalls` by design (nothing in Umbra needs it).
#[test]
fn unlisted_syscall_gets_eperm() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handle = std::thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        restrict_syscalls_for_tests()?;
        // The syscall must FAIL under the filter (fail-closed Errno
        // action). std may report the errno as PermissionDenied or as an
        // uncategorized error depending on the kernel's seccomp return —
        // only the Ok branch is a regression.
        match umbra_hardware::process::get_parent_pid() {
            Err(umbra_hardware::HardwareError::Syscall { .. }) => Ok(()),
            Err(other) => Err(Box::new(other)),
            Ok(_pid) => Err("getppid must fail under the filter".into()),
        }
    });
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;
    Ok(())
}

/// Kill-switch verification (TODO A.4, ADR-019): under the filter, IPv6
/// sockets of any type and UDP sockets of any family fail with EPERM at
/// the KERNEL level, while IPv4/UNIX STREAM sockets (the only transport
/// embedded Arti needs) stay available.
#[test]
fn ipv6_and_udp_sockets_are_blocked() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handle = std::thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        restrict_syscalls_for_tests()?;
        // IPv6: blocked regardless of socket type.
        for sock_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_RAW] {
            let err = match umbra_hardware::process::probe_socket(libc::AF_INET6, sock_type) {
                Err(err) => err,
                Ok(_fd) => return Err("AF_INET6 must be blocked".into()),
            };
            assert!(
                err.to_string().contains("EPERM")
                    || err.to_string().contains("denied")
                    || err.to_string().contains("peration not permitted"),
                "AF_INET6 block must be EPERM: {err}"
            );
        }
        // UDP (any family, including port 53 DNS): blocked.
        for domain in [libc::AF_INET, libc::AF_UNIX] {
            assert!(
                umbra_hardware::process::probe_socket(domain, libc::SOCK_DGRAM).is_err(),
                "SOCK_DGRAM must be blocked"
            );
        }
        // IPv4 STREAM (Tor relay TCP): still available (probe closes the
        // descriptor itself).
        let fd = umbra_hardware::process::probe_socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
        )?;
        assert!(fd >= 0, "AF_INET STREAM must remain allowed");
        Ok(())
    });
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;
    Ok(())
}
