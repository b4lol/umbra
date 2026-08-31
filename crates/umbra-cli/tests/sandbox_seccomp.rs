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
