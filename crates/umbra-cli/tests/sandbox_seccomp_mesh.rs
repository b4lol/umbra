//! Seccomp profile tests for mesh mode (TODO B.1). The DEFAULT profile
//! (`sandbox_seccomp.rs`'s `ipv6_and_udp_sockets_are_blocked`) must stay
//! passing unchanged — this file only tests the SEPARATE, more
//! permissive mesh profile.

#![cfg(feature = "mesh")]

use umbra_cli::sandbox::restrict_syscalls_mesh_for_tests;

/// Under the mesh filter, exactly the two additional socket kinds mesh
/// needs are now allowed, alongside the pre-existing IPv4/UNIX STREAM
/// allowance — NOT a blanket opendoor: IPv6 DGRAM/RAW and IPv4 DGRAM
/// stay blocked.
#[test]
fn mesh_profile_allows_ipv6_stream_and_unix_dgram_but_nothing_else()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handle = std::thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        restrict_syscalls_mesh_for_tests()?;

        // NEW allowances mesh needs:
        let fd = umbra_hardware::process::probe_socket(
            libc::AF_INET6,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
        )?;
        assert!(
            fd >= 0,
            "AF_INET6 STREAM must be allowed under the mesh profile"
        );
        let fd = umbra_hardware::process::probe_socket(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
        )?;
        assert!(
            fd >= 0,
            "AF_UNIX DGRAM must be allowed under the mesh profile"
        );

        // Still blocked — proves this is a narrow, scoped widening, not
        // "allow everything":
        assert!(
            umbra_hardware::process::probe_socket(libc::AF_INET6, libc::SOCK_DGRAM).is_err(),
            "AF_INET6 DGRAM must still be blocked"
        );
        assert!(
            umbra_hardware::process::probe_socket(libc::AF_INET6, libc::SOCK_RAW).is_err(),
            "AF_INET6 RAW must still be blocked"
        );
        assert!(
            umbra_hardware::process::probe_socket(libc::AF_INET, libc::SOCK_DGRAM).is_err(),
            "AF_INET DGRAM (UDP, e.g. DNS :53) must still be blocked"
        );

        // Pre-existing allowances still work:
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
