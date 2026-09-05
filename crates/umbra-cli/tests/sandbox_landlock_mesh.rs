//! Landlock exception tests for the mesh transport's control sockets
//! (TODO B.1). Mirrors `sandbox_landlock.rs`'s style (`Result`-returning
//! tests with `?` rather than `.expect()`, since the workspace denies
//! `clippy::expect_used`).

#![cfg(feature = "mesh")]

use umbra_cli::sandbox::restrict_filesystem_for_mesh;

fn temp_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "umbra-mesh-landlock-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ))
}

#[test]
fn can_create_and_connect_a_socket_in_the_own_ctrl_dir()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wpa_dir = temp_dir("wpa");
    let own_dir = temp_dir("own");
    std::fs::create_dir_all(&wpa_dir)?;
    std::fs::create_dir_all(&own_dir)?;

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            restrict_filesystem_for_mesh(&wpa_dir, &own_dir)?;

            // MakeSock + WriteFile on own_dir: binding a new UnixDatagram
            // there must succeed under the restriction.
            let sock_path = own_dir.join("client.sock");
            let socket = std::os::unix::net::UnixDatagram::bind(&sock_path);
            assert!(
                socket.is_ok(),
                "must be able to create our own ctrl socket: {socket:?}"
            );
            Ok(())
        },
    );
    match handle.join() {
        Ok(result) => result,
        Err(_panic) => Err("worker thread panicked".into()),
    }
}

#[test]
fn cannot_create_a_socket_outside_the_granted_dirs()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wpa_dir = temp_dir("wpa2");
    let own_dir = temp_dir("own2");
    let outside_dir = temp_dir("outside2");
    std::fs::create_dir_all(&wpa_dir)?;
    std::fs::create_dir_all(&own_dir)?;
    std::fs::create_dir_all(&outside_dir)?;

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            restrict_filesystem_for_mesh(&wpa_dir, &own_dir)?;

            let sock_path = outside_dir.join("client.sock");
            let socket = std::os::unix::net::UnixDatagram::bind(&sock_path);
            assert!(
                socket.is_err(),
                "must NOT be able to create a socket outside the grant"
            );
            Ok(())
        },
    );
    match handle.join() {
        Ok(result) => result,
        Err(_panic) => Err("worker thread panicked".into()),
    }
}

#[test]
fn can_read_and_write_in_the_wpa_ctrl_dir() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let wpa_dir = temp_dir("wpa3");
    let own_dir = temp_dir("own3");
    std::fs::create_dir_all(&wpa_dir)?;
    std::fs::create_dir_all(&own_dir)?;
    // Simulate wpa_supplicant's own socket already existing there,
    // created BEFORE the ruleset installs (in a real deployment the
    // daemon owns this path and creates it well before we ever run;
    // our grant deliberately does NOT include MakeReg for wpa_dir, so
    // the file must pre-exist for this test to reflect reality).
    let existing = wpa_dir.join("p2p-dev-wlan0");
    std::fs::write(&existing, b"seed")?;

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            restrict_filesystem_for_mesh(&wpa_dir, &own_dir)?;

            // We must be able to connect to (open for write) the
            // pre-existing socket-substitute file inside wpa_dir, i.e.
            // regular-file read+write — not create, not truncate (a
            // real UnixDatagram control socket is never truncated, so
            // the grant deliberately omits AccessFs::Truncate;
            // `std::fs::write` would O_TRUNC, so open explicitly
            // without it here).
            use std::io::Write as _;
            let write_result = std::fs::OpenOptions::new()
                .write(true)
                .open(&existing)
                .and_then(|mut file| file.write_all(b"x"));
            assert!(
                write_result.is_ok(),
                "must be able to write inside the wpa ctrl dir: {write_result:?}"
            );
            Ok(())
        },
    );
    match handle.join() {
        Ok(result) => result,
        Err(_panic) => Err("worker thread panicked".into()),
    }
}
