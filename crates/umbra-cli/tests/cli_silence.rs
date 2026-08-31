//! CLI Rule-of-Silence and NDJSON output tests (TODO A.5, ADR-022).
//!
//! Hermetic: spawns the built `umbra` binary; no network.

use std::process::Command;

/// Path to the built binary (provided by cargo for integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_umbra");

/// `umbra keygen` (plain) prints exactly 5 key=value lines, nothing else.
#[test]
fn keygen_plain_is_five_kv_lines() -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new(BIN).arg("keygen").output()?;
    assert!(out.status.success());
    assert!(out.stderr.is_empty(), "stderr must be empty on success");
    let stdout = String::from_utf8(out.stdout)?;
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5);
    for line in &lines {
        let (key, value) = line.split_once('=').ok_or("expected key=value line")?;
        assert!(!key.is_empty());
        assert!(
            value.chars().all(|c| c.is_ascii_hexdigit()),
            "values must be hex: {line}"
        );
    }
    let expected = [
        "x25519-public=",
        "spk-public=",
        "spk-signature=",
        "ml-kem-768-public=",
        "ml-dsa-65-public=",
    ];
    for (line, prefix) in lines.iter().zip(expected.iter()) {
        assert!(
            line.starts_with(prefix),
            "line {line} must start with {prefix}"
        );
    }
    Ok(())
}

/// `umbra --json keygen` prints one NDJSON object with the same keys.
#[test]
fn keygen_json_is_single_object() -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new(BIN).args(["--json", "keygen"]).output()?;
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8(out.stdout)?;
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "NDJSON: exactly one line");
    let object = lines.first().ok_or("expected one NDJSON line")?;
    assert!(object.starts_with("{\"x25519-public\":\""));
    assert!(object.ends_with("\"}"));
    // Values are hex inside quoted JSON strings.
    assert!(!object.contains('\\'), "no escapes expected for hex values");
    for key in [
        "x25519-public",
        "spk-public",
        "spk-signature",
        "ml-kem-768-public",
        "ml-dsa-65-public",
    ] {
        assert!(object.contains(&format!("\"{key}\":\"")), "missing {key}");
    }
    Ok(())
}

/// `umbra send` fails with a diagnostic on stderr and NOTHING on stdout
/// (Rule of Silence: errors never pollute the data channel). Both the
/// clap parse error and the runtime diagnostic path are covered.
#[test]
fn send_errors_go_to_stderr() -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new(BIN).arg("send").output()?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "stdout must stay clean on failure");
    let stderr = String::from_utf8(out.stderr)?;
    assert!(!stderr.trim().is_empty(), "a diagnostic must be present");

    // Runtime failure (missing keystore) exercises the `umbra: ` printer.
    let out = Command::new(BIN)
        .args([
            "send",
            "--peer",
            "nobody",
            "--keystore",
            "/nonexistent/umbra.enc",
        ])
        .output()?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "stdout must stay clean on failure");
    let stderr = String::from_utf8(out.stderr)?;
    assert!(stderr.starts_with("umbra: "));
    Ok(())
}

/// Same contract for `umbra recv`.
#[test]
fn recv_errors_go_to_stderr() -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new(BIN).arg("recv").output()?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8(out.stderr)?.starts_with("umbra: "));
    Ok(())
}

/// Version output is a single short line (no banner, Rule of Silence).
#[test]
fn version_is_one_line() -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new(BIN).arg("--version").output()?;
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8(out.stdout)?;
    assert_eq!(stdout.lines().count(), 1);
    Ok(())
}

/// `umbra fingerprint --peer NAME` prints exactly one 64-char hex line
/// to stdout (Rule of Silence: no banners, no prefixes). Uses the
/// `--peer` branch: peer records are public material and need no
/// privileged `mlockall`, keeping the test unprivileged.
#[test]
fn fingerprint_success_prints_single_hex_line() -> Result<(), Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("umbra-fp-silence-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let pass_path = dir.join("pass");
    std::fs::write(&pass_path, b"silence test passphrase")?;
    let keystore_path = dir.join("umbra.enc");
    let keystore_str = keystore_path.to_str().ok_or("keystore path")?;
    let pass_str = pass_path.to_str().ok_or("passphrase path")?;
    let base = ["--passphrase-file", pass_str, "--keystore", keystore_str];

    let out = Command::new(BIN).args(base).args(["init"]).output()?;
    assert!(
        out.status.success(),
        "init must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(BIN)
        .args(base)
        .args(["export-pairing"])
        .output()?;
    assert!(out.status.success());
    let payload = String::from_utf8(out.stdout)?.trim().to_string();
    assert!(!payload.is_empty());

    let out = Command::new(BIN)
        .args(base)
        .args(["pair", "--peer-name", "mirror", "--peer-payload", &payload])
        .output()?;
    assert!(
        out.status.success(),
        "pair must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(BIN)
        .args(base)
        .args(["fingerprint", "--peer", "mirror"])
        .output()?;
    assert!(out.status.success());
    assert!(out.stderr.is_empty(), "stderr must be empty on success");
    let stdout = String::from_utf8(out.stdout)?;
    let mut lines = stdout.lines();
    let line = lines.next().ok_or("expected one line")?;
    assert_eq!(lines.next(), None, "exactly one line");
    assert_eq!(line.len(), 64, "32-byte hex: {line}");
    assert!(line.bytes().all(|b| b.is_ascii_hexdigit()), "hex only");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
