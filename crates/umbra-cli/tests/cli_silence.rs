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
