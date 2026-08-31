//! Landlock ruleset tests (TODO A.4/A.2). In-process: the ruleset applies
//! to the spawned thread only, so the test runner is unaffected. Requires
//! a kernel with Landlock V5 enforcement (fail-closed: the test errors
//! rather than passing vacuously on an unsupported kernel).

use std::path::PathBuf;

use umbra_cli::sandbox::{restrict_filesystem, restrict_filesystem_with_exceptions};

/// Unique temp directory for this test process.
fn temp_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("umbra-ll-{}-{nanos}-{name}", std::process::id()))
}

/// Under the zero-FS ruleset with one exception directory, files inside
/// the exception stay readable and creatable while everything else
/// becomes inaccessible.
#[test]
fn exception_dir_grants_exactly_that_dir() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = temp_dir("exception");
    let inside = base.join("granted");
    let outside_root = temp_dir("denied-root");
    let outside = outside_root.join("outside.txt");
    std::fs::create_dir_all(&inside)?;
    std::fs::create_dir_all(&outside_root)?;
    std::fs::write(inside.join("seed.txt"), b"seed")?;
    std::fs::write(&outside, b"outside")?;

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let granted_path = inside.clone();
            restrict_filesystem_with_exceptions(&[granted_path.as_path()])?;

            // Read inside the exception: allowed.
            let seeded = std::fs::read(inside.join("seed.txt"))?;
            assert_eq!(seeded, b"seed");

            // Create/write inside the exception: allowed (full AccessFs).
            std::fs::write(inside.join("new.txt"), b"written")?;
            assert_eq!(std::fs::read(inside.join("new.txt"))?, b"written");

            // Everything outside: denied.
            assert!(
                std::fs::read(&outside).is_err(),
                "a path outside the exception must be unreadable"
            );
            assert!(
                std::fs::create_dir(inside.join("..").join("sibling")).is_err()
                    || !std::path::Path::new(&inside)
                        .parent()
                        .ok_or("parent")?
                        .join("sibling")
                        .join("..")
                        .exists(),
                "sibling creation outside the exception must be denied"
            );
            Ok(())
        },
    );
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;

    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&outside_root);
    Ok(())
}

/// The zero-FS ruleset (no exceptions) denies even a file that exists and
/// was readable before the ruleset installed.
#[test]
fn zero_fs_denies_preexisting_files() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = temp_dir("zerofs");
    let file = base.join("plain.txt");
    std::fs::create_dir_all(&base)?;
    std::fs::write(&file, b"plain")?;

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let file = file.clone();
            restrict_filesystem()?;
            assert!(
                std::fs::read(&file).is_err(),
                "zero-FS must deny a preexisting file"
            );
            Ok(())
        },
    );
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// A nonexistent exception path fails closed (the ruleset refuses to
/// install rather than granting nothing silently).
#[test]
fn nonexistent_exception_path_fails_closed() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let base = temp_dir("missing");
    std::fs::create_dir_all(&base)?;
    let missing = base.join("does-not-exist");

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let missing = missing.clone();
            assert!(
                restrict_filesystem_with_exceptions(&[missing.as_path()]).is_err(),
                "a nonexistent exception path must fail the ruleset"
            );
            Ok(())
        },
    );
    let result = match handle.join() {
        Ok(result) => result,
        Err(_panic) => return Err("worker thread panicked".into()),
    };
    result?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}
