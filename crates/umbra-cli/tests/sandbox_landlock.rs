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
            restrict_filesystem_with_exceptions(&[granted_path.as_path()], &[])?;

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
                restrict_filesystem_with_exceptions(&[missing.as_path()], &[]).is_err(),
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

/// The exact exception set `serve`/`tui` install (Tor tree + BOTH group
/// state directories, plus read-only `/etc`) actually enforces, and each
/// granted directory supports the temp-file + rename persistence its
/// writer uses (`persistence::save_group_state` for `groups/`,
/// `keypackage::save_keypackage_storage` for `keypackages/`) — the
/// hermetic inbound-loop tests run WITHOUT a sandbox, so only this test
/// can catch a grant that the kernel rejects or that is too narrow for
/// the actual write pattern.
#[test]
fn serve_exception_set_installs_and_grants_group_state()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = temp_dir("serve-set");
    let tor_base = base.join("tor");
    let groups = base.join("groups");
    let keypackages = base.join("keypackages");
    let keystore = base.join("keystore.enc");
    std::fs::create_dir_all(&tor_base)?;
    std::fs::create_dir_all(&groups)?;
    std::fs::create_dir_all(&keypackages)?;
    std::fs::write(&keystore, b"keystore")?;

    let sandboxed_base = base.clone();
    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            restrict_filesystem_with_exceptions(
                &[tor_base.as_path(), groups.as_path(), keypackages.as_path()],
                &[std::path::Path::new("/etc")],
            )?;
            // `inbound.rs`'s `process_welcome` calls `create_dir_all`
            // on the (already existing, granted) groups directory before
            // saving — that must NOT fail closed, or every inbound
            // Welcome would break under the sandbox.
            std::fs::create_dir_all(&groups)?;
            // `save_group_state` writes a same-dir temp file and renames
            // it over the target; both must be permitted.
            let tmp = groups.join("cell.enc.tmp");
            std::fs::write(&tmp, b"state")?;
            std::fs::rename(&tmp, groups.join("cell.enc"))?;
            assert_eq!(std::fs::read(groups.join("cell.enc"))?, b"state".to_vec());
            // `save_keypackage_storage` first ensures its own directory
            // exists, with this exact call shape, before writing.
            {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&keypackages)?;
            }
            // It then does the same temp-file + rename inside
            // `keypackages/` (its store is `keypackages/store.enc`, so
            // the temp file is `keypackages/store.enc.tmp`) — the whole
            // reason the store moved into its own directory.
            let kp_tmp = keypackages.join("store.enc.tmp");
            std::fs::write(&kp_tmp, b"kp")?;
            std::fs::rename(&kp_tmp, keypackages.join("store.enc"))?;
            assert_eq!(
                std::fs::read(keypackages.join("store.enc"))?,
                b"kp".to_vec()
            );
            // Re-saving over an existing store must keep working (every
            // export and every processed Welcome does exactly this).
            let kp_tmp = keypackages.join("store.enc.tmp");
            std::fs::write(&kp_tmp, b"kp2")?;
            std::fs::rename(&kp_tmp, keypackages.join("store.enc"))?;
            assert_eq!(
                std::fs::read(keypackages.join("store.enc"))?,
                b"kp2".to_vec()
            );
            // The keystore file itself stays unreachable (the invariant
            // the narrow, directories-only grant exists to preserve).
            assert!(
                std::fs::read(&keystore).is_err(),
                "the keystore file must stay denied post-sandbox"
            );
            // And nothing new can be created beside it.
            assert!(
                std::fs::write(sandboxed_base.join("smuggled"), b"x").is_err(),
                "the keystore directory itself must stay denied post-sandbox"
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

/// A REGULAR FILE cannot be an exception path here: the grant's
/// right-set is directory-shaped (`ReadDir`/`MakeReg`/`Refer`/…), which
/// Landlock rejects on a non-directory, and `CompatLevel::
/// HardRequirement` turns that into a hard failure — i.e. `serve`/`tui`
/// would refuse to start. Every caller must therefore grant a
/// DIRECTORY (which is why the key-package store lives in
/// `keypackages/` rather than as a bare file next to the keystore); this
/// test pins the constraint so it is not rediscovered in production.
#[test]
fn file_exception_path_fails_closed() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = temp_dir("file-exception");
    std::fs::create_dir_all(&base)?;
    let file = base.join("store.enc");
    std::fs::write(&file, b"stored")?;

    let handle = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            assert!(
                restrict_filesystem_with_exceptions(&[file.as_path()], &[]).is_err(),
                "a regular-file exception path must fail the ruleset closed"
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
