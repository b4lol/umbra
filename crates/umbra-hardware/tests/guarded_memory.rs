//! Hermetic tests for guard-page memory (TODO A.1, HARDWARE_SECURITY §4).
//!
//! Linux-only by nature (mmap/mprotect/mlock); CI runners are Linux.
//! Tests return `Result` so no `panic!`/`unwrap` appears in our code
//! (CODE_MANIFESTO §1).

#![cfg(target_os = "linux")]

use umbra_hardware::HardwareError;
use umbra_hardware::memory::GuardedBuffer;

/// Stores and reads back a scalar through the guarded page.
#[test]
fn guarded_scalar_roundtrip() -> Result<(), HardwareError> {
    let guarded = GuardedBuffer::new(0x4142_4344_4546_4748u64)?;
    guarded.with(|value| assert_eq!(*value, 0x4142_4344_4546_4748));
    Ok(())
}

/// Mutates the guarded value through the exclusive accessor.
#[test]
fn guarded_mutate() -> Result<(), HardwareError> {
    let mut guarded = GuardedBuffer::new(1u32)?;
    guarded.with_mut(|value| *value = value.wrapping_add(41));
    guarded.with(|value| assert_eq!(*value, 42));
    Ok(())
}

/// Larger-than-one-page values (a 4 KiB key blob) live in the data region.
#[test]
fn guarded_multi_page_value() -> Result<(), HardwareError> {
    let key = [7u8; 4096];
    let guarded = GuardedBuffer::new(key)?;
    guarded.with(|value| assert!(value.iter().all(|byte| *byte == 7)));
    Ok(())
}

/// Multiple concurrent guards coexist and do not alias.
#[test]
fn guarded_independent_instances() -> Result<(), HardwareError> {
    let a = GuardedBuffer::new(10u64)?;
    let b = GuardedBuffer::new(20u64)?;
    a.with(|value| assert_eq!(*value, 10));
    b.with(|value| assert_eq!(*value, 20));
    Ok(())
}

/// Drop clears the value and tears the mapping down without crashing;
/// repeated allocation cycles succeed (mapping reuse sanity).
#[test]
fn guarded_drop_reuse() -> Result<(), HardwareError> {
    for round in 0..8u64 {
        let guarded = GuardedBuffer::new(round)?;
        guarded.with(|value| assert_eq!(*value, round));
        drop(guarded);
    }
    Ok(())
}

/// Process-level core-dump suppression applies cleanly.
#[test]
fn core_dump_suppression() -> Result<(), HardwareError> {
    umbra_hardware::process::disable_core_dumps()?;
    Ok(())
}
