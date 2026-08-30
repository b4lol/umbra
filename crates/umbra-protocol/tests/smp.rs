//! Socialist Millionaire Protocol tests (TODO A.3, CRYPTOGRAPHY.md §5).
//!
//! Hermetic: pure math, no network/filesystem. Full protocol runs take
//! ~a second (several 1536-bit modexps per message).

use num_bigint::BigUint;
use num_traits::{Num, One};

use umbra_protocol::smp::{
    G1, P_HEX, SmpFirstParty, SmpMsg1, SmpMsg2, SmpMsg3, SmpMsg4, SmpSecondParty, smp_secret,
};

/// Deterministic-ish secret derivation for tests.
fn test_secret(id: u8) -> BigUint {
    let ident = [id; 32];
    BigUint::from_bytes_be(
        smp_secret(&ident, &[id.wrapping_add(1); 32], b"ssid", b"secret").as_ref(),
    )
}

/// The group constant matches the spec's algebraic definition
/// (RFC 3526 1536-bit MODP group, generator 2).
#[test]
fn group_constant_matches_spec() -> Result<(), Box<dyn std::error::Error>> {
    let hex: String = P_HEX.chars().filter(|c| !c.is_whitespace()).collect();
    let p = BigUint::from_str_radix(&hex, 16)?;
    assert_eq!(p.bits(), 1536);
    // Fermat: g^(p-1) == 1 mod p (cheap sanity that g=2 is in the group).
    let g = BigUint::from(G1);
    let pm1 = &p - BigUint::one();
    assert_eq!(g.modpow(&pm1, &p), BigUint::one());
    Ok(())
}

/// A full run with EQUAL secrets succeeds on both sides.
#[test]
fn smp_equal_secrets_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(7);
    let (alice, msg1) = SmpFirstParty::start(&secret)?;
    let (bob, msg2) = SmpSecondParty::receive_msg1(&secret, msg1)?;
    let (alice, msg3) = alice.receive_msg2(msg2)?;
    let (bob, result, msg4) = bob.receive_msg3(msg3)?;
    assert!(result, "Bob must accept equal secrets");
    assert_eq!(bob.result(), Some(true));
    let alice_result = alice.finish(msg4)?;
    assert!(alice_result, "Alice must accept equal secrets");
    Ok(())
}

/// A full run with DIFFERENT secrets rejects on both sides.
#[test]
fn smp_different_secrets_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secret_a = test_secret(11);
    let secret_b = test_secret(12);
    let (alice, msg1) = SmpFirstParty::start(&secret_a)?;
    let (bob, msg2) = SmpSecondParty::receive_msg1(&secret_b, msg1)?;
    let (alice, msg3) = alice.receive_msg2(msg2)?;
    let (_bob, result, msg4) = bob.receive_msg3(msg3)?;
    assert!(!result, "Bob must reject different secrets");
    let alice_result = alice.finish(msg4)?;
    assert!(!alice_result, "Alice must reject different secrets");
    Ok(())
}

/// Wire round-trips for all four message types.
#[test]
fn wire_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(21);
    let (_alice, msg1) = SmpFirstParty::start(&secret)?;
    let msg1_back = SmpMsg1::from_bytes(&msg1.to_bytes())?;
    assert_eq!(msg1_back, msg1);

    let (_bob, msg2) = SmpSecondParty::receive_msg1(&secret, msg1)?;
    let msg2_back = SmpMsg2::from_bytes(&msg2.to_bytes())?;
    assert_eq!(msg2_back, msg2);

    let (_alice, msg3) = _alice.receive_msg2(msg2)?;
    let msg3_back = SmpMsg3::from_bytes(&msg3.to_bytes())?;
    assert_eq!(msg3_back, msg3);

    let (_bob, _result, msg4) = _bob.receive_msg3(msg3)?;
    let msg4_back = SmpMsg4::from_bytes(&msg4.to_bytes())?;
    assert_eq!(msg4_back, msg4);
    Ok(())
}

/// Tampering with any MPI of a message fails verification.
#[test]
fn tampered_messages_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(31);
    let (alice, msg1) = SmpFirstParty::start(&secret)?;

    // Corrupt g2a on the wire: g2b proof stays, g2a proof breaks.
    let mut bad1 = msg1.clone();
    bad1.g2a += BigUint::from(1u32);
    let tampered = SmpMsg1::from_bytes(&bad1.to_bytes());
    assert!(SmpSecondParty::receive_msg1(&secret, tampered?).is_err());

    // Corrupt an MPI on msg2: proof verification must fail for Alice.
    let (_bob, msg2) = SmpSecondParty::receive_msg1(&secret, msg1)?;
    let mut bad2 = msg2.clone();
    bad2.pb += BigUint::from(1u32);
    let bad2 = SmpMsg2::from_bytes(&bad2.to_bytes())?;
    assert!(alice.receive_msg2(bad2).is_err());
    Ok(())
}

/// Tampering with the equal-logs values (Ra / Rb) fails verification.
#[test]
fn tampered_equal_logs_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(51);
    let (alice, msg1) = SmpFirstParty::start(&secret)?;
    let (bob, msg2) = SmpSecondParty::receive_msg1(&secret, msg1)?;
    let (_alice, msg3) = alice.receive_msg2(msg2)?;

    // Corrupt Ra on msg3: Bob's equal-logs check must fail.
    let mut bad3 = msg3.clone();
    bad3.ra += BigUint::from(1u32);
    let bad3 = SmpMsg3::from_bytes(&bad3.to_bytes())?;
    assert!(bob.receive_msg3(bad3).is_err());

    // Corrupt Rb on msg4: Alice's equal-logs check must fail.
    let (alice2, msg1b) = SmpFirstParty::start(&secret)?;
    let (bob2, msg2b) = SmpSecondParty::receive_msg1(&secret, msg1b)?;
    let (alice2, msg3b) = alice2.receive_msg2(msg2b)?;
    let (_bob2, _result, msg4) = bob2.receive_msg3(msg3b)?;
    let mut bad4 = msg4.clone();
    bad4.rb += BigUint::from(1u32);
    let bad4 = SmpMsg4::from_bytes(&bad4.to_bytes())?;
    assert!(alice2.finish(bad4).is_err());
    Ok(())
}

/// Group elements outside `[2, p-2]` are rejected at parse time
/// (regression: p-underflow panic guard).
#[test]
fn out_of_range_elements_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(61);
    let (_alice, msg1) = SmpFirstParty::start(&secret)?;
    // Above p: g2a larger than the modulus (fits the 200-byte MPI cap).
    let mut bad = msg1.clone();
    let hex: String = umbra_protocol::smp::P_HEX
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let p = BigUint::from_str_radix(&hex, 16)?;
    bad.g2a = p + BigUint::from(2u32);
    // Parse-time validation rejects the out-of-range element (and never
    // reaches receive_msg1 — this is the p-underflow panic regression).
    assert!(SmpMsg1::from_bytes(&bad.to_bytes()).is_err());
    Ok(())
}

/// Trailing bytes after the declared MPI list are rejected.
#[test]
fn trailing_bytes_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(71);
    let (_alice, msg1) = SmpFirstParty::start(&secret)?;
    let mut bytes = msg1.to_bytes();
    bytes.push(0x00);
    assert!(SmpMsg1::from_bytes(&bytes).is_err());
    Ok(())
}

/// A truncated or oversized wire message is rejected without panicking.
#[test]
fn malformed_wire_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secret = test_secret(41);
    let (_alice, msg1) = SmpFirstParty::start(&secret)?;
    let bytes = msg1.to_bytes();
    let truncated = bytes.get(0..16).ok_or("message longer than 16 bytes")?;
    assert!(SmpMsg1::from_bytes(truncated).is_err());
    // Oversized MPI: craft a message with a huge declared length.
    let mut hostile = bytes.clone();
    for byte in hostile.iter_mut().skip(4).take(4) {
        *byte = 0xff;
    }
    assert!(SmpMsg1::from_bytes(&hostile).is_err());
    Ok(())
}

/// The secret derivation is deterministic and binding (version + both
/// identities + ssid + user secret).
#[test]
fn secret_derivation_binding() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let s1 = smp_secret(&a, &b, b"ssid", b"pw");
    let s2 = smp_secret(&a, &b, b"ssid", b"pw");
    let s3 = smp_secret(&b, &a, b"ssid", b"pw");
    assert_eq!(s1.as_ref(), s2.as_ref());
    assert_ne!(s1.as_ref(), s3.as_ref());
}

/// Variable-length fields are length-prefixed: field splits cannot collide.
#[test]
fn secret_derivation_unambiguous() {
    let a = [1u8; 32];
    let s1 = smp_secret(&a, &[2u8; 32], b"ab", b"c");
    let s2 = smp_secret(&a, &[2u8; 32], b"a", b"bc");
    assert_ne!(s1.as_ref(), s2.as_ref());
}
