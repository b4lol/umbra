//! `/proc/net/if_inet6` parsing: finds an interface's IPv6 link-local
//! address without spawning any external tool (Seccomp blocks `execve`
//! for hardened commands, so no `ip`/`ifconfig`) and without a
//! netlink/routing-socket dependency.

use std::net::Ipv6Addr;

use crate::error::TransportError;

/// Kernel's `if_inet6` "scope" value for link-local addresses
/// (`IPV6_ADDR_LINKLOCAL`; see Linux `include/net/ipv6.h`).
const SCOPE_LINK_LOCAL: u32 = 0x20;

/// Finds `iface`'s IPv6 link-local address in the (already-read)
/// contents of `/proc/net/if_inet6`. Pure function — hermetically
/// testable with fixture text, independent of any real interface.
///
/// # Errors
///
/// Returns [`TransportError::Mesh`] if no link-local entry for `iface`
/// is found.
pub fn parse_if_inet6(contents: &str, iface: &str) -> Result<Ipv6Addr, TransportError> {
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [hex_addr, _devno, _prefix, scope, _flags, name] = fields.as_slice() else {
            continue; // malformed/short line: skip, don't fail the whole parse
        };
        if *name != iface {
            continue;
        }
        let Ok(scope) = u32::from_str_radix(scope, 16) else {
            continue;
        };
        if scope != SCOPE_LINK_LOCAL {
            continue;
        }
        return parse_hex_addr(hex_addr, iface);
    }
    Err(TransportError::Mesh(format!(
        "no IPv6 link-local address found for interface {iface}"
    )))
}

/// Decodes the 32-hex-digit, colon-free address form `if_inet6` uses.
fn parse_hex_addr(hex_addr: &str, iface: &str) -> Result<Ipv6Addr, TransportError> {
    if hex_addr.len() != 32 || !hex_addr.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TransportError::Mesh(format!(
            "malformed if_inet6 address for {iface}"
        )));
    }
    let mut octets = [0u8; 16];
    for (i, octet) in octets.iter_mut().enumerate() {
        // i ranges 0-15 (16-element array), so i*2 and i*2+2 cannot overflow usize.
        #[allow(clippy::arithmetic_side_effects)]
        {
            let start = i * 2;
            let end = start + 2;
            let byte_str = &hex_addr[start..end];
            *octet = u8::from_str_radix(byte_str, 16).map_err(|_e| {
                TransportError::Mesh(format!("malformed if_inet6 address for {iface}"))
            })?;
        }
    }
    Ok(Ipv6Addr::from(octets))
}

/// Reads `/proc/net/if_inet6` and finds `iface`'s link-local address.
/// The only I/O in this module — [`parse_if_inet6`] does the real work
/// and is what the tests exercise directly.
///
/// # Errors
///
/// Returns [`TransportError::Mesh`] if the file cannot be read, or see
/// [`parse_if_inet6`].
pub fn link_local_address(iface: &str) -> Result<Ipv6Addr, TransportError> {
    let contents = std::fs::read_to_string("/proc/net/if_inet6")
        .map_err(|e| TransportError::Mesh(format!("read /proc/net/if_inet6: {e}")))?;
    parse_if_inet6(&contents, iface)
}

#[cfg(test)]
mod tests {
    use super::parse_if_inet6;

    /// Realistic `/proc/net/if_inet6` excerpt: loopback (scope 10 =
    /// host) plus a fabricated Wi-Fi Direct group interface with a
    /// link-local address (scope 20).
    const FIXTURE: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000aabbccfffeddeeff 07 40 20 80       wlan0-p2p-0
fe800000000000000000000000000001 02 40 20 80       wlan0
";

    #[test]
    fn finds_the_named_interfaces_link_local_address()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = parse_if_inet6(FIXTURE, "wlan0-p2p-0")?;
        assert_eq!(
            addr,
            std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0xaabb, 0xccff, 0xfedd, 0xeeff)
        );
        Ok(())
    }

    #[test]
    fn does_not_match_a_different_interface() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let addr = parse_if_inet6(FIXTURE, "wlan0")?;
        assert_eq!(addr, std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        Ok(())
    }

    #[test]
    fn missing_interface_is_an_error() {
        assert!(parse_if_inet6(FIXTURE, "does-not-exist").is_err());
    }

    #[test]
    fn interface_present_but_only_host_scope_is_an_error() {
        // "lo" is present but only at scope 10 (host), never scope 20
        // (link-local) — must not be returned as a link-local match.
        assert!(parse_if_inet6(FIXTURE, "lo").is_err());
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture_with_garbage = format!("{FIXTURE}not a valid line at all\n");
        let addr = parse_if_inet6(&fixture_with_garbage, "wlan0-p2p-0")?;
        assert_eq!(addr.segments()[0], 0xfe80);
        Ok(())
    }

    #[test]
    fn empty_contents_is_an_error() {
        assert!(parse_if_inet6("", "wlan0-p2p-0").is_err());
    }
}
