//! The two rules `connection.md` puts on an advertised endpoint, shared by both roles.
//!
//! A peer that discovers a record over mDNS SHOULD only connect to an address that is not a
//! loopback or unspecified one, and only when the advertised `path` matches the `path-absolute` rule
//! of RFC 3986. The client dials servers and the server dials clients under the same rule, so the
//! rule lives here and not in either crate. Both functions are pure string checks: no socket, no
//! resolver.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Whether `path` matches the `path-absolute` rule of RFC 3986, section 3.3.
///
/// That is a `/`, then optionally a non-empty first segment and further `/`-separated segments,
/// each made of unreserved characters, percent-encoded octets, sub-delimiters, `:` and `@`. A
/// query, a fragment, a space or a control character is not part of it.
#[must_use]
pub fn is_path_absolute(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if rest.starts_with('/') {
        return false;
    }
    let mut bytes = rest.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'/' | b':' | b'@' | b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'('
            | b')' | b'*' | b'+' | b',' | b';' | b'=' => {}
            b'%' => {
                // A percent-encoded octet is exactly two hex digits; the iterator consumes them.
                let (Some(high), Some(low)) = (bytes.next(), bytes.next()) else {
                    return false;
                };
                if !(high.is_ascii_hexdigit() && low.is_ascii_hexdigit()) {
                    return false;
                }
            }
            byte if byte.is_ascii_alphanumeric() => {}
            _ => return false,
        }
    }
    true
}

/// Whether `address` is one a peer must not dial: a loopback or unspecified address, or a host
/// name that is a loopback by rule.
///
/// An IP literal, with or without a port, is judged by its address. An IPv6 address that embeds an
/// IPv4 one - mapped (`::ffff:a.b.c.d`), compatible (`::a.b.c.d`) or NAT64 (`64:ff9b::a.b.c.d`) -
/// is judged by the address it embeds. Any other text is a host name: it is local when it is
/// `localhost`, `localhost.localdomain` or a name under `.localhost` (RFC 6761), or when its last
/// label is a legacy numeric IPv4 spelling such as `127.1` or `0x7f.1`, which a resolver turns into
/// an address. A real host name never ends in an all-digit label or in `0x` followed by hex digits.
#[must_use]
pub fn is_local_address(address: &str) -> bool {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return is_local_ip(socket.ip());
    }
    let bare = address
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(address);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return is_local_ip(ip);
    }
    // `host:port`; a bare host has no port to strip, and an IPv6 literal was handled above.
    let host = address
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(address, |(host, _)| host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let last_label = host.rsplit('.').next().unwrap_or("");
    host == "localhost"
        || host == "localhost.localdomain"
        || host.ends_with(".localhost")
        || last_label
            .strip_prefix("0x")
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (!last_label.is_empty() && last_label.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether `ip` is loopback or unspecified, looking through an embedded IPv4 address.
fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_unspecified(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || embedded_ipv4(ip)
                    .is_some_and(|inner| inner.is_loopback() || inner.is_unspecified())
        }
    }
}

/// The IPv4 address an IPv6 one embeds, for the mapped, compatible and NAT64 forms.
fn embedded_ipv4(ip: Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let [a, b, c, d, e, f, g, h] = ip.segments();
    let inner = std::net::Ipv4Addr::new((g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8);
    let mapped = [a, b, c, d, e] == [0, 0, 0, 0, 0] && f == 0xffff;
    let compatible = [a, b, c, d, e, f] == [0; 6];
    let nat64 = [a, b, c, d, e, f] == [0x64, 0xff9b, 0, 0, 0, 0];
    (mapped || compatible || nat64).then_some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path rule accepts what RFC 3986 calls `path-absolute` and nothing else.
    #[test]
    fn a_path_must_be_path_absolute() {
        for path in [
            "/",
            "/sendspin",
            "/a/b",
            "/a%20b",
            "/%41",
            "/a%41",
            "/ab%41",
            "/a:b@c",
            "/~x_y-z.w",
            "/a/",
            "/a;b=c",
        ] {
            assert!(is_path_absolute(path), "{path:?}");
        }
        for path in [
            "", "sendspin", "//a", "/a?b", "/a#b", "/a b", "/a%zz", "/a%2G", "/a%", "/é",
        ] {
            assert!(!is_path_absolute(path), "{path:?}");
        }
    }

    /// The embedded address is taken whole: a shift that keeps only the low byte would still
    /// pass the local-address tests, because loopback depends on the first octet alone.
    #[test]
    fn an_embedded_ipv4_is_extracted_whole() {
        let parse = |address: &str| address.parse::<Ipv6Addr>().expect("the address parses");
        for address in ["::ffff:192.0.2.1", "::c000:201", "64:ff9b::c000:201"] {
            assert_eq!(
                embedded_ipv4(parse(address)),
                Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                "{address}"
            );
        }
        assert_eq!(embedded_ipv4(parse("2001:db8::1")), None);
    }

    #[test]
    fn local_addresses_are_refused_in_every_spelling() {
        for address in [
            "127.0.0.1:8927",
            "127.0.0.1",
            "[::1]:8927",
            "::1",
            "[::1]",
            "0.0.0.0:8927",
            "[::]:8927",
            "[::ffff:127.0.0.1]:8927",
            "[::ffff:0.0.0.0]:8927",
            "[::7f00:1]:8927",
            "[64:ff9b::7f00:1]:8927",
            "localhost:8927",
            "LOCALHOST.:8927",
            "kitchen.localhost:8927",
            "localhost.localdomain:8927",
            "127.1:8927",
            "0x7f.1:8927",
            "0x7f000001:8927",
            "2130706433:8927",
        ] {
            assert!(is_local_address(address), "{address}");
        }
    }

    /// A host name or address that merely looks like a loopback one is not refused.
    #[test]
    fn ordinary_addresses_are_kept() {
        for address in [
            "speaker.local:8927",
            "my-host2:8927",
            "a.localhosting.example:8927",
            "host.0xfoo:8927",
            "host.0x:8927",
            "192.0.2.1:8927",
            "192.0.2.1",
            "192.0.2.1:abc",
            "[1:2:3:4:5:ffff:7f00:1]:8927",
            "[2001:db8::1]:8927",
            "[fe80::1%eth0]:8927",
            "[64:ff9b::c000:201]:8927",
            "[::c000:201]:8927",
        ] {
            assert!(!is_local_address(address), "{address}");
        }
    }
}
