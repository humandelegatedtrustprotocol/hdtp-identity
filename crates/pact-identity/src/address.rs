//! The address guard of §3 and §14.2: no loopback, link-local or private host, and never the
//! receiver's own endpoint from a guest. Resolution is the host's; `ip_is_private` is the same
//! predicate for what it resolves.
use crate::util::{err, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
}

/// An IPv6 address that is not a public one — or that EMBEDS an IPv4 address which is not.
///
/// For a literal there is no name to resolve, so this predicate is the whole guard, and it knew one
/// embedding: IPv4-mapped. A translator dials the address INSIDE these too, so each is judged by it:
///
/// - `64:ff9b::/96`, the NAT64 well-known prefix (RFC 6052): `[64:ff9b::7f00:1]` is 127.0.0.1 on any
///   NAT64 network, which is the ordinary shape of an IPv6-only cloud host;
/// - `64:ff9b:1::/48`, NAT64's LOCAL-use prefix (RFC 8215): never a public address, whatever it holds;
/// - `2002::/16`, 6to4 (RFC 3056): the IPv4 address is the next 32 bits;
/// - `::/96`, IPv4-compatible (deprecated): refused until now only because `is_normal_https` happens
///   not to round-trip Rust's spelling of it, which is an accident and not a guard;
/// - `fec0::/10`, site-local (deprecated), beside unique-local and link-local.
fn v6_private(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_private(v4);
    }
    let s = ip.segments();
    let embedded = |hi: u16, lo: u16| v4_private(Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8));
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return s[2] != 0 || s[3] != 0 || s[4] != 0 || s[5] != 0 || embedded(s[6], s[7]);
    }
    if s[0] == 0x2002 {
        return embedded(s[1], s[2]);
    }
    if s[..6].iter().all(|x| *x == 0) {
        return embedded(s[6], s[7]);
    }
    (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0
}

/// Whether an IP literal is one the guard refuses (`v4_private`, `v6_private`), or an IPv6 literal
/// with a zone id. One leading `[` and one trailing `]` are dropped, as a URL writes an IPv6 host: this
/// trimmed every bracket from both ends, so `[[::1]]` was loopback here and no address to the Go port.
/// Text that is no address — a zone on an IPv4 address, or an empty zone, as Go's `netip` reads them —
/// is not private.
pub fn ip_is_private(ip: &str) -> bool {
    let ip = ip.strip_prefix('[').unwrap_or(ip);
    let ip = ip.strip_suffix(']').unwrap_or(ip);
    // A zone is an interface scope (RFC 4007 §6), which no global address carries: a literal with one
    // is never a public address. `std` cannot parse one, so this answered false for `fe80::1%eth0` — a
    // link-local address a resolver may hand a host — while the Go port judged it by its address.
    if let Some((address, zone)) = ip.split_once('%') {
        return !zone.is_empty() && address.parse::<Ipv6Addr>().is_ok();
    }
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4_private(v4),
        Ok(IpAddr::V6(v6)) => v6_private(v6),
        Err(_) => false,
    }
}

/// The host part of an https URL's authority, without brackets or port; `None` when it is not https.
pub fn host_of(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next()?.to_string()
    } else {
        authority.split(':').next()?.to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

pub fn address_guard(endpoint: &str, self_endpoint: Option<&str>, guest: bool) -> Result<()> {
    // The normal form first (§14.1): every other spelling of an address — an IPv4 in decimal,
    // hex or octal, a host with an odd case — is refused here, never resolved.
    if !crate::x509::is_normal_https(endpoint) {
        return err("bad_request", "endpoint is not an https URL in normal form");
    }
    let Some(host) = host_of(endpoint) else { return err("bad_request", "endpoint is not an https URL") };
    let host = host.trim_end_matches('.').to_string();
    if host == "localhost" || host.ends_with(".localhost") {
        return err("bad_request", "endpoint host is local");
    }
    if host.parse::<IpAddr>().is_ok() && ip_is_private(&host) {
        return err("bad_request", "endpoint host is a loopback, link-local or private address");
    }
    if guest && self_endpoint == Some(endpoint) {
        return err("bad_request", "a guest's endpoint names this node's own address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guards() {
        assert!(address_guard("https://agent.alina.example/mcp", None, true).is_ok());
        assert!(address_guard("https://203.0.113.9/mcp", None, true).is_ok());
        for bad in [
            "https://localhost/mcp",
            "https://api.localhost/mcp",
            "https://127.0.0.1/mcp",
            "https://10.1.2.3/mcp",
            "https://172.20.0.1/mcp",
            "https://192.168.1.1/mcp",
            "https://169.254.169.254/mcp",
            "https://100.64.0.1/mcp",
            "https://0.0.0.0/mcp",
            "https://[::1]/mcp",
            "https://[fe80::1]/mcp",
            "https://[fd00::1]/mcp",
            "https://[::ffff:10.0.0.1]/mcp",
            "http://agent.alina.example/mcp",
            "https://127.1/mcp",
            "https://2130706433/mcp",
            "https://0x7f000001/mcp",
            "https://0177.0.0.1/mcp",
            "https://localhost./mcp",
            "https://LOCALHOST/mcp",
        ] {
            assert!(address_guard(bad, None, false).is_err(), "{bad}");
        }
        assert!(address_guard("https://me.example/mcp", Some("https://me.example/mcp"), true).is_err());
        assert!(address_guard("https://me.example/mcp", Some("https://me.example/mcp"), false).is_ok());
        assert!(ip_is_private("10.0.0.1"));
        assert!(!ip_is_private("8.8.8.8"));
        assert!(!ip_is_private("not-an-ip"));
        // A zone id is never public; an empty zone, or one on an IPv4 address, is no address.
        for zoned in ["fe80::1%eth0", "2001:db8::1%eth0", "[fe80::1%eth0]", "fe80::1%eth0%x"] {
            assert!(ip_is_private(zoned), "{zoned}");
        }
        for not_one in ["fe80::1%", "10.0.0.1%eth0", "[[::1]]", "]::1[", "[[10.0.0.1]]"] {
            assert!(!ip_is_private(not_one), "{not_one}");
        }
        assert!(ip_is_private("[::1") && ip_is_private("::1]"));
    }
}
