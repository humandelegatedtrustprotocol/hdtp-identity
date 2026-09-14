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

fn v6_private(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_private(v4);
    }
    let s = ip.segments();
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
}

pub fn ip_is_private(ip: &str) -> bool {
    match ip.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
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
    }
}
