//! Signing requests (SPEC §9.1 in 2.2.0; CONTRACT §3.1): a host asking a web wallet for a leaf with a
//! form POSTed by top-level navigation. `signing_request_check` is everything the wallet can decide
//! about one before a person sees it — the request's members and their bounds, the asking origin
//! against the redirect, the redirect's scheme and host, the expiry window, and the CSR through
//! `csr::check` (proof of possession, the root-key refusal, a normal endpoint, the address guard).
//! What it cannot decide stays the wallet's: proving the root against `expect_root`, showing the
//! person the origin, the recipient, the endpoint and whether the host is new, and the validity the
//! person chooses.
use crate::csr;
use crate::time::parse_rfc3339;
use crate::util::{err, from_b64u, Result};
use crate::x509;
use serde_json::{json, Map, Value};

/// The members of a signing request, as its form carries them: every one a string.
pub const MEMBERS: &[&str] = &["csr", "purpose", "expect_root", "root_cert", "redirect", "state", "recipient", "valid_days", "expires"];
/// Required, in the order they are read.
pub const REQUIRED: &[&str] = &["csr", "purpose", "expect_root", "redirect", "state", "recipient", "valid_days", "expires"];
/// The most each member may carry: bytes for the base64url and URL members, characters (Unicode
/// scalar values) for `recipient`. The whole body is bounded by the wallet's host (16 KiB, by bytes).
pub const LIMITS: &[(&str, usize)] = &[
    ("csr", 4096),
    ("purpose", 16),
    ("expect_root", 64),
    ("root_cert", 4096),
    ("redirect", 2048),
    ("state", 43),
    ("recipient", 200),
    ("valid_days", 3),
    ("expires", 40),
];
/// How far ahead a request may expire.
pub const MAX_AHEAD_SECONDS: i64 = 600;
pub const PURPOSES: &[&str] = &["renew", "move"];

/// What a request that passed says: the CSR, where the answer goes, why, and the validity asked for.
#[derive(Debug)]
pub struct Checked {
    pub csr: String,
    pub redirect: String,
    pub purpose: String,
    pub valid_days: i64,
}

fn refuse<T>(why: impl Into<String>) -> Result<T> {
    err("bad_request", why)
}

fn is_b64url(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// A loopback host as a redirect may name one over `http`: `localhost`, a dotted-quad in
/// `127.0.0.0/8` written in the normal form (four decimal octets, no leading zero), or `[::1]`.
fn loopback(host: &str) -> bool {
    if host == "localhost" || host == "[::1]" {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets[0] == "127"
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.bytes().all(|c| c.is_ascii_digit())
                && (o.len() == 1 || !o.starts_with('0'))
                && o.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// The redirect's origin (`scheme://host[:port]`, the port left out when it is the scheme's
/// default), if the redirect is one a wallet may navigate to: absolute, ASCII, no userinfo, no
/// fragment, and `https`, or `http` only to a loopback host.
pub(crate) fn redirect_allowed(redirect: &str) -> std::result::Result<String, &'static str> {
    if redirect.bytes().any(|c| !(0x21..=0x7e).contains(&c) || c == b'\\') {
        return Err("the redirect is not an absolute URL");
    }
    if redirect.contains('#') {
        return Err("the redirect carries a fragment");
    }
    let (scheme, rest) = if let Some(r) = redirect.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = redirect.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err("the redirect is not https, or http to a loopback host");
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.contains('@') {
        return Err("the redirect carries userinfo");
    }
    let (host, port) = if authority.starts_with('[') {
        let Some(close) = authority.find(']') else { return Err("the redirect is not an absolute URL") };
        (&authority[..=close], &authority[close + 1..])
    } else {
        match authority.find(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        }
    };
    // Lower-case normal form (CONTRACT §3.1): an IPv6 literal's hex in lower case, and a name of
    // labels none of which is empty — no leading, trailing or doubled dot.
    let host_ok = !host.is_empty()
        && if host.starts_with('[') {
            host.len() > 2
                && host[1..host.len() - 1].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || c == b':' || c == b'.')
        } else {
            host.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
                && host.split('.').all(|l| !l.is_empty())
        };
    if !host_ok {
        return Err("the redirect's host is not in normal form");
    }
    let port = match port {
        "" => None,
        p => {
            let digits = &p[1..];
            if !p.starts_with(':')
                || digits.is_empty()
                || digits.len() > 5
                || !digits.bytes().all(|c| c.is_ascii_digit())
                || digits.starts_with('0')
            {
                return Err("the redirect's port is not in normal form");
            }
            match digits.parse::<u32>() {
                Ok(n) if (1..=65535).contains(&n) => Some(n),
                _ => return Err("the redirect's port is not in normal form"),
            }
        }
    };
    if !(path.is_empty() || path.starts_with('/') || path.starts_with('?')) {
        return Err("the redirect is not an absolute URL");
    }
    if scheme == "http" && !loopback(host) {
        return Err("the redirect is not https, or http to a loopback host");
    }
    let default = if scheme == "https" { 443 } else { 80 };
    Ok(match port {
        Some(p) if p != default => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    })
}

fn string<'a>(request: &'a Map<String, Value>, m: &str) -> Result<Option<&'a str>> {
    match request.get(m) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => refuse(format!("{m} is a string, as a form carries it")),
    }
}

/// The checks, in the order written in CONTRACT §3.1. A refusal names the first thing wrong.
pub fn check(request: &Value, origin: &str, now: i64, root_spkis: &[Vec<u8>]) -> Result<Checked> {
    let Some(request) = request.as_object() else { return refuse("request is required") };
    let mut strangers: Vec<&String> = request.keys().filter(|k| !MEMBERS.contains(&k.as_str())).collect();
    strangers.sort();
    if let Some(k) = strangers.first() {
        return refuse(format!("a signing request does not carry {k}"));
    }
    for m in MEMBERS {
        if let Some(v) = string(request, m)? {
            let (_, limit) = LIMITS.iter().find(|(n, _)| n == m).copied().unwrap_or((m, 0));
            let size = if *m == "recipient" { v.chars().count() } else { v.len() };
            if size > limit {
                return refuse(format!("{m} is longer than {limit}"));
            }
        }
    }
    for m in REQUIRED {
        if string(request, m)?.is_none_or(|v| v.is_empty()) {
            return refuse(format!("{m} is required"));
        }
    }
    let get = |m: &str| request.get(m).and_then(|v| v.as_str()).unwrap_or("");
    // Who asks, and where the answer goes: the host that asks is the host that collects.
    if origin.is_empty() || origin == "null" {
        return refuse("the request has no origin: a wallet answers only the origin that asked");
    }
    let redirect = get("redirect");
    let to = match redirect_allowed(redirect) {
        Ok(o) => o,
        Err(why) => return refuse(why),
    };
    if to != origin {
        return refuse("the redirect's origin is not the origin that asked");
    }
    // When.
    let Ok(expires) = parse_rfc3339(get("expires")) else { return refuse("expires is not an RFC 3339 instant") };
    if expires <= now {
        return refuse("the request has expired");
    }
    if expires > now + MAX_AHEAD_SECONDS {
        return refuse("the request expires more than ten minutes ahead");
    }
    // What for.
    let purpose = get("purpose");
    if !PURPOSES.contains(&purpose) {
        return refuse("purpose is renew or move");
    }
    let days = get("valid_days");
    let valid_days = match days.parse::<i64>() {
        Ok(n) if days.bytes().all(|c| c.is_ascii_digit()) && !days.starts_with('0') && (1..=x509::MAX_LEAF_DAYS).contains(&n) => n,
        _ => return refuse("valid_days is a whole number of days from 1 to 398"),
    };
    let state = get("state");
    if state.len() != 43 || !is_b64url(state) || from_b64u(state).map(|b| b.len()) != Ok(32) {
        return refuse("state is 32 bytes, base64url");
    }
    // Whose: the root the request names, and its certificate if the host sent one.
    let expect_root = get("expect_root");
    let fp_ok = expect_root.strip_prefix("sha256:").is_some_and(|h| h.len() == 43 && is_b64url(h));
    if !fp_ok {
        return refuse("expect_root is not a root fingerprint");
    }
    if let Some(cert) = string(request, "root_cert")? {
        let der = if is_b64url(cert) { from_b64u(cert).ok() } else { None };
        let Some(der) = der else { return refuse("root_cert is not base64url") };
        let Ok(parsed) = x509::parse(&der) else { return refuse("root_cert is not a certificate") };
        if x509::profile_error(&parsed, "root").is_some() {
            return refuse("root_cert is not a root certificate");
        }
        if parsed.public_key.fingerprint() != expect_root {
            return refuse("root_cert is not the root expect_root names");
        }
    }
    // The request itself: csr_check's rules.
    let text = get("csr");
    if !is_b64url(text) {
        return refuse("csr is not base64url");
    }
    csr::check(&from_b64u(text)?, root_spkis).map_err(|e| crate::util::Error::new("bad_request", e.why))?;
    Ok(Checked { csr: text.to_string(), redirect: redirect.to_string(), purpose: purpose.to_string(), valid_days })
}

impl Checked {
    pub fn to_value(&self) -> Value {
        json!({ "ok": true, "csr": self.csr, "redirect": self.redirect, "purpose": self.purpose, "valid_days": self.valid_days })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Alg, PrivateKey};
    use crate::util::{b64u, seed};

    const NOW: i64 = 1_789_214_400;
    const ORIGIN: &str = "http://localhost:8080";

    fn request() -> (Value, Vec<u8>) {
        let root = PrivateKey::from_seed(Alg::Ed25519, &seed("signing/root")).unwrap();
        let cert = x509::build_root("Alina Rao", &root, NOW, &x509::serial_of("signing/root")).unwrap();
        let host = PrivateKey::from_seed(Alg::P256, &seed("signing/host")).unwrap();
        let der = csr::csr_new("Alina Rao", &host, "https://agent.alina.example/mcp", None).unwrap();
        let r = json!({
            "csr": b64u(&der), "purpose": "move", "expect_root": root.public().fingerprint(), "root_cert": b64u(&cert),
            "redirect": format!("{ORIGIN}/wallet/return"), "state": b64u(&[7u8; 32]), "recipient": "a node",
            "valid_days": "90", "expires": crate::time::format_rfc3339(NOW + 300),
        });
        (r, root.public().spki().to_vec())
    }

    fn with(over: &[(&str, Value)]) -> Value {
        let (mut r, _) = request();
        for (k, v) in over {
            if v.is_null() {
                r.as_object_mut().unwrap().remove(*k);
            } else {
                r[*k] = v.clone();
            }
        }
        r
    }

    fn why(r: &Value, origin: &str) -> String {
        check(r, origin, NOW, &[]).map(|_| "passed".to_string()).unwrap_or_else(|e| e.why)
    }

    #[test]
    fn signing_request_check_passes_one_request_and_refuses_one_per_rule() {
        let (r, _) = request();
        let ok = check(&r, ORIGIN, NOW, &[]).unwrap();
        assert_eq!((ok.purpose.as_str(), ok.valid_days, ok.redirect.as_str()), ("move", 90, "http://localhost:8080/wallet/return"));
        for (over, origin, want) in [
            (vec![("extra", json!("x"))], ORIGIN, "a signing request does not carry extra"),
            (vec![("valid_days", json!(90))], ORIGIN, "valid_days is a string, as a form carries it"),
            (vec![("recipient", json!("é".repeat(201)))], ORIGIN, "recipient is longer than 200"),
            (vec![("state", Value::Null)], ORIGIN, "state is required"),
            (vec![], "null", "the request has no origin: a wallet answers only the origin that asked"),
            (vec![], "http://localhost:8081", "the redirect's origin is not the origin that asked"),
            (
                vec![("redirect", json!("http://node.example/r"))],
                "http://node.example",
                "the redirect is not https, or http to a loopback host",
            ),
            (vec![("redirect", json!("http://localhost:8080/r#x"))], ORIGIN, "the redirect carries a fragment"),
            (vec![("expires", json!(crate::time::format_rfc3339(NOW)))], ORIGIN, "the request has expired"),
            (vec![("expires", json!(crate::time::format_rfc3339(NOW + 601)))], ORIGIN, "the request expires more than ten minutes ahead"),
            (vec![("purpose", json!("signup"))], ORIGIN, "purpose is renew or move"),
            (vec![("valid_days", json!("399"))], ORIGIN, "valid_days is a whole number of days from 1 to 398"),
            (vec![("state", json!("A".repeat(42)))], ORIGIN, "state is 32 bytes, base64url"),
            (vec![("expect_root", json!("sha256:x"))], ORIGIN, "expect_root is not a root fingerprint"),
        ] {
            assert_eq!(why(&with(&over), origin), want, "{over:?} from {origin}");
        }
        // The root-key refusal is csr_check's, with the roots the wallet holds.
        let (_, spki) = request();
        let root = PrivateKey::from_seed(Alg::Ed25519, &seed("signing/root")).unwrap();
        let own = csr::csr_new("Alina Rao", &root, "https://agent.alina.example/mcp", None).unwrap();
        assert_eq!(check(&with(&[("csr", json!(b64u(&own)))]), ORIGIN, NOW, &[spki]).unwrap_err().why, "the request's key is a root");
        // A root_cert that is not the root expect_root names.
        let other = PrivateKey::from_seed(Alg::Ed25519, &seed("signing/other")).unwrap();
        let theirs = x509::build_root("Someone", &other, NOW, &x509::serial_of("signing/other")).unwrap();
        assert_eq!(why(&with(&[("root_cert", json!(b64u(&theirs)))]), ORIGIN), "root_cert is not the root expect_root names");
    }

    #[test]
    fn redirect_allowed_is_https_or_http_to_loopback_only() {
        for (redirect, origin) in [
            ("https://node.alina.example/r", "https://node.alina.example"),
            ("https://node.alina.example:443/r", "https://node.alina.example"),
            ("https://node.alina.example:8443/r", "https://node.alina.example:8443"),
            ("http://localhost:8080/r", "http://localhost:8080"),
            ("http://127.0.0.1/r", "http://127.0.0.1"),
            ("http://127.255.0.9:9/r", "http://127.255.0.9:9"),
            ("http://[::1]:8080/r", "http://[::1]:8080"),
        ] {
            assert_eq!(redirect_allowed(redirect), Ok(origin.to_string()), "{redirect}");
        }
        for redirect in [
            "http://node.alina.example/r",
            "http://10.0.0.1/r",
            "http://127.1/r",
            "http://0127.0.0.1/r",
            "http://127.0.0.256/r",
            "http://[::2]/r",
            "http://sub.localhost/r",
            "ftp://localhost/r",
            "//localhost/r",
            "http://user@localhost/r",
            "http://localhost/r#f",
            "http://LOCALHOST/r",
            "http://localhost:0/r",
            "http://localhost:99999/r",
            "http://localhost:80a/r",
            "http://localhost\\@evil.example/",
            "http://localhost/ r",
            "http://localhost/é",
            "https://[2001:DB8::1]/r",
            "https://node..alina.example/r",
            "https://.alina.example/r",
            "https://alina.example./r",
        ] {
            assert!(redirect_allowed(redirect).is_err(), "{redirect}");
        }
    }
}
