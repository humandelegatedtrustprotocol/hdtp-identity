//! The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.
use crate::keys::fingerprint_of_id;
use crate::time::DAY;
use crate::util::{b64u, from_b64u, err, Result};
use crate::x509::{self, Cert, MAX_LEAF_DAYS};

/// RFC 6350 folding, counted in **UTF-16 code units** — what the seed library counts, and so the
/// definition every port follows (CONTRACT §0). Counting code points (as this once did) or octets
/// (as the Go port once did) makes three implementations that agree only on ASCII.
///
/// One deliberate difference from the seed: where a break would fall between the halves of a
/// surrogate pair the break moves one unit earlier, so the pair stays whole. The seed emits a lone
/// surrogate there, which is not a thing UTF-8 can carry — a card's bytes could not hold it.
fn fold(line: &str) -> String {
    let units: Vec<u16> = line.encode_utf16().collect();
    if units.len() <= 75 {
        return line.to_string();
    }
    let whole = |i: usize| -> usize {
        // A high surrogate at the break means its pair continues past it: step back one unit.
        if i > 0 && i < units.len() && (0xD800..0xDC00).contains(&units[i - 1]) {
            i - 1
        } else {
            i
        }
    };
    let decode = |r: &[u16]| String::from_utf16_lossy(r);
    let first = whole(75);
    let mut parts = vec![decode(&units[..first])];
    let mut i = first;
    while i < units.len() {
        let end = whole((i + 74).min(units.len()));
        parts.push(format!(" {}", decode(&units[i..end])));
        i = end;
    }
    parts.join("\r\n")
}

fn assemble(lines: Vec<String>) -> String {
    let mut out = lines.iter().map(|l| fold(l)).collect::<Vec<_>>().join("\r\n");
    out.push_str("\r\n");
    out
}

pub fn encode(fn_: &str, cert: &[u8], seal: Option<&str>, extra: &[String]) -> String {
    let mut lines = vec!["BEGIN:VCARD".to_string(), "VERSION:4.0".to_string(), format!("FN:{fn_}"), "X-PACT-VERSION:2".to_string(), format!("X-PACT-CERT:{}", b64u(cert))];
    lines.extend(extra.iter().cloned());
    if let Some(s) = seal.filter(|s| !s.is_empty()) {
        lines.push(format!("X-PACT-SEAL:{s}"));
    }
    lines.push("END:VCARD".to_string());
    assemble(lines)
}

/// Appendix C: a `X-PACT-VERSION:1` card toward a peer known to be 1.x, the leaf's endpoint and key
/// spelled out as 1.x did, the certificate carried as an extra a 2.0 peer recognises.
pub fn encode_compat(fn_: &str, cert: &[u8], seal: Option<&str>) -> Result<String> {
    let leaf = x509::parse(cert)?;
    if leaf.uris.len() != 1 {
        return err("bad_request", format!("{} endpoints", leaf.uris.len()));
    }
    let mut lines = vec![
        "BEGIN:VCARD".to_string(),
        "VERSION:4.0".to_string(),
        format!("FN:{fn_}"),
        "X-PACT-VERSION:1".to_string(),
        format!("X-PACT-ENDPOINT:{}", leaf.uris[0]),
        format!("X-PACT-KEY:{}", leaf.public_key.fingerprint()),
        format!("X-PACT-CERT:{}", b64u(cert)),
    ];
    if let Some(s) = seal.filter(|s| !s.is_empty()) {
        lines.push(format!("X-PACT-SEAL:{s}"));
    }
    lines.push("END:VCARD".to_string());
    Ok(assemble(lines))
}

pub struct Card {
    pub fn_: String,
    pub seal: String,
    pub cert: Vec<u8>,
    pub leaf: Cert,
    pub root: String,
    pub endpoint: String,
    pub expired: bool,
    pub ignored: Vec<String>,
}

fn unfold(text: &str) -> Vec<String> {
    // `\r?\n[ \t]` joins a continuation; then lines split on `\r?\n`, empties dropped.
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let nl = if b[i] == b'\r' && i + 1 < b.len() && b[i + 1] == b'\n' { 2 } else if b[i] == b'\n' { 1 } else { 0 };
        if nl > 0 && i + nl < b.len() && (b[i + nl] == b' ' || b[i + nl] == b'\t') {
            i += nl + 1;
            continue;
        }
        bytes.push(b[i]);
        i += 1;
    }
    for line in String::from_utf8_lossy(&bytes).split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !line.is_empty() {
            out.push(line.to_string());
        }
    }
    out
}

/// Intake per §3: refuses what has no root to pin or no address to reach; an expired leaf is not a refusal.
pub fn decode(text: &str, now: i64) -> Result<Card> {
    let mut props: Vec<(String, Vec<String>)> = Vec::new();
    for line in unfold(text) {
        let Some(i) = line.find(':') else { continue };
        let name = line[..i].split(';').next().unwrap_or("").to_uppercase();
        let value = line[i + 1..].to_string();
        match props.iter_mut().find(|(n, _)| *n == name) {
            Some((_, v)) => v.push(value),
            None => props.push((name, vec![value])),
        }
    }
    let get = |n: &str| props.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_slice());
    let bad = |why: String| err("bad_request", why);
    match get("X-PACT-VERSION").and_then(|v| v.first()) {
        Some(v) if v == "2" => {}
        Some(_) => return bad("version not implemented".into()),
        None => return bad("no X-PACT-VERSION".into()),
    }
    let certs = get("X-PACT-CERT").unwrap_or(&[]);
    if certs.len() != 1 {
        return bad(format!("{} certificates", certs.len()));
    }
    let der = match from_b64u(&certs[0]) {
        Ok(d) => d,
        Err(e) => return bad(format!("certificate does not parse: {}", e.why)),
    };
    let leaf = match x509::parse(&der) {
        Ok(l) => l,
        Err(e) => return bad(format!("certificate does not parse: {}", e.why)),
    };
    let Some(aki) = &leaf.aki else { return bad("no issuer key identifier".into()) };
    if leaf.uris.len() != 1 {
        return bad(format!("{} endpoints", leaf.uris.len()));
    }
    if leaf.not_after - leaf.not_before > MAX_LEAF_DAYS * DAY {
        return bad("validity over 398 days".into());
    }
    let root = fingerprint_of_id(aki);
    let endpoint = leaf.uris[0].clone();
    let expired = leaf.not_after < now;
    Ok(Card {
        fn_: get("FN").and_then(|v| v.first().cloned()).unwrap_or_default(),
        seal: get("X-PACT-SEAL").and_then(|v| v.first().cloned()).unwrap_or_else(|| "none".into()),
        cert: der,
        leaf,
        root,
        endpoint,
        expired,
        ignored: props.iter().map(|(k, _)| k.clone()).filter(|k| k.starts_with("X-PACT-") && !["X-PACT-VERSION", "X-PACT-CERT", "X-PACT-SEAL"].contains(&k.as_str())).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The threshold is UTF-16 code units, as the seed counts them: a name of accented letters
    /// folds where JavaScript would fold it, not where its bytes or its code points would.
    #[test]
    fn folds_on_utf16_code_units() {
        // 40 two-byte characters: 40 code units, 80 octets. "FN:" + 40 = 43 units, under 75 — one line.
        let short = format!("FN:{}", "é".repeat(40));
        assert_eq!(fold(&short), short, "43 code units is one line, though it is 83 octets");
        // 80 of them is 83 units: folded once, at unit 75.
        let long = format!("FN:{}", "é".repeat(80));
        let folded = fold(&long);
        let lines: Vec<&str> = folded.split("\r\n").collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].encode_utf16().count(), 75);
        assert_eq!(lines[1].encode_utf16().count(), 1 + 8); // one space, the remaining 8 units
        assert_eq!(unfold(&format!("{folded}\r\nEND:VCARD\r\n"))[0], long);
        // A break that would land inside a surrogate pair moves one unit earlier, and the pair survives.
        let astral = format!("FN:{}{}", "a".repeat(74), "\u{1F600}".repeat(3));
        let f = fold(&astral);
        assert!(!f.contains('\u{FFFD}'), "no half of a pair is lost: {f}");
        assert_eq!(unfold(&format!("{f}\r\nEND:VCARD\r\n"))[0], astral);
    }

    #[test]
    fn folds_at_75() {
        let long = format!("X-PACT-CERT:{}", "A".repeat(200));
        let f = fold(&long);
        for (i, l) in f.split("\r\n").enumerate() {
            assert!(l.len() <= 75, "line {i} is {}", l.len());
            if i > 0 {
                assert!(l.starts_with(' '));
            }
        }
        assert_eq!(unfold(&format!("{f}\r\nEND:VCARD\r\n")), vec![long, "END:VCARD".to_string()]);
    }
}
