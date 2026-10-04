//! The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.
use crate::keys::fingerprint_of_id;
use crate::time::DAY;
use crate::util::{b64u, err, from_b64u, Result};
use crate::x509::{self, Cert, MAX_LEAF_DAYS};

/// RFC 6350 §3.2 folding: a line is at most 75 octets, a continuation a space and at most 74 more,
/// and a break never falls inside a UTF-8 sequence — it moves back to the start of the character.
/// The seed folds the same way (CONTRACT §4), so the ports agree beyond ASCII.
fn fold(line: &str) -> String {
    if line.len() <= 75 {
        return line.to_string();
    }
    let mut parts = Vec::new();
    let (mut i, mut width) = (0, 75);
    while i < line.len() {
        let mut end = (i + width).min(line.len());
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(if i == 0 { line[..end].to_string() } else { format!(" {}", &line[i..end]) });
        i = end;
        width = 74;
    }
    parts.join("\r\n")
}

fn assemble(lines: Vec<String>) -> String {
    let mut out = lines.iter().map(|l| fold(l)).collect::<Vec<_>>().join("\r\n");
    out.push_str("\r\n");
    out
}

/// A card is LINES, and everything a caller supplies is written into one. A control character in any
/// of it — a name, the seal policy, an extra line — is refused: a line break writes a property of the
/// writer's choosing, and the decoder reads the FIRST of a name, so `FN` "x\r\nX-HDTP-SEAL:none" made a
/// card that requires sealing into one that does not. A name with a line break in it is not a name.
/// (§3 puts the duty to SANITISE a name at the point of display; this is the other end, where a card
/// is made, and a card that says something its maker did not write is not a display problem.)
pub fn encode(fn_: &str, cert: &[u8], seal: Option<&str>, extra: &[String]) -> Result<String> {
    for (what, text) in [("fn", fn_), ("seal", seal.unwrap_or(""))].into_iter().chain(extra.iter().map(|e| ("extra", e.as_str()))) {
        if text.chars().any(char::is_control) {
            return err("bad_request", format!("{what} carries a control character"));
        }
    }
    let mut lines = vec![
        "BEGIN:VCARD".to_string(),
        "VERSION:4.0".to_string(),
        format!("FN:{fn_}"),
        "X-HDTP-VERSION:1".to_string(),
        format!("X-HDTP-CERT:{}", b64u(cert)),
    ];
    lines.extend(extra.iter().cloned());
    if let Some(s) = seal.filter(|s| !s.is_empty()) {
        lines.push(format!("X-HDTP-SEAL:{s}"));
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
        let nl = if b[i] == b'\r' && i + 1 < b.len() && b[i + 1] == b'\n' {
            2
        } else if b[i] == b'\n' {
            1
        } else {
            0
        };
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
    // An empty value names no version, as the seed's card.mjs reads it: this answered `version not
    // implemented` to `X-HDTP-VERSION:` and the Go port and the seed `no X-HDTP-VERSION` (C9).
    match get("X-HDTP-VERSION").and_then(|v| v.first()) {
        Some(v) if v == "1" => {}
        Some(v) if !v.is_empty() => return bad("version not implemented".into()),
        _ => return bad("no X-HDTP-VERSION".into()),
    }
    let certs = get("X-HDTP-CERT").unwrap_or(&[]);
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
    // What is about to be shown to a person as the identity to pin is this value, so it has to BE a
    // key identifier: 32 bytes (§14.1). Three bytes used to come out as `sha256:AQID` — a contact no
    // chain could ever satisfy, under a fingerprint that is not one.
    if aki.len() != 32 {
        return bad("issuer key identifier is not 32 bytes".into());
    }
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
        seal: get("X-HDTP-SEAL").and_then(|v| v.first().cloned()).unwrap_or_else(|| "none".into()),
        cert: der,
        leaf,
        root,
        endpoint,
        expired,
        ignored: props
            .iter()
            .map(|(k, _)| k.clone())
            .filter(|k| k.starts_with("X-HDTP-") && !["X-HDTP-VERSION", "X-HDTP-CERT", "X-HDTP-SEAL"].contains(&k.as_str()))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The threshold is octets (RFC 6350 §3.2), and a break never splits a UTF-8 sequence.
    #[test]
    fn folds_on_octets() {
        // "FN:" and 36 two-byte letters is 75 octets: one line. 37 is 77: folded once.
        let exact = format!("FN:{}", "é".repeat(36));
        assert_eq!(fold(&exact), exact, "75 octets is one line");
        let long = format!("FN:{}", "é".repeat(80));
        let folded = fold(&long);
        for (n, line) in folded.split("\r\n").enumerate() {
            assert!(line.len() <= 75, "line {n} is {} octets", line.len());
        }
        assert_eq!(folded.split("\r\n").next().unwrap().len(), 75);
        assert_eq!(unfold(&format!("{folded}\r\nEND:VCARD\r\n"))[0], long);
        // A break that would land inside a character moves back to its start, and nothing is lost.
        for tail in ["€€€", "\u{1F600}\u{1F600}"] {
            let line = format!("FN:{}{tail}", "a".repeat(71));
            let f = fold(&line);
            assert_eq!(f.split("\r\n").next().unwrap().len(), 74, "{tail}: the break moves before the character");
            assert_eq!(unfold(&format!("{f}\r\nEND:VCARD\r\n"))[0], line);
        }
    }

    #[test]
    fn folds_at_75() {
        let long = format!("X-HDTP-CERT:{}", "A".repeat(200));
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
