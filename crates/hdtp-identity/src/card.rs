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

/// The base64url-valued properties a card carries: their values are read by step 3 of `decode`.
const B64URL: [&str; 1] = ["X-HDTP-CERT"];

/// Whether a line STARTS A PROPERTY: it begins `[group.]NAME[;params]:`, the group and the name of
/// ASCII letters, digits and `-` (the seed's `PROPERTY`, `/^(?:[A-Za-z0-9-]+\.)?[A-Za-z0-9-]+(?:;[^:]*)?:/`).
/// A base64url line never does: it has no `:`.
fn starts_property(line: &str) -> bool {
    let b = line.as_bytes();
    let run = |from: usize| from + b[from..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'-').count();
    let mut end = run(0);
    if end == 0 {
        return false;
    }
    if b.get(end) == Some(&b'.') {
        let name = run(end + 1);
        if name == end + 1 {
            return false;
        }
        end = name;
    }
    match b.get(end) {
        Some(b':') => true,
        Some(b';') => b[end..].contains(&b':'),
        _ => false,
    }
}

/// Intake per §3: refuses what has no root to pin or no address to reach; an expired leaf is not a refusal.
///
/// Reading a card (§3, "Reading a card"), in three steps, as the seed's `decodeCard` reads one:
///   1. RFC 6350 §3.2 unfolding (`unfold`): a line break, CRLF or LF, followed by ONE space or tab is
///      removed, and the text is split into lines at CRLF or LF;
///   2. a line starts a property when it begins `[group.]NAME[;params]:` (`starts_property`);
///   3. a base64url-valued property (`B64URL`: X-HDTP-CERT) also takes every following line that starts
///      no property, and its value loses every space, tab, CR and LF.
///
/// Step 3 reads a card whose folding was damaged in transit: pasted through a chat, which drops a
/// continuation's leading space or adds blank lines. Base64url has none of those four characters, so
/// removing them gives back the writer's bytes whenever nothing else was damaged. A character that was
/// changed or lost still is, and is caught where it always was: by the DER parse below, or by chain
/// validation (§14.2) at the first exchange, since a card carries no root to check its leaf against.
/// Any other line that starts no property is ignored.
pub fn decode(text: &str, now: i64) -> Result<Card> {
    let mut props: Vec<(String, Vec<String>)> = Vec::new();
    // The value later lines join, while they start no property: (index in props, index in its values).
    let mut joining: Option<(usize, usize)> = None;
    for line in unfold(text) {
        if !starts_property(&line) {
            if let Some((p, v)) = joining {
                props[p].1[v].push_str(&line);
            }
            continue;
        }
        let i = line.find(':').unwrap_or_default();
        let name = line[..i].split(';').next().unwrap_or("").to_uppercase();
        let value = line[i + 1..].to_string();
        let p = match props.iter().position(|(n, _)| *n == name) {
            Some(p) => p,
            None => {
                props.push((name.clone(), Vec::new()));
                props.len() - 1
            }
        };
        props[p].1.push(value);
        joining = B64URL.contains(&name.as_str()).then(|| (p, props[p].1.len() - 1));
    }
    for (name, values) in props.iter_mut() {
        if B64URL.contains(&name.as_str()) {
            for v in values.iter_mut() {
                v.retain(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'));
            }
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
