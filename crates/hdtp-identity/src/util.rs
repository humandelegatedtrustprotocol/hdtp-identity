//! Errors, encodings and randomness shared by every module.
use base64::Engine;
use sha2::{Digest, Sha256};

/// Every failure that crosses the boundary: a code (a spec error where one applies) and one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub why: String,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn err<T>(code: &str, why: impl Into<String>) -> Result<T> {
    Err(Error { code: code.to_string(), why: why.into() })
}

impl Error {
    pub fn new(code: &str, why: impl Into<String>) -> Error {
        Error { code: code.to_string(), why: why.into() }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.why)
    }
}

/// The first member of an object, in sorted order, that `allowed` does not name: sorted, so that two
/// ports that iterate a map differently name the same one. The one copy: `api/limits.rs` kept its own
/// beside this one, which was `ledger.rs`'s.
pub(crate) fn stranger(doc: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) -> Option<String> {
    let mut extra: Vec<&String> = doc.keys().filter(|k| !allowed.contains(&k.as_str())).collect();
    extra.sort();
    extra.first().map(|k| k.to_string())
}

pub fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Bytes a caller hands the boundary (CONTRACT §0): base64url, forgiving the padding and the standard
/// alphabet's `+` and `/`, and nothing else — whitespace of any kind is a character outside the
/// alphabet, and a last character with a spare bit set is refused. js/b64url-arguments.json is the
/// list of cases this and the Go port's DecodeB64url are held to. It is NOT what Node's
/// `Buffer.from(s, 'base64url')` accepts, which skips any character it does not know and cannot fail.
/// It forgave every Unicode whitespace character, and the Go port four, so a key with a vertical tab
/// in it was read here and refused there (C10); the contract forgives padding and alphabet, and no
/// whitespace, so neither port does.
pub fn from_b64u(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim_end_matches('=');
    // One fixed message, not the decoder's: the Go port cannot reproduce another library's wording,
    // and CONTRACT §0 promises the same answer from both, `why` included.
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed).map_err(|_| Error::new("parse", "not base64url"))
}

/// A member of an envelope, as it travels: unpadded base64url in its ONE canonical spelling (§13.1).
///
/// `from_b64u` is for what a caller hands the boundary, and is forgiving on purpose — padding and the
/// standard alphabet. Neither may be forgiven on the wire: `sig` covers the DECODED
/// bytes, so every extra spelling a reader accepts is another envelope that verifies, and two readers
/// that forgive different things disagree about which envelopes exist. The Go port forgave a stray
/// character and a set spare bit, and accepted what this core refused.
pub fn wire_b64u(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::new("parse", "not base64url"))
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return err("parse", "odd hex length");
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| Error::new("parse", "not hex"))).collect()
}

pub fn random(n: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    getrandom::getrandom(&mut out).map_err(|_| Error::new("internal", "randomness unavailable"))?;
    Ok(out)
}

/// The vectors' key derivation: every secret is the hash of a label.
pub fn seed(label: &str) -> [u8; 32] {
    sha256(format!("hdtp-1.0-vectors/{label}").as_bytes())
}

/// What a value that serde_json will not write is answered with. Nothing the core builds is one; it
/// is a fixed line because `why` never carries a library's own words (CONTRACT §0).
pub const UNSERIALISABLE: &str = "does not serialise as JSON";

/// The containers JSON text may nest, one inside another: serde_json refuses the 128th with its own
/// words, and encoding/json reads ten thousand.
pub const JSON_MAX_DEPTH: usize = 127;
/// What `json_limit` finds, in the words both ports answer.
pub const JSON_NUMBER_BEYOND_DOUBLE: &str = "a number is outside the range of a double";
pub const JSON_NESTED_TOO_DEEP: &str = "nested more than 127 deep";

/// The first thing, in text order, that JSON text holds and one of the two ports' parsers refuses
/// while the other reads it: a number that is infinite as a double (`1e400`: serde_json refuses it,
/// encoding/json keeps its digits), or containers nested more than `JSON_MAX_DEPTH` deep. Strings are
/// skipped, escapes and all. The Go port's `jsonLimit` is the same scan, and its JSON readers refuse
/// what it finds, as serde_json does; `call` names it before anything reads the arguments.
pub fn json_limit(text: &str) -> Option<&'static str> {
    let b = text.as_bytes();
    let (mut i, mut depth) = (0, 0usize);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'[' | b'{' => {
                depth += 1;
                if depth > JSON_MAX_DEPTH {
                    return Some(JSON_NESTED_TOO_DEEP);
                }
                i += 1;
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < b.len() && matches!(b[i], b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E') {
                    i += 1;
                }
                if text[start..i].parse::<f64>().is_ok_and(f64::is_infinite) {
                    return Some(JSON_NUMBER_BEYOND_DOUBLE);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Whether JSON text holds a `\u` escape of half of a UTF-16 surrogate pair: a high one not followed
/// by a low one, or a low one on its own. An escaped backslash before a `u` is text, not an escape.
/// The Go port's `loneSurrogate` is the same scan.
pub fn lone_surrogate(text: &str) -> bool {
    let b = text.as_bytes();
    let hex4 = |i: usize| -> Option<u32> {
        b.get(i..i + 4).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u32::from_str_radix(h, 16).ok())
    };
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            i += 1;
            continue;
        }
        if b[i + 1] != b'u' {
            i += 2;
            continue;
        }
        match hex4(i + 2) {
            Some(0xdc00..=0xdfff) => return true,
            Some(0xd800..=0xdbff) => {
                let low = if b.get(i + 6) == Some(&b'\\') && b.get(i + 7) == Some(&b'u') { hex4(i + 8) } else { None };
                if !matches!(low, Some(0xdc00..=0xdfff)) {
                    return true;
                }
                i += 12;
            }
            _ => i += 6,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Bytes a caller hands the boundary, read as js/b64url-arguments.json says: one list, which the
    /// Go port's DecodeB64url is held to as well. This reader forgave every Unicode whitespace
    /// character and the Go port four, so a key with a vertical tab in it was a key here and `parse`
    /// there (C10).
    #[test]
    fn arguments_are_read_as_one_list_says() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../js/b64url-arguments.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        assert!(cases.len() >= 20, "js/b64url-arguments.json holds {} cases", cases.len());
        for c in cases {
            let (name, input) = (c["name"].as_str().unwrap(), c["in"].as_str().unwrap());
            match c["hex"].as_str() {
                Some(want) => assert_eq!(from_b64u(input).map(|b| hex(&b)), Ok(want.to_string()), "{name}"),
                None => assert_eq!(from_b64u(input), Err(Error::new("parse", "not base64url")), "{name}"),
            }
        }
    }
}
