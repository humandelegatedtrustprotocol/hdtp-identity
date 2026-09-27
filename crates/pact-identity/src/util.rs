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

pub fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Accepts what Node's `Buffer.from(s, 'base64url')` accepts: url-safe or standard alphabet, padding optional.
pub fn from_b64u(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
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
/// `from_b64u` is for what a caller hands the boundary, and is forgiving on purpose — padding, the
/// standard alphabet, whitespace. None of that may be forgiven on the wire: `sig` covers the DECODED
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
    getrandom::getrandom(&mut out).map_err(|e| Error::new("internal", format!("randomness unavailable: {e}")))?;
    Ok(out)
}

/// The vectors' key derivation: every secret is the hash of a label.
pub fn seed(label: &str) -> [u8; 32] {
    sha256(format!("pact-2.0-vectors/{label}").as_bytes())
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
