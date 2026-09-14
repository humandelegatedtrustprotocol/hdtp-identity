//! The little DER the profile needs: an encoder for building, a strict walker for reading.
//! Definite and minimal lengths only, nothing past the end — indefinite forms, padded lengths and
//! trailing bytes are how one parser is made to see what another does not.
use crate::util::{err, Result};

fn length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = Vec::new();
    let mut v = n;
    while v > 0 {
        bytes.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &concat(parts))
}
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &concat(parts))
}
pub fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}
pub fn implicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}
pub fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}
pub fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}
pub fn ia5(s: &str) -> Vec<u8> {
    tlv(0x16, s.as_bytes())
}
pub fn boolean(v: bool) -> Vec<u8> {
    tlv(0x01, &[if v { 0xff } else { 0x00 }])
}
pub fn null() -> Vec<u8> {
    tlv(0x05, &[])
}

/// INTEGER from big-endian magnitude bytes: a leading zero is added when the high bit is set.
pub fn int_bytes(v: &[u8]) -> Vec<u8> {
    if !v.is_empty() && v[0] & 0x80 != 0 {
        let mut c = vec![0u8];
        c.extend_from_slice(v);
        tlv(0x02, &c)
    } else {
        tlv(0x02, v)
    }
}

pub fn int(v: u64) -> Vec<u8> {
    // The seed writes the shortest hex form of the number, zero as one byte.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    int_bytes(&bytes)
}

pub fn bitstr(bytes: &[u8], unused: u8) -> Vec<u8> {
    let mut c = vec![unused];
    c.extend_from_slice(bytes);
    tlv(0x03, &c)
}

pub fn oid(s: &str) -> Vec<u8> {
    let parts: Vec<u64> = s.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    if parts.len() < 2 {
        return tlv(0x06, &[]);
    }
    let mut out = vec![(parts[0] * 40 + parts[1]) as u8];
    for &v in &parts[2..] {
        let mut b = vec![(v & 0x7f) as u8];
        let mut r = v >> 7;
        while r > 0 {
            b.insert(0, ((r & 0x7f) as u8) | 0x80);
            r >>= 7;
        }
        out.extend(b);
    }
    tlv(0x06, &out)
}

/// One TLV read strictly: `content` is what the tag carries, `raw` the whole node, `end` the offset after it.
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
    pub end: usize,
}

pub fn read(buf: &[u8], pos: usize) -> Result<Node<'_>> {
    if pos + 2 > buf.len() {
        return err("parse", "DER truncated");
    }
    let tag = buf[pos];
    let mut len = buf[pos + 1] as usize;
    let mut at = pos + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 {
            return err("parse", "DER indefinite or oversized length");
        }
        if at >= buf.len() {
            return err("parse", "DER truncated");
        }
        if buf[at] == 0 {
            return err("parse", "DER length not minimal");
        }
        len = 0;
        for _ in 0..n {
            if at >= buf.len() {
                return err("parse", "DER truncated");
            }
            len = (len << 8) | buf[at] as usize;
            at += 1;
        }
        if len < 0x80 {
            return err("parse", "DER length not minimal");
        }
    }
    if at + len > buf.len() {
        return err("parse", "DER length overruns the buffer");
    }
    Ok(Node { tag, content: &buf[at..at + len], raw: &buf[pos..at + len], end: at + len })
}

pub fn children<'a>(node: &Node<'a>) -> Result<Vec<Node<'a>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < node.content.len() {
        let c = read(node.content, pos)?;
        pos = c.end;
        out.push(c);
    }
    Ok(out)
}

/// DER's one encoding of TRUE: a single 0xFF byte.
pub fn bool_true(node: &Node<'_>) -> bool {
    node.tag == 0x01 && node.content == [0xff]
}

/// DER's INTEGER: at least one byte, and no leading 0x00 before a byte under 0x80 (nor 0xFF before
/// one at or above it) — the shortest two's-complement form.
pub fn int_minimal(content: &[u8]) -> bool {
    match content {
        [] => false,
        [_] => true,
        [0x00, b, ..] => b & 0x80 != 0,
        [0xff, b, ..] => b & 0x80 == 0,
        _ => true,
    }
}

pub fn read_oid(node: &Node<'_>) -> String {
    let b = node.content;
    if b.is_empty() {
        return String::new();
    }
    let mut out = vec![(b[0] / 40).to_string(), (b[0] % 40).to_string()];
    let mut v: u128 = 0;
    for &x in &b[1..] {
        v = (v << 7) | (x & 0x7f) as u128;
        if x & 0x80 == 0 {
            out.push(v.to_string());
            v = 0;
        }
    }
    out.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodes_and_reads() {
        assert_eq!(oid("1.2.840.10045.4.3.2"), vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
        assert_eq!(read_oid(&read(&oid("1.2.840.10045.4.3.2"), 0).unwrap()), "1.2.840.10045.4.3.2");
        assert_eq!(int(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(int(2), vec![0x02, 0x01, 0x02]);
        assert_eq!(int_bytes(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        let long = tlv(0x04, &vec![7u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert!(read(&[0x30, 0x81, 0x05, 1, 2, 3, 4, 5], 0).is_err()); // not minimal
        assert!(read(&[0x30, 0x80], 0).is_err()); // indefinite
        assert!(read(&[0x30, 0x02, 0x01], 0).is_err()); // overrun
        assert_eq!(read(&[0x30, 0x03, 0x02, 0x01, 0x05], 0).unwrap().end, 5);
    }
}
