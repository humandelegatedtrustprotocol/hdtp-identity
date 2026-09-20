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
/// A DER INTEGER: minimal two's-complement, always.
///
/// Prepending 0x00 for a set top bit was only half the rule; a *redundant* leading 0x00 has to
/// come off. `random_serial` hands eight random bytes straight here, so one serial in 256 began
/// 0x00 and was encoded non-minimally — and `parse_certificate`, strict since the cryptographic
/// review, then refused a certificate this core had just issued.
pub fn int_bytes(v: &[u8]) -> Vec<u8> {
    // Zero, and the empty input that means it, are one content byte — never none. `02 00` is not
    // a DER INTEGER, and this and the seed both wrote it for an empty slice while the Go port
    // wrote `02 01 00`: a three-way disagreement no gate could see, because nothing passes an
    // empty value. Fixed toward Go, which was right.
    if v.is_empty() {
        return tlv(0x02, &[0u8]);
    }
    let mut at = 0;
    while at + 1 < v.len() && v[at] == 0 && v[at + 1] & 0x80 == 0 {
        at += 1;
    }
    let v = &v[at..];
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
    // Compared WITHOUT adding, because the addition wrapped. `len` is built from up to four length
    // octets, so `0xFFFFFFFF` is reachable — and on wasm32 `usize` is 32 bits, so `at + len` wrapped
    // to a small number, this guard passed, and `&buf[at..at + len]` panicked on the slice range.
    // Six bytes (`30 84 FF FF FF FF`) did it, from any entry that parses DER: a card's certificate, a
    // CSR, an SPKI — and, with no caller cooperation at all, an attacker's envelope `chain` through
    // `decide`. Measured in the pinned build on 2026-09-20: `RuntimeError: unreachable`, which is the
    // boundary throwing across, the one thing CONTRACT section 0 says it never does. 64-bit hosts
    // computed the same guard correctly, so `cargo test`, the CLI and the Go node never saw it; the
    // wasm port is what the wallet page and the intrusion suite's default defender run.
    // `at <= buf.len()` holds here: every increment above is guarded by an `at >= buf.len()` check.
    if len > buf.len() - at {
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

/// DER's OBJECT IDENTIFIER: every subidentifier in its shortest base-128 form, so no leading 0x80,
/// and the last byte ends one. A padded arc reads as the same OID to a lenient parser and as nothing
/// at all to a strict one, which is the parser differential in four bytes.
pub fn oid_minimal(node: &Node<'_>) -> bool {
    let b = node.content;
    if node.tag != 0x06 || b.is_empty() || b[b.len() - 1] & 0x80 != 0 {
        return false;
    }
    let mut start = true;
    for &x in &b[1..] {
        if start && x == 0x80 {
            return false;
        }
        start = x & 0x80 == 0;
    }
    true
}

/// DER's BIT STRING for a named bit list (keyUsage): the unused bits are zero, and trailing zero bits
/// are removed, so the lowest bit still encoded is set. Either spelling of one set is a second
/// encoding. Not for the signature or the public key, where every bit is carried and `unused` is 0.
pub fn named_bits_ok(content: &[u8]) -> bool {
    let unused = content.first().copied().unwrap_or(0);
    let bits = &content[1.min(content.len())..];
    if unused > 7 {
        return false;
    }
    match bits.last() {
        None => unused == 0,
        Some(&last) => last & ((1u8 << unused) - 1) == 0 && last & (1u8 << unused) != 0,
    }
}

/// Every OID a certificate carries is read through this, so no call site can be the one that forgot:
/// the profile is exact, and an exactness applied at one of four read positions is not one.
pub fn read_oid_strict(node: &Node<'_>) -> Result<String> {
    if !oid_minimal(node) {
        return err("parse", "OID not in the DER form");
    }
    Ok(read_oid(node))
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
    /// The 1-in-256 bug: eight random bytes beginning 0x00 used to encode non-minimally, and the
    /// strict reader the cryptographic review added then refused a certificate this core had just
    /// issued. Asserted on the encoder and through the reader, because either half alone passes.
    #[test]
    fn integers_are_minimal_whatever_they_are_handed() {
        // A redundant leading zero comes off.
        assert_eq!(int_bytes(&[0x00, 0x11, 0x22]), vec![0x02, 0x02, 0x11, 0x22]);
        assert_eq!(int_bytes(&[0x00, 0x00, 0x01]), vec![0x02, 0x01, 0x01]);
        // A necessary one goes on, and is not then stripped again.
        assert_eq!(int_bytes(&[0x80, 0x11]), vec![0x02, 0x03, 0x00, 0x80, 0x11]);
        assert_eq!(int_bytes(&[0x00, 0x80, 0x11]), vec![0x02, 0x03, 0x00, 0x80, 0x11]);
        // Zero is one byte, not none — and so is the empty slice that means zero. `02 00` is not
        // a DER INTEGER, and this port and the seed both wrote it while Go wrote `02 01 00`: a
        // three-way disagreement all four cross-port gates missed, because nothing passes an
        // empty value. Asserted in every port now so it cannot drift back.
        assert_eq!(int_bytes(&[0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(int_bytes(&[]), vec![0x02, 0x01, 0x00]);
        // And every one of them reads back as minimal.
        for v in [vec![0x00, 0x11, 0x22], vec![0x00], vec![0x80, 0x11], vec![0x00, 0x00, 0x01]] {
            let encoded = int_bytes(&v);
            let node = read(&encoded, 0).unwrap();
            assert!(int_minimal(node.content), "{v:02x?} encoded non-minimally");
        }
    }

    /// A serial the profile will accept: eight significant bytes, never a leading zero, so the
    /// canonical encoding cannot shrink it under the 64 bits the profile asks for.
    #[test]
    fn random_serials_survive_canonical_encoding() {
        for _ in 0..512 {
            let serial = crate::x509::random_serial().unwrap();
            assert_eq!(serial.len(), 8);
            assert_ne!(serial[0], 0);
            let encoded = int_bytes(&serial);
            let node = read(&encoded, 0).unwrap();
            assert!(int_minimal(node.content));
            assert!(node.content.len() >= 8, "a serial must stay at least 64 bits");
        }
    }

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
