//! UTC instants as Unix seconds; RFC 3339 at the boundary, UTCTime/GeneralizedTime in DER.
use crate::util::{err, Result};

pub const DAY: i64 = 86_400;
pub const HOUR: i64 = 3_600;
/// `99991231235959Z`, RFC 5280's "no well-defined expiration".
pub const FOREVER: i64 = 253_402_300_799;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn from_civil(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    days_from_civil(y, mo, d) * DAY + h * HOUR + mi * 60 + s
}

pub fn to_civil(t: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = t.div_euclid(DAY);
    let rem = t.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    (y, m, d, rem / HOUR, (rem % HOUR) / 60, rem % 60)
}

pub fn year_of(t: i64) -> i64 {
    to_civil(t).0
}

fn valid(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> bool {
    (1..=12).contains(&mo) && (1..=31).contains(&d) && (0..24).contains(&h) && (0..60).contains(&mi) && (0..60).contains(&s) && {
        let (y2, m2, d2) = civil_from_days(days_from_civil(y, mo, d));
        (y2, m2, d2) == (y, mo, d)
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z`; fractions are dropped (the boundary is second precision).
pub fn parse_rfc3339(s: &str) -> Result<i64> {
    let b = s.as_bytes();
    let num = |from: usize, to: usize| -> Result<i64> {
        if to > b.len() || !b[from..to].iter().all(|c| c.is_ascii_digit()) {
            return err("parse", format!("not an RFC 3339 instant: {s}"));
        }
        Ok(s[from..to].parse().unwrap_or(0))
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') || b[13] != b':' || b[16] != b':' {
        return err("parse", format!("not an RFC 3339 instant: {s}"));
    }
    let (y, mo, d, h, mi, sec) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut i = 19;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return err("parse", format!("not an RFC 3339 instant: {s}"));
        }
    }
    if i + 1 != b.len() || (b[i] != b'Z' && b[i] != b'z') || !valid(y, mo, d, h, mi, sec) {
        return err("parse", format!("not an RFC 3339 instant: {s}"));
    }
    Ok(from_civil(y, mo, d, h, mi, sec))
}

pub fn format_rfc3339(t: i64) -> String {
    let (y, mo, d, h, mi, s) = to_civil(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// DER time as the profile encodes it: UTCTime before 2050, GeneralizedTime from 2050.
pub fn der_time(t: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = to_civil(t);
    let rest = format!("{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
    if y < 2050 {
        crate::der::tlv(0x17, format!("{:02}{rest}", y.rem_euclid(100)).as_bytes())
    } else {
        crate::der::tlv(0x18, format!("{y:04}{rest}").as_bytes())
    }
}

/// The tag a well-formed certificate must use for an instant.
pub fn tag_for(t: i64) -> u8 {
    if year_of(t) < 2050 {
        0x17
    } else {
        0x18
    }
}

/// Reads a UTCTime or GeneralizedTime node; anything but `YYYYMMDDHHMMSSZ` is refused.
pub fn read_der_time(tag: u8, content: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(content).map_err(|_| crate::util::Error::new("parse", "time not in the DER form"))?;
    let full = if tag == 0x17 {
        let yy: i64 = s.get(0..2).and_then(|x| x.parse().ok()).unwrap_or(99);
        format!("{}{}", if yy < 50 { "20" } else { "19" }, s)
    } else {
        s.to_string()
    };
    let b = full.as_bytes();
    if b.len() != 15 || !b[..14].iter().all(|c| c.is_ascii_digit()) || b[14] != b'Z' {
        return err("parse", "time not in the DER form");
    }
    let n = |a: usize, z: usize| full[a..z].parse::<i64>().unwrap_or(0);
    // A DER time is a DATE. This handed the digits straight to `from_civil`, which rolls an
    // out-of-range field over — `20260230120000Z` read as 2 March — and the comment that stood here
    // defended that by what the profile BUILDER emits, while this function is the READER of attacker
    // bytes. The Go port refused the same certificate; the seed normalised it as this did, and has
    // been corrected with this. `valid` is the check `parse_rfc3339` always applied.
    let (y, mo, d, h, mi, sec) = (n(0, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12), n(12, 14));
    if !valid(y, mo, d, h, mi, sec) {
        return err("parse", "time not in the DER form");
    }
    Ok(from_civil(y, mo, d, h, mi, sec))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips() {
        let t = parse_rfc3339("2026-09-13T12:00:00Z").unwrap();
        assert_eq!(t, 1_789_300_800);
        assert_eq!(format_rfc3339(t), "2026-09-13T12:00:00Z");
        assert_eq!(format_rfc3339(FOREVER), "9999-12-31T23:59:59Z");
        assert_eq!(der_time(FOREVER), crate::der::tlv(0x18, b"99991231235959Z"));
        assert_eq!(der_time(t), crate::der::tlv(0x17, b"260913120000Z"));
        assert_eq!(read_der_time(0x17, b"260913120000Z").unwrap(), t);
        assert!(parse_rfc3339("2026-02-30T00:00:00Z").is_err());
    }
}
