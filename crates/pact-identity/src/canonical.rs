//! RFC 8785 for the objects PACT canonicalises: members sorted by UTF-16 code unit, no whitespace,
//! numbers in their shortest form, strings escaped exactly as JSON.stringify escapes them.
use serde_json::Value;

pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => out.push_str(&string(s)),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&string(k));
                out.push(':');
                write(&o[*k], out);
            }
            out.push('}');
        }
    }
}

/// A number as ECMAScript's Number::toString prints it (what RFC 8785 requires): integers without
/// a fraction, the shortest round-trip form otherwise, and the exponent form — `1e+21`, `1e-7` —
/// past 1e21 and under 1e-6. Integers serde keeps as integers print as they are.
fn number(n: &serde_json::Number) -> String {
    // RFC 8785 prints a number as ECMAScript's Number does — as the DOUBLE it is. An integer keeps its
    // digits only while a double holds it exactly, which is up to 2^53. Past that serde still has the
    // digits and this printed them, where the seed — JavaScript, and the authority — prints the
    // nearest double: 9007199254740993 is 9007199254740992 there, and was not here.
    const EXACT: u64 = 1 << 53;
    let exact = match (n.as_i64(), n.as_u64()) {
        (Some(i), _) => i.unsigned_abs() <= EXACT,
        (None, Some(u)) => u <= EXACT,
        _ => false,
    };
    if exact {
        return n.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if !f.is_finite() {
        return "null".into();
    }
    if f == 0.0 {
        return "0".into();
    }
    let abs = f.abs();
    if (1e-6..1e21).contains(&abs) {
        // Rust's Display for f64 is the shortest round-trip form without an exponent, which is
        // ECMAScript's in this range; an integral value prints without ".0".
        return format!("{}", f);
    }
    // ECMAScript's exponent form: one digit, an optional fraction, `e`, an explicit sign.
    let s = format!("{:e}", f);
    match s.split_once('e') {
        Some((m, e)) if !e.starts_with('-') => format!("{m}e+{e}"),
        _ => s,
    }
}

/// JSON.stringify's escaping: `"`, `\`, the C0 controls as `\b \f \n \r \t` or `\u00xx`; nothing else.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sorts_and_strips() {
        let v: Value =
            serde_json::from_str(r#"{"v":2,"suite":"PACT-SEAL-P256","kid":"k","ts":1,"exp":2,"cty":"c","msg_id":"m\n"}"#).unwrap();
        assert_eq!(canonical(&v), r#"{"cty":"c","exp":2,"kid":"k","msg_id":"m\n","suite":"PACT-SEAL-P256","ts":1,"v":2}"#);
    }
    #[test]
    fn numbers_as_ecmascript_prints_them() {
        let cases: &[(&str, &str)] = &[
            ("1e21", "1e+21"),
            ("1.5e300", "1.5e+300"),
            ("1e-7", "1e-7"),
            ("0.000001", "0.000001"),
            ("100.0", "100"),
            ("9223372036854775808.0", "9223372036854776000"), // the shortest round-trip form, as ECMAScript prints 2^63
            ("1e20", "100000000000000000000"),
            ("0.1", "0.1"),
            ("-0.0", "0"),
            ("42", "42"),
            // …and the rows the Go port's table has carried since 2026-09-21: the two are one list.
            ("1e-5", "0.00001"),
            ("0.0000001", "1e-7"),
            ("1.25e-9", "1.25e-9"),
            ("-1e-7", "-1e-7"),
            ("1e100", "1e+100"),
            ("9007199254740992", "9007199254740992"),
            ("9007199254740993", "9007199254740992"),
            ("-9007199254740993", "-9007199254740992"),
            ("12345678901234567890", "12345678901234567000"),
        ];
        for (input, want) in cases {
            let v: Value = serde_json::from_str(input).unwrap();
            assert_eq!(canonical(&v), *want, "{input}");
        }
    }
}
