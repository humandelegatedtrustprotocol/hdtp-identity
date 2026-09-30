//! RFC 8785 for the objects PACT canonicalises: members sorted by UTF-16 code unit, no whitespace,
//! numbers in their shortest form, strings escaped exactly as JSON.stringify escapes them.
use serde_json::Value;

pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write(v, true, &mut out);
    out
}

/// A JSON value a caller handed in, as it is sealed into a plaintext (`params`, `result`, `error`, a
/// vault's document): strings as RFC 8785 writes them; an integer serde_json holds as one (an i64, or
/// a u64 past it) by its digits, and every other number as RFC 8785 writes it; and members in the
/// order the value holds them — the order they were written in, a member written twice once, where it
/// first appeared, with the value it was given last, as serde_json's `preserve_order` map reads it
/// (and JSON.parse). Not sorted: Appendix B's plaintexts write `name` before `arguments`. serde_json's
/// own writer printed `1e2` as `100.0` and `-0` as `-0.0`, and the Go port sealed the caller's text as
/// it was written, duplicates and escapes and all: two plaintexts for one call. The digits are the
/// owner's choice (M2 of the review of 2026-09-30): RFC 8785's double is the header's rule, and an
/// id of 12345678901234567891 in a caller's `params` was sealed as 12345678901234567000 until then.
pub fn in_order(v: &Value) -> String {
    let mut out = String::new();
    write(v, false, &mut out);
    out
}

fn write(v: &Value, sorted: bool, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        // An integer serde holds as one keeps its digits in a sealed value; `-0`, a fraction and an
        // exponent it holds as a double, as RFC 8785 does.
        Value::Number(n) if !sorted && (n.is_i64() || n.is_u64()) => out.push_str(&n.to_string()),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => out.push_str(&string(s)),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, sorted, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            if sorted {
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            }
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&string(k));
                out.push(':');
                write(&o[*k], sorted, out);
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
    /// A sealed value keeps its members in the order it holds them, where `canonical` sorts them; a
    /// member read twice is held once, where it first appeared, with its last value.
    #[test]
    fn in_order_keeps_the_order_written() {
        let v: Value = serde_json::from_str(r#"{"name":"x","arguments":{"b":1,"a":[2.50,-0,1e2]},"name":"y"}"#).unwrap();
        assert_eq!(in_order(&v), r#"{"name":"y","arguments":{"b":1,"a":[2.5,0,100]}}"#);
        assert_eq!(canonical(&v), r#"{"arguments":{"a":[2.5,0,100],"b":1},"name":"y"}"#);
        // An i64 or a u64 keeps its digits in a sealed value, and is RFC 8785's double in `canonical`.
        let v: Value = serde_json::from_str(r#"{"u":12345678901234567891,"i":-9223372036854775808,"f":9007199254740993.0}"#).unwrap();
        assert_eq!(in_order(&v), r#"{"u":12345678901234567891,"i":-9223372036854775808,"f":9007199254740992}"#);
        assert_eq!(canonical(&v), r#"{"f":9007199254740992,"i":-9223372036854776000,"u":12345678901234567000}"#);
    }
    /// The rows are contract/contract.json's `CanonicalNumbers`, one list, which go/review_test.go's
    /// TestNumbersAsECMAScriptPrintsThem runs through the Go port too. (Each port carried its own copy
    /// of the table until 2026-09-29, held to the other by nothing but a comment saying so.)
    #[test]
    fn numbers_as_ecmascript_prints_them() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contract/contract.json");
        let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rows = contract["$defs"]["CanonicalNumbers"]["const"].as_array().unwrap();
        assert!(rows.len() >= 19, "the contract carries {} rows", rows.len());
        for row in rows {
            let (input, want) = (row[0].as_str().unwrap(), row[1].as_str().unwrap());
            let v: Value = serde_json::from_str(input).unwrap();
            assert_eq!(canonical(&v), want, "{input}");
        }
    }
}
