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

fn number(n: &serde_json::Number) -> String {
    if let Some(f) = n.as_f64() {
        if n.is_f64() {
            if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e21 {
                return format!("{}", f as i64);
            }
            return n.to_string();
        }
    }
    n.to_string()
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
        let v: Value = serde_json::from_str(r#"{"v":2,"suite":"PACT-SEAL-P256","kid":"k","ts":1,"exp":2,"cty":"c","msg_id":"m\n"}"#).unwrap();
        assert_eq!(canonical(&v), r#"{"cty":"c","exp":2,"kid":"k","msg_id":"m\n","suite":"PACT-SEAL-P256","ts":1,"v":2}"#);
    }
}
