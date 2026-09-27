//! `export_merge` (SPEC §9.2, "Import", step 2): the rows of an export against the pins a host
//! already holds. An imported leaf never replaces a pin the host validated itself (§14.5).
use super::{is_fingerprint, refuse};
use crate::util::Result;
use serde_json::{json, Value};

/// The pin fields: what a row may not change about a contact the host holds with a pin.
const PIN: [&str; 3] = ["endpoint", "leaf", "root_cert"];

pub struct Merged {
    pub write: Vec<Value>,
    pub keep: Vec<String>,
    pub conflicts: Vec<Value>,
}

fn root_of(v: &Value, what: &str, i: usize) -> Result<String> {
    match v.get("root").and_then(|r| r.as_str()) {
        Some(r) if is_fingerprint(r) => Ok(r.to_string()),
        _ => refuse(format!("{what}[{i}]: root is not a fingerprint")),
    }
}

/// A row whose root the host does not hold is written. A row whose root it holds WITHOUT a leaf is
/// written when the row carries one (export_read kept it only because `[leaf, root_cert]` validated).
/// Every other held root is kept as held, and each pin field the row would change is a conflict.
pub fn merge(held: &[Value], rows: &[Value]) -> Result<Merged> {
    // The held rows by root, the first of each kept (a map: a scan per row was quadratic).
    let mut held_by_root: std::collections::HashMap<String, &Value> = std::collections::HashMap::new();
    for (i, h) in held.iter().enumerate() {
        held_by_root.entry(root_of(h, "held", i)?).or_insert(h);
    }
    let mut out = Merged { write: Vec::new(), keep: Vec::new(), conflicts: Vec::new() };
    for (i, r) in rows.iter().enumerate() {
        let root = root_of(r, "rows", i)?;
        let held_leaf = |h: &Value| h.get("leaf").is_some_and(|l| !l.is_null());
        match held_by_root.get(&root) {
            None => out.write.push(r.clone()),
            Some(h) if !held_leaf(h) && r.get("leaf").is_some_and(|l| !l.is_null()) => out.write.push(r.clone()),
            Some(h) => {
                for f in PIN {
                    let (was, now) = (h.get(f).unwrap_or(&Value::Null), r.get(f).unwrap_or(&Value::Null));
                    if !now.is_null() && was != now {
                        out.conflicts.push(json!({ "root": root, "field": f, "held": was, "row": now }));
                    }
                }
                out.keep.push(root);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC §9.2, import step 2: an imported leaf never replaces a pin the host validated itself,
    /// and a row the host holds without a leaf takes the row's (export_read kept it only because it
    /// validated).
    #[test]
    fn export_merge_never_replaces_a_held_pin() {
        let [a, b, c] = ["A", "B", "C"].map(|x| format!("sha256:{}", x.repeat(43)));
        let row = |root: &str, endpoint: &str, leaf: Value| json!({ "root": root, "endpoint": endpoint, "leaf": leaf, "root_cert": null });
        let held = [row(&a, "https://a.example/mcp", json!("MIIheld")), row(&b, "https://b.example/mcp", Value::Null)];
        let rows = [
            row(&a, "https://moved.example/mcp", json!("MIIrow")),
            row(&b, "https://b.example/mcp", json!("MIIrow")),
            row(&c, "https://c.example/mcp", Value::Null),
        ];
        let m = merge(&held, &rows).unwrap();
        assert_eq!(m.write.iter().map(|w| w["root"].as_str().unwrap().to_string()).collect::<Vec<_>>(), [b, c]);
        assert_eq!(m.keep, [a]);
        assert_eq!(m.conflicts.len(), 2, "the held pin's endpoint and leaf: {:?}", m.conflicts);
    }
}
