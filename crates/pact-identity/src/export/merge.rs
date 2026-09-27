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
    let mut held_by_root = Vec::new();
    for (i, h) in held.iter().enumerate() {
        held_by_root.push((root_of(h, "held", i)?, h));
    }
    let mut out = Merged { write: Vec::new(), keep: Vec::new(), conflicts: Vec::new() };
    for (i, r) in rows.iter().enumerate() {
        let root = root_of(r, "rows", i)?;
        let held_leaf = |h: &Value| h.get("leaf").is_some_and(|l| !l.is_null());
        match held_by_root.iter().find(|(k, _)| *k == root) {
            None => out.write.push(r.clone()),
            Some((_, h)) if !held_leaf(h) && r.get("leaf").is_some_and(|l| !l.is_null()) => out.write.push(r.clone()),
            Some((_, h)) => {
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
