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

/// A row's root, and the two other members merge reads a meaning from, held to what the contract
/// says they are (`ContactRow`), in export_read's words: a `status` outside the three was read as not
/// blocked, so a held contact the host wrote as `Blocked` lost its block on an import, and an `added`
/// that is no instant was carried into what the host writes (the review of 2026-09-30, found by
/// parity's nested "" cases). A member that is absent is left to the host, as before.
fn root_of(v: &Value, what: &str, i: usize) -> Result<String> {
    let root = match v.get("root").and_then(|r| r.as_str()) {
        Some(r) if is_fingerprint(r) => r.to_string(),
        _ => return refuse(format!("{what}[{i}]: root is not a fingerprint")),
    };
    if v.get("status").and_then(|s| s.as_str()).is_some_and(|s| !super::STATUSES.contains(&s)) {
        return refuse(format!("{what}[{i}]: status is not active, blocked or pending_out"));
    }
    if v.get("added").and_then(|s| s.as_str()).is_some_and(|a| crate::time::parse_rfc3339(a).is_err()) {
        return refuse(format!("{what}[{i}]: added is not an RFC 3339 instant"));
    }
    Ok(root)
}

/// What the person decided about a contact the host holds: never taken from a file.
const DECIDED: [&str; 2] = ["status", "permissions"];

/// Two values alike: a list of names compared as a set, anything else as JSON.
fn same(a: &Value, b: &Value) -> bool {
    match (a.as_array(), b.as_array()) {
        (Some(x), Some(y)) => {
            let mut x: Vec<String> = x.iter().map(|v| v.to_string()).collect();
            let mut y: Vec<String> = y.iter().map(|v| v.to_string()).collect();
            x.sort();
            y.sort();
            x == y
        }
        _ => a == b,
    }
}

/// A row whose root the host does not hold is written. A row whose root it holds WITHOUT a leaf is
/// written when the row carries one (export_read kept it only because `[leaf, root_cert]` validated),
/// with what the person decided about the contact kept as held: a blocked contact stays blocked,
/// and the permissions granted stay those granted. Every other held root is kept as held. Each pin
/// field the row would change, and each decision it would, is a conflict for the host to show.
pub fn merge(held: &[Value], rows: &[Value]) -> Result<Merged> {
    // The held rows by root, the first of each kept (a map: a scan per row was quadratic).
    let mut held_by_root: std::collections::HashMap<String, &Value> = std::collections::HashMap::new();
    for (i, h) in held.iter().enumerate() {
        held_by_root.entry(root_of(h, "held", i)?).or_insert(h);
    }
    let mut out = Merged { write: Vec::new(), keep: Vec::new(), conflicts: Vec::new() };
    let conflict = |out: &mut Merged, root: &str, f: &str, h: &Value, r: &Value| {
        let (was, now) = (h.get(f).unwrap_or(&Value::Null), r.get(f).unwrap_or(&Value::Null));
        if !now.is_null() && !same(was, now) {
            out.conflicts.push(json!({ "root": root, "field": f, "held": was, "row": now }));
        }
    };
    for (i, r) in rows.iter().enumerate() {
        let root = root_of(r, "rows", i)?;
        let held_leaf = |h: &Value| h.get("leaf").is_some_and(|l| !l.is_null());
        match held_by_root.get(&root) {
            None => out.write.push(r.clone()),
            Some(h) if !held_leaf(h) && r.get("leaf").is_some_and(|l| !l.is_null()) => {
                for f in DECIDED {
                    conflict(&mut out, &root, f, h, r);
                }
                let mut w = r.clone();
                if h.get("status").and_then(|s| s.as_str()) == Some("blocked") {
                    w["status"] = json!("blocked");
                }
                if let Some(p) = h.get("permissions").filter(|p| !p.is_null()) {
                    w["permissions"] = p.clone();
                }
                out.write.push(w);
            }
            Some(h) => {
                for f in PIN.iter().chain(DECIDED.iter()) {
                    conflict(&mut out, &root, f, h, r);
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
        let [a, b, c] = ["A", "B", "C"].map(|x| format!("sha256:{}A", x.repeat(42)));
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

    /// A contact held without a leaf, blocked and granted one thing, keeps what the person decided when
    /// a file brings its leaf: it stays blocked and granted what it was, and each difference the file
    /// carried is a conflict. A blocked contact came back active with the file's grants, before.
    #[test]
    fn export_merge_keeps_what_the_person_decided_about_a_held_contact() {
        let root = format!("sha256:{}A", "B".repeat(42));
        let held = [
            json!({ "root": root, "endpoint": "https://b.example/mcp", "leaf": null, "root_cert": null, "status": "blocked", "permissions": ["message.text"] }),
        ];
        let rows = [
            json!({ "root": root, "endpoint": "https://b.example/mcp", "leaf": "MIIrow", "root_cert": "MIIroot", "status": "active", "permissions": ["message.media", "message.text"] }),
        ];
        let m = merge(&held, &rows).unwrap();
        assert_eq!(m.write.len(), 1);
        assert_eq!(m.write[0]["status"], "blocked", "a blocked contact stays blocked");
        assert_eq!(m.write[0]["permissions"], json!(["message.text"]), "the grants stay the person's");
        assert_eq!(m.write[0]["leaf"], "MIIrow", "the leaf that validated is taken");
        let fields: Vec<&str> = m.conflicts.iter().filter_map(|c| c["field"].as_str()).collect();
        assert_eq!(fields, ["status", "permissions"]);
        // The same permissions in another order are no difference.
        let rows = [
            json!({ "root": root, "endpoint": "https://b.example/mcp", "leaf": "MIIrow", "status": "blocked", "permissions": ["message.text"] }),
        ];
        assert!(merge(&held, &rows).unwrap().conflicts.is_empty());
    }
}
