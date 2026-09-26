//! The contact book the record keeps: `pact contacts export` and `pact contacts import`.
use super::files::{open_record, open_vault, save_record};
use crate::io::{confirm, core, fail, instant, now_or, read_input, Fail, Res};
use serde_json::{json, Value};

pub fn contacts_export(vault: &str) -> Res<i32> {
    // The vault first, as `id ledger`: it proves the passphrase and refuses a mistyped path.
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    if !r.found {
        eprintln!("no record at {}: this vault's contact book is not here", r.path);
    }
    println!("{}", serde_json::to_string_pretty(&r.plaintext["contacts"])?);
    Ok(0)
}

fn contact_line(c: &Value) -> String {
    format!("{}  {}  {}", c["root"].as_str().unwrap_or("?"), c["endpoint"].as_str().unwrap_or("?"), c["name"].as_str().unwrap_or(""))
}

/// A root fingerprint as §2 writes one: `sha256:` and the base64url of a 32-byte hash.
fn is_fingerprint(v: &Value) -> bool {
    v.as_str().is_some_and(|f| {
        f.strip_prefix("sha256:").is_some_and(|b| b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
    })
}

/// A contact's `root_cert` is what proves a leaf of theirs off the wire (an archive's, say), so it
/// is worth exactly as much as its binding to the fingerprint the book pins. A certificate that
/// hashes to something else is a former host's certificate under a friend's name: refused here, not
/// stored and shown later as a difference.
fn check_root_cert(c: &Value) -> Res<()> {
    let Some(cert) = c["root_cert"].as_str() else { return Ok(()) };
    let root = c["root"].as_str().unwrap_or("?");
    let parsed =
        core("parse_certificate", json!({ "der": cert })).map_err(|e| Fail(format!("{root}: root_cert does not parse ({})", e.0)))?;
    if parsed["fingerprint"].as_str() != Some(root) {
        return fail(format!(
            "{root}: root_cert is a certificate for {}, not for the root this contact is pinned by",
            parsed["fingerprint"].as_str().unwrap_or("an unreadable key")
        ));
    }
    if parsed["kind"].as_str() != Some("root") {
        return fail(format!(
            "{root}: root_cert is not a root certificate ({})",
            parsed["profile_error"].as_str().unwrap_or("not self-signed")
        ));
    }
    Ok(())
}

pub fn contacts_import(vault: &str, file: &str, yes: bool) -> Res<i32> {
    let incoming: Vec<Value> =
        serde_json::from_slice(&read_input(file)?).map_err(|e| Fail(format!("{file}: a JSON array of contacts ({e})")))?;
    for c in &incoming {
        if !is_fingerprint(&c["root"]) || c["endpoint"].as_str().is_none() {
            return fail(format!("{file}: every contact needs a root fingerprint and an endpoint"));
        }
        check_root_cert(c)?;
    }
    // The vault first: a record is sealed under the passphrase it proves, never under one nothing
    // checked (an absent record used to be started under whatever was typed).
    let v = open_vault(vault, false)?;
    let mut r = open_record(&v)?;
    if !r.found {
        eprintln!("no record at {}: starting one with this contact book", r.path);
    }
    let mine: Vec<Value> = r.plaintext["contacts"].as_array().cloned().unwrap_or_default();
    let mut added = 0;
    let mut removed = 0;
    let mut changed = 0;
    for c in &incoming {
        match mine.iter().find(|m| m["root"] == c["root"]) {
            None => {
                added += 1;
                eprintln!("+ {}", contact_line(c));
            }
            // `root_cert` is the contact's root certificate, kept beside the leaf: it is what
            // proves a leaf of theirs off the wire, so a book that gains or changes one differs.
            Some(m) if m["endpoint"] != c["endpoint"] || m["leaf"] != c["leaf"] || m["root_cert"] != c["root_cert"] => {
                changed += 1;
                eprintln!("~ {}", contact_line(m));
                eprintln!(
                    "  now {}{}{}",
                    c["endpoint"].as_str().unwrap_or("?"),
                    if m["leaf"] != c["leaf"] { " (leaf differs)" } else { "" },
                    if m["root_cert"] != c["root_cert"] { " (root certificate differs)" } else { "" }
                );
            }
            Some(_) => {}
        }
    }
    for m in &mine {
        if !incoming.iter().any(|c| c["root"] == m["root"]) {
            removed += 1;
            eprintln!("- {}", contact_line(m));
        }
    }
    if added + removed + changed == 0 {
        eprintln!("no differences: the book already matches");
        return Ok(0);
    }
    eprintln!("{added} added, {removed} removed, {changed} changed");
    if !confirm("Make this the wallet's contact book?", yes)? {
        eprintln!("nothing written");
        return Ok(1);
    }
    let now = instant(now_or(None)?);
    let merged: Vec<Value> = incoming
        .into_iter()
        .map(|mut c| {
            if c.get("added").is_none() {
                c["added"] = json!(mine.iter().find(|m| m["root"] == c["root"]).and_then(|m| m["added"].as_str()).unwrap_or(&now));
            }
            c
        })
        .collect();
    r.plaintext["contacts"] = Value::Array(merged);
    save_record(&v, &r)?;
    eprintln!("written");
    Ok(0)
}
