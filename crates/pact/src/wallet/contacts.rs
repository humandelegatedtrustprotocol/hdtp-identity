//! The contact book the record keeps: `pact contacts export` writes it as a book (SPEC §9.2: an
//! export holding `manifest.json` and `contacts.csv` only), and `pact contacts import` reads an export
//! or a book, uses its `contacts.csv`, and shows every difference before the book is replaced.
use super::exportzip::{read_export, write_book};
use super::files::{open_record, open_vault, pick_root, save_record};
use crate::io::{check_writable, confirm, core, fail, instant, now_or, Fail, Res};
use serde_json::{json, Value};
use std::path::Path;

/// The most `contacts import` decompresses from one file: a whole export is read and checked, its
/// messages and files included, though only its contacts are kept.
pub const IMPORT_CEILING: u64 = 1 << 30;

/// §9.2's notice, before the book is written, in the words of the cloud's book page. A book holds
/// contacts only, so it says the contact list and not the conversations and files a full export
/// carries; this CLI writes no full export.
pub const BOOK_NOTICE: &str = "This file is not encrypted. Anyone who gets it can read your contact list. It holds no keys, so it cannot be used to speak as you. Keep it where you keep private documents, and delete it once it has been imported.";

/// And back: a row as the book keeps a contact. The row's leaf is there only when it validated.
fn contact_of(r: &Value) -> Value {
    let mut c = json!({ "root": r["root"], "endpoint": r["endpoint"], "name": r["name"], "added": r["added"] });
    for k in ["leaf", "root_cert"] {
        if let Some(v) = r[k].as_str() {
            c[k] = json!(v);
        }
    }
    c
}

pub fn contacts_export(vault: &str, out: &str) -> Res<i32> {
    check_writable(Some(out))?;
    if Path::new(out).exists() {
        return fail(format!("{out} exists: a book is not written over a file"));
    }
    // The vault first, as `id ledger`: it proves the passphrase and refuses a mistyped path.
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    if !r.found {
        eprintln!("no record at {}: this vault's contact book is not here", r.path);
    }
    let root = pick_root(&v.plaintext, None)?;
    let now = instant(now_or(None)?);
    // The book's contacts as rows, through the core's book_rows: the one mapping every wallet uses.
    let book = r.plaintext["contacts"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Value> =
        core("book_rows", json!({ "contacts": book, "exported_at": now }))?["rows"].as_array().cloned().unwrap_or_default();
    eprintln!("{BOOK_NOTICE}");
    write_book(Path::new(out), root["fingerprint"].as_str().unwrap_or(""), root["cn"].as_str().unwrap_or(""), &now, &rows).map_err(Fail)?;
    eprintln!("wrote {out}: {} contact{}", rows.len(), if rows.len() == 1 { "" } else { "s" });
    Ok(0)
}

fn contact_line(c: &Value) -> String {
    format!("{}  {}  {}", c["root"].as_str().unwrap_or("?"), c["endpoint"].as_str().unwrap_or("?"), c["name"].as_str().unwrap_or(""))
}

pub fn contacts_import(vault: &str, file: &str, yes: bool) -> Res<i32> {
    // The vault first: the file is checked against the identity it is imported into (§9.2's owner),
    // and a record is sealed under the passphrase the vault proves, never under one nothing checked.
    let v = open_vault(vault, false)?;
    let root = pick_root(&v.plaintext, None)?;
    let now = instant(now_or(None)?);
    let contents = read_export(Path::new(file), root["fingerprint"].as_str().unwrap_or(""), &now, IMPORT_CEILING)
        .map_err(|why| Fail(format!("{file}: {why}")))?;
    let incoming: Vec<Value> = contents.contacts.iter().map(contact_of).collect();
    let plural = |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    eprintln!(
        "{file}: {}, {}, {} and {}, all checked; the wallet keeps only the contacts",
        plural(contents.contacts.len(), "contact", "contacts"),
        plural(contents.threads.len(), "thread", "threads"),
        plural(contents.messages.len(), "message", "messages"),
        plural(contents.media.len(), "file", "files")
    );
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
    r.plaintext["contacts"] = Value::Array(incoming);
    save_record(&v, &r)?;
    eprintln!("written");
    Ok(0)
}
