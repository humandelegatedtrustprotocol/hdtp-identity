//! The export (SPEC §9.2; CONTRACT §6.2): one unencrypted zip carrying a person's contacts,
//! conversations and files between hosts, and the wallet's book in the same format.
//!
//! The core never opens a zip. A host reads the container — its central directory, the text
//! members, the messages in batches of lines, the media while it streams them — and hands this module
//! what it read; every rule of §9.2's validation that can be decided on what was handed over is
//! decided here, once, for every host. What only the host can do is the host's: counting the bytes
//! it actually decompresses, hashing `messages.jsonl` and each media file as it streams them, and
//! refusing a member that is not UTF-8 text.
//!
//! Every refusal is `bad_request`, and its `why` begins with where: the member, then the row or line,
//! then the column or member of a message.
pub mod csv;
pub mod jsonl;
pub mod manifest;
pub mod merge;

use crate::der;
use crate::util::{err, from_b64u, hex, sha256, Error, Result};
use crate::{address, x509};
use serde_json::{json, Value};

pub const MANIFEST_MAX: usize = 64 * 1024;
pub const CONTACTS_MAX: usize = 4 * 1024 * 1024;
pub const CONTACTS_ROWS_MAX: usize = 5000;
pub const THREADS_MAX: usize = 16 * 1024 * 1024;
pub const LINE_MAX: usize = 64 * 1024;
pub const MEDIA_MAX: usize = 5 * 1024 * 1024;
pub const BODY_MAX: usize = 16 * 1024;
pub const NAME_MAX: usize = 200;

pub const CONTACT_COLUMNS: [&str; 11] =
    ["root", "endpoint", "name", "display_name", "status", "was_active", "permissions", "their_permissions", "leaf", "root_cert", "added"];
pub const THREAD_COLUMNS: [&str; 5] = ["id", "contact", "topic", "created_at", "last_at"];
pub const STATUSES: [&str; 3] = ["active", "blocked", "pending_out"];
/// §8's permissions but `integration.<name>`, which is checked by its shape.
pub const PERMISSIONS: [&str; 5] = ["message.text", "message.media", "status.view", "calendar.availability", "calendar.book"];

pub(crate) fn refuse<T>(why: impl Into<String>) -> Result<T> {
    err("bad_request", why)
}

pub fn is_fingerprint(s: &str) -> bool {
    crate::ledger::is_fingerprint(s)
}

pub fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

fn is_b64url(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn is_base64_text(s: &str) -> bool {
    s.len() >= 16 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'+' | b'/' | b'='))
}

/// Whether DER is a private key: PKCS #8 (`SEQUENCE { INTEGER 0|1, SEQUENCE { OID … }, OCTET STRING … }`)
/// or SEC1 (`SEQUENCE { INTEGER 1, OCTET STRING, [0]?, [1]? }`), whatever its algorithm. By shape, so
/// a key of an algorithm this library does not implement is still one.
fn is_private_key_der(bytes: &[u8]) -> bool {
    let Ok(node) = der::read(bytes, 0) else { return false };
    if node.tag != 0x30 || node.end != bytes.len() {
        return false;
    }
    let Ok(f) = der::children(&node) else { return false };
    let version = |n: &der::Node<'_>, allowed: &[u8]| n.tag == 0x02 && n.content.len() == 1 && allowed.contains(&n.content[0]);
    let pkcs8 = f.len() >= 3
        && version(&f[0], &[0, 1])
        && f[1].tag == 0x30
        && der::children(&f[1]).is_ok_and(|a| a.first().is_some_and(|o| o.tag == 0x06))
        && f[2].tag == 0x04;
    let sec1 = (2..=4).contains(&f.len())
        && version(&f[0], &[1])
        && f[1].tag == 0x04
        && f[2..].iter().enumerate().all(|(k, n)| n.tag == 0xa0 + k as u8 || (k == 0 && n.tag == 0xa1));
    pkcs8 || sec1
}

/// Whether text holds a private key (SPEC §9.2, "key material"): PEM armour naming one, or any
/// whitespace-separated word that decodes, as base64 or base64url, to a PKCS #8 or SEC1 key.
pub fn holds_private_key(text: &str) -> bool {
    if text.contains("PRIVATE KEY-----") {
        return true;
    }
    text.split_ascii_whitespace().any(|w| is_base64_text(w) && from_b64u(w).is_ok_and(|der| is_private_key_der(&der)))
}

/// A cell's own rules, as `contacts.csv` holds it and as `export_write` is handed it.
pub struct Cells<'a> {
    pub owner: &'a str,
}

fn permissions(cell: &str) -> std::result::Result<Vec<String>, String> {
    if cell.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen: Vec<String> = Vec::new();
    for p in cell.split(' ') {
        let integration = p.strip_prefix("integration.").is_some_and(|n| {
            !n.is_empty() && n.len() <= 64 && n.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        });
        if p.is_empty() {
            return Err("not names separated by single spaces".into());
        }
        if !PERMISSIONS.contains(&p) && !integration {
            return Err(format!("{} is not a permission of §8", crate::canonical::string(p)));
        }
        if seen.iter().any(|s| s == p) {
            return Err(format!("{p} twice"));
        }
        seen.push(p.to_string());
    }
    Ok(seen)
}

fn certificate(cell: &str) -> std::result::Result<Option<x509::Cert>, &'static str> {
    if cell.is_empty() {
        return Ok(None);
    }
    if !is_b64url(cell) {
        return Err("not base64url");
    }
    let der = from_b64u(cell).map_err(|_| "not base64url")?;
    x509::parse(&der).map(Some).map_err(|_| "not a certificate")
}

/// One contact row's cells, in column order, checked: the row as a ContactRow, or the column and why.
/// `pin_at` decides the leaf: a leaf is kept only when `[leaf, root_cert]` validates at the row's
/// endpoint at that instant, and is null otherwise (it pins nothing). `None` keeps it as written.
pub fn contact_row(cells: &[String], c: &Cells<'_>, pin_at: Option<i64>) -> std::result::Result<Value, (usize, String)> {
    let at = |k: usize, why: String| Err((k, why));
    for (k, cell) in cells.iter().enumerate() {
        if holds_private_key(cell) {
            return at(k, "holds a private key".into());
        }
    }
    let [root, endpoint, name, display_name, status, was_active, perms, theirs, leaf, root_cert, added] = cells else {
        return at(0, format!("{} fields, not 11", cells.len()));
    };
    if !is_fingerprint(root) {
        return at(0, "not a fingerprint".into());
    }
    if root == c.owner {
        return at(0, "the owner's own root".into());
    }
    if !x509::is_normal_https(endpoint) {
        return at(1, "not an https URL in normal form".into());
    }
    if let Err(e) = address::address_guard(endpoint, None, false) {
        return at(1, e.why);
    }
    for (k, v) in [(2, name), (3, display_name)] {
        if v.chars().count() > NAME_MAX {
            return at(k, format!("over {NAME_MAX} characters"));
        }
    }
    if !STATUSES.contains(&status.as_str()) {
        return at(4, "not active, blocked or pending_out".into());
    }
    let was = match was_active.as_str() {
        "true" => true,
        "false" => false,
        _ => return at(5, "not true or false".into()),
    };
    let granted = permissions(perms).map_err(|why| (6, why))?;
    let told = permissions(theirs).map_err(|why| (7, why))?;
    let leaf_cert = certificate(leaf).map_err(|why| (8, why.to_string()))?;
    if leaf_cert.as_ref().is_some_and(|l| x509::profile_error(l, "leaf").is_some()) {
        return at(8, "not a leaf of §14.1's profile".into());
    }
    let root_parsed = certificate(root_cert).map_err(|why| (9, why.to_string()))?;
    if let Some(r) = &root_parsed {
        if x509::profile_error(r, "root").is_some() {
            return at(9, "not a root of §14.1's profile".into());
        }
        if r.public_key.fingerprint() != *root {
            return at(9, "not the certificate of this row's root".into());
        }
    }
    let Ok(added_at) = crate::time::parse_rfc3339(added) else { return at(10, "not an RFC 3339 instant".into()) };
    let pinned = match (pin_at, &leaf_cert, &root_parsed) {
        (None, Some(_), _) => Some(leaf.clone()),
        (Some(now), Some(l), Some(r)) => {
            matches!(x509::validate_chain(&[l.der.clone(), r.der.clone()], now, Some(root), Some(endpoint)), x509::ChainResult::Ok(_))
                .then(|| leaf.clone())
        }
        _ => None,
    };
    Ok(json!({
        "root": root, "endpoint": endpoint, "name": name, "display_name": display_name, "status": status,
        "was_active": was, "permissions": granted, "their_permissions": told,
        "leaf": pinned, "root_cert": root_parsed.map(|_| root_cert.clone()),
        "added": crate::time::format_rfc3339(added_at),
    }))
}

/// One thread row's cells, checked against the contacts' roots.
pub fn thread_row(cells: &[String], roots: &[&str]) -> std::result::Result<Value, (usize, String)> {
    for (k, cell) in cells.iter().enumerate() {
        if holds_private_key(cell) {
            return Err((k, "holds a private key".into()));
        }
    }
    let [id, contact, topic, created_at, last_at] = cells else { return Err((0, format!("{} fields, not 5", cells.len()))) };
    if id.is_empty() {
        return Err((0, "empty".into()));
    }
    if !roots.contains(&contact.as_str()) {
        return Err((1, "names no contact in contacts.csv".into()));
    }
    let mut times = Vec::new();
    for (k, t) in [(3, created_at), (4, last_at)] {
        match crate::time::parse_rfc3339(t) {
            Ok(v) => times.push(crate::time::format_rfc3339(v)),
            Err(_) => return Err((k, "not an RFC 3339 instant".into())),
        }
    }
    Ok(json!({ "id": id, "contact": contact, "topic": topic, "created_at": times[0], "last_at": times[1] }))
}

/// The CSV member's text parsed and its header held to `columns`: the data records, each with its
/// row number (the header is row 1).
fn table(member: &str, text: &str, columns: &[&str]) -> Result<Vec<(usize, Vec<String>)>> {
    let records = csv::read(text).map_err(|(n, why)| Error::new("bad_request", format!("{member}: row {n}: {why}")))?;
    let header: Vec<&str> = records.first().map(|r| r.iter().map(String::as_str).collect()).unwrap_or_default();
    if header != columns {
        return refuse(format!("{member}: row 1: the header is not {}", columns.join(",")));
    }
    Ok(records
        .into_iter()
        .enumerate()
        .skip(1)
        .map(|(i, r)| (i + 1, r.into_iter().map(|c| csv::unguard(&c).to_string()).collect()))
        .collect())
}

/// What `export_read` reads: the directory, the manifest, `contacts.csv` and `threads.csv`.
pub struct Read {
    pub contacts: Vec<Value>,
    pub threads: Vec<Value>,
    pub media: Vec<(String, u64)>,
}

/// One entry of the zip's central directory, as the host read it.
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub encrypted: bool,
    pub mode: u32,
}

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;

fn member_limit(name: &str) -> Option<usize> {
    match name {
        "manifest.json" => Some(MANIFEST_MAX),
        "contacts.csv" => Some(CONTACTS_MAX),
        "threads.csv" => Some(THREADS_MAX),
        _ if name.starts_with("media/") && name.len() > 6 => Some(MEDIA_MAX),
        _ => None,
    }
}

fn is_media(name: &str) -> bool {
    name.strip_prefix("media/").is_some_and(is_hash)
}

/// A name §9.2 allows in an export, exactly.
pub fn allowed_name(name: &str) -> bool {
    matches!(name, "manifest.json" | "contacts.csv" | "threads.csv" | "messages.jsonl" | "media/") || is_media(name)
}

fn entry_label(name: &str) -> String {
    format!("entry {}", crate::canonical::string(name))
}

/// §9.2's validation of everything but the messages and the media bytes, in this order: the
/// directory, the members the file must have, the manifest, the directory against the manifest's
/// `files` and `counts`, `contacts.csv`, `threads.csv`.
pub fn read(
    directory: &[Entry],
    manifest_text: Option<&str>,
    contacts_csv: Option<&str>,
    threads_csv: Option<&str>,
    owner: &str,
    now: i64,
) -> Result<Read> {
    let mut seen: Vec<&str> = Vec::new();
    for e in directory {
        let label = entry_label(&e.name);
        if !allowed_name(&e.name) {
            return refuse(format!("{label}: not a name an export holds"));
        }
        if seen.contains(&e.name.as_str()) {
            return refuse(format!("{label}: appears twice"));
        }
        seen.push(&e.name);
        if e.encrypted {
            return refuse(format!("{label}: encrypted"));
        }
        if e.mode & S_IFMT == S_IFLNK {
            return refuse(format!("{label}: a symbolic link"));
        }
        if e.mode & S_IFMT == S_IFDIR && e.name != "media/" {
            return refuse(format!("{label}: a directory"));
        }
        if let Some(limit) = member_limit(&e.name) {
            if e.size > limit as u64 {
                return refuse(format!("{label}: {} bytes, over the {limit} an export allows", e.size));
            }
        }
    }
    let has = |n: &str| seen.contains(&n);
    for required in ["manifest.json", "contacts.csv"] {
        if !has(required) {
            return refuse(format!("{required}: the file lacks it"));
        }
    }
    let Some(manifest_text) = manifest_text else { return refuse("manifest is required") };
    let m = manifest::parse(manifest_text, Some(owner))?;
    for e in directory {
        if e.name == "manifest.json" || e.name == "media/" {
            continue;
        }
        if !m.files.contains_key(&e.name) {
            return refuse(format!("{}: manifest.json's files does not list it", e.name));
        }
    }
    for name in m.files.keys() {
        if !has(name) {
            return refuse(format!("{name}: manifest.json's files lists it, and the file lacks it"));
        }
    }
    for (member, count) in [("threads.csv", m.threads), ("messages.jsonl", m.messages), ("media/", m.media)] {
        if count > 0 && !has(member) {
            return refuse(format!("{member}: the file lacks it"));
        }
    }
    let media: Vec<(String, u64)> = {
        let mut v: Vec<(String, u64)> = directory.iter().filter(|e| is_media(&e.name)).map(|e| (e.name[6..].to_string(), e.size)).collect();
        v.sort();
        v
    };
    if media.len() as u64 != m.media {
        return refuse(format!("manifest.json: counts: media is {}, and the file holds {}", m.media, media.len()));
    }

    let Some(contacts_text) = contacts_csv else { return refuse("contacts_csv is required") };
    if contacts_text.len() > CONTACTS_MAX {
        return refuse(format!("contacts.csv: over {CONTACTS_MAX} bytes"));
    }
    if Some(&sha256_hex(contacts_text.as_bytes())) != m.files.get("contacts.csv") {
        return refuse("contacts.csv: its sha256 is not manifest.json's");
    }
    let rows = table("contacts.csv", contacts_text, &CONTACT_COLUMNS)?;
    if rows.len() > CONTACTS_ROWS_MAX {
        return refuse(format!("contacts.csv: over {CONTACTS_ROWS_MAX} rows"));
    }
    let cells = Cells { owner };
    let mut contacts: Vec<Value> = Vec::new();
    for (n, r) in &rows {
        if r.len() != CONTACT_COLUMNS.len() {
            return refuse(format!("contacts.csv: row {n}: {} fields, not {}", r.len(), CONTACT_COLUMNS.len()));
        }
        let row = contact_row(r, &cells, Some(now))
            .map_err(|(k, why)| Error::new("bad_request", format!("contacts.csv: row {n}, column {}: {why}", CONTACT_COLUMNS[k])))?;
        if contacts.iter().any(|c| c["root"] == row["root"]) {
            return refuse(format!("contacts.csv: row {n}, column root: appears twice"));
        }
        contacts.push(row);
    }
    if contacts.len() as u64 != m.contacts {
        return refuse(format!("manifest.json: counts: contacts is {}, and contacts.csv holds {}", m.contacts, contacts.len()));
    }

    let mut threads: Vec<Value> = Vec::new();
    if has("threads.csv") {
        let Some(threads_text) = threads_csv else { return refuse("threads_csv is required: the file has threads.csv") };
        if threads_text.len() > THREADS_MAX {
            return refuse(format!("threads.csv: over {THREADS_MAX} bytes"));
        }
        if Some(&sha256_hex(threads_text.as_bytes())) != m.files.get("threads.csv") {
            return refuse("threads.csv: its sha256 is not manifest.json's");
        }
        let roots: Vec<&str> = contacts.iter().filter_map(|c| c["root"].as_str()).collect();
        for (n, r) in table("threads.csv", threads_text, &THREAD_COLUMNS)? {
            if r.len() != THREAD_COLUMNS.len() {
                return refuse(format!("threads.csv: row {n}: {} fields, not {}", r.len(), THREAD_COLUMNS.len()));
            }
            let row = thread_row(&r, &roots)
                .map_err(|(k, why)| Error::new("bad_request", format!("threads.csv: row {n}, column {}: {why}", THREAD_COLUMNS[k])))?;
            if threads.iter().any(|t| t["id"] == row["id"]) {
                return refuse(format!("threads.csv: row {n}, column id: appears twice"));
            }
            threads.push(row);
        }
        if threads.len() as u64 != m.threads {
            return refuse(format!("manifest.json: counts: threads is {}, and threads.csv holds {}", m.threads, threads.len()));
        }
    } else if threads_csv.is_some() {
        return refuse("threads_csv is given, and the file has no threads.csv");
    }
    Ok(Read { contacts, threads, media })
}

/// §9.2's cross-batch rules, once the host has streamed `messages.jsonl` through `jsonl::read`: the
/// line count and the member's hash against the manifest, `id` unique in the file, every `reply_to`
/// naming a message in it, and every media file named by one.
/// What the host gathered while it streamed `messages.jsonl`.
pub struct End<'a> {
    /// The lowercase hex sha256 of the member's bytes, when the file has the member.
    pub messages_sha256: Option<&'a str>,
    pub lines: u64,
    pub ids: &'a [String],
    pub msg_ids: &'a [String],
    pub reply_tos: &'a [String],
    pub media_seen: &'a [String],
}

pub fn read_end(manifest_text: &str, end: &End<'_>) -> Result<()> {
    let End { messages_sha256, lines, ids, msg_ids, reply_tos, media_seen } = *end;
    let m = manifest::parse(manifest_text, None)?;
    if lines != m.messages {
        return refuse(format!("manifest.json: counts: messages is {}, and messages.jsonl holds {lines} lines", m.messages));
    }
    match (m.files.get("messages.jsonl"), messages_sha256) {
        (Some(want), Some(got)) if want == got => {}
        (Some(_), _) => return refuse("messages.jsonl: its sha256 is not manifest.json's"),
        (None, Some(_)) => return refuse("messages.jsonl: manifest.json's files does not list it"),
        (None, None) => {}
    }
    let mut sorted: Vec<&String> = ids.iter().collect();
    sorted.sort();
    if let Some(w) = sorted.windows(2).find(|w| w[0] == w[1]) {
        return refuse(format!("messages.jsonl: id {} appears twice", crate::canonical::string(w[0])));
    }
    if let Some(r) = reply_tos.iter().find(|r| !msg_ids.contains(r)) {
        return refuse(format!("messages.jsonl: reply_to {} names no message in the file", crate::canonical::string(r)));
    }
    for name in m.files.keys().filter(|k| is_media(k)) {
        if !media_seen.iter().any(|h| h == &name[6..]) {
            return refuse(format!("{name}: nothing names it"));
        }
    }
    Ok(())
}

/// A ContactRow handed to `export_write`, as its cells.
fn contact_cells(v: &Value) -> std::result::Result<Vec<String>, (usize, String)> {
    let Some(o) = v.as_object() else { return Err((0, "a contact row is an object".into())) };
    if let Some(k) = crate::ledger::stranger(o, &CONTACT_COLUMNS) {
        return Err((0, format!("{k} is not a column of contacts.csv")));
    }
    let mut cells = Vec::new();
    for (k, col) in CONTACT_COLUMNS.iter().enumerate() {
        let cell = match (*col, o.get(*col)) {
            ("was_active", Some(Value::Bool(b))) => b.to_string(),
            ("permissions" | "their_permissions", Some(Value::Array(items))) => {
                let mut names = Vec::new();
                for i in items {
                    let Some(s) = i.as_str() else { return Err((k, "a list of names".into())) };
                    names.push(s.to_string());
                }
                names.sort();
                names.join(" ")
            }
            ("leaf" | "root_cert", None | Some(Value::Null)) => String::new(),
            (_, Some(Value::String(s))) if !matches!(*col, "was_active" | "permissions" | "their_permissions") => s.clone(),
            _ => return Err((k, "missing, or of the wrong type".into())),
        };
        cells.push(cell);
    }
    Ok(cells)
}

fn thread_cells(v: &Value) -> std::result::Result<Vec<String>, (usize, String)> {
    let Some(o) = v.as_object() else { return Err((0, "a thread row is an object".into())) };
    if let Some(k) = crate::ledger::stranger(o, &THREAD_COLUMNS) {
        return Err((0, format!("{k} is not a column of threads.csv")));
    }
    THREAD_COLUMNS
        .iter()
        .enumerate()
        .map(|(k, col)| o.get(*col).and_then(|c| c.as_str()).map(String::from).ok_or((k, "missing, or not a string".to_string())))
        .collect()
}

pub struct Written {
    pub partial: Value,
    pub contacts_csv: String,
    pub threads_csv: Option<String>,
}

/// The canonical `contacts.csv` and `threads.csv`, and the manifest without the messages: every row
/// checked by the reader's rules (so no host writes what a host refuses), contacts sorted by root and
/// threads by id, every cell guarded and quoted one way.
pub fn write(
    owner: &str,
    owner_name: &str,
    exported_at: i64,
    tool: &str,
    contacts: &[Value],
    threads: &[Value],
    media: &[Value],
) -> Result<Written> {
    if !is_fingerprint(owner) {
        return refuse("owner is not a fingerprint");
    }
    let cells = Cells { owner };
    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    for (i, c) in contacts.iter().enumerate() {
        let located = |(k, why): (usize, String)| Error::new("bad_request", format!("contacts[{i}], column {}: {why}", CONTACT_COLUMNS[k]));
        let r = contact_cells(c).map_err(located)?;
        let row = contact_row(&r, &cells, None).map_err(located)?;
        let mut r = r;
        r[10] = row["added"].as_str().unwrap_or_default().to_string();
        if rows.iter().any(|(root, _)| *root == r[0]) {
            return refuse(format!("contacts[{i}], column root: appears twice"));
        }
        rows.push((r[0].clone(), r));
    }
    if rows.len() > CONTACTS_ROWS_MAX {
        return refuse(format!("contacts: over {CONTACTS_ROWS_MAX} rows"));
    }
    rows.sort();
    let roots: Vec<String> = rows.iter().map(|(r, _)| r.clone()).collect();
    let root_refs: Vec<&str> = roots.iter().map(String::as_str).collect();
    let mut contacts_csv = String::new();
    csv::write_record(&mut contacts_csv, &CONTACT_COLUMNS.map(String::from));
    for (_, r) in &rows {
        csv::write_record(&mut contacts_csv, &r.iter().map(|c| csv::guard(c)).collect::<Vec<_>>());
    }
    if contacts_csv.len() > CONTACTS_MAX {
        return refuse(format!("contacts: over {CONTACTS_MAX} bytes as contacts.csv"));
    }

    let mut trows: Vec<(String, Vec<String>)> = Vec::new();
    for (i, t) in threads.iter().enumerate() {
        let located = |(k, why): (usize, String)| Error::new("bad_request", format!("threads[{i}], column {}: {why}", THREAD_COLUMNS[k]));
        let mut r = thread_cells(t).map_err(located)?;
        let row = thread_row(&r, &root_refs).map_err(located)?;
        r[3] = row["created_at"].as_str().unwrap_or_default().to_string();
        r[4] = row["last_at"].as_str().unwrap_or_default().to_string();
        if trows.iter().any(|(id, _)| *id == r[0]) {
            return refuse(format!("threads[{i}], column id: appears twice"));
        }
        trows.push((r[0].clone(), r));
    }
    trows.sort();
    let threads_csv = (!trows.is_empty()).then(|| {
        let mut out = String::new();
        csv::write_record(&mut out, &THREAD_COLUMNS.map(String::from));
        for (_, r) in &trows {
            csv::write_record(&mut out, &r.iter().map(|c| csv::guard(c)).collect::<Vec<_>>());
        }
        out
    });
    if threads_csv.as_ref().is_some_and(|t| t.len() > THREADS_MAX) {
        return refuse(format!("threads: over {THREADS_MAX} bytes as threads.csv"));
    }

    let mut files = serde_json::Map::new();
    files.insert("contacts.csv".into(), json!(sha256_hex(contacts_csv.as_bytes())));
    if let Some(t) = &threads_csv {
        files.insert("threads.csv".into(), json!(sha256_hex(t.as_bytes())));
    }
    for (i, item) in media.iter().enumerate() {
        let hash = item.get("hash").and_then(|h| h.as_str()).unwrap_or("");
        if !is_hash(hash) {
            return refuse(format!("media[{i}]: hash is not a lowercase hex sha256"));
        }
        match item.get("size").and_then(|s| s.as_u64()) {
            Some(s) if s <= MEDIA_MAX as u64 => {}
            _ => return refuse(format!("media[{i}]: size is a number of bytes up to {MEDIA_MAX}")),
        }
        if files.insert(format!("media/{hash}"), json!(hash)).is_some() {
            return refuse(format!("media[{i}]: appears twice"));
        }
    }
    let partial = json!({
        "pact_export": manifest::VERSION, "owner": owner, "owner_name": owner_name,
        "exported_at": crate::time::format_rfc3339(exported_at), "tool": tool,
        "counts": { "contacts": rows.len(), "threads": trows.len(), "messages": 0, "media": media.len() },
        "files": files,
    });
    Ok(Written { partial, contacts_csv, threads_csv })
}

/// The members of the wallet's own copy of a contact (CONTRACT §6, `VaultContact`).
const VAULT_CONTACT: [&str; 6] = ["root", "endpoint", "name", "leaf", "root_cert", "added"];

/// The wallet's book as rows of `contacts.csv` (SPEC §9.2: a book is an export of contacts only). The
/// book keeps the root, the endpoint, the name, the leaf, the root certificate and when the contact was
/// added; a row's other columns are what a contact the wallet keeps is — active, ever active, nothing
/// granted — and `added` is the export's time when the book has none. The one mapping every wallet
/// uses; export_write then holds each row to the reader's rules.
pub fn book_rows(contacts: &[Value], exported_at: i64) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for (i, c) in contacts.iter().enumerate() {
        let Some(o) = c.as_object() else { return refuse(format!("contacts[{i}] is an object")) };
        if let Some(k) = crate::ledger::stranger(o, &VAULT_CONTACT) {
            return refuse(format!("contacts[{i}]: {} is not a member of a wallet contact", crate::canonical::string(&k)));
        }
        for m in ["root", "endpoint"] {
            if !o.get(m).is_some_and(|v| v.is_string()) {
                return refuse(format!("contacts[{i}]: {m} is required"));
            }
        }
        for m in ["name", "leaf", "root_cert", "added"] {
            if o.get(m).is_some_and(|v| !v.is_string()) {
                return refuse(format!("contacts[{i}]: {m} is a string"));
            }
        }
        let text = |m: &str| o.get(m).and_then(|v| v.as_str());
        rows.push(json!({
            "root": text("root"), "endpoint": text("endpoint"), "name": text("name").unwrap_or(""), "display_name": "",
            "status": "active", "was_active": true, "permissions": [], "their_permissions": [],
            "leaf": text("leaf"), "root_cert": text("root_cert"),
            "added": text("added").map(String::from).unwrap_or_else(|| crate::time::format_rfc3339(exported_at)),
        }));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Alg, PrivateKey};
    use crate::util::{b64u, seed};

    /// SPEC §9 and §9.2: a host that makes an export puts no key material in it. The writer holds its
    /// rows and messages to the reader's rules, so a private key in a cell or a body is refused before
    /// a byte is written — PKCS #8 as base64url, and SEC1 as base64 with padding.
    #[test]
    fn export_write_refuses_a_row_or_message_holding_a_private_key() {
        let key = PrivateKey::from_seed(Alg::Ed25519, &seed("export/key")).unwrap();
        let pkcs8 = b64u(&key.to_pkcs8());
        let owner = format!("sha256:{}", "O".repeat(43));
        let row = |name: &str| {
            json!({ "root": format!("sha256:{}", "B".repeat(43)), "endpoint": "https://b.example/mcp", "name": name, "display_name": "",
                "status": "active", "was_active": true, "permissions": [], "their_permissions": [], "leaf": null, "root_cert": null,
                "added": "2026-09-27T10:00:00Z" })
        };
        let write = |name: &str| write(&owner, "", 0, "t", &[row(name)], &[], &[]).map(|_| ()).map_err(|e| e.why);
        assert_eq!(write("Bharat"), Ok(()), "the control");
        assert_eq!(write(&pkcs8), Err("contacts[0], column name: holds a private key".to_string()));
        let mut sec1 = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        sec1.extend_from_slice(&seed("export/sec1"));
        use base64::Engine;
        let body = format!("keep this: {}", base64::engine::general_purpose::STANDARD.encode(&sec1));
        let message = json!({ "id": "1", "thread": "t", "contact": "c", "msg_id": "m", "direction": "in", "sender": "human",
            "time": "2026-09-27T10:00:00Z", "body": body, "reply_to": null, "status": "read", "attachments": [] });
        assert_eq!(jsonl::write(&[message]).map_err(|e| e.why), Err("messages[0], member body: holds a private key".to_string()));
    }
}
