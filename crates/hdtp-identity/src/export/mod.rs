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

use crate::util::{err, from_b64u, hex, sha256, Error, Result};
use crate::{address, x509};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::HashSet;

pub const MANIFEST_MAX: usize = 64 * 1024;
pub const CONTACTS_MAX: usize = 4 * 1024 * 1024;
pub const CONTACTS_ROWS_MAX: usize = 5000;
pub const THREADS_MAX: usize = 16 * 1024 * 1024;
pub const LINE_MAX: usize = 64 * 1024;
pub const MEDIA_MAX: usize = 5 * 1024 * 1024;
pub const BODY_MAX: usize = 16 * 1024;
pub const NAME_MAX: usize = 200;
pub const ATTACHMENTS_MAX: usize = 1;

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

// ── key material (SPEC §9.2: an importer MUST refuse anything "that decodes as a private key") ─────
//
// Detection reads LENIENTLY, and on purpose, where every other reader here is strict: what a lenient
// decoder reads as a key is key material, and a check that decodes more strictly than the tools a
// person has is a check a key can be spelled past. The ports read a base64 word with a spare bit set
// in its last character, and a PKCS #8 whose length is written in a longer form than it needs
// (`81 2e`), as no key; the cloud's copy of this check (atob, and a length reader that takes any
// definite form) and OpenSSL read both as the key, byte for byte (CW-07, R38). So here a word forgives
// its padding, either alphabet and its spare bits, and a length may take any definite form of up to
// four octets. The refusals this makes are more, never fewer. js/key-material.json is the list of
// cases both ports' tests and the parity cases read. TO REVERSE (a reading the owner may change):
// `loose_read` back to `der::read`, and `loose_b64` back to `from_b64u`, here and in go/export.go.

/// A DER-shaped element read for detection: a tag, and a definite length in the short form or in a
/// long form of one to four octets, minimal or not.
struct Loose<'a> {
    tag: u8,
    content: &'a [u8],
    end: usize,
}

fn loose_read(b: &[u8], at: usize) -> Option<Loose<'_>> {
    let tag = *b.get(at)?;
    let first = *b.get(at + 1)? as usize;
    let (len, start) = if first & 0x80 == 0 {
        (first, at + 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let octets = b.get(at + 2..at + 2 + n)?;
        (octets.iter().fold(0usize, |l, o| (l << 8) | *o as usize), at + 2 + n)
    };
    let end = start.checked_add(len)?;
    Some(Loose { tag, content: b.get(start..end)?, end })
}

fn loose_children(content: &[u8]) -> Option<Vec<Loose<'_>>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < content.len() {
        let c = loose_read(content, at)?;
        at = c.end;
        out.push(c);
    }
    Some(out)
}

/// A word decoded as base64 or base64url for detection: its padding, either alphabet and a last
/// character with a spare bit set are forgiven, as a lenient decoder forgives them.
fn loose_b64(w: &str) -> Option<Vec<u8>> {
    use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
    use base64::{alphabet, Engine};
    const LOOSE: GeneralPurpose = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::RequireNone).with_decode_allow_trailing_bits(true),
    );
    let cleaned: String = w
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    LOOSE.decode(cleaned.trim_end_matches('=')).ok()
}

/// Whether bytes are a private key: PKCS #8 (`SEQUENCE { INTEGER 0|1, SEQUENCE { OID … }, OCTET STRING … }`)
/// or SEC1 (`SEQUENCE { INTEGER 1, OCTET STRING, [0]?, [1]? }`), whatever its algorithm, read by the
/// lenient reader above. By shape, so a key of an algorithm this library does not implement is still one.
fn is_private_key_der(bytes: &[u8]) -> bool {
    let Some(node) = loose_read(bytes, 0) else { return false };
    if node.tag != 0x30 || node.end != bytes.len() {
        return false;
    }
    let Some(f) = loose_children(node.content) else { return false };
    let version = |n: &Loose<'_>, allowed: &[u8]| n.tag == 0x02 && n.content.len() == 1 && allowed.contains(&n.content[0]);
    let pkcs8 = f.len() >= 3
        && version(&f[0], &[0, 1])
        && f[1].tag == 0x30
        && loose_children(f[1].content).is_some_and(|a| a.first().is_some_and(|o| o.tag == 0x06))
        && f[2].tag == 0x04;
    let sec1 = (2..=4).contains(&f.len())
        && version(&f[0], &[1])
        && f[1].tag == 0x04
        && f[2..].iter().enumerate().all(|(k, n)| n.tag == 0xa0 + k as u8 || (k == 0 && n.tag == 0xa1));
    pkcs8 || sec1
}

/// Whether a media file's bytes are a private key (SPEC 9.2#15): PKCS #8 or SEC1 in DER, or
/// text that holds one (PEM, or a base64 word) — the rule a cell is held to, over the file.
pub fn media_holds_private_key(bytes: &[u8]) -> bool {
    is_private_key_der(bytes) || std::str::from_utf8(bytes).is_ok_and(holds_private_key)
}

/// Whether text holds a private key (SPEC §9.2, "key material"): PEM armour naming one, or any
/// whitespace-separated word that decodes, as base64 or base64url, to a PKCS #8 or SEC1 key.
pub fn holds_private_key(text: &str) -> bool {
    if text.contains("PRIVATE KEY-----") {
        return true;
    }
    // A private key's DER begins with 0x30, which base64 of either alphabet writes as `M`: only a word
    // that begins so is decoded, so no other cell of a file costs a decoded copy of itself.
    text.split_ascii_whitespace()
        .any(|w| w.starts_with('M') && is_base64_text(w) && loose_b64(w).is_some_and(|der| is_private_key_der(&der)))
}

/// A cell's own rules, as `contacts.csv` holds it and as `export_write` is handed it.
pub struct Cells<'a> {
    pub owner: &'a str,
}

/// A permissions cell checked: §8's names, single-spaced, none twice. The names are the cell's own
/// words; a reader answers them by splitting the cell, never a copy of it.
/// A permission of §8: one of its names, or `integration.<name>`.
fn is_permission(p: &str) -> bool {
    PERMISSIONS.contains(&p)
        || p.strip_prefix("integration.").is_some_and(|n| {
            !n.is_empty() && n.len() <= 64 && n.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        })
}

fn permissions(cell: &str) -> std::result::Result<(), String> {
    if cell.is_empty() {
        return Ok(());
    }
    let mut have: HashSet<&str> = HashSet::new();
    for p in cell.split(' ') {
        if p.is_empty() {
            return Err("not names separated by single spaces".into());
        }
        if !is_permission(p) {
            return Err(format!("{} is not a permission of §8", crate::canonical::string(p)));
        }
        if !have.insert(p) {
            return Err(format!("{p} twice"));
        }
    }
    Ok(())
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

/// One contact row, checked, holding its cells as the reader found them: borrowed from the member's
/// text wherever the CSV did not escape them. `added` is kept as the instant it names.
pub struct ContactRow<'a> {
    pub root: Cow<'a, str>,
    pub endpoint: Cow<'a, str>,
    pub name: Cow<'a, str>,
    pub display_name: Cow<'a, str>,
    pub status: Cow<'a, str>,
    pub was_active: bool,
    pub permissions: Cow<'a, str>,
    pub their_permissions: Cow<'a, str>,
    pub leaf: Option<Cow<'a, str>>,
    pub root_cert: Option<Cow<'a, str>>,
    pub added: i64,
}

/// One thread row, checked, likewise.
pub struct ThreadRow<'a> {
    pub id: Cow<'a, str>,
    pub contact: Cow<'a, str>,
    pub topic: Cow<'a, str>,
    pub created_at: i64,
    pub last_at: i64,
}

/// A JSON string, written into an answer being built: serde_json's escaping, no Value between.
fn json_str(out: &mut Vec<u8>, s: &str) {
    // Writing into a Vec cannot fail.
    let _ = serde_json::to_writer(&mut *out, s);
}

fn json_names(out: &mut Vec<u8>, cell: &str) {
    out.push(b'[');
    for (k, p) in cell.split(' ').filter(|p| !p.is_empty()).enumerate() {
        if k > 0 {
            out.push(b',');
        }
        json_str(out, p);
    }
    out.push(b']');
}

fn json_opt(out: &mut Vec<u8>, v: &Option<Cow<'_, str>>) {
    match v {
        Some(s) => json_str(out, s),
        None => out.extend_from_slice(b"null"),
    }
}

impl ContactRow<'_> {
    /// The row as `export_read` answers it (CONTRACT §6.2, `ContactRow`).
    pub fn write_json(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"{\"root\":");
        json_str(out, &self.root);
        out.extend_from_slice(b",\"endpoint\":");
        json_str(out, &self.endpoint);
        out.extend_from_slice(b",\"name\":");
        json_str(out, &self.name);
        out.extend_from_slice(b",\"display_name\":");
        json_str(out, &self.display_name);
        out.extend_from_slice(b",\"status\":");
        json_str(out, &self.status);
        out.extend_from_slice(if self.was_active { b",\"was_active\":true" } else { b",\"was_active\":false" });
        out.extend_from_slice(b",\"permissions\":");
        json_names(out, &self.permissions);
        out.extend_from_slice(b",\"their_permissions\":");
        json_names(out, &self.their_permissions);
        out.extend_from_slice(b",\"leaf\":");
        json_opt(out, &self.leaf);
        out.extend_from_slice(b",\"root_cert\":");
        json_opt(out, &self.root_cert);
        out.extend_from_slice(b",\"added\":");
        json_str(out, &crate::time::format_rfc3339(self.added));
        out.push(b'}');
    }
}

impl ThreadRow<'_> {
    /// The row as `export_read` answers it (CONTRACT §6.2, `ThreadRow`).
    pub fn write_json(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"{\"id\":");
        json_str(out, &self.id);
        out.extend_from_slice(b",\"contact\":");
        json_str(out, &self.contact);
        out.extend_from_slice(b",\"topic\":");
        json_str(out, &self.topic);
        out.extend_from_slice(b",\"created_at\":");
        json_str(out, &crate::time::format_rfc3339(self.created_at));
        out.extend_from_slice(b",\"last_at\":");
        json_str(out, &crate::time::format_rfc3339(self.last_at));
        out.push(b'}');
    }
}

/// One contact row's cells, in column order, checked: the row, or the column and why. `pin_at`
/// decides the leaf: a leaf is kept only when `[leaf, root_cert]` validates at the row's endpoint at
/// that instant, and is null otherwise (it pins nothing). `None` keeps it as written.
pub fn contact_row<'a>(
    cells: Vec<Cow<'a, str>>,
    c: &Cells<'_>,
    pin_at: Option<i64>,
) -> std::result::Result<ContactRow<'a>, (usize, String)> {
    let at = |k: usize, why: String| Err((k, why));
    for (k, cell) in cells.iter().enumerate() {
        if holds_private_key(cell) {
            return at(k, "holds a private key".into());
        }
    }
    let count = cells.len();
    let Ok([root, endpoint, name, display_name, status, was_active, perms, theirs, leaf, root_cert, added]) =
        <[Cow<'a, str>; 11]>::try_from(cells)
    else {
        return at(0, format!("{count} fields, not 11"));
    };
    if !is_fingerprint(&root) {
        return at(0, "not a fingerprint".into());
    }
    if root == c.owner {
        return at(0, "the owner's own root".into());
    }
    if !x509::is_normal_https(&endpoint) {
        return at(1, "not an https URL in normal form".into());
    }
    if let Err(e) = address::address_guard(&endpoint, None, false) {
        return at(1, e.why);
    }
    for (k, v) in [(2, &name), (3, &display_name)] {
        if v.chars().count() > NAME_MAX {
            return at(k, format!("over {NAME_MAX} characters"));
        }
    }
    if !STATUSES.contains(&status.as_ref()) {
        return at(4, "not active, blocked or pending_out".into());
    }
    let was = match was_active.as_ref() {
        "true" => true,
        "false" => false,
        _ => return at(5, "not true or false".into()),
    };
    permissions(&perms).map_err(|why| (6, why))?;
    permissions(&theirs).map_err(|why| (7, why))?;
    let leaf_cert = certificate(&leaf).map_err(|why| (8, why.to_string()))?;
    if leaf_cert.as_ref().is_some_and(|l| x509::profile_error(l, "leaf").is_some()) {
        return at(8, "not a leaf of §14.1's profile".into());
    }
    let root_parsed = certificate(&root_cert).map_err(|why| (9, why.to_string()))?;
    if let Some(r) = &root_parsed {
        if x509::profile_error(r, "root").is_some() {
            return at(9, "not a root of §14.1's profile".into());
        }
        if r.public_key.fingerprint() != *root {
            return at(9, "not the certificate of this row's root".into());
        }
    }
    let Ok(added_at) = crate::time::parse_rfc3339(&added) else { return at(10, "not an RFC 3339 instant".into()) };
    let pins = match (pin_at, &leaf_cert, &root_parsed) {
        (None, Some(_), _) => true,
        (Some(now), Some(l), Some(r)) => {
            matches!(x509::validate_chain(&[l.der.clone(), r.der.clone()], now, Some(&root), Some(&endpoint)), x509::ChainResult::Ok(_))
        }
        _ => false,
    };
    let has_root_cert = root_parsed.is_some();
    Ok(ContactRow {
        root,
        endpoint,
        name,
        display_name,
        status,
        was_active: was,
        permissions: perms,
        their_permissions: theirs,
        leaf: pins.then_some(leaf),
        root_cert: has_root_cert.then_some(root_cert),
        added: added_at,
    })
}

/// One thread row's cells, checked against the contacts' roots.
pub fn thread_row<'a>(cells: Vec<Cow<'a, str>>, roots: &HashSet<&str>) -> std::result::Result<ThreadRow<'a>, (usize, String)> {
    for (k, cell) in cells.iter().enumerate() {
        if holds_private_key(cell) {
            return Err((k, "holds a private key".into()));
        }
    }
    let count = cells.len();
    let Ok([id, contact, topic, created_at, last_at]) = <[Cow<'a, str>; 5]>::try_from(cells) else {
        return Err((0, format!("{count} fields, not 5")));
    };
    if id.is_empty() {
        return Err((0, "empty".into()));
    }
    if !roots.contains(contact.as_ref()) {
        return Err((1, "names no contact in contacts.csv".into()));
    }
    let Ok(created) = crate::time::parse_rfc3339(&created_at) else { return Err((3, "not an RFC 3339 instant".into())) };
    let Ok(last) = crate::time::parse_rfc3339(&last_at) else { return Err((4, "not an RFC 3339 instant".into())) };
    Ok(ThreadRow { id, contact, topic, created_at: created, last_at: last })
}

/// The CSV member's text checked whole (every record reads, and the header is `columns`), and then
/// its data records one at a time, each with its row number (the header is row 1), one leading `'`
/// stripped from every cell. Two passes over the text, and never a copy of it: the first refuses
/// what the second would otherwise find partway, so a syntax fault anywhere is still the first thing
/// named. The count is the data records'.
/// One data record of a CSV member: its row number and its cells.
type Record<'a> = (usize, Vec<Cow<'a, str>>);

fn table<'a>(member: &str, text: &'a str, columns: &[&str]) -> Result<(usize, impl Iterator<Item = Record<'a>>)> {
    let mut count = 0;
    let mut header_ok = true;
    for r in csv::Records::new(text) {
        let (n, fields) = r.map_err(|(n, why)| Error::new("bad_request", format!("{member}: row {n}: {why}")))?;
        if n == 1 {
            header_ok = fields.iter().map(|f| f.as_ref()).eq(columns.iter().copied());
        } else {
            count += 1;
        }
    }
    if count == 0 && text.is_empty() {
        header_ok = columns.is_empty();
    }
    if !header_ok {
        return refuse(format!("{member}: row 1: the header is not {}", columns.join(",")));
    }
    let rows =
        csv::Records::new(text).skip(1).filter_map(|r| r.ok()).map(|(n, fields)| (n, fields.into_iter().map(csv::unguard_cow).collect()));
    Ok((count, rows))
}

/// What `export_read` reads: the directory, the manifest, `contacts.csv` and `threads.csv`.
pub struct Read {
    /// The answer of `export_read`, JSON text written as each row was checked: the rows are never
    /// held twice, as rows and again as a tree of values.
    pub answer: String,
}

/// Thread ids as they pass, to find the earliest row that repeats one (see `read`).
struct Repeats {
    seen: Vec<([u8; 32], usize)>,
}

impl Repeats {
    fn with_capacity(n: usize) -> Repeats {
        Repeats { seen: Vec::with_capacity(n) }
    }
    fn push(&mut self, id: &str, row: usize) {
        self.seen.push((crate::util::sha256(id.as_bytes()), row));
    }
    /// The refusal of the earliest row whose id an earlier row has, if any row has one.
    fn refuse_first(&mut self) -> Result<()> {
        self.seen.sort_unstable();
        let repeat = self.seen.windows(2).filter(|w| w[0].0 == w[1].0).map(|w| w[1].1).min();
        match repeat {
            Some(n) => refuse(format!("threads.csv: row {n}, column id: appears twice")),
            None => Ok(()),
        }
    }
}

fn json_list_open(out: &mut Vec<u8>, first: &mut bool) {
    if !std::mem::take(first) {
        out.push(b',');
    }
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
pub fn read<'a>(
    directory: &[Entry],
    manifest_text: Option<&str>,
    contacts_csv: Option<&'a str>,
    threads_csv: Option<&'a str>,
    owner: &str,
    now: i64,
) -> Result<Read> {
    // Every name the rules look up in a list the FILE sizes — the directory, the roots, the thread
    // ids, the msg_ids, the media — is looked up in a set, never by a scan: a scan per row made this
    // quadratic in threads.csv's rows (16k threads: 11 s in the Wasm core), and a file within every
    // bound pinned a host for minutes. js/perf.test.mjs and both ports' growth tests hold it.
    let mut seen: HashSet<&str> = HashSet::new();
    for e in directory {
        let label = entry_label(&e.name);
        if !allowed_name(&e.name) {
            return refuse(format!("{label}: not a name an export holds"));
        }
        if !seen.insert(&e.name) {
            return refuse(format!("{label}: appears twice"));
        }
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
    let has = |n: &str| seen.contains(n);
    for required in ["manifest.json", "contacts.csv"] {
        if !has(required) {
            return refuse(format!("{required}: the file lacks it"));
        }
    }
    let Some(manifest_text) = manifest_text else { return refuse("manifest is required") };
    let m = manifest::parse(manifest_text, Some(owner))?;
    for e in directory {
        if e.name == "manifest.json" || e.name == "media/" || is_media(&e.name) {
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
    let (count, rows) = table("contacts.csv", contacts_text, &CONTACT_COLUMNS)?;
    if count > CONTACTS_ROWS_MAX {
        return refuse(format!("contacts.csv: over {CONTACTS_ROWS_MAX} rows"));
    }
    let cells = Cells { owner };
    let mut contacts: Vec<ContactRow<'a>> = Vec::with_capacity(count);
    // The roots, as sha256 digests: 5000 rows at most, and a fixed 32 bytes each whatever a root
    // cell holds; a digest collision cannot pass a duplicate, and 2^-256 cannot fail a distinct one.
    let mut roots: HashSet<[u8; 32]> = HashSet::with_capacity(count);
    for (n, r) in rows {
        if r.len() != CONTACT_COLUMNS.len() {
            return refuse(format!("contacts.csv: row {n}: {} fields, not {}", r.len(), CONTACT_COLUMNS.len()));
        }
        let row = contact_row(r, &cells, Some(now))
            .map_err(|(k, why)| Error::new("bad_request", format!("contacts.csv: row {n}, column {}: {why}", CONTACT_COLUMNS[k])))?;
        if !roots.insert(crate::util::sha256(row.root.as_bytes())) {
            return refuse(format!("contacts.csv: row {n}, column root: appears twice"));
        }
        contacts.push(row);
    }
    if contacts.len() as u64 != m.contacts {
        return refuse(format!("manifest.json: counts: contacts is {}, and contacts.csv holds {}", m.contacts, contacts.len()));
    }

    // The answer, written as each row passes: its size is about the members' text plus the keys, so
    // it is reserved once from their lengths rather than grown by doubling.
    let threads_text = if has("threads.csv") {
        let Some(t) = threads_csv else { return refuse("threads_csv is required: the file has threads.csv") };
        Some(t)
    } else if threads_csv.is_some() {
        return refuse("threads_csv is given, and the file has no threads.csv");
    } else {
        None
    };
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"{\"contacts\":[");
    let mut first = true;
    for c in &contacts {
        json_list_open(&mut out, &mut first);
        c.write_json(&mut out);
    }
    out.extend_from_slice(b"],\"threads\":[");
    let mut threads: u64 = 0;
    if let Some(threads_text) = threads_text {
        if threads_text.len() > THREADS_MAX {
            return refuse(format!("threads.csv: over {THREADS_MAX} bytes"));
        }
        if Some(&sha256_hex(threads_text.as_bytes())) != m.files.get("threads.csv") {
            return refuse("threads.csv: its sha256 is not manifest.json's");
        }
        let roots: HashSet<&str> = contacts.iter().map(|c| c.root.as_ref()).collect();
        let (count, rows) = table("threads.csv", threads_text, &THREAD_COLUMNS)?;
        // A thread's answer is its CSV row and some 57 bytes of keys and quotes.
        out.reserve_exact(threads_text.len() + 64 * count + 96 * media.len() + 16);
        // The thread ids seen, as sha256 digests beside their row numbers: a fixed 40 bytes a row,
        // never a copy of an id of any length, and no hash table's slack. A digest collision cannot pass
        // a duplicate (at 2^-256 it could refuse a distinct pair). A repeat is looked for when a row is
        // refused and when the rows end, and the earliest row that repeats an id is the one named, as
        // it was when each row was looked up as it came.
        let mut ids = Repeats::with_capacity(count);
        let mut first = true;
        for (n, r) in rows {
            let checked = if r.len() != THREAD_COLUMNS.len() {
                Err(format!("threads.csv: row {n}: {} fields, not {}", r.len(), THREAD_COLUMNS.len()))
            } else {
                thread_row(r, &roots).map_err(|(k, why)| format!("threads.csv: row {n}, column {}: {why}", THREAD_COLUMNS[k]))
            };
            let row = match checked {
                Ok(row) => row,
                Err(why) => {
                    ids.refuse_first()?;
                    return refuse(why);
                }
            };
            ids.push(&row.id, n);
            json_list_open(&mut out, &mut first);
            row.write_json(&mut out);
            threads += 1;
        }
        ids.refuse_first()?;
        if threads != m.threads {
            return refuse(format!("manifest.json: counts: threads is {}, and threads.csv holds {threads}", m.threads));
        }
    }
    out.extend_from_slice(b"],\"media\":[");
    let mut first = true;
    for (hash, size) in &media {
        json_list_open(&mut out, &mut first);
        out.extend_from_slice(b"{\"hash\":");
        json_str(&mut out, hash);
        out.extend_from_slice(format!(",\"size\":{size}}}").as_bytes());
    }
    out.extend_from_slice(b"]}");
    // Everything written is JSON text: UTF-8 by construction.
    Ok(Read { answer: String::from_utf8(out).unwrap_or_default() })
}

/// §9.2's cross-batch rules, once the host has streamed `messages.jsonl` through `jsonl::read`: the
/// line count and the member's hash against the manifest, `id` unique in the file, every `reply_to`
/// naming a message in it, and every media file named by one.
/// What the host gathered while it streamed `messages.jsonl`.
pub struct End<'a> {
    /// The lowercase hex sha256 of the member's bytes, when the file has the member.
    pub messages_sha256: Option<&'a str>,
    pub lines: u64,
    pub ids: &'a [&'a str],
    pub msg_ids: &'a [&'a str],
    pub reply_tos: &'a [&'a str],
    pub media_seen: &'a [&'a str],
    /// The file's media members, by hash: export_read's `media`. Each must be named by a message.
    pub media: &'a [&'a str],
}

pub fn read_end(manifest_text: &str, end: &End<'_>) -> Result<()> {
    let End { messages_sha256, lines, ids, msg_ids, reply_tos, media_seen, media } = *end;
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
    // `id` unique in the file, and every reply_to a msg_id in it: the ids sorted in a list of the
    // borrowed strings, 16 bytes each, no copy and no hash table's slack. The least id that repeats
    // is the one named.
    let mut sorted: Vec<&str> = ids.to_vec();
    sorted.sort_unstable();
    if let Some(w) = sorted.windows(2).find(|w| w[0] == w[1]) {
        return refuse(format!("messages.jsonl: id {} appears twice", crate::canonical::string(w[0])));
    }
    drop(sorted);
    let mut msg_ids: Vec<&str> = msg_ids.to_vec();
    msg_ids.sort_unstable();
    let media_seen: HashSet<&str> = media_seen.iter().copied().collect();
    if let Some(r) = reply_tos.iter().find(|r| msg_ids.binary_search(r).is_err()) {
        return refuse(format!("messages.jsonl: reply_to {} names no message in the file", crate::canonical::string(r)));
    }
    for hash in media {
        if !media_seen.contains(hash) {
            return refuse(format!("media/{hash}: nothing names it"));
        }
    }
    Ok(())
}

/// A ContactRow handed to `export_write`, as its cells.
fn contact_cells(v: &Value) -> std::result::Result<Vec<String>, (usize, String)> {
    let Some(o) = v.as_object() else { return Err((0, "a contact row is an object".into())) };
    if let Some(k) = crate::util::stranger(o, &CONTACT_COLUMNS) {
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
                if *col == "their_permissions" {
                    // SPEC §9.2, what a contact controls: the column is the contact's own claim and
                    // informative only, so a name §8 does not have, or one repeated, is dropped rather
                    // than stopping the owner's export.
                    names.retain(|n| is_permission(n));
                    names.sort();
                    names.dedup();
                }
                names.sort();
                names.join(" ")
            }
            ("leaf" | "root_cert", None | Some(Value::Null)) => String::new(),
            // The contact's name for themselves is their own claim: cut to 200 characters, on a
            // character, rather than refused (SPEC §9.2, what a contact controls).
            ("display_name", Some(Value::String(s))) => s.chars().take(NAME_MAX).collect(),
            (_, Some(Value::String(s))) if !matches!(*col, "was_active" | "permissions" | "their_permissions") => s.clone(),
            _ => return Err((k, "missing, or of the wrong type".into())),
        };
        cells.push(cell);
    }
    Ok(cells)
}

fn thread_cells(v: &Value) -> std::result::Result<Vec<String>, (usize, String)> {
    let Some(o) = v.as_object() else { return Err((0, "a thread row is an object".into())) };
    if let Some(k) = crate::util::stranger(o, &THREAD_COLUMNS) {
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
    // SPEC 9.2#28: the owner's and the host's own strings are refused, naming the member —
    // there is nothing of a contact's to leave out.
    for (m, text) in [("owner_name", owner_name), ("tool", tool)] {
        if holds_private_key(text) {
            return refuse(format!("{m} holds a private key"));
        }
    }
    let cells = Cells { owner };
    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    let mut written: HashSet<String> = HashSet::new();
    for (i, c) in contacts.iter().enumerate() {
        let located = |(k, why): (usize, String)| Error::new("bad_request", format!("contacts[{i}], column {}: {why}", CONTACT_COLUMNS[k]));
        let r = contact_cells(c).map_err(located)?;
        let added = contact_row(r.iter().map(|c| Cow::Borrowed(c.as_str())).collect(), &cells, None).map_err(located)?.added;
        let mut r = r;
        r[10] = crate::time::format_rfc3339(added);
        if !written.insert(r[0].clone()) {
            return refuse(format!("contacts[{i}], column root: appears twice"));
        }
        rows.push((r[0].clone(), r));
    }
    if rows.len() > CONTACTS_ROWS_MAX {
        return refuse(format!("contacts: over {CONTACTS_ROWS_MAX} rows"));
    }
    rows.sort();
    let roots: Vec<String> = rows.iter().map(|(r, _)| r.clone()).collect();
    let root_refs: HashSet<&str> = roots.iter().map(String::as_str).collect();
    let mut contacts_csv = String::new();
    csv::write_record(&mut contacts_csv, &CONTACT_COLUMNS.map(String::from));
    for (_, r) in &rows {
        csv::write_record(&mut contacts_csv, &r.iter().map(|c| csv::guard(c)).collect::<Vec<_>>());
    }
    if contacts_csv.len() > CONTACTS_MAX {
        return refuse(format!("contacts: over {CONTACTS_MAX} bytes as contacts.csv"));
    }

    let mut trows: Vec<(String, Vec<String>)> = Vec::new();
    let mut thread_ids: HashSet<String> = HashSet::new();
    for (i, t) in threads.iter().enumerate() {
        let located = |(k, why): (usize, String)| Error::new("bad_request", format!("threads[{i}], column {}: {why}", THREAD_COLUMNS[k]));
        let mut r = thread_cells(t).map_err(located)?;
        let (created, last) = {
            let row = thread_row(r.iter().map(|c| Cow::Borrowed(c.as_str())).collect(), &root_refs).map_err(located)?;
            (row.created_at, row.last_at)
        };
        r[3] = crate::time::format_rfc3339(created);
        r[4] = crate::time::format_rfc3339(last);
        if !thread_ids.insert(r[0].clone()) {
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
    // The media are counted, never listed: `files` holds the text members alone (SPEC 9.2#11).
    let mut hashes: HashSet<&str> = HashSet::with_capacity(media.len());
    for (i, item) in media.iter().enumerate() {
        let hash = item.get("hash").and_then(|h| h.as_str()).unwrap_or("");
        if !is_hash(hash) {
            return refuse(format!("media[{i}]: hash is not a lowercase hex sha256"));
        }
        match item.get("size").and_then(|s| s.as_u64()) {
            Some(s) if s <= MEDIA_MAX as u64 => {}
            _ => return refuse(format!("media[{i}]: size is a number of bytes up to {MEDIA_MAX}")),
        }
        if !hashes.insert(hash) {
            return refuse(format!("media[{i}]: appears twice"));
        }
    }
    let partial = json!({
        "hdtp_export": manifest::VERSION, "owner": owner, "owner_name": owner_name,
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
        if let Some(k) = crate::util::stranger(o, &VAULT_CONTACT) {
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
        // A row carries the root and `added` into export_write and to the host as the contract types
        // them: a root that is no fingerprint, or an `added` that is no instant, came back in a row
        // off the contract (the review of 2026-09-30, found by parity's nested "" cases).
        if !text("root").is_some_and(is_fingerprint) {
            return refuse(format!("contacts[{i}]: root is not a fingerprint"));
        }
        if text("added").is_some_and(|a| crate::time::parse_rfc3339(a).is_err()) {
            return refuse(format!("contacts[{i}]: added is not an RFC 3339 instant"));
        }
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
        // The owner's and the host's own strings are refused, naming the member (SPEC 9.2#28), and a
        // manifest someone else wrote with one is refused on read (9.2#15).
        let own = |owner_name: &str, tool: &str| super::write(&owner, owner_name, 0, tool, &[], &[], &[]).map(|_| ()).map_err(|e| e.why);
        assert_eq!(own(&pkcs8, "t"), Err("owner_name holds a private key".to_string()));
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", base64_std(&key.to_pkcs8()));
        assert_eq!(own("Alina", &pem), Err("tool holds a private key".to_string()));
        let partial = super::write(&owner, "Alina", 0, "t", &[], &[], &[]).unwrap().partial;
        let finished = manifest::finish(&partial, None, 0).unwrap();
        assert!(manifest::parse(&finished, Some(&owner)).is_ok(), "the control reads");
        let with_key = finished.replace("\"owner_name\":\"Alina\"", &format!("\"owner_name\":\"{pkcs8}\""));
        assert_eq!(
            manifest::parse(&with_key, Some(&owner)).map(|_| ()).map_err(|e| e.why),
            Err("manifest.json: owner_name holds a private key".to_string())
        );
        let mut sec1 = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        sec1.extend_from_slice(&seed("export/sec1"));
        use base64::Engine;
        let body = format!("keep this: {}", base64::engine::general_purpose::STANDARD.encode(&sec1));
        let message = json!({ "id": "1", "thread": "t", "contact": "c", "msg_id": "m", "direction": "in", "sender": "human",
            "time": "2026-09-27T10:00:00Z", "body": body, "reply_to": null, "status": "read", "attachments": [] });
        // A message's body is the contact's: one holding a key is left out and listed, never refused
        // (SPEC §9.2, what a contact controls); the same key in a member the host writes is refused.
        let (lines, left_out) = jsonl::write(std::slice::from_ref(&message), None).unwrap();
        assert!(lines.is_empty());
        assert_eq!(left_out.iter().map(|l| (l.id.as_str(), l.reason)).collect::<Vec<_>>(), [("1", jsonl::BODY_HOLDS_A_KEY)]);
        let mut in_a_thread = message;
        in_a_thread["body"] = json!("hi");
        in_a_thread["thread"] = json!(body);
        assert_eq!(
            jsonl::write(&[in_a_thread], None).map(|_| ()).map_err(|e| e.why),
            Err("messages[0], member thread: holds a private key".to_string())
        );
    }

    /// SPEC §9.2, what a contact controls: none of it stops the owner's export, and what is written
    /// reads back whole. A reply to a message the file does not carry is written null; a permission
    /// the contact claims and §8 does not have, or one repeated, is dropped; a name the contact gives
    /// themselves over 200 characters is cut to 200, on a character; a message whose body holds what
    /// reads as a key is left out and listed, and the rest of the file writes.
    #[test]
    fn what_a_contact_controls_never_stops_an_export_and_it_reads_back() {
        let owner = format!("sha256:{}", "O".repeat(43));
        let peer = format!("sha256:{}", "B".repeat(43));
        let long: String = "é".repeat(150) + &"x".repeat(150);
        let row = json!({ "root": peer, "endpoint": "https://b.example/mcp", "name": "", "display_name": long, "status": "active",
            "was_active": true, "permissions": ["message.text"], "their_permissions": ["message.media", "root.everything", "message.media", "integration.cal"],
            "leaf": null, "root_cert": null, "added": "2026-09-27T10:00:00Z" });
        let thread =
            json!({ "id": "t1", "contact": peer, "topic": "", "created_at": "2026-09-27T10:00:00Z", "last_at": "2026-09-27T10:00:00Z" });
        let w = write(&owner, "", 0, "t", &[row], &[thread], &[]).unwrap();
        let cells = &csv::read(&w.contacts_csv).unwrap()[1];
        assert_eq!(cells[3].chars().count(), NAME_MAX, "the name is cut to 200 characters");
        assert!(long.starts_with(cells[3].as_str()), "on a character, keeping its start");
        assert_eq!(cells[7], "integration.cal message.media", "unknown and repeated names are dropped");
        let key = PrivateKey::from_seed(Alg::Ed25519, &seed("export/contact-key")).unwrap();
        let message = |id: &str, msg_id: &str, body: &str, reply_to: Value| {
            json!({ "id": id, "thread": "t1", "contact": peer, "msg_id": msg_id, "direction": "in", "sender": "human",
                "time": "2026-09-27T10:00:00Z", "body": body, "reply_to": reply_to, "status": "read", "attachments": [] })
        };
        let messages = [
            message("m1", "x1", "hello", json!("x-elsewhere")),
            message("m2", "x2", &b64u(&key.to_pkcs8()), Value::Null),
            message("m3", "x3", "about that", json!("x2")),
            message("m4", "x4", "and this", json!("x1")),
        ];
        let (lines, left_out) = jsonl::write(&messages, None).unwrap();
        assert_eq!(left_out.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(), ["m2"], "the message holding a key is left out and listed");
        let replies: Vec<Value> = lines.iter().map(|l| serde_json::from_str::<Value>(l).unwrap()["reply_to"].clone()).collect();
        assert_eq!(
            replies,
            [Value::Null, Value::Null, json!("x1")],
            "a reply to a message not carried, the left-out one included, is null"
        );
        // Batches: the file's msg_ids named by the host decide what is carried.
        let (lines, _) = jsonl::write(&messages[..1], Some(&["x1", "x-elsewhere"])).unwrap();
        assert!(lines[0].contains("\"reply_to\":\"x-elsewhere\""));
        // And it all reads back.
        let text = lines_to_file(&jsonl::write(&messages, None).unwrap().0);
        let m = manifest::finish(&w.partial, Some(&sha256_hex(text.as_bytes())), 3).unwrap();
        let entry = |name: &str| Entry { name: name.into(), size: 1, encrypted: false, mode: 0 };
        let directory = [entry("manifest.json"), entry("contacts.csv"), entry("threads.csv"), entry("messages.jsonl")];
        let r = read(&directory, Some(&m), Some(&w.contacts_csv), w.threads_csv.as_deref(), &owner, 0).unwrap();
        assert!(r.answer.contains("\"their_permissions\":[\"integration.cal\",\"message.media\"]"));
        let file_lines: Vec<&str> = text.lines().collect();
        let (threads, contacts) = (["t1"], [peer.as_str()]);
        let (read_back, _) = jsonl::read(&file_lines, 1, &jsonl::Names { threads: &threads, contacts: &contacts, media: &[] }).unwrap();
        let ids: Vec<&str> = read_back.iter().filter_map(|m| m["id"].as_str()).collect();
        assert_eq!(ids, ["m1", "m3", "m4"]);
        let msg_ids: Vec<&str> = read_back.iter().filter_map(|m| m["msg_id"].as_str()).collect();
        let reply_tos: Vec<&str> = read_back.iter().filter_map(|m| m["reply_to"].as_str()).collect();
        read_end(
            &m,
            &End {
                messages_sha256: Some(&sha256_hex(text.as_bytes())),
                lines: 3,
                ids: &ids,
                msg_ids: &msg_ids,
                reply_tos: &reply_tos,
                media_seen: &[],
                media: &[],
            },
        )
        .unwrap();
    }

    /// `files` lists the text members only: an export of 5000 media files has a
    /// manifest well under 64 KiB, and the reader takes it, counting every file.
    #[test]
    fn an_export_of_5000_media_files_has_a_small_manifest_and_reads_back() {
        let owner = format!("sha256:{}", "O".repeat(43));
        let hashes: Vec<String> = (0..5000).map(|i| sha256_hex(format!("media {i}").as_bytes())).collect();
        let media: Vec<Value> = hashes.iter().map(|h| json!({ "hash": h, "size": 1 })).collect();
        let w = write(&owner, "", 0, "t", &[], &[], &media).unwrap();
        let m = manifest::finish(&w.partial, None, 0).unwrap();
        assert!(m.len() < MANIFEST_MAX / 8, "a manifest of {} bytes for 5000 media files", m.len());
        let entry = |name: String, mode: u32| Entry { name, size: 1, encrypted: false, mode };
        let mut directory = vec![entry("manifest.json".into(), 0), entry("contacts.csv".into(), 0), entry("media/".into(), 0o040755)];
        directory.extend(hashes.iter().map(|h| entry(format!("media/{h}"), 0)));
        let r = read(&directory, Some(&m), Some(&w.contacts_csv), None, &owner, 0).unwrap();
        let answer: Value = serde_json::from_str(&r.answer).unwrap();
        assert_eq!(answer["media"].as_array().unwrap().len(), 5000);
    }

    /// A media file is key material when its bytes are a PKCS #8 or SEC1 key in DER, or text holding
    /// one in PEM or base64 (SPEC 9.2#15), read leniently: js/key-material.json, the one list of
    /// cases, which the Go port's test and the parity cases read too.
    #[test]
    fn a_media_file_is_key_material_in_der_or_pem() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../js/key-material.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        assert!(cases.len() >= 20, "js/key-material.json holds {} cases", cases.len());
        for c in cases {
            let bytes = match (c["hex"].as_str(), c["text"].as_str()) {
                (Some(h), None) => crate::util::from_hex(h).unwrap(),
                (None, Some(t)) => t.as_bytes().to_vec(),
                _ => panic!("a case is hex or text: {c}"),
            };
            assert_eq!(media_holds_private_key(&bytes), c["holds"].as_bool().unwrap(), "{}", c["what"]);
        }
    }

    fn base64_std(b: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn lines_to_file(lines: &[String]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    /// The export's functions grow linearly in the rows a file holds. Each is timed at N and 4N rows
    /// (threads, messages, and held and imported contacts), the two sizes interleaved over five
    /// rounds so a busy machine slows both alike, the best round of each kept; 4N may take at most 8×
    /// N. Why 8: linear work is 4×, n·log n about 4.6×, and a scan per row 16× — the defect of 0.3.0,
    /// where export_read took 0.2 s at 2k threads and 11 s at 16k. 8 is halfway (in log terms)
    /// between linear and quadratic, a 2× margin for noise that no quadratic fits in. A function under
    /// 20 ms at 4N is too fast to judge and passes: a scan per row at 4N rows is far above that. The
    /// bound is on rows and a ratio, never on seconds, so it cannot go stale with the machine.
    #[test]
    fn export_functions_grow_linearly_in_the_rows_of_a_file() {
        let n = 5_000;
        let owner = format!("sha256:{}", "O".repeat(43));
        let fp = |i: usize| format!("sha256:{}", b64u(&crate::util::sha256(format!("c{i}").as_bytes())));
        let contacts: Vec<Value> = (0..200)
            .map(|i| {
                json!({ "root": fp(i), "endpoint": format!("https://c{i}.example/mcp"), "name": "", "display_name": "", "status": "active",
                    "was_active": true, "permissions": [], "their_permissions": [], "added": "2026-09-01T00:00:00Z" })
            })
            .collect();
        let roots: Vec<String> = (0..200).map(fp).collect();
        struct Data {
            rows: usize,
            threads: Vec<Value>,
            messages: Vec<Value>,
            many: Vec<Value>,
            thread_ids: Vec<String>,
            ids: Vec<String>,
            msg_ids: Vec<String>,
            reply_tos: Vec<String>,
        }
        let data = |rows: usize| {
            Data {
            rows,
            threads: (0..rows)
                .map(|i| json!({ "id": format!("t{i}"), "contact": fp(i % 200), "topic": "x", "created_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z" }))
                .collect(),
            messages: (0..rows)
                .map(|i| {
                    json!({ "id": format!("m{i}"), "thread": format!("t{i}"), "contact": fp(i % 200), "msg_id": format!("x{i}"), "direction": "in",
                        "sender": "human", "time": "2026-09-01T00:00:00Z", "body": "hi", "reply_to": if i > 0 { json!(format!("x{}", i - 1)) } else { Value::Null },
                        "status": "read", "attachments": [] })
                })
                .collect(),
            many: (0..rows).map(|i| json!({ "root": fp(1000 + i), "leaf": null })).collect(),
            thread_ids: (0..rows).map(|i| format!("t{i}")).collect(),
            ids: (0..rows).map(|i| format!("m{i}")).collect(),
            msg_ids: (0..rows).map(|i| format!("x{i}")).collect(),
            reply_tos: (0..rows - 1).map(|i| format!("x{i}")).collect(),
        }
        };
        let entry = |name: &str| Entry { name: name.into(), size: 1, encrypted: false, mode: 0 };
        let directory = [entry("manifest.json"), entry("contacts.csv"), entry("threads.csv")];
        let hash = "a".repeat(64);
        // One pass over every function at one size: the seconds each took.
        let pass = |d: &Data| -> [f64; 6] {
            let clock = std::time::Instant::now;
            let t = clock();
            let w = write(&owner, "", 0, "t", &contacts, &d.threads, &[]).unwrap();
            let t_write = t.elapsed().as_secs_f64();
            let manifest_text = manifest::finish(&w.partial, None, 0).unwrap();
            let t = clock();
            read(&directory, Some(&manifest_text), Some(&w.contacts_csv), w.threads_csv.as_deref(), &owner, 0).unwrap();
            let t_read = t.elapsed().as_secs_f64();
            let t = clock();
            let lines = jsonl::write(&d.messages, None).unwrap().0;
            let t_write_messages = t.elapsed().as_secs_f64();
            let (thread_ids, roots, lines) = (refs(&d.thread_ids), refs(&roots), refs(&lines));
            let names = jsonl::Names { threads: &thread_ids, contacts: &roots, media: &[] };
            let t = clock();
            jsonl::read(&lines, 1, &names).unwrap();
            let t_read_messages = t.elapsed().as_secs_f64();
            let with_messages = manifest::finish(&w.partial, Some(&hash), d.rows as u64).unwrap();
            fn refs(l: &[String]) -> Vec<&str> {
                l.iter().map(String::as_str).collect()
            }
            let (ids, msg_ids, reply_tos) = (refs(&d.ids), refs(&d.msg_ids), refs(&d.reply_tos));
            let end = End {
                messages_sha256: Some(&hash),
                lines: d.rows as u64,
                ids: &ids,
                msg_ids: &msg_ids,
                reply_tos: &reply_tos,
                media_seen: &[],
                media: &[],
            };
            let t = clock();
            read_end(&with_messages, &end).unwrap();
            let t_read_end = t.elapsed().as_secs_f64();
            let t = clock();
            merge::merge(&d.many, &d.many).unwrap();
            [t_write, t_read, t_write_messages, t_read_messages, t_read_end, t.elapsed().as_secs_f64()]
        };
        let names = ["export_write", "export_read", "export_write_messages", "export_read_messages", "export_read_end", "export_merge"];
        let (small, large) = (data(n), data(4 * n));
        let (mut a, mut b) = ([f64::MAX; 6], [f64::MAX; 6]);
        for _ in 0..5 {
            for (best, d) in [(&mut a, &small), (&mut b, &large)] {
                for (k, t) in pass(d).into_iter().enumerate() {
                    best[k] = best[k].min(t);
                }
            }
        }
        let mut slow = Vec::new();
        for k in 0..6 {
            let line = format!("{}: {:.1} ms at {n} rows, {:.1} ms at {} ({:.1}×)", names[k], a[k] * 1e3, b[k] * 1e3, 4 * n, b[k] / a[k]);
            eprintln!("{line}");
            if b[k] >= 0.020 && b[k] / a[k] > 8.0 {
                slow.push(line);
            }
        }
        assert!(slow.is_empty(), "superlinear in the rows of a file:\n  {}", slow.join("\n  "));
    }
}
