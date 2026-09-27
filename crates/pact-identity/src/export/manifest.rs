//! `manifest.json` (SPEC §9.2): read strictly, and written as RFC 8785 JSON so both ports write the
//! same bytes.
use super::{holds_private_key, is_fingerprint, is_hash, refuse, MANIFEST_MAX};
use crate::util::Result;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const VERSION: u64 = 2;
const MEMBERS: [&str; 7] = ["pact_export", "owner", "owner_name", "exported_at", "tool", "counts", "files"];
const COUNTS: [&str; 4] = ["contacts", "threads", "messages", "media"];
const LISTED: [&str; 3] = ["contacts.csv", "threads.csv", "messages.jsonl"];

pub struct Manifest {
    pub contacts: u64,
    pub threads: u64,
    pub messages: u64,
    pub media: u64,
    pub files: BTreeMap<String, String>,
}

fn at<T>(why: impl AsRef<str>) -> Result<T> {
    refuse(format!("manifest.json: {}", why.as_ref()))
}

/// The manifest's members held to §9.2, and its owner to the importing identity's when `owner` is
/// given.
pub fn check(doc: &Map<String, Value>, owner: Option<&str>) -> Result<Manifest> {
    if let Some(k) = crate::ledger::stranger(doc, &MEMBERS) {
        return at(format!("{} is not a member of a manifest", crate::canonical::string(&k)));
    }
    if let Some(k) = MEMBERS.iter().find(|m| !doc.contains_key(**m)) {
        return at(format!("{k} is missing"));
    }
    if doc["pact_export"].as_u64() != Some(VERSION) {
        return at("pact_export is 2");
    }
    let Some(file_owner) = doc["owner"].as_str().filter(|o| is_fingerprint(o)) else { return at("owner is not a fingerprint") };
    if let Some(owner) = owner.filter(|o| *o != file_owner) {
        return at(format!("owner: the file is {file_owner}'s, not this identity's ({owner})"));
    }
    for m in ["owner_name", "tool"] {
        let Some(text) = doc[m].as_str() else { return at(format!("{m} is a string")) };
        // SPEC §9.2, key material: every string member of the manifest, as every cell.
        if holds_private_key(text) {
            return at(format!("{m} holds a private key"));
        }
    }
    if doc["exported_at"].as_str().is_none_or(|t| crate::time::parse_rfc3339(t).is_err()) {
        return at("exported_at is not an RFC 3339 instant");
    }
    let Some(counts) = doc["counts"].as_object() else { return at("counts is an object") };
    if let Some(k) = crate::ledger::stranger(counts, &COUNTS) {
        return at(format!("counts: {} is not a count of a manifest", crate::canonical::string(&k)));
    }
    let mut n = [0u64; 4];
    for (i, k) in COUNTS.iter().enumerate() {
        n[i] = match counts.get(*k).and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return at(format!("counts: {k} is not a whole number")),
        };
    }
    let Some(listed) = doc["files"].as_object() else { return at("files is an object") };
    let mut files = BTreeMap::new();
    // SPEC 2.2.2, 9.2#11: `files` lists the text members only. A media member is bound by its name,
    // which is the sha256 of its bytes, and counted by `counts.media`; listing each one made a
    // manifest's 64 KiB hold at most some 460 of them.
    for (name, hash) in listed {
        if !LISTED.contains(&name.as_str()) {
            return at(format!("files: {} is not a member an export lists", crate::canonical::string(name)));
        }
        let Some(hash) = hash.as_str().filter(|h| is_hash(h)) else { return at(format!("files: {name}: not a lowercase hex sha256")) };
        files.insert(name.clone(), hash.to_string());
    }
    Ok(Manifest { contacts: n[0], threads: n[1], messages: n[2], media: n[3], files })
}

/// The manifest's text parsed and checked.
pub fn parse(text: &str, owner: Option<&str>) -> Result<Manifest> {
    if text.len() > MANIFEST_MAX {
        return at(format!("over {MANIFEST_MAX} bytes"));
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(doc)) => check(&doc, owner),
        _ => at("not a JSON object"),
    }
}

/// The finished manifest, from `export_write`'s partial one and what the host counted and hashed
/// while it streamed `messages.jsonl`.
pub fn finish(partial: &Value, messages_sha256: Option<&str>, messages: u64) -> Result<String> {
    let Some(doc) = partial.as_object() else { return refuse("partial is required") };
    let mut doc = doc.clone();
    // The partial is held to the manifest's rules first: a host may not add to it what it did not
    // write through export_write.
    let before = check(&doc, None)?;
    if before.messages != 0 || before.files.contains_key("messages.jsonl") {
        return refuse("partial: the messages are counted and hashed here, not before");
    }
    match messages_sha256 {
        Some(h) if is_hash(h) => {
            if let Some(files) = doc.get_mut("files").and_then(|f| f.as_object_mut()) {
                files.insert("messages.jsonl".into(), Value::String(h.to_string()));
            }
        }
        Some(_) => return refuse("hashes: messages.jsonl: not a lowercase hex sha256"),
        None if messages > 0 => return refuse("hashes: messages.jsonl is required when there are messages"),
        None => {}
    }
    if let Some(counts) = doc.get_mut("counts").and_then(|c| c.as_object_mut()) {
        counts.insert("messages".into(), Value::from(messages));
    }
    let text = crate::canonical::canonical(&Value::Object(doc));
    parse(&text, None)?;
    Ok(text)
}
