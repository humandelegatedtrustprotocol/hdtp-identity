//! The export section of contract/contract.json (§6.2 the export): a body for each function it
//! declares, which `api.rs`'s `dispatch` names.
use super::*;
use crate::export::{self, jsonl, manifest, merge, Entry};

fn list<'a>(a: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    a.get(k).and_then(|v| v.as_array()).ok_or_else(|| Error::new("bad_request", format!("{k} is required")))
}

fn opt_list(a: &Value, k: &str) -> Result<Vec<Value>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(v)) => Ok(v.clone()),
        Some(_) => err("bad_request", format!("{k} is required")),
    }
}

fn strings(a: &Value, k: &str) -> Result<Vec<String>> {
    list(a, k)?
        .iter()
        .map(|v| v.as_str().map(String::from).ok_or_else(|| Error::new("bad_request", format!("{k} is a list of strings"))))
        .collect()
}

fn count(a: &Value, k: &str) -> Result<u64> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v.as_u64().ok_or_else(|| Error::new("bad_request", format!("{k} is a whole number"))),
    }
}

pub(super) fn export_read(a: &Value) -> Result<Value> {
    let mut directory = Vec::new();
    for (i, e) in list(a, "directory")?.iter().enumerate() {
        let unread = || Error::new("bad_request", format!("directory[{i}] does not read"));
        directory.push(Entry {
            name: e.get("name").and_then(|v| v.as_str()).ok_or_else(unread)?.to_string(),
            size: e.get("size").and_then(|v| v.as_u64()).ok_or_else(unread)?,
            encrypted: e.get("encrypted").and_then(|v| v.as_bool()).ok_or_else(unread)?,
            mode: e.get("mode").and_then(|v| v.as_u64()).and_then(|m| u32::try_from(m).ok()).ok_or_else(unread)?,
        });
    }
    let owner = s(a, "owner")?;
    let now = instant(a, "now")?;
    let r = export::read(&directory, opt_s(a, "manifest"), opt_s(a, "contacts_csv"), opt_s(a, "threads_csv"), owner, now)?;
    Ok(json!({
        "contacts": r.contacts, "threads": r.threads,
        "media": r.media.iter().map(|(h, size)| json!({ "hash": h, "size": size })).collect::<Vec<_>>(),
    }))
}

pub(super) fn export_read_messages(a: &Value) -> Result<Value> {
    let lines = strings(a, "lines")?;
    let names = jsonl::Names { threads: &strings(a, "threads")?, contacts: &strings(a, "contacts")?, media: &strings(a, "media")? };
    let first = match a.get("first_line") {
        None | Some(Value::Null) => 1,
        Some(v) => v.as_u64().filter(|n| *n >= 1).ok_or_else(|| Error::new("bad_request", "first_line is a line number from 1"))?,
    };
    let (messages, media_seen) = jsonl::read(&lines, first, &names)?;
    Ok(json!({ "messages": messages, "media_seen": media_seen }))
}

pub(super) fn export_read_end(a: &Value) -> Result<Value> {
    let text = s(a, "manifest")?;
    let sha = match a.get("messages_sha256") {
        None | Some(Value::Null) => None,
        Some(Value::String(h)) => Some(h.as_str()),
        Some(_) => return err("bad_request", "messages_sha256 is a lowercase hex sha256 or null"),
    };
    let lines = count(a, "lines")?;
    let (ids, msg_ids, reply_tos, media_seen) =
        (strings(a, "ids")?, strings(a, "msg_ids")?, strings(a, "reply_tos")?, strings(a, "media_seen")?);
    export::read_end(
        text,
        &export::End { messages_sha256: sha, lines, ids: &ids, msg_ids: &msg_ids, reply_tos: &reply_tos, media_seen: &media_seen },
    )?;
    Ok(json!({ "ok": true }))
}

pub(super) fn export_write(a: &Value) -> Result<Value> {
    let owner = s(a, "owner")?;
    let owner_name = s(a, "owner_name")?;
    let exported_at = instant(a, "exported_at")?;
    let tool = s(a, "tool")?;
    let contacts = list(a, "contacts")?;
    let w = export::write(owner, owner_name, exported_at, tool, contacts, &opt_list(a, "threads")?, &opt_list(a, "media")?)?;
    Ok(json!({ "partial": w.partial, "contacts_csv": w.contacts_csv, "threads_csv": w.threads_csv }))
}

pub(super) fn export_write_messages(a: &Value) -> Result<Value> {
    Ok(json!({ "lines": jsonl::write(list(a, "messages")?)? }))
}

pub(super) fn export_manifest(a: &Value) -> Result<Value> {
    let Some(partial) = a.get("partial").filter(|p| p.is_object()) else { return err("bad_request", "partial is required") };
    let sha = match a.get("hashes") {
        None | Some(Value::Null) => None,
        Some(Value::Object(h)) => {
            if let Some(k) = crate::ledger::stranger(h, &["messages.jsonl"]) {
                return err(
                    "bad_request",
                    format!("hashes: {} is not hashed by the host: only messages.jsonl is", crate::canonical::string(&k)),
                );
            }
            match h.get("messages.jsonl") {
                None => None,
                Some(Value::String(v)) => Some(v.as_str()),
                Some(_) => return err("bad_request", "hashes: messages.jsonl: not a lowercase hex sha256"),
            }
        }
        Some(_) => return err("bad_request", "hashes is an object"),
    };
    Ok(json!({ "manifest": manifest::finish(partial, sha, count(a, "messages")?)? }))
}

pub(super) fn export_merge(a: &Value) -> Result<Value> {
    let m = merge::merge(list(a, "held")?, list(a, "rows")?)?;
    Ok(json!({ "write": m.write, "keep": m.keep, "conflicts": m.conflicts }))
}
