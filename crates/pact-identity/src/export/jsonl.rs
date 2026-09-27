//! `messages.jsonl` (SPEC §9.2): one message per line, read strictly batch by batch as the host
//! streams it, and written as RFC 8785 JSON so both ports write the same bytes.
use super::{holds_private_key, is_hash, refuse, BODY_MAX, LINE_MAX, MEDIA_MAX};
use crate::util::Result;
use serde_json::{json, Map, Value};

pub const MEMBERS: [&str; 11] =
    ["id", "thread", "contact", "msg_id", "direction", "sender", "time", "body", "reply_to", "status", "attachments"];
pub const ATTACHMENT: [&str; 4] = ["file", "filename", "mime", "size"];
const DIRECTIONS: [&str; 2] = ["in", "out"];
const SENDERS: [&str; 2] = ["agent", "human"];
const STATUSES: [&str; 4] = ["delivered", "queued", "failed", "read"];

/// What a message may name: the file's threads, contacts and media.
pub struct Names<'a> {
    pub threads: &'a [String],
    pub contacts: &'a [String],
    pub media: &'a [String],
}

fn key_material(v: &Value) -> bool {
    match v {
        Value::String(s) => holds_private_key(s),
        Value::Array(items) => items.iter().any(key_material),
        Value::Object(o) => o.values().any(key_material),
        _ => false,
    }
}

/// One message, its members held to §9.2; `names` absent skips the references (a writer's check).
/// The refusal is the member and why.
pub fn message(doc: &Map<String, Value>, names: Option<&Names<'_>>) -> std::result::Result<Value, (Option<&'static str>, String)> {
    if let Some(k) = crate::ledger::stranger(doc, &MEMBERS) {
        return Err((None, format!("{} is not a member of a message", crate::canonical::string(&k))));
    }
    if let Some(k) = MEMBERS.iter().find(|m| !doc.contains_key(**m)) {
        return Err((None, format!("{k} is missing")));
    }
    for m in MEMBERS {
        if key_material(&doc[m]) {
            return Err((Some(m), "holds a private key".into()));
        }
    }
    let text = |m: &'static str| doc[m].as_str().ok_or((Some(m), "not a string".to_string()));
    let one_of = |m: &'static str, allowed: &[&str]| -> std::result::Result<(), (Option<&'static str>, String)> {
        if allowed.contains(&text(m)?) {
            Ok(())
        } else {
            Err((Some(m), format!("not {}", allowed.join(" or "))))
        }
    };
    for m in ["id", "msg_id"] {
        if text(m)?.is_empty() {
            return Err((Some(m), "empty".into()));
        }
    }
    let thread = text("thread")?;
    let contact = text("contact")?;
    if let Some(n) = names {
        if !n.threads.iter().any(|t| t == thread) {
            return Err((Some("thread"), "names no thread in threads.csv".into()));
        }
        if !n.contacts.iter().any(|c| c == contact) {
            return Err((Some("contact"), "names no contact in contacts.csv".into()));
        }
    }
    one_of("direction", &DIRECTIONS)?;
    one_of("sender", &SENDERS)?;
    let Ok(time) = crate::time::parse_rfc3339(text("time")?) else { return Err((Some("time"), "not an RFC 3339 instant".into())) };
    if text("body")?.len() > BODY_MAX {
        return Err((Some("body"), format!("over {BODY_MAX} bytes")));
    }
    match &doc["reply_to"] {
        Value::Null => {}
        Value::String(s) if !s.is_empty() => {}
        _ => return Err((Some("reply_to"), "not a msg_id or null".into())),
    }
    one_of("status", &STATUSES)?;
    let Some(attachments) = doc["attachments"].as_array() else { return Err((Some("attachments"), "not a list".into())) };
    if attachments.len() > 1 {
        return Err((Some("attachments"), "more than one attachment: a message carries at most one file".into()));
    }
    let mut kept = Vec::new();
    for a in attachments {
        let at = |why: String| Err((Some("attachments"), why));
        let Some(o) = a.as_object() else { return at("an attachment is an object".into()) };
        if let Some(k) = crate::ledger::stranger(o, &ATTACHMENT) {
            return at(format!("{} is not a member of an attachment", crate::canonical::string(&k)));
        }
        if let Some(k) = ATTACHMENT.iter().find(|m| !o.contains_key(**m)) {
            return at(format!("{k} is missing"));
        }
        let Some(file) = o["file"].as_str().filter(|f| is_hash(f)) else { return at("file is not a lowercase hex sha256".into()) };
        if names.is_some_and(|n| !n.media.iter().any(|m| m == file)) {
            return at("file names no media member".into());
        }
        if !o["filename"].is_string() || !o["mime"].is_string() {
            return at("filename and mime are strings".into());
        }
        let Some(size) = o["size"].as_u64().filter(|s| *s <= MEDIA_MAX as u64) else {
            return at(format!("size is a number of bytes up to {MEDIA_MAX}"));
        };
        kept.push(json!({ "file": file, "filename": o["filename"], "mime": o["mime"], "size": size }));
    }
    // A message carries a file or text, never both: neither host's send_media carries a caption.
    if !kept.is_empty() && !text("body")?.is_empty() {
        return Err((Some("body"), "not empty, and the message carries a file: a message with an attachment has no text".into()));
    }
    Ok(json!({
        "id": doc["id"], "thread": thread, "contact": contact, "msg_id": doc["msg_id"], "direction": doc["direction"],
        "sender": doc["sender"], "time": crate::time::format_rfc3339(time), "body": doc["body"], "reply_to": doc["reply_to"],
        "status": doc["status"], "attachments": kept,
    }))
}

/// One batch of lines; `first_line` is the number of the first in the whole file. Answers the
/// messages and the media they name.
pub fn read(lines: &[String], first_line: u64, names: &Names<'_>) -> Result<(Vec<Value>, Vec<String>)> {
    let mut messages = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let n = first_line + i as u64;
        if line.len() > LINE_MAX {
            return refuse(format!("messages.jsonl: line {n}: over {LINE_MAX} bytes"));
        }
        let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(line) else {
            return refuse(format!("messages.jsonl: line {n}: not a JSON object"));
        };
        let m = message(&doc, Some(names)).map_err(|(member, why)| {
            crate::util::Error::new(
                "bad_request",
                match member {
                    Some(k) => format!("messages.jsonl: line {n}, member {k}: {why}"),
                    None => format!("messages.jsonl: line {n}: {why}"),
                },
            )
        })?;
        for a in m["attachments"].as_array().into_iter().flatten() {
            if let Some(f) = a["file"].as_str() {
                seen.push(f.to_string());
            }
        }
        messages.push(m);
    }
    seen.sort();
    seen.dedup();
    Ok((messages, seen))
}

/// The lines of `messages.jsonl` for these messages, in the order given, each checked by the
/// reader's rules but the references (the host holds those) and written as RFC 8785 JSON.
pub fn write(messages: &[Value]) -> Result<Vec<String>> {
    messages
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let Some(doc) = v.as_object() else { return refuse(format!("messages[{i}]: a message is an object")) };
            let m = message(doc, None).map_err(|(member, why)| {
                crate::util::Error::new(
                    "bad_request",
                    match member {
                        Some(k) => format!("messages[{i}], member {k}: {why}"),
                        None => format!("messages[{i}]: {why}"),
                    },
                )
            })?;
            let line = crate::canonical::canonical(&m);
            if line.len() > LINE_MAX {
                return refuse(format!("messages[{i}]: over {LINE_MAX} bytes as a line"));
            }
            Ok(line)
        })
        .collect()
}
