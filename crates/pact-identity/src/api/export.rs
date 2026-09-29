//! The export section of contract/contract.json (§6.2 the export): a body for each function it
//! declares, which `api.rs`'s `dispatch` names.
use super::*;
use crate::export::{self, jsonl, manifest, merge, Entry};
use std::borrow::Cow;

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

/// A list of strings, borrowed from the arguments: a copy of every id would double what the call holds.
fn strs<'a>(a: &'a Value, k: &str) -> Result<Vec<&'a str>> {
    list(a, k)?.iter().map(|v| v.as_str().ok_or_else(|| Error::new("bad_request", format!("{k} is a list of strings")))).collect()
}

fn count(a: &Value, k: &str) -> Result<u64> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v.as_u64().ok_or_else(|| Error::new("bad_request", format!("{k} is a whole number"))),
    }
}

pub(super) fn export_read(a: &Value) -> Result<Answer> {
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
    // Written straight from the rows, which borrow the members' text: no tree of values beside them.
    Ok(Answer::Text(r.answer))
}

pub(super) fn export_read_messages(a: &Value) -> Result<Value> {
    let lines = strs(a, "lines")?;
    let names = jsonl::Names { threads: &strs(a, "threads")?, contacts: &strs(a, "contacts")?, media: &strs(a, "media")? };
    let first = match a.get("first_line") {
        None | Some(Value::Null) => 1,
        Some(v) => v.as_u64().filter(|n| *n >= 1).ok_or_else(|| Error::new("bad_request", "first_line is a line number from 1"))?,
    };
    let (messages, media_seen) = jsonl::read(&lines, first, &names)?;
    Ok(json!({ "messages": messages, "media_seen": media_seen }))
}

/// A list-of-strings argument as it arrived: absent (or null), not a list, a list holding something
/// that is not a string, or the strings — borrowed from the argument text wherever JSON did not
/// escape them.
enum StrList<'a> {
    Absent,
    NotList,
    NotStrings,
    Strs(Vec<Cow<'a, str>>),
}

impl<'a> StrList<'a> {
    fn of_value(v: Option<&'a Value>) -> StrList<'a> {
        match v {
            None | Some(Value::Null) => StrList::Absent,
            Some(Value::Array(items)) => match items.iter().map(|i| i.as_str().map(Cow::Borrowed)).collect::<Option<Vec<_>>>() {
                Some(v) => StrList::Strs(v),
                None => StrList::NotStrings,
            },
            Some(_) => StrList::NotList,
        }
    }
    fn get(&self, k: &str) -> Result<Vec<&str>> {
        match self {
            StrList::Strs(v) => Ok(v.iter().map(|s| s.as_ref()).collect()),
            StrList::NotStrings => err("bad_request", format!("{k} is a list of strings")),
            StrList::Absent | StrList::NotList => err("bad_request", format!("{k} is required")),
        }
    }
}

impl<'de: 'a, 'a> serde::Deserialize<'de> for StrList<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
        /// One element: a string, borrowed where it can be, or anything else, consumed.
        enum Elem<'a> {
            Str(Cow<'a, str>),
            Other,
        }
        impl<'de> serde::Deserialize<'de> for Elem<'de> {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                d.deserialize_any(Any(true)).map(|a| match a {
                    Seen::Str(s) => Elem::Str(s),
                    _ => Elem::Other,
                })
            }
        }
        enum Seen<'a> {
            Str(Cow<'a, str>),
            Null,
            List(StrList<'a>),
            Other,
        }
        /// A visitor that accepts any JSON value; `elem` says whether it is reading a list's element
        /// (whose own lists are only consumed) or the argument itself.
        struct Any(bool);
        impl<'de> Visitor<'de> for Any {
            type Value = Seen<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Str(Cow::Borrowed(v)))
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Str(Cow::Owned(v.to_string())))
            }
            fn visit_string<E>(self, v: String) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Str(Cow::Owned(v)))
            }
            fn visit_unit<E>(self) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Null)
            }
            fn visit_none<E>(self) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Null)
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Other)
            }
            fn visit_i64<E>(self, _: i64) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Other)
            }
            fn visit_u64<E>(self, _: u64) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Other)
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<Seen<'de>, E> {
                Ok(Seen::Other)
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> std::result::Result<Seen<'de>, M::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Seen::Other)
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> std::result::Result<Seen<'de>, S::Error> {
                if self.0 {
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                    return Ok(Seen::Other);
                }
                let mut strs = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                let mut all = true;
                while let Some(e) = seq.next_element::<Elem<'de>>()? {
                    match e {
                        Elem::Str(s) if all => strs.push(s),
                        _ => {
                            all = false;
                            strs = Vec::new();
                        }
                    }
                }
                Ok(Seen::List(if all { StrList::Strs(strs) } else { StrList::NotStrings }))
            }
        }
        d.deserialize_any(Any(false)).map(|s: Seen<'de>| match s {
            Seen::List(l) => l,
            Seen::Null => StrList::Absent,
            _ => StrList::NotList,
        })
    }
}

/// The arguments of `export_read_end`. Read either out of the parsed arguments or, on the lean path
/// `call` takes for this function, straight from the argument text: its lists can hold an id per
/// message of the file, and a tree of values holding each of them three times over was most of what
/// the call cost (CHANGELOG 0.3.2).
#[derive(serde::Deserialize)]
pub(super) struct EndArgs<'a> {
    manifest: Option<Value>,
    messages_sha256: Option<Value>,
    lines: Option<Value>,
    #[serde(borrow)]
    ids: Option<StrList<'a>>,
    #[serde(borrow)]
    msg_ids: Option<StrList<'a>>,
    #[serde(borrow)]
    reply_tos: Option<StrList<'a>>,
    #[serde(borrow)]
    media_seen: Option<StrList<'a>>,
    #[serde(borrow)]
    media: Option<StrList<'a>>,
}

impl<'a> EndArgs<'a> {
    fn of_value(a: &'a Value) -> EndArgs<'a> {
        EndArgs {
            manifest: a.get("manifest").cloned(),
            messages_sha256: a.get("messages_sha256").cloned(),
            lines: a.get("lines").cloned(),
            ids: Some(StrList::of_value(a.get("ids"))),
            msg_ids: Some(StrList::of_value(a.get("msg_ids"))),
            reply_tos: Some(StrList::of_value(a.get("reply_tos"))),
            media_seen: Some(StrList::of_value(a.get("media_seen"))),
            media: Some(StrList::of_value(a.get("media"))),
        }
    }
}

pub(super) fn export_read_end(a: &Value) -> Result<Value> {
    read_end(&EndArgs::of_value(a))
}

/// The lean path: `export_read_end`'s arguments read straight from their text. `None` when the text
/// is not an object this reads (a duplicate member, say), and the call is then answered by the
/// ordinary path, word for word as before.
pub(super) fn export_read_end_lean(args: &str) -> Option<Result<Value>> {
    // An object only: a derived struct would also read a JSON array, by position.
    if !args.trim_start().starts_with('{') {
        return None;
    }
    // Every value of the text read as the ordinary path reads it — a number out of range included —
    // without keeping any of it: the lean path answers only what the ordinary one would. A member the
    // struct does not name is otherwise skipped unread, and `{"x": 1e400, ...}` was answered `ok` here
    // where the ordinary path refuses it.
    let TopKeys(keys) = serde_json::from_str(args).ok()?;
    // A member the function does not declare, refused as `call` refuses it for every other function.
    if let Some(e) = super::undeclared("export_read_end", keys.iter().map(String::as_str)) {
        return Some(Err(e));
    }
    let a: EndArgs<'_> = serde_json::from_str(args).ok()?;
    Some(read_end(&a))
}

/// An object's member names, its values walked whole as `Walk` walks them and not kept.
struct TopKeys(Vec<String>);

impl<'de> serde::Deserialize<'de> for TopKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::{MapAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = TopKeys;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> std::result::Result<TopKeys, M::Error> {
                let mut keys = Vec::new();
                while let Some((k, Walk)) = m.next_entry::<String, Walk>()? {
                    keys.push(k);
                }
                Ok(TopKeys(keys))
            }
        }
        d.deserialize_map(V)
    }
}

/// A JSON value walked whole, every number parsed and nothing kept.
struct Walk;

impl<'de> serde::Deserialize<'de> for Walk {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::{MapAccess, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Walk;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_i64<E>(self, _: i64) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_u64<E>(self, _: u64) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_borrowed_str<E>(self, _: &'de str) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_str<E>(self, _: &str) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_unit<E>(self) -> std::result::Result<Walk, E> {
                Ok(Walk)
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> std::result::Result<Walk, S::Error> {
                while seq.next_element::<Walk>()?.is_some() {}
                Ok(Walk)
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> std::result::Result<Walk, M::Error> {
                while m.next_entry::<Walk, Walk>()?.is_some() {}
                Ok(Walk)
            }
        }
        d.deserialize_any(V)
    }
}

fn read_end<'b>(a: &'b EndArgs<'_>) -> Result<Value> {
    // In the order the function needs them (CONTRACT §0).
    let Some(text) = a.manifest.as_ref().and_then(|v| v.as_str()) else { return err("bad_request", "manifest is required") };
    let sha = match &a.messages_sha256 {
        None | Some(Value::Null) => None,
        Some(Value::String(h)) => Some(h.as_str()),
        Some(_) => return err("bad_request", "messages_sha256 is a lowercase hex sha256 or null"),
    };
    let lines = match &a.lines {
        None | Some(Value::Null) => 0,
        Some(v) => v.as_u64().ok_or_else(|| Error::new("bad_request", "lines is a whole number"))?,
    };
    let list = |l: &'b Option<StrList<'_>>, k: &str| match l {
        Some(l) => l.get(k),
        None => StrList::Absent.get(k),
    };
    let (ids, msg_ids, reply_tos, media_seen) =
        (list(&a.ids, "ids")?, list(&a.msg_ids, "msg_ids")?, list(&a.reply_tos, "reply_tos")?, list(&a.media_seen, "media_seen")?);
    let media = list(&a.media, "media")?;
    export::read_end(
        text,
        &export::End {
            messages_sha256: sha,
            lines,
            ids: &ids,
            msg_ids: &msg_ids,
            reply_tos: &reply_tos,
            media_seen: &media_seen,
            media: &media,
        },
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
    let messages = list(a, "messages")?;
    let file_msg_ids = match a.get("msg_ids") {
        None | Some(Value::Null) => None,
        Some(_) => Some(strs(a, "msg_ids")?),
    };
    let (lines, left_out) = jsonl::write(messages, file_msg_ids.as_deref())?;
    let left_out: Vec<Value> = left_out.iter().map(|l| json!({ "id": l.id, "reason": l.reason })).collect();
    Ok(json!({ "lines": lines, "left_out": left_out }))
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

pub(super) fn book_rows(a: &Value) -> Result<Value> {
    let contacts = list(a, "contacts")?;
    let at = instant(a, "exported_at")?;
    Ok(json!({ "rows": export::book_rows(contacts, at)? }))
}
