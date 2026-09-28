//! The export's container (SPEC §9.2; CONTRACT §6.2), the CLI's side of it: reading an export or a
//! book with the `zip` crate and writing the wallet's book. Every rule that can be decided on what
//! was read is the core's (`export_read`, `export_read_messages`, `export_read_end`); what is here
//! is what only a host can do — list the central directory, count the bytes it actually
//! decompresses, refuse what is not UTF-8, hash `messages.jsonl` and each media file as it streams
//! them — in the words the Go port's `ReadExportZip` uses for the same refusals.
use pact_identity::export;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

// The bounds of SPEC §9.2 are the core's, one copy of them (a test holds contract.json to them).
const MANIFEST_MAX: u64 = export::MANIFEST_MAX as u64;
const CONTACTS_MAX: u64 = export::CONTACTS_MAX as u64;
const THREADS_MAX: u64 = export::THREADS_MAX as u64;
const LINE_MAX: usize = export::LINE_MAX;
const MEDIA_MAX: u64 = export::MEDIA_MAX as u64;
const BATCH: usize = 500;

/// The host's words for this ceiling, as the Go port has them.
fn over_ceiling(ceiling: u64) -> String {
    format!("the file is over the {ceiling}-byte ceiling this host sets")
}

/// One call into the core, its refusal as the core words it.
fn call(name: &str, args: Value) -> Result<Value, String> {
    let out: Value = serde_json::from_str(&pact_identity::call(name, &args.to_string())).map_err(|e| format!("{name}: {e}"))?;
    match out.get("why").and_then(|w| w.as_str()) {
        Some(why) if out.get("error").is_some() => Err(why.to_string()),
        _ => Ok(out),
    }
}

/// One entry of the central directory, as the zip holds it.
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub encrypted: bool,
    pub mode: u32,
}

fn u16_at(b: &[u8], i: usize) -> Option<u64> {
    b.get(i..i + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as u64)
}
fn u32_at(b: &[u8], i: usize) -> Option<u64> {
    b.get(i..i + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64)
}
fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    b.get(i..i + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

/// The central directory read entry by entry, duplicates and all. The `zip` crate indexes its
/// entries by name and keeps one of each, so a file that names a member twice would read as one
/// that names it once; §9.2 refuses the file, and this is how it is seen.
pub fn central_directory(f: &mut File) -> Option<Vec<Entry>> {
    let len = f.seek(SeekFrom::End(0)).ok()?;
    let tail_len = len.min(65_535 + 22);
    let mut tail = vec![0u8; tail_len as usize];
    f.seek(SeekFrom::Start(len - tail_len)).ok()?;
    f.read_exact(&mut tail).ok()?;
    let eocd = (0..=tail.len().checked_sub(22)?).rev().find(|&i| tail[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])?;
    let mut count = u16_at(&tail, eocd + 10)?;
    let mut cd_size = u32_at(&tail, eocd + 12)?;
    let mut cd_start = u32_at(&tail, eocd + 16)?;
    if count == 0xffff || cd_size == 0xffff_ffff || cd_start == 0xffff_ffff {
        // ZIP64: the locator just before the record names where the ZIP64 record is.
        let loc = eocd.checked_sub(20)?;
        if tail[loc..loc + 4] != [0x50, 0x4b, 0x06, 0x07] {
            return None;
        }
        let at = u64_at(&tail, loc + 8)?;
        let mut rec = [0u8; 56];
        f.seek(SeekFrom::Start(at)).ok()?;
        f.read_exact(&mut rec).ok()?;
        if rec[0..4] != [0x50, 0x4b, 0x06, 0x06] {
            return None;
        }
        count = u64_at(&rec, 32)?;
        cd_size = u64_at(&rec, 40)?;
        cd_start = u64_at(&rec, 48)?;
    }
    if cd_start.checked_add(cd_size)? > len || count > cd_size / 46 {
        return None;
    }
    let mut cd = vec![0u8; cd_size as usize];
    f.seek(SeekFrom::Start(cd_start)).ok()?;
    f.read_exact(&mut cd).ok()?;
    let mut entries = Vec::new();
    let mut i = 0usize;
    for _ in 0..count {
        if cd.get(i..i + 4)? != [0x50, 0x4b, 0x01, 0x02] {
            return None;
        }
        let made_by = u16_at(&cd, i + 4)?;
        let flags = u16_at(&cd, i + 8)?;
        let mut size = u32_at(&cd, i + 24)?;
        let (name_len, extra_len, comment_len) =
            (u16_at(&cd, i + 28)? as usize, u16_at(&cd, i + 30)? as usize, u16_at(&cd, i + 32)? as usize);
        let external = u32_at(&cd, i + 38)?;
        let name = String::from_utf8_lossy(cd.get(i + 46..i + 46 + name_len)?).into_owned();
        if size == 0xffff_ffff {
            // The ZIP64 extra field (0x0001) carries the real uncompressed size first.
            let extra = cd.get(i + 46 + name_len..i + 46 + name_len + extra_len)?;
            let mut j = 0;
            while j + 4 <= extra.len() {
                let (id, n) = (u16_at(extra, j)?, u16_at(extra, j + 2)? as usize);
                if id == 1 {
                    size = u64_at(extra, j + 4)?;
                    break;
                }
                j += 4 + n;
            }
        }
        // The Unix mode: the external attributes' high half when it is set; an MS-DOS entry's
        // directory bit otherwise; nothing else. Only the file-type bits are read by the core.
        let high = (external >> 16) as u32;
        let mode = if high != 0 {
            high
        } else if made_by >> 8 == 0 && external & 0x10 != 0 {
            0o040775
        } else {
            0
        };
        entries.push(Entry { name, size, encrypted: flags & 1 != 0, mode });
        i += 46 + name_len + extra_len + comment_len;
    }
    Some(entries)
}

/// What an export holds, once the whole file has been checked.
pub struct Contents {
    pub contacts: Vec<Value>,
    pub threads: Vec<Value>,
    pub messages: Vec<Value>,
    pub media: Vec<Value>,
}

struct Counter {
    read: u64,
    ceiling: u64,
}

impl Counter {
    fn add(&mut self, n: u64) -> Result<(), String> {
        self.read += n;
        if self.read > self.ceiling {
            return Err(over_ceiling(self.ceiling));
        }
        Ok(())
    }
}

/// A text member read with its bound counted in bytes actually decompressed: the text, or the host's
/// reason it cannot be one. The ceiling's refusal is the whole answer at once.
fn text_member<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
    limit: u64,
    n: &mut Counter,
) -> Result<Result<String, String>, String> {
    let Ok(file) = zip.by_name(name) else { return Ok(Err(format!("{name}: does not decompress"))) };
    let mut bytes = Vec::new();
    let read = file.take(limit + 1).read_to_end(&mut bytes);
    n.add(bytes.len() as u64)?;
    if read.is_err() {
        return Ok(Err(format!("{name}: does not decompress")));
    }
    if bytes.len() as u64 > limit {
        return Ok(Err(format!("{name}: over {limit} bytes")));
    }
    Ok(String::from_utf8(bytes).map_err(|_| format!("{name}: not UTF-8 text")))
}

/// §9.2's validation of a whole export or book, and what it holds. `owner` is the importing
/// identity's root; `ceiling` the most this host decompresses from one file.
pub fn read_export(path: &Path, owner: &str, now: &str, ceiling: u64) -> Result<Contents, String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let entries = central_directory(&mut f).ok_or("the file is not a zip")?;
    let mut zip = zip::ZipArchive::new(f).map_err(|_| "the file is not a zip".to_string())?;
    let has = |n: &str| entries.iter().any(|e| e.name == n);
    let mut n = Counter { read: 0, ceiling };
    let mut texts: Vec<(&str, Result<String, String>)> = Vec::new();
    for (name, limit) in [("manifest.json", MANIFEST_MAX), ("contacts.csv", CONTACTS_MAX), ("threads.csv", THREADS_MAX)] {
        if has(name) {
            texts.push((name, text_member(&mut zip, name, limit, &mut n)?));
        }
    }
    let text = |name: &str| texts.iter().find(|(k, _)| *k == name).and_then(|(_, t)| t.as_ref().ok().cloned());
    let held = |name: &str| texts.iter().find(|(k, _)| *k == name).and_then(|(_, t)| t.as_ref().err().cloned());
    let directory: Vec<Value> =
        entries.iter().map(|e| json!({ "name": e.name, "size": e.size, "encrypted": e.encrypted, "mode": e.mode })).collect();
    let mut args = json!({ "directory": directory, "owner": owner, "now": now });
    for (arg, name) in [("manifest", "manifest.json"), ("contacts_csv", "contacts.csv"), ("threads_csv", "threads.csv")] {
        if let Some(t) = text(name) {
            args[arg] = json!(t);
        }
    }
    let read = call("export_read", args).map_err(|why| {
        // The core's directory and manifest refusals come first; a text member the host could not
        // read is the refusal only when the core reaches the member and finds it absent.
        let member = match why.as_str() {
            "manifest is required" => "manifest.json",
            "contacts_csv is required" => "contacts.csv",
            "threads_csv is required: the file has threads.csv" => "threads.csv",
            _ => return why,
        };
        held(member).unwrap_or(why)
    })?;
    let strings = |v: &Value, k: &str| -> Vec<String> {
        v.as_array().into_iter().flatten().filter_map(|x| x[k].as_str().map(String::from)).collect()
    };
    let (thread_ids, roots, hashes) =
        (strings(&read["threads"], "id"), strings(&read["contacts"], "root"), strings(&read["media"], "hash"));

    let mut messages = Vec::new();
    let (mut ids, mut msg_ids, mut reply_tos, mut media_seen) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut lines_read: u64 = 0;
    let mut messages_sha256 = None;
    if has("messages.jsonl") {
        let mut file = zip.by_name("messages.jsonl").map_err(|_| "messages.jsonl: does not decompress".to_string())?;
        let mut hasher = Sha256::new();
        let mut batch: Vec<String> = Vec::new();
        let mut first = 1u64;
        let mut line: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut flush = |batch: &mut Vec<String>, first: &mut u64| -> Result<(), String> {
            if batch.is_empty() {
                return Ok(());
            }
            let out = call(
                "export_read_messages",
                json!({ "lines": batch, "threads": thread_ids, "contacts": roots, "media": hashes, "first_line": *first }),
            )?;
            for m in out["messages"].as_array().into_iter().flatten() {
                ids.push(m["id"].as_str().unwrap_or_default().to_string());
                msg_ids.push(m["msg_id"].as_str().unwrap_or_default().to_string());
                if let Some(r) = m["reply_to"].as_str() {
                    reply_tos.push(r.to_string());
                }
                messages.push(m.clone());
            }
            for h in out["media_seen"].as_array().into_iter().flatten().filter_map(|h| h.as_str()) {
                media_seen.push(h.to_string());
            }
            *first += batch.len() as u64;
            batch.clear();
            Ok(())
        };
        let end_line = |line: &mut Vec<u8>, number: u64, batch: &mut Vec<String>| -> Result<(), String> {
            let text = String::from_utf8(std::mem::take(line)).map_err(|_| format!("messages.jsonl: line {number}: not UTF-8 text"))?;
            batch.push(text);
            Ok(())
        };
        loop {
            let got = file.read(&mut buf).map_err(|_| "messages.jsonl: does not decompress".to_string())?;
            if got == 0 {
                break;
            }
            n.add(got as u64)?;
            hasher.update(&buf[..got]);
            for &b in &buf[..got] {
                if b == b'\n' {
                    lines_read += 1;
                    end_line(&mut line, lines_read, &mut batch)?;
                    if batch.len() == BATCH {
                        flush(&mut batch, &mut first)?;
                    }
                } else {
                    line.push(b);
                    if line.len() > LINE_MAX {
                        return Err(format!("messages.jsonl: line {}: over {LINE_MAX} bytes", lines_read + 1));
                    }
                }
            }
        }
        if !line.is_empty() {
            lines_read += 1;
            end_line(&mut line, lines_read, &mut batch)?;
        }
        flush(&mut batch, &mut first)?;
        messages_sha256 = Some(pact_identity::util::hex(&hasher.finalize()));
    }
    media_seen.sort();
    media_seen.dedup();

    for e in entries.iter().filter(|e| e.name.len() == 70 && e.name.starts_with("media/")) {
        let name = &e.name;
        let file = zip.by_name(name).map_err(|_| format!("{name}: does not decompress"))?;
        let mut bytes = Vec::new();
        let read = file.take(MEDIA_MAX + 1).read_to_end(&mut bytes);
        n.add(bytes.len() as u64)?;
        read.map_err(|_| format!("{name}: does not decompress"))?;
        if bytes.len() as u64 > MEDIA_MAX {
            return Err(format!("{name}: over {MEDIA_MAX} bytes"));
        }
        if pact_identity::util::hex(&Sha256::digest(&bytes)) != name[6..] {
            return Err(format!("{name}: its sha256 is not its name"));
        }
        // SPEC 2.2.2, 9.2#15: a media file that is a private key is refused, in the Go port's words.
        if export::media_holds_private_key(&bytes) {
            return Err(format!("{name}: holds a private key"));
        }
    }
    call(
        "export_read_end",
        json!({
            "manifest": text("manifest.json").unwrap_or_default(), "messages_sha256": messages_sha256, "lines": lines_read,
            "ids": ids, "msg_ids": msg_ids, "reply_tos": reply_tos, "media_seen": media_seen,
            "media": read["media"].as_array().into_iter().flatten().filter_map(|m| m["hash"].as_str()).collect::<Vec<_>>(),
        }),
    )?;
    Ok(Contents {
        contacts: read["contacts"].as_array().cloned().unwrap_or_default(),
        threads: read["threads"].as_array().cloned().unwrap_or_default(),
        messages,
        media: read["media"].as_array().cloned().unwrap_or_default(),
    })
}

/// The wallet's book (SPEC §9.2): an export holding `manifest.json` and `contacts.csv` only, the
/// members written by the core so every port writes the same bytes. Written to a new file, never over
/// one.
pub fn write_book(path: &Path, owner: &str, owner_name: &str, exported_at: &str, contacts: &[Value]) -> Result<(), String> {
    let tool = format!("pact {}", env!("CARGO_PKG_VERSION"));
    let w = call(
        "export_write",
        json!({ "owner": owner, "owner_name": owner_name, "exported_at": exported_at, "tool": tool, "contacts": contacts }),
    )?;
    let manifest = call("export_manifest", json!({ "partial": w["partial"], "messages": 0 }))?;
    let at = pact_identity::time::parse_rfc3339(exported_at).map_err(|e| e.why)?;
    let (y, mo, d, h, mi, s) = pact_identity::time::to_civil(at);
    let when = zip::DateTime::from_date_and_time(y as u16, mo as u8, d as u8, h as u8, mi as u8, s as u8)
        .map_err(|_| "exported_at is outside a zip's dates".to_string())?;
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(when)
        .unix_permissions(0o600);
    let file = File::options().write(true).create_new(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut z = zip::ZipWriter::new(file);
    for (name, text) in [
        ("contacts.csv", w["contacts_csv"].as_str().unwrap_or_default()),
        ("manifest.json", manifest["manifest"].as_str().unwrap_or_default()),
    ] {
        z.start_file(name, opts).map_err(|e| format!("{name}: {e}"))?;
        z.write_all(text.as_bytes()).map_err(|e| format!("{name}: {e}"))?;
    }
    let file = z.finish().map_err(|e| format!("{}: {e}", path.display()))?;
    file.sync_all().map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn corpus() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../go/exportcorpus")
    }

    /// Every file of the corpus (go/exportcorpus, the one the Go port's ReadExportZip and
    /// js/parity.mjs read): each hostile one refused with the refusal it names, both controls
    /// accepted with what they hold.
    #[test]
    fn read_export_answers_the_whole_corpus() {
        answers_the_corpus_in(&corpus());
    }

    /// The corpus re-issued for other owners (`pact vectors corpus`) reads as the committed one does:
    /// each hostile file refused with ITS refusal, and not at the owner check, and each valid file
    /// taken whole — under each new owner, where the committed files are all refused as another
    /// identity's.
    #[test]
    fn the_corpus_reissued_for_another_owner_reaches_every_check() {
        let fixed: Value = serde_json::from_slice(&std::fs::read(corpus().join("cases.json")).unwrap()).unwrap();
        let fixed_owner = fixed["owner"].as_str().unwrap().to_string();
        for label in ["another owner", "a third"] {
            let owner = format!("sha256:{}", pact_identity::util::b64u(&Sha256::digest(label.as_bytes())));
            let dir = tempfile::tempdir().unwrap();
            for (name, bytes) in crate::vectors::corpus::corpus_for(&owner).unwrap() {
                std::fs::write(dir.path().join(name), bytes).unwrap();
            }
            let index: Value = serde_json::from_slice(&std::fs::read(dir.path().join("cases.json")).unwrap()).unwrap();
            assert_eq!(index["owner"], owner);
            assert!(!serde_json::to_string(&index).unwrap().contains(&fixed_owner), "cases.json still names the fixed owner");
            answers_the_corpus_in(dir.path());
            // The control: the committed valid export, read as this owner, is another identity's.
            let refused = read_export(&corpus().join("valid-export.zip"), &owner, index["now"].as_str().unwrap(), 1 << 30).err().unwrap();
            assert!(refused.starts_with("manifest.json: owner: the file is "), "{refused}");
        }
        // A root the corpus gives someone else is not an owner it can be re-issued for.
        let peer = fixed["cases"][0]["accept"]["leafless"][0].as_str().unwrap();
        assert_eq!(
            crate::vectors::corpus::corpus_for(peer).map(|_| ()),
            Err(format!("{peer}: the corpus already names this root as someone other than the owner"))
        );
        let wrong_owner = format!("sha256:{}", "A".repeat(43));
        assert_eq!(
            crate::vectors::corpus::corpus_for(&wrong_owner).map(|_| ()),
            Err(format!("{wrong_owner}: the corpus already names this root as someone other than the owner"))
        );
    }

    fn answers_the_corpus_in(dir: &Path) {
        let corpus = || dir.to_path_buf();
        let index: Value = serde_json::from_slice(&std::fs::read(corpus().join("cases.json")).unwrap()).unwrap();
        let (owner, now) = (index["owner"].as_str().unwrap(), index["now"].as_str().unwrap());
        let mut wrong = Vec::new();
        let mut accepted = 0;
        for c in index["cases"].as_array().unwrap() {
            let file = c["file"].as_str().unwrap();
            let got = read_export(&corpus().join(file), owner, now, 1 << 30);
            match (&c["accept"], got) {
                (Value::Object(want), Ok(got)) => {
                    accepted += 1;
                    let pinned = got.contacts.iter().filter(|r| !r["leaf"].is_null()).count();
                    let leafless: Vec<&str> = want["leafless"].as_array().unwrap().iter().filter_map(|l| l.as_str()).collect();
                    if got.contacts.iter().any(|r| leafless.contains(&r["root"].as_str().unwrap_or("")) && !r["leaf"].is_null()) {
                        wrong.push(format!("{file}: a leafless row's leaf pins"));
                    }
                    let counts = [got.contacts.len(), got.threads.len(), got.messages.len(), got.media.len(), pinned];
                    let expected = ["contacts", "threads", "messages", "media", "pinned"].map(|k| want[k].as_u64().unwrap() as usize);
                    if counts != expected {
                        wrong.push(format!("{file}: holds {counts:?}, want {expected:?}"));
                    }
                }
                (Value::Object(_), Err(why)) => wrong.push(format!("{file}: refused: {why}")),
                (_, Ok(_)) => wrong.push(format!("{file}: accepted, and must be refused")),
                (_, Err(why)) => {
                    let exact = c["refusal"].as_str().is_some_and(|r| r == why);
                    let prefix = c["refusal_prefix"].as_str().is_some_and(|p| why.starts_with(p));
                    if !exact && !prefix {
                        wrong.push(format!(
                            "{file}:\n  got  {why}\n  want {}{}",
                            c["refusal"].as_str().unwrap_or(""),
                            c["refusal_prefix"].as_str().unwrap_or("")
                        ));
                    }
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        // Every file cases.json marks as accepted, and at least one: a reader that refuses everything
        // must fail here.
        let want = index["cases"].as_array().unwrap().iter().filter(|c| c["accept"].is_object()).count();
        assert!(want > 0 && accepted == want, "{accepted} files accepted; cases.json accepts {want}");
    }
}
