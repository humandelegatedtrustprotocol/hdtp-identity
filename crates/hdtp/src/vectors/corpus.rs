//! The export corpus (go/exportcorpus) re-issued for any owner: what `hdtp vectors corpus` writes.
//!
//! Every file of the committed corpus names one fixed owner root, and a host whose identities
//! cannot hold that root refuses each hostile file at the owner check, before the check the file
//! targets. That result is UNREACHED, not proven. This writes the same corpus for a root the host
//! does hold.
//!
//! How:
//! - The owner's fingerprint appears only in stored members: every manifest, and the one
//!   `contacts.csv` row whose defect is the owner's own root. It is replaced with the new root.
//!   A fingerprint is always 50 bytes, so every size, offset and stated size stays as it was, and
//!   each file keeps its one defect, whatever the defect does to the container.
//! - Each changed member's CRC-32 is written again. A sha256 the manifest lists for a changed
//!   member is replaced with the new sha256 only where the old one was TRUE of the old bytes. A
//!   file whose defect is a wrong hash keeps it.
//! - A deflated member that held the old root could not be re-issued this way, so it is refused
//!   rather than left behind.
//! - cases.json follows: its `owner`, and each refusal that quotes the owner.
//!
//! The corpus the ports' own tests read stays the committed one.
use crate::io::{fail, Fail, Res};
use flate2::read::DeflateDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/corpus.rs"));
}

/// The members whose sha256 a manifest lists.
const LISTED: [&str; 3] = ["contacts.csv", "threads.csv", "messages.jsonl"];

fn u16_at(b: &[u8], at: usize) -> Result<usize, String> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as usize).ok_or_else(|| "a header runs past the file".into())
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| "a header runs past the file".into())
}

fn sha(b: &[u8]) -> String {
    hdtp_identity::util::hex(&Sha256::digest(b))
}

fn replace_all(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    debug_assert_eq!(from.len(), to.len());
    let mut out = hay.to_vec();
    let mut i = 0;
    while i + from.len() <= out.len() {
        if &out[i..i + from.len()] == from {
            out[i..i + from.len()].copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// One entry as the central directory places it.
struct Entry {
    name: String,
    central: usize,
    local: usize,
    flags: usize,
    method: usize,
    data: std::ops::Range<usize>,
}

fn entries(zip: &[u8]) -> Result<Vec<Entry>, String> {
    let eocd = (0..zip.len().saturating_sub(21))
        .rev()
        .find(|&i| zip[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or("no end of central directory")?;
    let count = u16_at(zip, eocd + 10)?;
    let mut at = u32_at(zip, eocd + 16)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(zip, at)? != 0x0201_4b50 {
            return Err("a central directory entry without its signature".into());
        }
        let (flags, method, size) = (u16_at(zip, at + 8)?, u16_at(zip, at + 10)?, u32_at(zip, at + 20)? as usize);
        let (n, e, c) = (u16_at(zip, at + 28)?, u16_at(zip, at + 30)?, u16_at(zip, at + 32)?);
        let local = u32_at(zip, at + 42)? as usize;
        let name = String::from_utf8_lossy(zip.get(at + 46..at + 46 + n).ok_or("a name runs past the file")?).into_owned();
        if u32_at(zip, local)? != 0x0403_4b50 {
            return Err(format!("{name}: a local header without its signature"));
        }
        let start = local + 30 + u16_at(zip, local + 26)? + u16_at(zip, local + 28)?;
        if start + size > zip.len() {
            return Err(format!("{name}: its data runs past the file"));
        }
        out.push(Entry { name, central: at, local, flags, method, data: start..start + size });
        at += 46 + n + e + c;
    }
    Ok(out)
}

/// `fp` with its last character the next base64url one: the same root's bits with a spare bit set,
/// the misspelling the owner-alias case carries. A canonical root's last character is never `_`.
pub fn alias(fp: &str) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (head, last) = fp.split_at(fp.len() - 1);
    let at = B64.iter().position(|&c| c == last.as_bytes()[0]).unwrap_or(B64.len() - 2);
    format!("{head}{}", B64[at + 1] as char)
}

/// Each `from` in `text` replaced by its `to`, in order.
fn replace_each(text: &[u8], pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    pairs.iter().fold(text.to_vec(), |t, (from, to)| replace_all(&t, from, to))
}

/// One file of the corpus with every `from` in its stored members replaced by its `to`.
fn reissue(file: &str, zip: &[u8], pairs: &[(&[u8], &[u8])]) -> Result<Vec<u8>, String> {
    let list = entries(zip).map_err(|e| format!("{file}: {e}"))?;
    let mut out = zip.to_vec();
    // The text members first: a manifest's hashes are of their NEW bytes.
    let mut rehashed: Vec<(String, String)> = Vec::new();
    let mut changed: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, e) in list.iter().enumerate() {
        let old = &zip[e.data.clone()];
        match e.method {
            0 => {
                let new = replace_each(old, pairs);
                if new != old {
                    if LISTED.contains(&e.name.as_str()) {
                        rehashed.push((sha(old), sha(&new)));
                    }
                    changed.push((i, new));
                }
            }
            8 => {
                let mut text = Vec::new();
                DeflateDecoder::new(old).read_to_end(&mut text).map_err(|e2| format!("{file}: {}: {e2}", e.name))?;
                if pairs.iter().any(|(from, _)| contains(&text, from)) {
                    return Err(format!("{file}: {} is deflated and holds the owner: it cannot be re-issued byte for byte", e.name));
                }
            }
            m => return Err(format!("{file}: {}: method {m}", e.name)),
        }
    }
    // A manifest's sha256 of a changed member is replaced only where it was that member's true
    // hash: a defect in the hash stays a defect.
    for (i, e) in list.iter().enumerate() {
        if e.method != 0 || !e.name.ends_with("manifest.json") {
            continue;
        }
        let mut text = changed.iter().find(|(j, _)| *j == i).map(|(_, t)| t.clone()).unwrap_or_else(|| zip[e.data.clone()].to_vec());
        let before = text.clone();
        for (old, new) in &rehashed {
            text = replace_all(&text, old.as_bytes(), new.as_bytes());
        }
        if text != before {
            changed.retain(|(j, _)| *j != i);
            changed.push((i, text));
        }
    }
    for (i, new) in changed {
        let e = &list[i];
        out[e.data.clone()].copy_from_slice(&new);
        let crc = crc32(&new).to_le_bytes();
        out[e.central + 16..e.central + 20].copy_from_slice(&crc);
        if e.flags & 0x8 == 0 {
            out[e.local + 14..e.local + 18].copy_from_slice(&crc);
        } else {
            // The CRC is in the data descriptor, after the data, with or without its signature.
            let d = e.data.end;
            let at = if u32_at(zip, d)? == 0x0807_4b50 { d + 4 } else { d };
            out[at..at + 4].copy_from_slice(&crc);
        }
    }
    Ok(out)
}

/// CRC-32 (IEEE), as zip writes it.
fn crc32(b: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(b);
    crc.sum()
}

/// The whole corpus for `owner`: cases.json and every file, by name.
pub fn corpus_for(owner: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    if !hdtp_identity::export::is_fingerprint(owner) {
        return Err(format!("{owner}: not a root fingerprint (sha256: and 43 base64url characters)"));
    }
    let index: serde_json::Value = serde_json::from_str(embedded::CASES).map_err(|e| format!("cases.json: {e}"))?;
    let fixed = index["owner"].as_str().ok_or("cases.json: no owner")?.to_string();
    // The owner's alias goes with the owner, or the owner-alias case would name the old owner's.
    let (fixed_alias, owner_alias) = (alias(&fixed), alias(owner));
    // A root the corpus already gives someone else (a contact, another identity's export) would
    // change what a file means: the owner would be a contact of their own, or the file theirs.
    let named = |root: &str| {
        embedded::CASES.contains(root)
            || embedded::FILES
                .iter()
                .any(|(_, z)| entries(z).is_ok_and(|l| l.iter().any(|e| e.method == 0 && contains(&z[e.data.clone()], root.as_bytes()))))
    };
    if owner != fixed && (named(owner) || named(&owner_alias)) {
        return Err(format!("{owner}: the corpus already names this root as someone other than the owner"));
    }
    let pairs: [(&[u8], &[u8]); 2] = [(fixed.as_bytes(), owner.as_bytes()), (fixed_alias.as_bytes(), owner_alias.as_bytes())];
    let mut out = vec![("cases.json".to_string(), embedded::CASES.replace(&fixed, owner).replace(&fixed_alias, &owner_alias).into_bytes())];
    for (name, zip) in embedded::FILES {
        out.push((name.to_string(), reissue(name, zip, &pairs)?));
    }
    Ok(out)
}

/// `hdtp vectors corpus --owner <root> --out <dir>`: writes into a directory that holds none of
/// the corpus's names, creating it if it is not there.
pub fn corpus(owner: &str, out: &str) -> Res<i32> {
    let files = corpus_for(owner).map_err(Fail)?;
    let dir = Path::new(out);
    std::fs::create_dir_all(dir).map_err(|e| Fail(format!("{out}: {e}")))?;
    if let Some((name, _)) = files.iter().find(|(n, _)| dir.join(n).exists()) {
        return fail(format!("{}: exists: the corpus is not written over a file", dir.join(name).display()));
    }
    for (name, bytes) in &files {
        std::fs::write(dir.join(name), bytes).map_err(|e| Fail(format!("{}: {e}", dir.join(name).display())))?;
    }
    println!("wrote {} files for owner {owner} into {out}: cases.json names each file's refusal", files.len());
    Ok(0)
}
