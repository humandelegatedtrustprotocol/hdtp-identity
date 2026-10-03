//! The two files of an identity, the vault and its record: where the record is, how each is opened
//! and checked, and how they are written — one at a time, or landed together so that both are
//! there or neither is.
use super::record_path;
use crate::io::{core, fail, passphrase, read_input, unique_tmp, write_new_private, write_private, Fail, Res};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) struct Vault {
    /// As typed, for messages.
    pub(super) path: String,
    /// Where it really is, for reading and writing (`real`).
    pub(super) real: String,
    pub(super) passphrase: Zeroizing<String>,
    pub(super) plaintext: Value,
}

// What the vault held in memory is cleared when the command is done with it: the passphrase by its
// type, and every string of the plaintext — root keys among them — overwritten before it is freed.
// (It used to be dropped to Null, which frees the buffers as they stand.)
impl Drop for Vault {
    fn drop(&mut self) {
        crate::io::wipe(&mut self.plaintext);
    }
}

/// The record beside a vault: the ledger and the contact book, sealed under the vault's passphrase.
pub(super) struct Record {
    /// For messages: the path as typed when that is where it is, else the real one.
    pub(super) path: String,
    pub(super) real: String,
    /// False when there was no record: `plaintext` is then an empty one, not yet on disk.
    pub(super) found: bool,
    pub(super) plaintext: Value,
}

impl Drop for Record {
    fn drop(&mut self) {
        crate::io::wipe(&mut self.plaintext);
    }
}

pub(super) fn empty_record() -> Value {
    json!({ "v": 1, "ledger": [], "contacts": [] })
}

/// Where a path really leads: a file that exists, through every link; a name that does not, its
/// directory's real location and the name. The writes here replace a file by renaming a new one
/// over its name, so a write to a link's own path would leave a file beside the link's target and
/// the target unwritten; reading one place and writing another would split an identity in two.
pub(super) fn real(path: &str) -> String {
    let p = Path::new(path);
    if let Ok(c) = std::fs::canonicalize(p) {
        return c.to_string_lossy().into_owned();
    }
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    match (std::fs::canonicalize(dir), p.file_name()) {
        (Ok(d), Some(n)) => d.join(n).to_string_lossy().into_owned(),
        _ => path.to_string(),
    }
}

/// A vault's record: where to say it is, and where it really is — beside the file the vault's path
/// leads to, not beside a link to it.
pub(super) fn record_of(vault: &str) -> (String, String) {
    let really = real(&record_path(&real(vault)));
    let typed = record_path(vault);
    let shown = if real(&typed) == really { typed } else { really.clone() };
    (shown, really)
}

/// A sealed document at `real`, opened under `passphrase`: its plaintext, or a refusal naming the
/// file by `shown`. The one read → parse → open every file here goes through.
fn opened(shown: &str, real: &str, passphrase: &str) -> Res<Value> {
    let raw = read_input(real).map_err(|e| Fail(e.0.replacen(real, shown, 1)))?;
    let doc: Value = serde_json::from_slice(&raw).map_err(|e| Fail(format!("{shown}: not a sealed document ({e})")))?;
    let plaintext = core("vault_open", json!({ "passphrase": passphrase, "vault": doc })).map_err(|e| Fail(format!("{shown}: {}", e.0)))?
        ["plaintext"]
        .take();
    Ok(plaintext)
}

pub(super) fn open_vault(path: &str, confirm_passphrase: bool) -> Res<Vault> {
    let really = real(path);
    // Absent is said before a passphrase is asked for: a mistyped path is not an identity.
    if !Path::new(&really).exists() {
        return fail(format!("{path}: no vault there"));
    }
    let passphrase = passphrase(confirm_passphrase)?;
    let mut plaintext = opened(path, &really, &passphrase)?;
    // The core refuses another generation; this refuses a document of this one that carries what
    // belongs in the record, because nothing here would read it and a person would think it kept.
    if plaintext.get("ledger").is_some() || plaintext.get("contacts").is_some() {
        crate::io::wipe(&mut plaintext);
        return fail(format!(
            "{path}: a vault is the root and nothing else; this one carries a ledger or contacts, which belong in the record beside it"
        ));
    }
    Ok(Vault { path: path.to_string(), real: really, passphrase, plaintext })
}

/// The record beside a vault, under the vault's passphrase — which opening the vault has proved.
/// No file there is not an error: `found` is false and the record is an empty one, and each command
/// says what that means for it (for a signing: the leaf is a replacement). A file there that is not
/// a record — no ledger, no contact book; a vault's bytes at the record's name — is refused before
/// anything is signed.
pub(super) fn open_record(v: &Vault) -> Res<Record> {
    let (shown, really) = record_of(&v.path);
    if !Path::new(&really).exists() {
        return Ok(Record { path: shown, real: really, found: false, plaintext: empty_record() });
    }
    let mut plaintext = opened(&shown, &really, &v.passphrase)?;
    for member in ["ledger", "contacts"] {
        if !plaintext[member].is_array() {
            crate::io::wipe(&mut plaintext);
            return fail(format!(
                "{shown}: not a record — it has no {member}; a record holds the ledger and the contact book (is a vault's copy at this name?)"
            ));
        }
    }
    // Every entry read as the core reads it: the card path applies the one-live-leaf rule to this
    // ledger itself, and an entry that did not read would be skipped there — failing open.
    if let Err(e) = hdtp_identity::vault::check_record(&plaintext) {
        crate::io::wipe(&mut plaintext);
        return fail(format!("{shown}: {}", e.why));
    }
    Ok(Record { path: shown, real: really, found: true, plaintext })
}

pub(super) fn sealed_bytes(passphrase: &str, plaintext: &Value) -> Res<Vec<u8>> {
    let sealed = core("vault_seal", json!({ "passphrase": passphrase, "plaintext": plaintext }))?["vault"].take();
    Ok(format!("{}\n", serde_json::to_string_pretty(&sealed)?).into_bytes())
}

/// The vault written again: only `card-attach`, where a card takes the root and the root's entry
/// says so. Nothing else ever writes a vault after `id create`.
pub(super) fn save_vault(v: &Vault) -> Res<()> {
    write_private(Path::new(&v.real), &sealed_bytes(&v.passphrase, &v.plaintext)?)
}

/// A signing's write of the record: over the one that was there, or — when there was none — a new
/// one, exclusively, because "none" was true a moment ago and has to still be true now.
pub(super) fn save_record(v: &Vault, r: &Record) -> Res<()> {
    let bytes = sealed_bytes(&v.passphrase, &r.plaintext)?;
    match r.found {
        true => write_private(Path::new(&r.real), &bytes),
        false => write_new_private(Path::new(&r.real), &bytes).map_err(|e| Fail(e.0.replacen(&r.real, &r.path, 1))),
    }
}

/// Files that belong together — a vault and its record — landed so that either every one is there
/// and opens under `passphrase`, or nothing this call made is left: a vault without its record, or
/// a record nobody can open, is the half-made identity the next run would refuse as "exists".
///
/// Without `force` each file is created exclusively, where there is none, and on any failure the
/// files this call created are removed — no link or special rename, so a backup to a USB stick or a
/// share behaves as one to the home directory. With `force` each is written to a new name beside
/// its destination and proved there, and only when all have proved are they renamed over what was
/// there. Answers each file's plaintext, in order, for the caller to count and then drop.
pub(super) fn land_all(files: &[(&str, &str, Vec<u8>)], passphrase: &str, force: bool) -> Res<Vec<Value>> {
    let mut made: Vec<std::path::PathBuf> = Vec::new();
    let mut plaintexts = Vec::new();
    let undo = |made: &[std::path::PathBuf], plaintexts: &mut Vec<Value>| {
        for p in made {
            let _ = std::fs::remove_file(p);
        }
        plaintexts.iter_mut().for_each(crate::io::wipe);
    };
    for (shown, really, bytes) in files {
        let at = if force { unique_tmp(Path::new(really)) } else { Path::new(really).to_path_buf() };
        if let Err(e) = write_new_private(&at, bytes) {
            undo(&made, &mut plaintexts);
            return fail(format!("{}; nothing this run made is left", e.0.replacen(&*at.to_string_lossy(), shown, 1)));
        }
        made.push(at.clone());
        match opened(shown, &at.to_string_lossy(), passphrase) {
            Ok(p) => plaintexts.push(p),
            Err(e) => {
                undo(&made, &mut plaintexts);
                return fail(format!("{shown}: written, and what was written did not open ({}); nothing this run made is left", e.0));
            }
        }
    }
    if force {
        for (i, (shown, really, _)) in files.iter().enumerate() {
            if let Err(e) = std::fs::rename(&made[i], really) {
                // What is already renamed has replaced what was there; the rest are removed.
                undo(&made[i..], &mut plaintexts);
                let done: Vec<&str> = files[..i].iter().map(|f| f.0).collect();
                return fail(format!("{shown}: {e}; replaced before this: [{}]", done.join(", ")));
            }
        }
        if let Some((_, really, _)) = files.first() {
            crate::io::sync_parent(Path::new(really))?;
        }
    }
    Ok(plaintexts)
}

pub(super) fn roots(v: &Value) -> Vec<Value> {
    v.get("roots").and_then(|r| r.as_array()).cloned().unwrap_or_default()
}

/// The root a command works with: the named one, or the only one.
pub(super) fn pick_root(v: &Value, wanted: Option<&str>) -> Res<Value> {
    let all = roots(v);
    match wanted {
        Some(fp) => {
            all.into_iter().find(|r| r["fingerprint"].as_str() == Some(fp)).ok_or_else(|| Fail(format!("no root {fp} in this vault")))
        }
        None => match all.len() {
            0 => fail("the vault holds no identity yet: hdtp id create"),
            1 => Ok(all[0].clone()),
            n => fail(format!("the vault holds {n} identities: say which with --root <fingerprint>")),
        },
    }
}

#[cfg(test)]
mod restore_tests {
    use super::*;

    fn sealed(pass: &str, plaintext: Value) -> Vec<u8> {
        let v = core(
            "vault_seal",
            json!({ "passphrase": pass, "plaintext": plaintext, "kdf": { "name": "argon2id", "m_kib": 8192, "t": 1, "p": 1 } }),
        )
        .unwrap()["vault"]
            .take();
        serde_json::to_vec(&v).unwrap()
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hdtp-land-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // A vault and its record land together or not at all. The vault used to be written first and
    // the record after, so a record that failed left a made identity the rerun refused as "exists".
    #[test]
    fn a_pair_that_does_not_prove_leaves_nothing_behind() {
        let d = dir("prove");
        let (vault, record) = (d.join("a.hdtp-vault.json"), d.join("a.hdtp-record.json"));
        let (vs, rs) = (vault.to_string_lossy().into_owned(), record.to_string_lossy().into_owned());
        let good = sealed("right", json!({ "v": 1, "roots": [] }));
        let other = sealed("other", json!({ "v": 1, "ledger": [], "contacts": [] }));
        let why = land_all(&[(&vs, &vs, good.clone()), (&rs, &rs, other)], "right", false).expect_err("the record does not open").0;
        assert!(!vault.exists() && !record.exists(), "left behind after: {why}");
        // …so the same pair can be landed again, and a pair that proves stays.
        let rec = sealed("right", json!({ "v": 1, "ledger": [], "contacts": [] }));
        land_all(&[(&vs, &vs, good), (&rs, &rs, rec)], "right", false).unwrap();
        assert!(vault.exists() && record.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    // The second name taken: the first file this call made goes, and what was there is untouched.
    #[test]
    fn a_pair_whose_second_name_is_taken_leaves_the_first_unmade() {
        let d = dir("taken");
        let (vault, record) = (d.join("b.hdtp-vault.json"), d.join("b.hdtp-record.json"));
        std::fs::write(&record, b"someone else's").unwrap();
        let (vs, rs) = (vault.to_string_lossy().into_owned(), record.to_string_lossy().into_owned());
        let why = land_all(
            &[
                (&vs, &vs, sealed("p", json!({ "v": 1, "roots": [] }))),
                (&rs, &rs, sealed("p", json!({ "v": 1, "ledger": [], "contacts": [] }))),
            ],
            "p",
            false,
        )
        .expect_err("the record's name is taken")
        .0;
        assert!(!vault.exists(), "the vault was left: {why}");
        assert_eq!(std::fs::read(&record).unwrap(), b"someone else's");
        std::fs::remove_dir_all(&d).unwrap();
    }

    // With --force, what was there stays until every new copy has proved.
    #[test]
    fn a_forced_pair_replaces_nothing_until_all_have_proved() {
        let d = dir("force");
        let (vault, record) = (d.join("c.hdtp-vault.json"), d.join("c.hdtp-record.json"));
        std::fs::write(&vault, b"old vault").unwrap();
        std::fs::write(&record, b"old record").unwrap();
        let (vs, rs) = (vault.to_string_lossy().into_owned(), record.to_string_lossy().into_owned());
        let bad = sealed("other", json!({ "v": 1, "ledger": [], "contacts": [] }));
        land_all(&[(&vs, &vs, sealed("p", json!({ "v": 1, "roots": [] }))), (&rs, &rs, bad)], "p", true)
            .expect_err("the record does not open");
        assert_eq!(std::fs::read(&vault).unwrap(), b"old vault");
        assert_eq!(std::fs::read(&record).unwrap(), b"old record");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2, "a temporary was left");
        std::fs::remove_dir_all(&d).unwrap();
    }

    // The record's name follows the vault's, so a person who kept one file finds the other.
    #[test]
    fn a_record_is_named_after_its_vault() {
        assert_eq!(record_path("alina.hdtp-vault.json"), "alina.hdtp-record.json");
        assert_eq!(record_path("/home/a/alina.hdtp-vault.json"), "/home/a/alina.hdtp-record.json");
        assert_eq!(record_path("v.json"), "v.hdtp-record.json");
        assert_eq!(record_path("vault"), "vault.hdtp-record.json");
    }
}
