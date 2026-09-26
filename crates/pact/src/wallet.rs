//! The wallet half: a root in a vault, leaves issued from it under SPEC §9's rules, the ledger, the
//! contact book. The rules live in the core's `wallet_issue`; this file adds the terminal's
//! discipline — the passphrase from a prompt, the vault owner-only, nothing a root key ever printed.
//!
//! An identity is two files under one passphrase (SPEC §9). The **vault** is the root and nothing
//! else — `<name>.pact-vault.json`, written when the identity is made and again only when a card
//! takes its root (`card-attach`), the copy a person keeps. The **record** beside it —
//! `<name>.pact-record.json` — is the ledger and the contact book, and is what every signing
//! writes. A vault carried to a new machine without its record has no ledger there, so the first
//! leaf it issues is a replacement of whatever was live, said so before it is signed; there is
//! nothing to convert.
//!
//! Both files are found, read and written at the vault's REAL location: through a link to the
//! vault, the record is the one beside the file it leads to. Messages name the paths as typed.
use crate::io::{
    check_writable, confirm, core, fail, instant, now_or, passphrase, pem, read_der, read_input, unique_tmp, write_new_private,
    write_output, write_private, Fail, Res,
};
use crate::piv::{digest_of, CardSigner};
use pact_identity::csr;
use pact_identity::keys::{Alg, PrivateKey};
use pact_identity::time::parse_rfc3339;
use pact_identity::util::{b64u, from_b64u};
use pact_identity::x509;
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

struct Vault {
    /// As typed, for messages.
    path: String,
    /// Where it really is, for reading and writing (`real`).
    real: String,
    passphrase: Zeroizing<String>,
    plaintext: Value,
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
struct Record {
    /// For messages: the path as typed when that is where it is, else the real one.
    path: String,
    real: String,
    /// False when there was no record: `plaintext` is then an empty one, not yet on disk.
    found: bool,
    plaintext: Value,
}

impl Drop for Record {
    fn drop(&mut self) {
        crate::io::wipe(&mut self.plaintext);
    }
}

/// Where a vault's record lives: the same name with `pact-record` for `pact-vault`, and
/// `.pact-record.json` appended to a name that says neither. `alina.pact-vault.json` keeps its
/// record at `alina.pact-record.json`; `v.json` at `v.pact-record.json`.
pub fn record_path(vault: &str) -> String {
    let stem = vault.strip_suffix(".json").unwrap_or(vault);
    let stem = stem.strip_suffix(".pact-vault").unwrap_or(stem);
    format!("{stem}.pact-record.json")
}

fn empty_record() -> Value {
    json!({ "v": 2, "ledger": [], "contacts": [] })
}

/// Where a path really leads: a file that exists, through every link; a name that does not, its
/// directory's real location and the name. The writes here replace a file by renaming a new one
/// over its name, so a write to a link's own path would leave a file beside the link's target and
/// the target unwritten; reading one place and writing another would split an identity in two.
fn real(path: &str) -> String {
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
fn record_of(vault: &str) -> (String, String) {
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

fn open_vault(path: &str, confirm_passphrase: bool) -> Res<Vault> {
    let really = real(path);
    // Absent is said before a passphrase is asked for: a mistyped path is not an identity.
    if !Path::new(&really).exists() {
        return fail(format!("{path}: no vault there"));
    }
    let passphrase = passphrase(confirm_passphrase)?;
    let mut plaintext = opened(path, &really, &passphrase)?;
    // The core refuses an earlier generation; this refuses a document of this one that carries what
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
fn open_record(v: &Vault) -> Res<Record> {
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
    if let Err(e) = pact_identity::vault::check_record(&plaintext) {
        crate::io::wipe(&mut plaintext);
        return fail(format!("{shown}: {}", e.why));
    }
    Ok(Record { path: shown, real: really, found: true, plaintext })
}

fn sealed_bytes(passphrase: &str, plaintext: &Value) -> Res<Vec<u8>> {
    let sealed = core("vault_seal", json!({ "passphrase": passphrase, "plaintext": plaintext }))?["vault"].take();
    Ok(format!("{}\n", serde_json::to_string_pretty(&sealed)?).into_bytes())
}

/// The vault written again: only `card-attach`, where a card takes the root and the root's entry
/// says so. Nothing else ever writes a vault after `id create`.
fn save_vault(v: &Vault) -> Res<()> {
    write_private(Path::new(&v.real), &sealed_bytes(&v.passphrase, &v.plaintext)?)
}

/// A signing's write of the record: over the one that was there, or — when there was none — a new
/// one, exclusively, because "none" was true a moment ago and has to still be true now.
fn save_record(v: &Vault, r: &Record) -> Res<()> {
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
fn land_all(files: &[(&str, &str, Vec<u8>)], passphrase: &str, force: bool) -> Res<Vec<Value>> {
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

fn roots(v: &Value) -> Vec<Value> {
    v.get("roots").and_then(|r| r.as_array()).cloned().unwrap_or_default()
}

/// The root a command works with: the named one, or the only one.
fn pick_root(v: &Value, wanted: Option<&str>) -> Res<Value> {
    let all = roots(v);
    match wanted {
        Some(fp) => {
            all.into_iter().find(|r| r["fingerprint"].as_str() == Some(fp)).ok_or_else(|| Fail(format!("no root {fp} in this vault")))
        }
        None => match all.len() {
            0 => fail("the vault holds no identity yet: pact id create"),
            1 => Ok(all[0].clone()),
            n => fail(format!("the vault holds {n} identities: say which with --root <fingerprint>")),
        },
    }
}

/// How a root is held. A vault entry with a `pkcs8` alone is software. One with a `holder` signs on
/// a card: generated there (`id create --piv`), the entry has the certificate and no key at all —
/// there is nothing to hold, which is the whole point of that arrangement; imported (`card-attach`),
/// the vault keeps the key as well, and the card is a way to sign rather than the identity.
pub fn card_holder(root: &Value) -> Option<&Value> {
    root.get("holder").filter(|h| h["kind"].as_str() == Some("piv"))
}

/// The card a root names, opened and checked against the root it is supposed to be. A different
/// card, or a slot regenerated since, is the one mistake that would otherwise produce certificates
/// under a root nobody pinned.
fn card_for(root: &Value, reader: Option<&str>) -> Res<Box<dyn CardSigner>> {
    let holder = card_holder(root).ok_or_else(|| Fail("this root is not held on a card".into()))?;
    let slot = holder["slot"].as_str().unwrap_or(crate::piv::DEFAULT_SLOT);
    let card = crate::piv::open(reader.or_else(|| holder["reader"].as_str()), slot)?;
    match_root(root, card.as_ref())?;
    Ok(card)
}

/// The card in hand is the one this identity's root lives on — or nothing is signed. A different
/// card, or a slot generated again since, would otherwise mint certificates under a root no
/// contact has ever pinned.
fn match_root(root: &Value, card: &dyn CardSigner) -> Res<()> {
    let on_card = card.public_key()?.fingerprint();
    let wanted = root["fingerprint"].as_str().unwrap_or("");
    if on_card != wanted {
        return fail(format!(
            "the key in slot {} is {on_card}, and this identity's root is {wanted}: a different card, or that slot has been generated again. Nothing signed.",
            card.describe().slot
        ));
    }
    Ok(())
}

/// A card proves it can *sign* under the key it shows, before a vault records it as this root's
/// card. Reading the slot's certificate is not that proof: PIV keeps the certificate and the key in
/// two separate objects and nothing makes them agree, so a slot can show exactly the right
/// certificate over a key that is not this root's. An attach that believed the certificate would
/// record a card that then fails at every issuance, burning a PIN try each time, for a reason
/// nobody could see.
///
/// The challenge is domain-separated and carries fresh randomness, so this signature is not a
/// certificate signature and no captured signature is this one: it begins with ASCII text, and a
/// TBSCertificate begins with 0x30.
fn card_proves_it_holds(card: &dyn CardSigner, key: &pact_identity::keys::PublicKey) -> Res<()> {
    // 32 random bytes of its own, as §2.2 asks of the analogous root-possession proof. It used to
    // borrow the certificate-SERIAL generator, which makes 8: enough here, since the domain prefix
    // does the real work, and the wrong number to have on loan.
    let nonce = pact_identity::util::random(32).map_err(|e| Fail(e.why))?;
    let mut challenge = b"PACT card-attach proof v1\n".to_vec();
    challenge.extend_from_slice(key.fingerprint().as_bytes());
    challenge.push(b'\n');
    challenge.extend_from_slice(&nonce);
    let sig = card.sign_digest(&digest_of(&challenge))?;
    if !key.verify(&challenge, &sig) {
        return fail("the card's signature does not verify under this identity's root: the slot holds this root's certificate over a different key, so it could show the right key and sign with the wrong one. Nothing written.");
    }
    Ok(())
}

/// The root certificate a card's key signs for itself, through the seam: the core builds the bytes,
/// the card signs them, the core assembles, and the signature is checked here before a vault is
/// written — a card that signed with another key must not become an identity on disk.
fn root_from_card(card: &dyn CardSigner, name: &str, now: i64) -> Res<(Vec<u8>, pact_identity::keys::PublicKey)> {
    let key = card.public_key()?;
    if key.alg().name() != "p256" {
        return fail(format!(
            "that slot holds a {} key; a card-held root is P-256 (SPEC §14.1 allows Ed25519 or P-256, and PIV's Ed25519 is too new to rely on)",
            key.alg().name()
        ));
    }
    let serial = x509::random_serial().map_err(|e| Fail(e.why))?;
    let u = core("root_tbs", json!({ "cn": name, "spki": b64u(key.spki()), "not_before": instant(now), "serial": b64u(&serial) }))?;
    let tbs = from_b64u(u["tbs"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let sig = card.sign_digest(&digest_of(&tbs))?;
    if !key.verify(&tbs, &sig) {
        return fail("the card's signature does not verify under the slot's key: nothing written");
    }
    let cert = from_b64u(
        core("assemble_root", json!({ "tbs": u["tbs"], "sig": b64u(&sig), "sig_alg": u["sig_alg"] }))?["der"].as_str().unwrap_or(""),
    )
    .map_err(|e| Fail(e.why))?;
    Ok((cert, key))
}

/// SPEC §9's one-live-leaf rule, which the core applies for a software root inside `wallet_issue`
/// and which the card path must apply for itself — the core cannot, because there is no key to hand
/// it. `live_leaf_refusal` and the core's rule are held to the same behaviour by a test that runs a
/// software root and a card-held root through the same vault and expects the same refusal.
fn live_leaf_refusal(mine: &[&Value], endpoint: &str, now: i64, moving: bool) -> Option<String> {
    let newest = mine.iter().max_by_key(|l| l["not_before"].as_str().and_then(|t| parse_rfc3339(t).ok()).unwrap_or(0))?;
    let live = newest["not_after"].as_str().and_then(|t| parse_rfc3339(t).ok()).is_some_and(|t| t > now);
    let elsewhere = newest["endpoint"].as_str() != Some(endpoint);
    if live && elsewhere && !moving {
        return Some(format!(
            "a leaf is live for {}: a second endpoint is a move, not a second home",
            newest["endpoint"].as_str().unwrap_or("?")
        ));
    }
    None
}

/// The key this identity *is*: read out of the root certificate the vault holds, which is the
/// certificate a contact pinned. Everything a card signs is checked against this and never against
/// what the card says about itself, because the card is the thing that might be lying — or might
/// simply have been swapped for another since the last question. The entry's own fingerprint is
/// checked against its certificate on the way past: a vault whose two halves disagree is a vault
/// that would issue under a root nobody has.
fn root_key(root: &Value) -> Res<pact_identity::keys::PublicKey> {
    let der = from_b64u(root["cert"].as_str().unwrap_or("")).map_err(|e| Fail(format!("this identity's root certificate: {}", e.why)))?;
    let cert = x509::parse(&der).map_err(|e| Fail(format!("this identity's root certificate: {}", e.why)))?;
    let fp = cert.public_key.fingerprint();
    if root["fingerprint"].as_str() != Some(fp.as_str()) {
        return fail(format!(
            "this vault's entry says the root is {}, and the certificate it keeps is for {fp}: the vault has been edited, and nothing is signed under it",
            root["fingerprint"].as_str().unwrap_or("nothing")
        ));
    }
    Ok(cert.public_key)
}

/// A leaf signed by a card, through the core's seam: the core makes the bytes and checks the
/// request, the card makes the signature, the core puts the certificate together — and the
/// signature is verified under the pinned root before any of it is assembled. The verification is
/// not a formality: a PIV slot's certificate and its key are not made to agree by anything, so a
/// card can pass the check with one key and sign with another, and what would come back is a leaf
/// naming this root as its issuer that no contact could ever validate.
fn issue_on_card(
    card: &dyn CardSigner,
    root: &Value,
    vault_roots: &[Value],
    csr_der: &[u8],
    now: i64,
    previous: Option<i64>,
    valid_days: i64,
) -> Res<Value> {
    let pinned = root_key(root)?;
    // The card in hand is this root's card. `id_issue` asked already; asking here too is what makes
    // this function safe to call from anywhere, which is how the gap above it arrived.
    match_root(root, card)?;
    // §9 refuses a request whose key is a root — ANY root this wallet holds, not only the one that
    // is issuing. The software path hands the core every root in the vault; this one handed it only
    // `root_spki`, so a request carrying a sibling identity's root key was given a leaf. Each root's
    // key is read from its certificate, which a card-held root has and a private key it has not.
    let every_root = vault_roots.iter().map(|r| root_key(r).map(|k| b64u(k.spki()))).collect::<Res<Vec<String>>>()?;
    let mut args = json!({
        "csr": b64u(csr_der),
        "root_cn": root["cn"].as_str().unwrap_or(""),
        "root_spki": b64u(pinned.spki()),
        "root_spkis": every_root,
        "now": instant(now),
        "valid_days": valid_days,
    });
    if let Some(p) = previous {
        args["previous_not_before"] = json!(instant(p));
    }
    let u = core("issue_tbs_from_csr", args)?;
    let tbs = from_b64u(u["tbs"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let sig = card.sign_digest(&digest_of(&tbs))?;
    if !pinned.verify(&tbs, &sig) {
        return fail("the card's signature does not verify under this identity's root: the slot's certificate and its key are for different keys, or the card was changed mid-ceremony. Nothing signed, nothing written.");
    }
    let der = core("assemble_leaf", json!({ "tbs": u["tbs"], "sig": b64u(&sig), "sig_alg": u["sig_alg"] }))?["der"].clone();
    Ok(json!({
        "der": der,
        "endpoint": u["endpoint"],
        "not_before": u["not_before"],
        "not_after": u["not_after"],
    }))
}

/// An identity whose root is a card: the certificate is built from the slot's public key and signed
/// by the slot, so no private key exists anywhere but the card, including here.
pub fn id_create_piv(name: &str, slot: &str, reader: Option<&str>, vault: &str) -> Res<i32> {
    let (record, record_real) = record_of(vault);
    for (taken, really) in [(vault, real(vault)), (record.as_str(), record_real.clone())] {
        if Path::new(&really).exists() {
            return fail(format!("{taken} exists; a second identity goes in with --vault pointing elsewhere, or is a decision for later"));
        }
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let card = crate::piv::open(reader, slot)?;
    let info = card.describe();
    eprintln!("reader      {}", info.reader);
    eprintln!("card        {}", info.serial.clone().unwrap_or_else(|| "serial unknown".into()));
    eprintln!("slot        {}", info.slot);
    let pass = passphrase(true)?;
    let now = now_or(None)?;
    let (cert, key) = root_from_card(card.as_ref(), name, now)?;
    eprintln!("root        {}", key.fingerprint());
    let plaintext = json!({
        "v": 2,
        "roots": [{
            "fingerprint": key.fingerprint(),
            "cn": name,
            "cert": b64u(&cert),
            "created": instant(now),
            "holder": { "kind": "piv", "mode": "generated", "slot": info.slot, "serial": info.serial, "reader": info.reader },
        }],
    });
    let vault_real = real(vault);
    let files = [
        (vault, vault_real.as_str(), sealed_bytes(&pass, &plaintext)?),
        (record.as_str(), record_real.as_str(), sealed_bytes(&pass, &empty_record())?),
    ];
    land_all(&files, &pass, false)?.iter_mut().for_each(crate::io::wipe);
    println!("{}", key.fingerprint());
    eprintln!("wrote {vault} (mode 0600) — the certificate; the key stays on the card. {record}: the ledger and the contact book");
    eprintln!("This card is the identity. The vault cannot hold the key and there is no export: lose the card and the identity is gone, exactly as a lost vault ends a software one. A second card is a second identity, not a copy.");
    Ok(0)
}

pub fn card_status(vault: Option<&str>, slot: &str, reader: Option<&str>) -> Res<i32> {
    let card = crate::piv::open(reader, slot)?;
    let info = card.describe();
    let key = card.public_key()?;
    println!("reader      {}", info.reader);
    println!("card        {}", info.serial.unwrap_or_else(|| "serial unknown".into()));
    println!("slot        {}", info.slot);
    println!("algorithm   {}", key.alg().name());
    println!("key         {}", key.fingerprint());
    let Some(path) = vault else { return Ok(0) };
    let v = open_vault(path, false)?;
    let matching = roots(&v.plaintext).into_iter().find(|r| r["fingerprint"].as_str() == Some(&key.fingerprint()));
    match matching {
        Some(r) => {
            // The same question every signing path asks: is this entry and the certificate it keeps
            // one key? A person asking "is this card my identity?" gets the whole answer or none.
            root_key(&r)?;
            println!("identity    {} ({})", r["fingerprint"].as_str().unwrap_or(""), r["cn"].as_str().unwrap_or(""));
            println!(
                "held        {}",
                match card_holder(&r).and_then(|h| h["mode"].as_str()) {
                    Some("generated") => "on this card, generated there: the vault has no key and there is no backup",
                    Some("imported") => "on this card, imported: the vault keeps the key too, so a lost card is not a lost identity",
                    Some(_) | None => "as a key in the vault; this card signs nothing for it",
                }
            );
            Ok(0)
        }
        None => {
            println!("identity    none in {path} has this key");
            Ok(1)
        }
    }
}

/// Hands a vault's own root over to a card that has been given a copy of its key. The card is
/// proved to hold that very key before anything is written — an attach that recorded a card holding
/// some other key would send every later signature somewhere nobody pinned.
pub fn card_attach(vault: &str, slot: &str, reader: Option<&str>, root: Option<&str>) -> Res<i32> {
    let mut v = open_vault(vault, false)?;
    let chosen = pick_root(&v.plaintext, root)?;
    let fp = chosen["fingerprint"].as_str().unwrap_or("").to_string();
    let pinned = root_key(&chosen)?;
    let card = crate::piv::open(reader, slot)?;
    let info = card.describe();
    let on_card = card.public_key()?.fingerprint();
    if on_card != fp {
        return fail(format!(
            "the key in slot {slot} is {on_card}, and this identity's root is {fp}: import the right key, or attach the right identity"
        ));
    }
    // One signature now, and the PIN it costs, in exchange for never recording a card that cannot
    // sign for this root.
    card_proves_it_holds(card.as_ref(), &pinned)?;
    let roots = v.plaintext["roots"].as_array_mut().ok_or_else(|| Fail("vault roots".into()))?;
    let entry = roots.iter_mut().find(|r| r["fingerprint"].as_str() == Some(&fp)).ok_or_else(|| Fail("the root went missing".into()))?;
    entry["holder"] = json!({ "kind": "piv", "mode": "imported", "slot": info.slot, "serial": info.serial, "reader": info.reader });
    save_vault(&v)?;
    eprintln!("{fp} now signs on card {} slot {}", info.serial.unwrap_or_else(|| "?".into()), info.slot);
    eprintln!("The vault still holds this root's key, so this is a card that signs rather than a card that is the identity: a lost card is an inconvenience, and a copied vault is still a copied identity. `pact id create --piv` is the other arrangement.");
    Ok(0)
}

pub fn id_create(name: &str, alg: &str, vault: &str, key_out: Option<&str>) -> Res<i32> {
    // Every reason this command can refuse is found before a person is asked for a passphrase and
    // before a vault exists on disk. The `--key-out` check used to sit after the vault was
    // written, which left a made identity behind and told the person it had failed.
    let (record, record_real) = record_of(vault);
    for (taken, really) in [(vault, real(vault)), (record.as_str(), record_real.clone())] {
        if Path::new(&really).exists() {
            return fail(format!("{taken} exists; a second identity goes in with --vault pointing elsewhere, or is a decision for later"));
        }
    }
    if let Some(path) = key_out {
        if Path::new(path).exists() {
            return fail(format!("{path} exists: the key is not written over a file"));
        }
        check_writable(Some(path))?;
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let alg = Alg::parse(alg).map_err(|e| Fail(e.why))?;
    let pass = passphrase(true)?;
    let now = now_or(None)?;
    let key = PrivateKey::generate(alg).map_err(|e| Fail(e.why))?;
    let cert = x509::build_root(name, &key, now, &x509::random_serial().map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.why))?;
    let fp = key.public().fingerprint();
    let mut plaintext = json!({
        "v": 2,
        "roots": [{ "fingerprint": fp, "cn": name, "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(&cert), "created": instant(now) }],
    });
    // Both files, or neither: a vault whose record could not be written is taken away again.
    let vault_real = real(vault);
    let files = [
        (vault, vault_real.as_str(), sealed_bytes(&pass, &plaintext)?),
        (record.as_str(), record_real.as_str(), sealed_bytes(&pass, &empty_record())?),
    ];
    crate::io::wipe(&mut plaintext);
    land_all(&files, &pass, false)?.iter_mut().for_each(crate::io::wipe);
    println!("{fp}");
    eprintln!("wrote {vault} (mode 0600): the root, and nothing else — written again only if a card takes the root");
    eprintln!("wrote {record} (mode 0600): the ledger and the contact book, under the same passphrase");
    eprintln!("The vault is the identity. There is no recovery: a lost vault, or a forgotten passphrase, is a lost identity. Keep a copy somewhere else (pact id backup).");
    if let Some(path) = key_out {
        // Exclusive, because the check above is a moment old by now: nothing else may have taken
        // this name, and nothing that did will be written over or followed.
        write_new_private(Path::new(path), pem("PRIVATE KEY", &key.to_pkcs8()).as_bytes())?;
        eprintln!();
        eprintln!("wrote {path} (mode 0600): this file IS the root key, in the clear.");
        eprintln!("  ykman piv keys import 9c {path}");
        eprintln!("  ykman piv certificates generate 9c --subject 'CN={name}'   # a certificate in the slot, so the key can be read back");
        eprintln!("  pact card-attach --vault {vault} --slot 9c");
        eprintln!("Destroy {path} once the card holds it. The vault keeps this key, which is what makes this arrangement recoverable and weaker than a root generated on the card.");
    }
    Ok(0)
}

pub struct IssueArgs<'a> {
    pub vault: &'a str,
    pub csr: &'a str,
    pub valid_days: i64,
    pub moving: bool,
    pub renew_only: bool,
    pub origin: Option<&'a str>,
    pub root: Option<&'a str>,
    pub yes: bool,
    pub out: Option<&'a str>,
    pub chain_out: Option<&'a str>,
    pub now: Option<&'a str>,
    /// Which reader, when the root is held on a card and this machine has more than one.
    pub reader: Option<&'a str>,
}

pub fn id_issue(a: IssueArgs<'_>) -> Res<i32> {
    let csr_der = read_der(a.csr)?;
    let request = csr::parse(&csr_der).map_err(|e| Fail(format!("{}: {}", a.csr, e.why)))?;
    let now = now_or(a.now)?;
    let v = open_vault(a.vault, false)?;
    let mut rec = open_record(&v)?;
    // No record here means no ledger here: this vault cannot say which leaf is live, so what it signs
    // is a replacement of whatever is (owner, 2026-09-26) — said before the question, not after.
    let replacing = !rec.found;
    let root = pick_root(&v.plaintext, a.root)?;
    // The entry and the certificate it keeps must be for the same key on either path, software or
    // card: a vault edited between the two would issue under a root no contact has.
    root_key(&root)?;
    // And where the leaf is going is checked before it is signed. A leaf signed, written into the
    // ledger, and then lost to a directory that does not exist would leave this identity's one live
    // leaf spoken for by a certificate nobody has.
    check_writable(a.out)?;
    check_writable(a.chain_out)?;
    let fp = root["fingerprint"].as_str().unwrap_or("").to_string();
    let ledger: Vec<Value> = rec.plaintext["ledger"].as_array().cloned().unwrap_or_default();
    let mine: Vec<&Value> = ledger.iter().filter(|l| l["root"].as_str() == Some(&fp)).collect();
    let host = x509::host_of(&request.endpoint).to_string();
    let known_endpoint = mine.iter().any(|l| l["endpoint"].as_str() == Some(request.endpoint.as_str()));
    let new_host = !mine.iter().any(|l| l["endpoint"].as_str().map(|e| x509::host_of(e) == host).unwrap_or(false));
    if a.renew_only && replacing {
        return fail(format!(
            "no record at {}: a renewal is for an endpoint the ledger knows, and the ledger is not here; restore the record, or issue a replacement with pact id issue",
            rec.path
        ));
    }
    if a.renew_only && !known_endpoint {
        return fail(format!(
            "{} is not in the ledger: a renewal is for an endpoint already issued to; use pact id issue",
            request.endpoint
        ));
    }
    let previous = mine.iter().filter_map(|l| l["not_before"].as_str().and_then(|t| parse_rfc3339(t).ok())).max();
    let (nb, na) = csr::validity(now, previous, a.valid_days).map_err(|e| Fail(e.why))?;

    eprintln!("identity    {} ({})", fp, root["cn"].as_str().unwrap_or(""));
    eprintln!(
        "endpoint    {}{}",
        request.endpoint,
        if replacing {
            "  (no ledger here to compare it with)"
        } else if new_host {
            "  NEW HOST: never issued to before"
        } else if known_endpoint {
            "  (renewal)"
        } else {
            "  (a new address on a known host)"
        }
    );
    eprintln!("origin      {}", a.origin.unwrap_or("(not given)"));
    eprintln!("host key    {} ({})", request.key.fingerprint(), request.key.alg().name());
    eprintln!("valid       {} to {}  ({} days)", instant(nb), instant(na), a.valid_days);
    if a.moving {
        eprintln!("move        the live leaf at the previous endpoint is superseded once contacts see this one");
    }
    if replacing {
        eprintln!("record      none at {}: this vault's ledger is not here, so it cannot say which leaf is live", rec.path);
        eprintln!(
            "replaces    whatever leaf this identity has live, wherever it is — contacts take the newest — and {} is started with this one",
            rec.path
        );
    }
    if !known_endpoint {
        // SPEC §9: a NEW ENDPOINT needs the passphrase again, even in an unlocked session — a new
        // host is only the loudest case of one. The vault was just opened with it; asking once
        // more is the deliberate friction, and `--yes` does not skip it: `--yes` answers the
        // question below, not this one. With PACT_PASSPHRASE_FILE the file is read again, so the
        // re-check proves the file still opens the vault rather than asking a person.
        let again = passphrase(false)?;
        if *again != *v.passphrase {
            return fail("the passphrase does not match: nothing signed");
        }
    }
    // The card is opened before the question, not after: a card that is absent, or holds another
    // key, is a thing to say now rather than after a person has agreed to a signature.
    let card = match card_holder(&root) {
        Some(h) => {
            let c = card_for(&root, a.reader)?;
            let i = c.describe();
            eprintln!(
                "held        on card {} slot {}{}",
                i.serial.clone().unwrap_or_else(|| "?".into()),
                i.slot,
                if h["serial"].as_str().is_some_and(|s| Some(s) != i.serial.as_deref()) {
                    "  (a different card from the one this identity was made on)"
                } else {
                    ""
                }
            );
            Some(c)
        }
        None => None,
    };
    if !confirm("Sign this leaf?", a.yes)? {
        eprintln!("nothing signed");
        return Ok(1);
    }
    let r = match &card {
        // A card-held root: the core checks the request and makes the bytes, the card signs them,
        // the core assembles. The one rule `wallet_issue` would have applied and cannot here —
        // one live leaf per identity — is applied just above, against the same ledger.
        Some(c) => {
            if let Some(why) = live_leaf_refusal(&mine, &request.endpoint, now, a.moving) {
                return fail(format!("bad_request: {why}"));
            }
            let mut out = issue_on_card(c.as_ref(), &root, &roots(&v.plaintext), &csr_der, now, previous, a.valid_days)?;
            // The endpoint and the dates, as the core's entry: never the leaf.
            out["ledger_entry"] = json!({
                "root": fp,
                "endpoint": out["endpoint"].clone(),
                "not_before": out["not_before"].clone(),
                "not_after": out["not_after"].clone(),
                "issued_at": instant(now),
            });
            out
        }
        None => core(
            "wallet_issue",
            json!({ "vault_plaintext": v.plaintext, "record_plaintext": rec.plaintext, "root_fingerprint": fp, "csr": b64u(&csr_der), "now": instant(now), "valid_days": a.valid_days, "move": a.moving }),
        )?,
    };
    for w in r["warnings"].as_array().cloned().unwrap_or_default() {
        eprintln!("note        {}", w.as_str().unwrap_or(""));
    }
    let mut entry = r["ledger_entry"].clone();
    if let Some(o) = a.origin {
        entry["origin"] = json!(o);
    }
    // The record is what a signing writes; the vault is never touched. (`open_record` refused a
    // record without a ledger before anything was signed.)
    rec.plaintext["ledger"].as_array_mut().ok_or_else(|| Fail(format!("{}: the ledger went missing", rec.path)))?.push(entry);
    save_record(&v, &rec)?;
    if replacing {
        eprintln!("started     {}: the ledger begins with this leaf", rec.path);
    }
    let leaf = from_b64u(r["der"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    write_output(a.out, &pem("CERTIFICATE", &leaf))?;
    if let Some(p) = a.chain_out {
        let root_der = from_b64u(root["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
        write_output(Some(p), &format!("{}{}", pem("CERTIFICATE", &leaf), pem("CERTIFICATE", &root_der)))?;
    }
    eprintln!("issued      {} for {}", x509::parse(&leaf).map(|c| c.public_key.fingerprint()).unwrap_or_default(), request.endpoint);
    Ok(0)
}

pub fn id_ledger(vault: &str, root: Option<&str>, json: bool) -> Res<i32> {
    // The vault first: it is what proves the passphrase (a record that is not there proves nothing)
    // and what refuses a mistyped path, which would otherwise read as an identity with no leaves.
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    if !r.found {
        eprintln!("no record at {}: this vault's ledger is not here", r.path);
    }
    let now = now_or(None)?;
    let ledger: Vec<Value> = r.plaintext["ledger"].as_array().cloned().unwrap_or_default();
    let filter = root.map(String::from);
    let rows: Vec<&Value> = ledger.iter().filter(|l| filter.as_deref().is_none_or(|f| l["root"].as_str() == Some(f))).collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(0);
    }
    if rows.is_empty() {
        println!("{}", if r.found { "no leaves issued" } else { "no ledger here" });
        return Ok(0);
    }
    // The current leaf of a root is the live one with the latest notBefore.
    let mut seen: Vec<&str> = rows.iter().filter_map(|l| l["root"].as_str()).collect();
    seen.sort_unstable();
    seen.dedup();
    let current: Vec<usize> = seen
        .iter()
        .filter_map(|fp| {
            let fp = *fp;
            rows.iter()
                .enumerate()
                .filter(|(_, l)| {
                    l["root"].as_str() == Some(fp) && l["not_after"].as_str().and_then(|t| parse_rfc3339(t).ok()).is_some_and(|t| t > now)
                })
                .max_by_key(|(_, l)| l["not_before"].as_str().and_then(|t| parse_rfc3339(t).ok()).unwrap_or(0))
                .map(|(i, _)| i)
        })
        .collect();
    for (i, l) in rows.iter().enumerate() {
        println!(
            "{} {}  {}  {} to {}  root {}{}",
            if current.contains(&i) { "*" } else { " " },
            l["issued_at"].as_str().unwrap_or("-"),
            l["endpoint"].as_str().unwrap_or("-"),
            l["not_before"].as_str().unwrap_or("-"),
            l["not_after"].as_str().unwrap_or("-"),
            l["root"].as_str().unwrap_or("-"),
            l["origin"].as_str().map(|o| format!("  asked by {o}")).unwrap_or_default()
        );
    }
    println!("* current");
    Ok(0)
}

pub fn id_show(vault: &str, root: Option<&str>, out: Option<&str>) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let r = pick_root(&v.plaintext, root)?;
    // What is printed here is what a contact pins, so it is the entry's own key or nothing.
    root_key(&r)?;
    let der = from_b64u(r["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    eprintln!(
        "{}  {}  created {}",
        r["fingerprint"].as_str().unwrap_or(""),
        r["cn"].as_str().unwrap_or(""),
        r["created"].as_str().unwrap_or("")
    );
    write_output(out, &pem("CERTIFICATE", &der))?;
    Ok(0)
}

pub fn id_backup(vault: &str, to: &str, force: bool) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    let (record_to, record_to_real) = record_of(to);
    let dests = [(to, real(to)), (record_to.as_str(), record_to_real.clone())];
    // A backup onto either of its own sources would replace the identity with a copy of itself — or,
    // onto the record, with the vault's bytes, and the ledger and contacts gone with no copy anywhere.
    for (shown, really) in &dests {
        for source in [&v.real, &r.real] {
            if really == source {
                return fail(format!(
                    "{shown} is {}: a backup goes somewhere other than the identity it copies",
                    if *source == v.real { vault } else { &r.path }
                ));
            }
        }
    }
    for (shown, really) in &dests {
        if Path::new(really).exists() && !force {
            return fail(format!("{shown} exists: a backup never writes over a file (pass --force to replace it)"));
        }
    }
    check_writable(Some(to))?;
    check_writable(Some(&record_to))?;
    // Both copies or neither, each proven to open before it counts (`land_all`).
    let mut files = vec![(to, dests[0].1.as_str(), read_input(&v.real)?)];
    if r.found {
        files.push((record_to.as_str(), dests[1].1.as_str(), read_input(&r.real)?));
    }
    land_all(&files, &v.passphrase, force)?.iter_mut().for_each(crate::io::wipe);
    eprintln!("copied {vault} to {to}; the copy opens");
    if r.found {
        eprintln!("copied {} to {record_to}; the copy opens", r.path);
    } else {
        eprintln!("no record at {}: the ledger and the contacts were not there to copy", r.path);
    }
    Ok(0)
}

pub fn id_restore(from: &str, vault: &str) -> Res<i32> {
    let (record, record_real) = record_of(vault);
    for (taken, really) in [(vault, real(vault)), (record.as_str(), record_real.clone())] {
        if Path::new(&really).exists() {
            return fail(format!("{taken} exists: restore goes to a path that is empty"));
        }
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let v = open_vault(from, false)?;
    let (record_from, record_from_real) = record_of(from);
    let with_record = Path::new(&record_from_real).exists();
    // Both, or neither: a vault landed without the record it came with would run on an empty ledger.
    let mut files = vec![(vault, real(vault), read_input(&v.real)?)];
    if with_record {
        files.push((record.as_str(), record_real.clone(), read_input(&record_from_real)?));
    }
    let files: Vec<(&str, &str, Vec<u8>)> = files.iter().map(|(a, b, c)| (*a, b.as_str(), c.clone())).collect();
    let mut landed = land_all(&files, &v.passphrase, false)?;
    eprint!("restored {from} to {vault}: {} identities", roots(&v.plaintext).len());
    if let Some(r) = landed.get(1) {
        eprintln!(
            "; and its record {record_from} to {record}: {} leaves, {} contacts",
            r["ledger"].as_array().map_or(0, |a| a.len()),
            r["contacts"].as_array().map_or(0, |a| a.len())
        );
    } else {
        eprintln!("; no record beside {from}, so the next leaf this vault issues replaces whatever was live");
    }
    landed.iter_mut().for_each(crate::io::wipe);
    Ok(0)
}

pub fn contacts_export(vault: &str) -> Res<i32> {
    // The vault first, as `id ledger`: it proves the passphrase and refuses a mistyped path.
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    if !r.found {
        eprintln!("no record at {}: this vault's contact book is not here", r.path);
    }
    println!("{}", serde_json::to_string_pretty(&r.plaintext["contacts"])?);
    Ok(0)
}

fn contact_line(c: &Value) -> String {
    format!("{}  {}  {}", c["root"].as_str().unwrap_or("?"), c["endpoint"].as_str().unwrap_or("?"), c["name"].as_str().unwrap_or(""))
}

/// A root fingerprint as §2 writes one: `sha256:` and the base64url of a 32-byte hash.
fn is_fingerprint(v: &Value) -> bool {
    v.as_str().is_some_and(|f| {
        f.strip_prefix("sha256:").is_some_and(|b| b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
    })
}

/// A contact's `root_cert` is what proves a leaf of theirs off the wire (an archive's, say), so it
/// is worth exactly as much as its binding to the fingerprint the book pins. A certificate that
/// hashes to something else is a former host's certificate under a friend's name: refused here, not
/// stored and shown later as a difference.
fn check_root_cert(c: &Value) -> Res<()> {
    let Some(cert) = c["root_cert"].as_str() else { return Ok(()) };
    let root = c["root"].as_str().unwrap_or("?");
    let parsed =
        core("parse_certificate", json!({ "der": cert })).map_err(|e| Fail(format!("{root}: root_cert does not parse ({})", e.0)))?;
    if parsed["fingerprint"].as_str() != Some(root) {
        return fail(format!(
            "{root}: root_cert is a certificate for {}, not for the root this contact is pinned by",
            parsed["fingerprint"].as_str().unwrap_or("an unreadable key")
        ));
    }
    if parsed["kind"].as_str() != Some("root") {
        return fail(format!(
            "{root}: root_cert is not a root certificate ({})",
            parsed["profile_error"].as_str().unwrap_or("not self-signed")
        ));
    }
    Ok(())
}

pub fn contacts_import(vault: &str, file: &str, yes: bool) -> Res<i32> {
    let incoming: Vec<Value> =
        serde_json::from_slice(&read_input(file)?).map_err(|e| Fail(format!("{file}: a JSON array of contacts ({e})")))?;
    for c in &incoming {
        if !is_fingerprint(&c["root"]) || c["endpoint"].as_str().is_none() {
            return fail(format!("{file}: every contact needs a root fingerprint and an endpoint"));
        }
        check_root_cert(c)?;
    }
    // The vault first: a record is sealed under the passphrase it proves, never under one nothing
    // checked (an absent record used to be started under whatever was typed).
    let v = open_vault(vault, false)?;
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
    let now = instant(now_or(None)?);
    let merged: Vec<Value> = incoming
        .into_iter()
        .map(|mut c| {
            if c.get("added").is_none() {
                c["added"] = json!(mine.iter().find(|m| m["root"] == c["root"]).and_then(|m| m["added"].as_str()).unwrap_or(&now));
            }
            c
        })
        .collect();
    r.plaintext["contacts"] = Value::Array(merged);
    save_record(&v, &r)?;
    eprintln!("written");
    Ok(0)
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
        let d = std::env::temp_dir().join(format!("pact-land-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // A vault and its record land together or not at all. The vault used to be written first and
    // the record after, so a record that failed left a made identity the rerun refused as "exists".
    #[test]
    fn a_pair_that_does_not_prove_leaves_nothing_behind() {
        let d = dir("prove");
        let (vault, record) = (d.join("a.pact-vault.json"), d.join("a.pact-record.json"));
        let (vs, rs) = (vault.to_string_lossy().into_owned(), record.to_string_lossy().into_owned());
        let good = sealed("right", json!({ "v": 2, "roots": [] }));
        let other = sealed("other", json!({ "v": 2, "ledger": [], "contacts": [] }));
        let why = land_all(&[(&vs, &vs, good.clone()), (&rs, &rs, other)], "right", false).expect_err("the record does not open").0;
        assert!(!vault.exists() && !record.exists(), "left behind after: {why}");
        // …so the same pair can be landed again, and a pair that proves stays.
        let rec = sealed("right", json!({ "v": 2, "ledger": [], "contacts": [] }));
        land_all(&[(&vs, &vs, good), (&rs, &rs, rec)], "right", false).unwrap();
        assert!(vault.exists() && record.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    // The second name taken: the first file this call made goes, and what was there is untouched.
    #[test]
    fn a_pair_whose_second_name_is_taken_leaves_the_first_unmade() {
        let d = dir("taken");
        let (vault, record) = (d.join("b.pact-vault.json"), d.join("b.pact-record.json"));
        std::fs::write(&record, b"someone else's").unwrap();
        let (vs, rs) = (vault.to_string_lossy().into_owned(), record.to_string_lossy().into_owned());
        let why = land_all(
            &[
                (&vs, &vs, sealed("p", json!({ "v": 2, "roots": [] }))),
                (&rs, &rs, sealed("p", json!({ "v": 2, "ledger": [], "contacts": [] }))),
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
        let (vault, record) = (d.join("c.pact-vault.json"), d.join("c.pact-record.json"));
        std::fs::write(&vault, b"old vault").unwrap();
        std::fs::write(&record, b"old record").unwrap();
        let (vs, rs) = (vault.to_string_lossy().into_owned(), record.to_string_lossy().into_owned());
        let bad = sealed("other", json!({ "v": 2, "ledger": [], "contacts": [] }));
        land_all(&[(&vs, &vs, sealed("p", json!({ "v": 2, "roots": [] }))), (&rs, &rs, bad)], "p", true)
            .expect_err("the record does not open");
        assert_eq!(std::fs::read(&vault).unwrap(), b"old vault");
        assert_eq!(std::fs::read(&record).unwrap(), b"old record");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2, "a temporary was left");
        std::fs::remove_dir_all(&d).unwrap();
    }

    // The record's name follows the vault's, so a person who kept one file finds the other.
    #[test]
    fn a_record_is_named_after_its_vault() {
        assert_eq!(record_path("alina.pact-vault.json"), "alina.pact-record.json");
        assert_eq!(record_path("/home/a/alina.pact-vault.json"), "/home/a/alina.pact-record.json");
        assert_eq!(record_path("v.json"), "v.pact-record.json");
        assert_eq!(record_path("vault"), "vault.pact-record.json");
    }
}

#[cfg(test)]
mod card_tests {
    //! A card-held root, proven without a card: the fake signs a digest exactly as PIV's GENERAL
    //! AUTHENTICATE does, so everything above the trait — the seam, the profile, the rules, the
    //! refusals — is the real thing.
    use super::*;
    use crate::piv::fake::FakeCard;
    use pact_identity::csr as csr_mod;
    use pact_identity::keys::{Alg, PrivateKey};

    const NOW: i64 = 1_789_000_000;
    const ENDPOINT: &str = "https://agent.alina.example/mcp";

    fn root_of(card: &FakeCard) -> Res<(Vec<u8>, Value)> {
        let (cert, key) = root_from_card(card, "Alina Rao", NOW)?;
        let root = json!({
            "fingerprint": key.fingerprint(),
            "cn": "Alina Rao",
            "cert": b64u(&cert),
            "created": instant(NOW),
            "holder": { "kind": "piv", "mode": "generated", "slot": "9c", "serial": "1", "reader": "Fake Reader" },
        });
        Ok((cert, root))
    }

    fn a_request(endpoint: &str) -> Vec<u8> {
        let host = PrivateKey::generate(Alg::Ed25519).expect("a host key");
        csr_mod::csr_new("A Host", &host, endpoint, None).expect("a request")
    }

    #[test]
    fn a_root_the_card_signed_is_a_root() {
        let card = FakeCard::p256("7777");
        let (cert, root) = root_of(&card).expect("a root");
        // §14.2 rule 1 refuses a single self-signed certificate as a chain, so a chain of it
        // twice is what asks "is this a root of the profile?": rule 2 is where a bad one would die.
        let r = core("validate_chain", json!({ "chain": [b64u(&cert), b64u(&cert)], "now": instant(NOW) })).expect("an answer");
        assert_eq!(r["ok"], json!(false), "a root is not a chain");
        assert_eq!(r["rule"], json!(1), "it fails for being one certificate, not for its profile: {r}");
        let parsed = core("parse_certificate", json!({ "der": b64u(&cert) })).expect("parsed");
        assert_eq!(parsed["kind"], json!("root"), "the profile accepts it: {parsed}");
        assert_eq!(parsed["profile_error"], json!(null));
        assert_eq!(parsed["fingerprint"].as_str(), root["fingerprint"].as_str());
    }

    #[test]
    fn a_leaf_the_card_signed_validates_to_that_root_at_its_endpoint() {
        let card = FakeCard::p256("7777");
        let (cert, root) = root_of(&card).expect("a root");
        let out = issue_on_card(&card, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365).expect("a leaf");
        let r = core(
            "validate_chain",
            json!({ "chain": [out["der"].clone(), b64u(&cert)], "now": instant(NOW), "expected_root": root["fingerprint"], "expected_endpoint": ENDPOINT }),
        )
        .expect("an answer");
        assert_eq!(r["ok"], json!(true), "the chain validates: {r}");
        assert_eq!(r["endpoint"].as_str(), Some(ENDPOINT));
    }

    #[test]
    fn a_card_that_refuses_says_which_refusal_it_was() {
        let honest = FakeCard::p256("7777");
        let root = root_of(&honest).expect("a root").1;
        let csr = a_request(ENDPOINT);

        // An empty slot cannot even be read.
        let e = root_from_card(&FakeCard::empty_slot(), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no certificate"), "{}", e.0);

        // A slot holding an RSA key: the CARD refuses the parameters (6A80), and that message says
        // the profile signs with P-256. This is not the wallet's own guard — see the test below.
        let e = root_from_card(&FakeCard::rsa(), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("P-256"), "{}", e.0);

        // A wrong PIN comes back with the tries left, because that is what a person needs next.
        let e = issue_on_card(&FakeCard::wrong_pin_for(&honest), &root, std::slice::from_ref(&root), &csr, NOW, None, 365).unwrap_err();
        assert!(e.0.contains("wrong PIN") && e.0.contains("2 tries left"), "{}", e.0);
    }

    // The guard on a card-held root's algorithm had no test. The one above that names P-256 passes
    // on the CARD's refusal of RSA parameters (status 6A80, whose text also says P-256) and never
    // reaches the guard; a slot that reports an Ed25519 key — which a newer PIV token can — does.
    #[test]
    fn a_card_reporting_an_ed25519_key_is_refused_by_the_guard_itself() {
        let e = root_from_card(&FakeCard::reports_ed25519(), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("that slot holds a ed25519 key") && e.0.contains("a card-held root is P-256"), "{}", e.0);
    }

    // §9: a wallet refuses a request whose key is a root. The software path hands the core every
    // root in the vault; the card path handed it only the root that was issuing, so on a card-held
    // identity a request carrying a SIBLING root's key was given a leaf.
    #[test]
    fn a_request_carrying_a_sibling_roots_key_is_refused_on_the_card_path_too() {
        let card = FakeCard::p256("7777");
        let root = root_of(&card).expect("a root").1;
        let sibling_key = PrivateKey::generate(Alg::Ed25519).expect("a key");
        let sibling_cert = x509::build_root("Alina at work", &sibling_key, NOW, &x509::serial_of("sibling")).expect("a root");
        let sibling = json!({ "fingerprint": sibling_key.public().fingerprint(), "cn": "Alina at work", "cert": b64u(&sibling_cert) });
        let csr = csr_mod::csr_new("A Host", &sibling_key, ENDPOINT, None).expect("a request");

        let e = issue_on_card(&card, &root, &[root.clone(), sibling], &csr, NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("the request's key is a root"), "{}", e.0);
    }

    #[test]
    fn another_card_signs_nothing_for_this_identity() {
        let root = root_of(&FakeCard::p256("7777")).expect("a root").1;
        // A second card, or the same slot generated again: a different key, and the check is the
        // fingerprint rather than the serial, which a card need not even report.
        let e = match_root(&root, &FakeCard::p256("8888")).unwrap_err();
        assert!(e.0.contains("a different card, or that slot has been generated again"), "{}", e.0);
        assert!(match_root(&root, &FakeCard::p256("7777")).is_err(), "a fake card's key is fresh each time, so this too is a mismatch");
    }

    #[test]
    fn a_card_held_identity_writes_no_key_into_the_vault() {
        let card = FakeCard::p256("7777");
        let (_, root) = root_of(&card).expect("a root");
        let plaintext = json!({ "v": 2, "roots": [root.clone()] });
        let text = serde_json::to_string(&plaintext).expect("json");
        assert!(!text.contains("pkcs8"), "no key material anywhere in the vault: {text}");
        assert_eq!(card_holder(&root).and_then(|h| h["mode"].as_str()), Some("generated"));
        // And the thing it does keep is the certificate, which is public.
        assert!(root["cert"].as_str().is_some());
    }

    #[test]
    fn one_live_leaf_is_refused_the_same_way_on_both_paths() {
        // The core applies this rule for a software root inside `wallet_issue`; the card path
        // applies it in `live_leaf_refusal`, because there is no key to hand the core. The two must
        // not drift, so here they are asked the same question about the same ledger.
        let key = PrivateKey::generate(Alg::P256).expect("a key");
        let cert = x509::build_root("Alina Rao", &key, NOW, &x509::serial_of("both-paths")).expect("a root");
        let fp = key.public().fingerprint();
        let software =
            json!({ "fingerprint": fp, "cn": "Alina Rao", "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(&cert), "created": instant(NOW) });
        let first = core(
            "wallet_issue",
            json!({ "vault_plaintext": { "v": 2, "roots": [software.clone()] }, "record_plaintext": { "v": 2, "ledger": [] }, "root_fingerprint": fp, "csr": b64u(&a_request(ENDPOINT)), "now": instant(NOW), "valid_days": 365 }),
        )
        .expect("a first leaf");
        let ledger = vec![first["ledger_entry"].clone()];
        let mine: Vec<&Value> = ledger.iter().collect();

        let elsewhere = "https://agent.alina.example/second/mcp";
        let core_says = core(
            "wallet_issue",
            json!({ "vault_plaintext": { "v": 2, "roots": [software] }, "record_plaintext": { "v": 2, "ledger": ledger.clone() }, "root_fingerprint": fp, "csr": b64u(&a_request(elsewhere)), "now": instant(NOW + 10), "valid_days": 365 }),
        )
        .unwrap_err();
        let cli_says = live_leaf_refusal(&mine, elsewhere, NOW + 10, false).expect("the card path refuses too");
        assert!(core_says.0.contains(&cli_says), "the same words on both paths:\n  core: {}\n  card: {cli_says}", core_says.0);
        // And a move says so on both.
        assert!(live_leaf_refusal(&mine, elsewhere, NOW + 10, true).is_none(), "--move allows it, as the core does");
        // A renewal at the same endpoint is never a second home.
        assert!(live_leaf_refusal(&mine, ENDPOINT, NOW + 10, false).is_none());
    }

    /// A card whose certificate names one key and whose slot holds another. Nothing it signs may
    /// become a certificate: the leaf would carry the pinned root as its issuer and a stranger's
    /// signature, and no contact could ever validate it.
    #[test]
    fn a_card_whose_certificate_and_key_disagree_gets_no_leaf() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let hostile = FakeCard::signs_with_another_key(&honest, "7777");
        // Every check that reads the certificate passes: the certificate is this root's.
        match_root(&root, &hostile).expect("the certificate in the slot is this identity's root");
        // The signature is the only thing that tells, and it is checked before anything is built.
        let e = issue_on_card(&hostile, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("does not verify"), "{}", e.0);
    }

    /// The check passes and the signature is a stranger's: the card was pulled and replaced, or the
    /// slot was generated again, between the two. This is the one that ends in an artefact if the
    /// signature is not verified — a leaf in the ledger that no contact can validate.
    #[test]
    fn a_card_that_swaps_its_key_after_the_check_signs_nothing_that_is_kept() {
        let honest = FakeCard::p256("7777");
        let (cert, root) = root_of(&honest).expect("a root");
        let hostile = FakeCard::swapped_after(&honest, 1);
        match issue_on_card(&hostile, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365) {
            Err(e) => assert!(e.0.contains("does not verify"), "{}", e.0),
            Ok(out) => {
                // What was assembled, and what it is worth, before failing — the defect is the
                // artefact, not the exit code.
                let r = core(
                    "validate_chain",
                    json!({ "chain": [out["der"].clone(), b64u(&cert)], "now": instant(NOW), "expected_root": root["fingerprint"] }),
                )
                .expect("an answer");
                panic!("a leaf was assembled from a card that swapped its key after the check; against the pinned root it is {r}");
            }
        }
    }

    /// Taken out of the reader between the check and the signature: the refusal says so, and
    /// nothing is assembled from a signature that never came.
    #[test]
    fn a_card_that_leaves_the_reader_mid_ceremony_says_so() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let gone = FakeCard::vanishes_after(1);
        let e = issue_on_card(&gone, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no longer in") || e.0.contains("a different card"), "{}", e.0);
        // And a card gone before the first word is the same refusal, not a panic.
        let e = root_from_card(&FakeCard::vanishes_after(0), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no longer in"), "{}", e.0);
    }

    /// Attaching a card records that every later signature comes from it, so the card proves it can
    /// sign before that is written down. The certificate in the slot is not that proof: this is the
    /// card `card-attach` used to wave through, and the failure would then have arrived at the
    /// first issuance, one PIN try at a time.
    #[test]
    fn attaching_a_card_that_only_holds_the_certificate_is_refused() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let pinned = root_key(&root).expect("the pinned key");
        card_proves_it_holds(&honest, &pinned).expect("the card that made this root can sign for it");
        let e = card_proves_it_holds(&FakeCard::signs_with_another_key(&honest, "8888"), &pinned).map(|_| ()).unwrap_err();
        assert!(e.0.contains("does not verify"), "{}", e.0);
        let e = card_proves_it_holds(&FakeCard::vanishes_after(0), &pinned).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no longer in"), "{}", e.0);
    }

    /// A vault whose entry and whose certificate are for different keys is not an identity: it
    /// would issue under a key no contact pinned, and print a certificate nobody can check against
    /// the fingerprint they were given. Both halves are read together, everywhere.
    #[test]
    fn a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let stranger = root_of(&FakeCard::p256("8888")).expect("another root").1;
        let mut edited = root.clone();
        edited["cert"] = stranger["cert"].clone();
        let e = root_key(&edited).map(|_| ()).unwrap_err();
        assert!(e.0.contains("the vault has been edited"), "{}", e.0);
        let e =
            issue_on_card(&honest, &edited, std::slice::from_ref(&edited), &a_request(ENDPOINT), NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("the vault has been edited"), "{}", e.0);
    }
}
