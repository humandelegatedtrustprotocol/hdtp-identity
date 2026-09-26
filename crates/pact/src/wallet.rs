//! The wallet half: a root in a vault, leaves issued from it under SPEC §9's rules, the ledger, the
//! contact book. The rules live in the core's `wallet_issue`; this file adds the terminal's
//! discipline — the passphrase from a prompt, the vault owner-only, nothing a root key ever printed.
//!
//! An identity is two files under one passphrase (SPEC §9). The **vault** is the root and nothing
//! else — `<name>.pact-vault.json`, written when the identity is made and never again, the copy a
//! person keeps. The **record** beside it — `<name>.pact-record.json` — is the ledger and the
//! contact book, and is what every signing writes. A vault carried to a new machine without its
//! record starts one with an empty ledger: that is the lost path, and there is nothing to convert.
use crate::io::{
    check_writable, confirm, core, fail, instant, now_or, passphrase, pem, read_der, read_input, write_new_private, write_output,
    write_private, Fail, Res,
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
    path: String,
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
    path: String,
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

fn open_vault(path: &str, confirm_passphrase: bool) -> Res<Vault> {
    let raw = read_input(path)?;
    let doc: Value = serde_json::from_slice(&raw).map_err(|e| Fail(format!("{path}: not a vault document ({e})")))?;
    let passphrase = passphrase(confirm_passphrase)?;
    let plaintext = core("vault_open", json!({ "passphrase": passphrase.as_str(), "vault": doc }))?["plaintext"].take();
    // The core refuses an earlier generation; this refuses a document of this one that carries what
    // belongs in the record, because nothing here would read it and a person would think it kept.
    if plaintext.get("ledger").is_some() || plaintext.get("contacts").is_some() {
        return fail(format!(
            "{path}: a vault is the root and nothing else; this one carries a ledger or contacts, which belong in the record beside it"
        ));
    }
    Ok(Vault { path: path.to_string(), passphrase, plaintext })
}

/// The record beside a vault, under the vault's passphrase. No file there is not an error: a vault
/// brought to a machine without its record — the copy a person kept — starts one with an empty
/// ledger and says so, and the first signing lands it.
fn open_record(v: &Vault) -> Res<Record> {
    open_record_with(&record_path(&v.path), &v.passphrase)
}

fn open_record_with(path: &str, passphrase: &str) -> Res<Record> {
    if !Path::new(path).exists() {
        eprintln!("no record at {path}: starting one with an empty ledger and no contacts");
        return Ok(Record { path: path.to_string(), plaintext: empty_record() });
    }
    let raw = read_input(path)?;
    let doc: Value = serde_json::from_slice(&raw).map_err(|e| Fail(format!("{path}: not a record document ({e})")))?;
    let plaintext = core("vault_open", json!({ "passphrase": passphrase, "vault": doc }))?["plaintext"].take();
    Ok(Record { path: path.to_string(), plaintext })
}

fn sealed_bytes(passphrase: &str, plaintext: &Value) -> Res<Vec<u8>> {
    let sealed = core("vault_seal", json!({ "passphrase": passphrase, "plaintext": plaintext }))?["vault"].take();
    Ok(format!("{}\n", serde_json::to_string_pretty(&sealed)?).into_bytes())
}

fn save_vault(v: &Vault) -> Res<()> {
    write_private(Path::new(&v.path), &sealed_bytes(&v.passphrase, &v.plaintext)?)
}

/// The first write of a new identity's vault: exclusive, because `id create` refused a path that
/// was taken and that refusal has to still be true at the moment the file appears. A later save
/// (`save_vault`) is a card attached: the root's entry changes, and nothing else ever does.
fn save_new_vault(v: &Vault) -> Res<()> {
    write_new_private(Path::new(&v.path), &sealed_bytes(&v.passphrase, &v.plaintext)?)
}

fn save_record_with(passphrase: &str, r: &Record) -> Res<()> {
    write_private(Path::new(&r.path), &sealed_bytes(passphrase, &r.plaintext)?)
}

fn save_record(v: &Vault, r: &Record) -> Res<()> {
    save_record_with(&v.passphrase, r)
}

fn save_new_record(v: &Vault, r: &Record) -> Res<()> {
    write_new_private(Path::new(&r.path), &sealed_bytes(&v.passphrase, &r.plaintext)?)
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

/// How a root is held. A vault entry with a `pkcs8` is software; one with a `holder` is a card, and
/// then the vault holds the certificate and the ledger and no key at all — there is nothing to hold,
/// which is the whole point of the arrangement.
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
    let record = record_path(vault);
    for taken in [vault, record.as_str()] {
        if Path::new(taken).exists() {
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
    let v = Vault { path: vault.to_string(), passphrase: pass, plaintext };
    save_new_vault(&v)?;
    save_new_record(&v, &Record { path: record.clone(), plaintext: empty_record() })?;
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
    let record = record_path(vault);
    for taken in [vault, record.as_str()] {
        if Path::new(taken).exists() {
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
    let plaintext = json!({
        "v": 2,
        "roots": [{ "fingerprint": fp, "cn": name, "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(&cert), "created": instant(now) }],
    });
    let v = Vault { path: vault.to_string(), passphrase: pass, plaintext };
    save_new_vault(&v)?;
    save_new_record(&v, &Record { path: record.clone(), plaintext: empty_record() })?;
    println!("{fp}");
    eprintln!("wrote {vault} (mode 0600): the root, and nothing else — this file is never written again");
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
        if new_host {
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
    // The record is what a signing writes; the vault is never touched.
    rec.plaintext["ledger"].as_array_mut().ok_or_else(|| Fail("record ledger".into()))?.push(entry);
    save_record(&v, &rec)?;
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
    // The record alone: the ledger is there, and the root's key has no reason to be unsealed.
    let pass = passphrase(false)?;
    let r = open_record_with(&record_path(vault), &pass)?;
    let now = now_or(None)?;
    let ledger: Vec<Value> = r.plaintext["ledger"].as_array().cloned().unwrap_or_default();
    let filter = root.map(String::from);
    let rows: Vec<&Value> = ledger.iter().filter(|l| filter.as_deref().is_none_or(|f| l["root"].as_str() == Some(f))).collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(0);
    }
    if rows.is_empty() {
        println!("no leaves issued");
        return Ok(0);
    }
    // The current leaf of a root is the live one with the latest notBefore.
    let mut seen: Vec<&str> = rows.iter().filter_map(|l| l["root"].as_str()).collect();
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
    let (record, record_to) = (record_path(vault), record_path(to));
    let with_record = Path::new(&record).exists();
    for taken in [to, record_to.as_str()] {
        if Path::new(taken).exists() && !force {
            return fail(format!("{taken} exists: a backup never writes over a file (pass --force to replace it)"));
        }
    }
    check_writable(Some(to))?;
    check_writable(Some(&record_to))?;
    let v = open_vault(vault, false)?;
    // Each copy exclusive unless `--force` said otherwise: the check above is a moment old, and
    // what is at that name might be the only copy of another identity. And each proven to open.
    let mut pairs = vec![(vault, to)];
    if with_record {
        pairs.push((record.as_str(), record_to.as_str()));
    }
    for (from, dest) in pairs {
        let raw = read_input(from)?;
        match force {
            false => write_new_private(Path::new(dest), &raw)?,
            true => write_private(Path::new(dest), &raw)?,
        }
        let doc: Value = serde_json::from_slice(&read_input(dest)?)?;
        core("vault_open", json!({ "passphrase": v.passphrase.as_str(), "vault": doc }))?;
    }
    eprintln!("copied {vault} to {to}; the copy opens");
    if with_record {
        eprintln!("copied {record} to {record_to}; the copy opens");
    } else {
        eprintln!("no record at {record}: the ledger and the contacts were not there to copy");
    }
    Ok(0)
}

pub fn id_restore(from: &str, vault: &str) -> Res<i32> {
    let (record_from, record) = (record_path(from), record_path(vault));
    let with_record = Path::new(&record_from).exists();
    for taken in [vault, record.as_str()] {
        if Path::new(taken).exists() {
            return fail(format!("{taken} exists: restore goes to a path that is empty"));
        }
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let v = open_vault(from, false)?;
    land_and_prove(Path::new(vault), &read_input(from)?, &v.passphrase)?;
    eprint!("restored {from} to {vault}: {} identities", roots(&v.plaintext).len());
    if with_record {
        land_and_prove(Path::new(&record), &read_input(&record_from)?, &v.passphrase)?;
        let r = open_record_with(&record, &v.passphrase)?;
        eprintln!(
            "; and its record to {record}: {} leaves, {} contacts",
            r.plaintext["ledger"].as_array().map_or(0, |a| a.len()),
            r.plaintext["contacts"].as_array().map_or(0, |a| a.len())
        );
    } else {
        eprintln!("; no record beside {from}, so the ledger starts empty at the first signing");
    }
    Ok(0)
}

/// Writes a vault where there is none and proves that what is now ON DISK opens. A vault that does
/// not prove is taken away again: it used to stay, and the next restore to the same path was then
/// refused — "exists" — by a file of unknown validity that the failed run had put there itself.
/// Only a file this call created is removed; `write_new_private` fails, and nothing is touched,
/// when the name was already taken.
fn land_and_prove(vault: &Path, bytes: &[u8], passphrase: &str) -> Res<()> {
    write_new_private(vault, bytes)?;
    let proven = (|| -> Res<()> {
        let doc: Value = serde_json::from_slice(&read_input(&vault.to_string_lossy())?)?;
        core("vault_open", json!({ "passphrase": passphrase, "vault": doc }))?;
        Ok(())
    })();
    proven.map_err(|e| {
        let _ = std::fs::remove_file(vault);
        Fail(format!(
            "{}: written, and what was written did not open ({}); it has been removed, so the restore can be run again",
            vault.display(),
            e.0
        ))
    })
}

pub fn contacts_export(vault: &str) -> Res<i32> {
    let pass = passphrase(false)?;
    let r = open_record_with(&record_path(vault), &pass)?;
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
    let pass = passphrase(false)?;
    let mut r = open_record_with(&record_path(vault), &pass)?;
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
    save_record_with(&pass, &r)?;
    eprintln!("written");
    Ok(0)
}

#[cfg(test)]
mod restore_tests {
    use super::*;

    // `id restore` writes the vault and THEN proves it opens. When the proof failed the file stayed,
    // so the next restore to that path was refused — "exists" — by a file of unknown validity that
    // the failed run had put there itself.
    #[test]
    fn a_restore_that_does_not_prove_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("pact-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sealed = core("vault_seal", json!({ "passphrase": "right", "plaintext": { "v": 2, "roots": [] }, "kdf": { "name": "argon2id", "m_kib": 8192, "t": 1, "p": 1 } })).unwrap()["vault"].take();
        let bytes = serde_json::to_vec(&sealed).unwrap();

        let path = dir.join("vault.json");
        let why = land_and_prove(&path, &bytes, "wrong").expect_err("the wrong passphrase proves nothing").0;
        assert!(!path.exists(), "the unproven vault was left at {}: {why}", path.display());

        // …so the same path can be restored to again, and a vault that does prove stays.
        land_and_prove(&path, &bytes, "right").unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
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
