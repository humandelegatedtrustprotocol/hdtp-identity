//! The vault (SPEC §9; CONTRACT §6): two documents under Argon2id and AES-256-GCM with the
//! document's header as AAD — the FILE, the root and nothing else, and the RECORD, the issued-leaf
//! ledger and the contact book. Shared by the wallet page and the CLI.
use crate::canonical::{canonical, in_order};
use crate::csr;
use crate::keys::PrivateKey;
use crate::ledger::{self, is_fingerprint};
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::stranger;
use crate::util::{b64u, err, from_b64u, Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

pub const FORMAT: &str = "pact-vault/1";
/// The plaintext generation both documents carry: the file (the root and nothing else) and the
/// record (the ledger and the contacts). There is no earlier one to open: a `v` that is not this is
/// refused at both ends, sealing and opening, and nothing converts.
pub const PLAINTEXT_V: u64 = 2;

fn plaintext_v(plaintext: &Value) -> Option<u64> {
    plaintext.get("v").and_then(|v| v.as_u64())
}

const GENERATION: &str = "a vault plaintext is v 2: the root, or the record";
const FILE_MEMBERS: &[&str] = &["v", "roots", "prf", "passkey"];
const RECORD_MEMBERS: &[&str] = &["v", "roots", "ledger", "contacts", "passkey", "backup_verified_at"];

/// The file's plaintext as CONTRACT §6 has it, or the refusal that names what is wrong with it.
/// Held here, where the rules read it, and not at `seal`/`open`: those carry the documents a live
/// wallet already keeps, and a stricter open would lock a person out of one.
pub fn check_file(vault: &Value) -> Result<()> {
    // Absent or null is `<name> is required`, as CONTRACT §0 has every absent member (S1-2).
    if vault.is_null() {
        return err("bad_request", "vault_plaintext is required");
    }
    let Some(doc) = vault.as_object() else { return err("bad_request", "vault_plaintext is required: the root lives there") };
    if doc.contains_key("ledger") || doc.contains_key("contacts") {
        return err("bad_request", "a vault holds the root and nothing else: its ledger and contacts belong in the record");
    }
    if plaintext_v(vault) != Some(PLAINTEXT_V) {
        return err("bad_request", GENERATION);
    }
    if let Some(k) = stranger(doc, FILE_MEMBERS) {
        return err("bad_request", format!("vault_plaintext holds v, roots, prf and passkey, and nothing else: {k}"));
    }
    // Then each member, as CONTRACT §6 types it, in the order VaultPlaintext lists them. Read as their
    // types were never read: a root's key given as a number was a card-held root here and `arguments
    // do not read` in the Go port, a root that was not an object was skipped here, and a `prf` of any
    // type was carried (F18, R31).
    read_roots(doc.get("roots"), "vault", true)?;
    if let Some(prf) = doc.get("prf") {
        if prf.as_str().and_then(|p| from_b64u(p).ok()).is_none_or(|b| b.len() != 32) {
            return err("bad_request", "the vault's prf does not read");
        }
    }
    read_passkey(doc.get("passkey"), "vault")
}

const ROOT_REQUIRED: &[&str] = &["fingerprint", "cn", "cert", "created"];
const ROOT_MEMBERS: &[&str] = &["fingerprint", "cn", "alg", "cert", "created", "pkcs8", "holder", "rebound_at"];

/// A document's `roots`, each entry read as CONTRACT §6's `VaultRoot`: a list, each entry an object
/// whose `fingerprint` is a fingerprint, `cn` and `cert` strings and `created` an instant, whose
/// `alg`, `pkcs8`, `holder` and `rebound_at` are of their types where present, and that holds nothing
/// else. The first that does not read is named by its index and member, as a ledger entry is.
/// `whose` is `vault` or `record`; the file must have `roots`, and the record may leave it out.
fn read_roots(roots: Option<&Value>, whose: &str, required: bool) -> Result<()> {
    let entries = match roots {
        None if !required => return Ok(()),
        Some(Value::Array(entries)) => entries,
        _ => return err("bad_request", format!("the {whose}'s roots is a list")),
    };
    for (i, r) in entries.iter().enumerate() {
        let Some(o) = r.as_object() else { return err("bad_request", format!("the {whose}'s root {i} does not read")) };
        let unread = |m: &str| err("bad_request", format!("the {whose}'s root {i} does not read: {m}"));
        for m in ROOT_REQUIRED {
            let Some(text) = o.get(*m).and_then(|v| v.as_str()) else { return unread(m) };
            let wrong = match *m {
                "fingerprint" => !is_fingerprint(text),
                "created" => parse_rfc3339(text).is_err(),
                _ => false,
            };
            if wrong {
                return unread(m);
            }
        }
        for (m, reads) in [
            ("alg", o.get("alg").map(|v| matches!(v.as_str(), Some("ed25519" | "p256")))),
            ("pkcs8", o.get("pkcs8").map(Value::is_string)),
            ("holder", o.get("holder").map(Value::is_object)),
            ("rebound_at", o.get("rebound_at").map(|v| v.as_u64().is_some())),
        ] {
            if reads == Some(false) {
                return unread(m);
            }
        }
        if let Some(k) = stranger(o, ROOT_MEMBERS) {
            return unread(&k);
        }
    }
    Ok(())
}

const CONTACT_REQUIRED: &[&str] = &["root", "endpoint"];
const CONTACT_MEMBERS: &[&str] = &["root", "endpoint", "name", "leaf", "root_cert", "added"];

/// The record's `contacts`, each entry read as CONTRACT §6's `VaultContact`, as a root is: a list, each
/// entry an object whose `root` is a fingerprint and `endpoint` a string, whose `name`, `leaf`,
/// `root_cert` and `added` are strings where present, `added` an instant, and that holds nothing else.
fn read_contacts(contacts: Option<&Value>) -> Result<()> {
    let entries = match contacts {
        None => return Ok(()),
        Some(Value::Array(entries)) => entries,
        Some(_) => return err("bad_request", "the record's contacts is a list"),
    };
    for (i, c) in entries.iter().enumerate() {
        let Some(o) = c.as_object() else { return err("bad_request", format!("the record's contact {i} does not read")) };
        let unread = |m: &str| err("bad_request", format!("the record's contact {i} does not read: {m}"));
        for m in CONTACT_REQUIRED {
            let Some(text) = o.get(*m).and_then(|v| v.as_str()) else { return unread(m) };
            if *m == "root" && !is_fingerprint(text) {
                return unread(m);
            }
        }
        for m in ["name", "leaf", "root_cert", "added"] {
            let reads = o.get(m).map(|v| v.as_str().is_some_and(|text| m != "added" || parse_rfc3339(text).is_ok()));
            if reads == Some(false) {
                return unread(m);
            }
        }
        if let Some(k) = stranger(o, CONTACT_MEMBERS) {
            return unread(&k);
        }
    }
    Ok(())
}

/// `passkey`, where a document carries one: an object naming its credential and nothing else.
fn read_passkey(passkey: Option<&Value>, whose: &str) -> Result<()> {
    let Some(p) = passkey else { return Ok(()) };
    let reads =
        p.as_object().is_some_and(|o| o.get("credential_id").is_some_and(Value::is_string) && stranger(o, &["credential_id"]).is_none());
    if !reads {
        return err("bad_request", format!("the {whose}'s passkey does not read"));
    }
    Ok(())
}

/// The record's plaintext as CONTRACT §6 has it, every ledger entry included. An entry that does not
/// read is refused, never skipped: skipped, it could be the live leaf, and one live leaf per identity
/// (SPEC §9) would fail open. Every entry is read, not only one root's — an unreadable `root` is how
/// an entry would hide from that filter. The CLI's card path, which reads the ledger itself, calls
/// this too.
pub fn check_record(record: &Value) -> Result<()> {
    if record.is_null() {
        return err("bad_request", "record_plaintext is required");
    }
    let Some(doc) = record.as_object() else { return err("bad_request", "record_plaintext is required: the ledger lives there") };
    if plaintext_v(record) != Some(PLAINTEXT_V) {
        return err("bad_request", GENERATION);
    }
    if let Some(k) = stranger(doc, RECORD_MEMBERS) {
        return err(
            "bad_request",
            format!("record_plaintext holds v, roots, ledger, contacts, passkey and backup_verified_at, and nothing else: {k}"),
        );
    }
    // Then each member, in the order RecordPlaintext lists them (F18: a record whose contacts were a
    // number issued here and was `arguments do not read` in the Go port).
    read_roots(doc.get("roots"), "record", false)?;
    if let Some(ledger) = doc.get("ledger") {
        ledger::read(ledger)?;
    }
    read_contacts(doc.get("contacts"))?;
    read_passkey(doc.get("passkey"), "record")?;
    if doc.get("backup_verified_at").is_some_and(|b| b.as_u64().is_none()) {
        return err("bad_request", "the record's backup_verified_at does not read");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Kdf {
    fn default() -> Kdf {
        Kdf { m_kib: 65_536, t: 3, p: 1 }
    }
}

/// The range a passphrase KDF may name, at BOTH ends, and it is not negotiable by the document.
///
/// The parameters are read out of the vault's own header and handed to Argon2id BEFORE the passphrase
/// is tested, so forging them costs an attacker nothing. Unbounded above, `m_kib: 268435455` asks for
/// ~256 GiB — an allocation failure, and with `panic = "abort"` a wasm trap that kills the wallet page
/// mid-restore — and `t: 4000000000` simply never returns. Unbounded below, `{"m_kib":8,"t":1,"p":1}`
/// seals a document indistinguishable from an honest one except for three numbers in its own header,
/// with the person's ROOT behind a KDF a laptop brute-forces.
///
/// The ceiling is far above any honest wallet and the floor is the documented default, so nothing a
/// real caller asks for moves. The Go port carries the same four numbers, and contract/contract.json's
/// `Kdf` and `KdfArgs` a third copy of them: a test here and one in go/constants_test.go hold each
/// port's to the contract's.
const MAX_M_KIB: u32 = 1 << 21; // 2 GiB
const MIN_M_KIB: u32 = 8 * 1024; // 8 MiB: enough to be worth doing, low enough for a test
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;

/// The shortest salt either end takes, in bytes: contract/contract.json's `VaultSaltMin`, which a
/// test here and one in go/constants_test.go hold both ports to. Argon2id's own floor is the same
/// number, and its words (`salt is too short`) reached `why` here while the Go port answered `not a
/// pact-vault/1 document` (R29, C6); the floor is named before Argon2id is asked for anything.
const MIN_SALT: usize = 8;

impl Kdf {
    /// The one reader of a KDF, for a document's and for a caller's (S5; CONTRACT §6). A document's
    /// `Kdf` names all four members; a caller's `KdfArgs` may leave any out, and it takes the default.
    /// `name` is `argon2id`, and anything else — another name, one that is not a string, or, in a
    /// document, none — is `unknown kdf`. Each parameter is a whole number written as one that fits
    /// in 32 bits, and inside its range; anything else, a parameter a document lacks included, is
    /// `kdf parameters out of range`. `u32::try_from`, never `as`: a truncating cast turned `m_kib:
    /// 4294967304` (2^32 + 8) into 8. This read a `name` that was not a string as `argon2id`, a
    /// document with no `kdf` as the default and opened it, and a `kdf` that was not an object as
    /// the default and sealed under it (R28, R30, T12, F17).
    fn read(o: &Map<String, Value>, document: bool) -> Result<Kdf> {
        match o.get("name") {
            Some(Value::String(n)) if n == "argon2id" => {}
            None | Some(Value::Null) if !document => {}
            _ => return err("vault", "unknown kdf"),
        }
        let d = Kdf::default();
        let out_of_range = || Error::new("vault", "kdf parameters out of range");
        let g = |k: &str, dflt: u32| -> Result<u32> {
            match o.get(k) {
                None | Some(Value::Null) if !document => Ok(dflt),
                None => Err(out_of_range()),
                Some(x) => x.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(out_of_range),
            }
        };
        let kdf = Kdf { m_kib: g("m_kib", d.m_kib)?, t: g("t", d.t)?, p: g("p", d.p)? }.check()?;
        // Members by their exact names, and no others (`Kdf`, `KdfArgs`: additionalProperties false).
        // The Go port matched `M_KIB` to `m_kib`, as encoding/json does, and sealed under what this
        // read as absent.
        if let Some(k) = stranger(o, &["name", "m_kib", "t", "p"]) {
            return err("vault", format!("kdf holds name, m_kib, t and p, and nothing else: {k}"));
        }
        Ok(kdf)
    }

    /// The range, which every derivation is held to: the typed `seal` took any `Kdf` and handed it to
    /// Argon2id unbounded, and only the JSON reader checked it, so a typed caller could write a
    /// document both ports' `open` refuse (T19).
    fn check(self) -> Result<Kdf> {
        if !(MIN_M_KIB..=MAX_M_KIB).contains(&self.m_kib) || self.t < 1 || self.t > MAX_T || self.p < 1 || self.p > MAX_P {
            return err("vault", "kdf parameters out of range");
        }
        Ok(self)
    }

    fn to_value(self) -> Value {
        json!({ "name": "argon2id", "m_kib": self.m_kib, "t": self.t, "p": self.p })
    }
}

/// `vault_seal`'s `kdf` argument: absent or null is the default, an object is read by the one reader
/// `vault_open` reads a document's with, and anything else is `kdf is required` (CONTRACT §0: a member
/// of the wrong type is refused in the words its absence gets, and never read as absent).
pub fn kdf_from_args(v: Option<&Value>) -> Result<Option<Kdf>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(o)) => Kdf::read(o, false).map(Some),
        Some(_) => err("bad_request", "kdf is required"),
    }
}

/// A document's `kdf`: an object with all four members. One that is not an object names no KDF.
fn kdf_of_document(v: Option<&Value>) -> Result<Kdf> {
    match v {
        Some(Value::Object(o)) => Kdf::read(o, true),
        _ => err("vault", "unknown kdf"),
    }
}

/// Argon2id, after the one range and the salt floor, so no caller — typed or JSON, sealing or
/// opening — reaches it with parameters the other end would refuse, and no refusal of its is worded
/// by the library. What it could still refuse (a passphrase or salt past 4 GiB) no argument reaches.
fn derive(passphrase: &str, salt: &[u8], kdf: Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let kdf = kdf.check()?;
    if salt.len() < MIN_SALT {
        return err("vault", "salt is at least 8 bytes");
    }
    let unreachable = |_| Error::new("internal", "the key derivation refused its parameters");
    let params = argon2::Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(unreachable)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key[..]).map_err(unreachable)?;
    Ok(key)
}

fn header(kdf: Kdf, salt: &[u8], nonce: &[u8]) -> Map<String, Value> {
    let mut h = Map::new();
    h.insert("format".into(), json!(FORMAT));
    h.insert("kdf".into(), kdf.to_value());
    h.insert("salt".into(), json!(b64u(salt)));
    h.insert("nonce".into(), json!(b64u(nonce)));
    h
}

pub fn seal(passphrase: &str, plaintext: &Value, kdf: Option<Kdf>, salt: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> Result<Value> {
    check_sealable(passphrase, plaintext)?;
    seal_any(passphrase, plaintext, kdf, salt, nonce)
}

/// What `seal` refuses before it reads a KDF: the passphrase, then the generation (CONTRACT §0, the
/// order a function needs its members). The KDF is read after, so the two ports name the same one.
pub fn check_sealable(passphrase: &str, plaintext: &Value) -> Result<()> {
    if passphrase.is_empty() {
        return err("bad_request", "empty passphrase");
    }
    if plaintext_v(plaintext) != Some(PLAINTEXT_V) {
        return err("bad_request", GENERATION);
    }
    Ok(())
}

/// The sealing itself, with no opinion about the plaintext: `seal` holds the generation, and the
/// test of `open`'s refusal needs a document `seal` would not write.
fn seal_any(passphrase: &str, plaintext: &Value, kdf: Option<Kdf>, salt: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> Result<Value> {
    let kdf = kdf.unwrap_or_default();
    let salt = match salt {
        Some(s) => s,
        None => crate::util::random(16)?,
    };
    let nonce = match nonce {
        Some(n) => n,
        None => crate::util::random(12)?,
    };
    if nonce.len() != 12 {
        return err("vault", "nonce is 12 bytes");
    }
    let key = derive(passphrase, &salt, kdf)?;
    let h = header(kdf, &salt, &nonce);
    let aad = canonical(&Value::Object(h.clone()));
    // Written as a sealed plaintext is (`canonical::in_order`), so the two ports seal one document alike.
    let pt = Zeroizing::new(in_order(plaintext).into_bytes());
    let ct = aes_gcm::Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| Error::new("internal", "key length"))?
        .encrypt(nonce.as_slice().into(), Payload { msg: &pt, aad: aad.as_bytes() })
        .map_err(|_| Error::new("internal", "AEAD failure"))?;
    let mut doc = h;
    doc.insert("ct".into(), json!(b64u(&ct)));
    Ok(Value::Object(doc))
}

/// A wrong passphrase and a tampered document are one message: nothing distinguishes them. The
/// header is read first, in its members' order, and named where it does not read: a document that
/// is not an object, or whose `format` is not this one, is `not a pact-vault/1 document` (this said
/// the passphrase was wrong when the document was not an object, and the Go port said this, T12); then
/// its `kdf`; then `salt`, `nonce` and `ct`, of which one that does not read is damage.
pub fn open(passphrase: &str, vault: &Value) -> Result<Value> {
    let fail = || Error::new("vault", "the passphrase is wrong or the vault is damaged");
    let Some(doc) = vault.as_object().filter(|d| d.get("format").and_then(|f| f.as_str()) == Some(FORMAT)) else {
        return err("vault", "not a pact-vault/1 document");
    };
    let kdf = kdf_of_document(doc.get("kdf"))?;
    let salt = from_b64u(doc.get("salt").and_then(|s| s.as_str()).unwrap_or("")).map_err(|_| fail())?;
    let nonce = from_b64u(doc.get("nonce").and_then(|s| s.as_str()).unwrap_or("")).map_err(|_| fail())?;
    let ct = from_b64u(doc.get("ct").and_then(|s| s.as_str()).unwrap_or("")).map_err(|_| fail())?;
    if nonce.len() != 12 {
        return Err(fail());
    }
    let mut h = doc.clone();
    h.remove("ct");
    let aad = canonical(&Value::Object(h));
    let key = derive(passphrase, &salt, kdf)?;
    let pt = Zeroizing::new(
        aes_gcm::Aes256Gcm::new_from_slice(&key[..])
            .map_err(|_| fail())?
            .decrypt(nonce.as_slice().into(), Payload { msg: &ct, aad: aad.as_bytes() })
            .map_err(|_| fail())?,
    );
    let plaintext: Value = serde_json::from_slice(&pt).map_err(|_| fail())?;
    if plaintext_v(&plaintext) != Some(PLAINTEXT_V) {
        return err("vault", "this vault was written by an earlier wallet and is not opened: there is no conversion");
    }
    Ok(plaintext)
}

/// The wallet's issuance (SPEC §9): the request checked against the vault's roots, a new host
/// flagged, one live leaf per identity, `notBefore` monotonic over the ledger.
///
/// Two documents, as §9 keeps them: the `vault` is the root and nothing else, and the `record`
/// holds the ledger this reads and the entry this answers is appended to. A vault carrying a
/// ledger or contacts was written by an earlier wallet and is refused, not read around.
/// SPEC §2.2's challenge: `PACT root proof v1` and a newline, before 32 random bytes, so that proving
/// possession of the root key can never be made to sign a certificate.
const ROOT_PROOF: &[u8] = b"PACT root proof v1\n";

/// SPEC §2.2, before any certificate is issued: the vault's root key is the root the identity is known
/// by; the root certificate parses and is that key's; and the key signs a challenge that verifies under
/// the certificate's key. `wallet_issue` signed with whatever key sat beside the fingerprint, and a vault
/// entry holding another key's PKCS #8 got a leaf that failed chain rule 3, in both ports (TC-8).
/// Answers the root certificate, for the chain the wallet validates before it returns one.
fn prove_root(root: &Value, key: &PrivateKey, fingerprint: &str) -> Result<crate::x509::Cert> {
    let public = key.public();
    if public.fingerprint() != fingerprint {
        return err("bad_request", "the vault's root key is not the root it is filed under");
    }
    let cert = crate::x509::parse(&from_b64u(root.get("cert").and_then(|c| c.as_str()).unwrap_or(""))?)?;
    if cert.spki != public.spki() {
        return err("bad_request", "the vault's root certificate is not its key's");
    }
    let mut challenge = ROOT_PROOF.to_vec();
    challenge.extend_from_slice(&crate::util::random(32)?);
    if !cert.public_key.verify(&challenge, &key.sign(&challenge)) {
        return err("bad_request", "the vault's root key does not sign for its certificate");
    }
    Ok(cert)
}

pub fn wallet_issue(
    vault: &Value,
    record: &Value,
    root_fingerprint: &str,
    csr_der: &[u8],
    now: i64,
    valid_days: i64,
    moving: bool,
) -> Result<Value> {
    check_file(vault)?;
    check_record(record)?;
    let roots = vault.get("roots").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    // EVERY root this vault holds, and a root is held as its certificate: a software root has a
    // `pkcs8` beside it and a card-held one has not. This read `pkcs8` alone, so a request carrying a
    // CARD-held sibling's key was not "a request whose key is a root" (§9) and was given a leaf. The
    // `pkcs8` reading stays, for a root entry that has lost its certificate.
    let mut root_spkis: Vec<Vec<u8>> = roots
        .iter()
        .filter_map(|r| r.get("cert").and_then(|c| c.as_str()))
        .filter_map(|c| from_b64u(c).ok())
        .filter_map(|der| crate::x509::parse(&der).ok().map(|cert| cert.spki.clone()))
        .collect();
    root_spkis.extend(
        roots
            .iter()
            .filter_map(|r| r.get("pkcs8").and_then(|p| p.as_str()))
            .filter_map(|p| from_b64u(p).ok().map(Zeroizing::new))
            .filter_map(|p| PrivateKey::from_pkcs8(&p).ok().map(|k| k.public().spki().to_vec())),
    );
    let Some(root) = roots.iter().find(|r| r.get("fingerprint").and_then(|f| f.as_str()) == Some(root_fingerprint)) else {
        return err("bad_request", "no such root in the vault");
    };
    let Some(pkcs8) = root.get("pkcs8").and_then(|p| p.as_str()) else {
        return err("bad_request", "this root is held on a card: wallet_issue signs only with a key the vault holds");
    };
    let root_key = PrivateKey::from_pkcs8(&Zeroizing::new(from_b64u(pkcs8)?))?;
    let root_cert = prove_root(root, &root_key, root_fingerprint)?;
    let root_cn = root.get("cn").and_then(|c| c.as_str()).unwrap_or("");
    let request = csr::check(csr_der, &root_spkis)?;
    // The ledger's rules, in the one place they are written (ledger.rs): the record was read whole
    // above, so what is refused here is the one live leaf per identity, and nothing else.
    let facts = ledger::check(record.get("ledger"), root_fingerprint, &request.endpoint, now, moving)?;
    if let Some(why) = facts.refusal {
        return err("bad_request", why);
    }
    let mut warnings = Vec::new();
    let new_host = facts.new_host;
    if new_host {
        warnings.push(json!("new host: this endpoint's host has never been issued to"));
    }
    if matches!(facts.kind, ledger::Kind::Move | ledger::Kind::MoveBack) {
        warnings.push(json!("move: the live leaf at the previous endpoint is superseded once contacts see this one"));
    }
    let previous = facts.previous_not_before;
    let issued = csr::issue(&request, root_cn, &root_key, now, previous, valid_days)?;
    // §2.2: a chain the wallet assembled is validated against the expected root and endpoint before it
    // is returned — a chain that fails is the wallet's defect, and returned it would be the host's to find.
    if let crate::x509::ChainResult::Refused { rule, reason } =
        crate::x509::validate_chain(&[issued.der.clone(), root_cert.der.clone()], now, Some(root_fingerprint), Some(&request.endpoint))
    {
        return err("bad_request", format!("the chain it issued does not validate: chain rule {rule}: {reason}"));
    }
    // The endpoint and the dates: what every rule above reads. Never the leaf, which is the host's
    // to serve and grants nothing (SPEC §9).
    let entry = json!({
        "root": root_fingerprint,
        "endpoint": request.endpoint,
        "not_before": format_rfc3339(issued.not_before),
        "not_after": format_rfc3339(issued.not_after),
        "issued_at": format_rfc3339(now),
    });
    Ok(
        json!({ "der": b64u(&issued.der), "endpoint": request.endpoint, "not_before": entry["not_before"], "not_after": entry["not_after"], "ledger_entry": entry, "new_host": new_host, "warnings": warnings }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Alg;
    use crate::util::seed;
    use crate::x509;

    fn small() -> Kdf {
        Kdf { m_kib: 8192, t: 1, p: 1 }
    }

    /// contract/contract.json's `Kdf`, `KdfArgs` and `KdfDefault` are the bounds and the default this
    /// file writes down (and go/constants_test.go holds the Go port's to the same): each bound read
    /// from the contract, and one past it refused through the boundary, which costs nothing because
    /// the range is checked before Argon2id is asked for anything. The accepted side of the memory
    /// ceiling is 2 GiB, which no test allocates; the equality above is what holds it.
    #[test]
    fn the_contracts_kdf_bounds_and_default_are_these() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contract/contract.json");
        let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let defs = &contract["$defs"];
        let mine = json!({ "m_kib": [MIN_M_KIB, MAX_M_KIB], "t": [1, MAX_T], "p": [1, MAX_P] });
        for schema in ["Kdf", "KdfArgs"] {
            let p = &defs[schema]["properties"];
            let theirs = json!({
                "m_kib": [p["m_kib"]["minimum"], p["m_kib"]["maximum"]],
                "t": [p["t"]["minimum"], p["t"]["maximum"]],
                "p": [p["p"]["minimum"], p["p"]["maximum"]],
            });
            assert_eq!(theirs, mine, "contract/contract.json's {schema} and this file's bounds");
        }
        assert_eq!(defs["KdfDefault"]["const"], Kdf::default().to_value(), "contract/contract.json's KdfDefault and Kdf::default()");
        for (member, over) in [
            ("m_kib", u64::from(MAX_M_KIB) + 1),
            ("m_kib", u64::from(MIN_M_KIB) - 1),
            ("t", u64::from(MAX_T) + 1),
            ("t", 0),
            ("p", u64::from(MAX_P) + 1),
            ("p", 0),
        ] {
            let mut kdf = Kdf::default().to_value();
            kdf[member] = json!(over);
            let args = json!({ "passphrase": "x", "plaintext": { "v": 2 }, "kdf": kdf }).to_string();
            let out: Value = serde_json::from_str(&crate::api::call("vault_seal", &args)).unwrap();
            assert_eq!(out, json!({ "error": "vault", "why": "kdf parameters out of range" }), "{member} {over}");
        }
    }

    /// contract/contract.json's `VaultSaltMin` is this file's floor (go/constants_test.go holds the Go
    /// port's to it): a salt one byte shorter is refused in the words both ports use, before Argon2id
    /// is asked for anything — whose own words (`salt is too short`) reached `why` here (R29, C6) — and
    /// one of that length is taken, at both ends.
    #[test]
    fn the_contracts_salt_floor_is_this_one() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contract/contract.json");
        let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(contract["$defs"]["VaultSaltMin"]["const"], json!(MIN_SALT), "contract/contract.json's VaultSaltMin and MIN_SALT");
        let short = seal("x", &json!({"v": 2}), Some(small()), Some(vec![0; MIN_SALT - 1]), None).unwrap_err();
        assert_eq!((short.code.as_str(), short.why.as_str()), ("vault", "salt is at least 8 bytes"));
        let mut v = seal("x", &json!({"v": 2}), Some(small()), Some(vec![0; MIN_SALT]), None).unwrap();
        assert_eq!(open("x", &v).unwrap()["v"], 2);
        v["salt"] = json!(b64u(&[0; MIN_SALT - 1]));
        assert_eq!(open("x", &v).unwrap_err().why, "salt is at least 8 bytes");
    }

    /// The typed `seal` is held to the range, as the JSON reader is: it handed any `Kdf` to Argon2id,
    /// so a typed caller could write a document both ports' `open` refuse (T19).
    #[test]
    fn a_typed_seal_is_held_to_the_range() {
        for kdf in [Kdf { m_kib: 64, t: 1, p: 1 }, Kdf { m_kib: MIN_M_KIB, t: MAX_T + 1, p: 1 }, Kdf { m_kib: MIN_M_KIB, t: 1, p: 0 }] {
            let e = seal("x", &json!({"v": 2}), Some(kdf), None, None).unwrap_err();
            assert_eq!((e.code.as_str(), e.why.as_str()), ("vault", "kdf parameters out of range"), "{kdf:?}");
        }
    }

    #[test]
    fn seals_opens_and_refuses() {
        let v = seal("correct horse", &json!({"v": 2, "roots": []}), Some(small()), None, None).unwrap();
        assert_eq!(v["format"], FORMAT);
        assert_eq!(open("correct horse", &v).unwrap()["v"], 2);
        assert_eq!(open("wrong", &v).unwrap_err().why, "the passphrase is wrong or the vault is damaged");
        let mut t = v.clone();
        t["kdf"]["t"] = json!(2);
        assert_eq!(open("correct horse", &t).unwrap_err().why, "the passphrase is wrong or the vault is damaged");
    }

    #[test]
    fn an_earlier_generation_is_refused_at_both_ends_and_nothing_converts() {
        assert_eq!(
            seal("correct horse", &json!({"v": 1, "roots": [], "ledger": []}), Some(small()), None, None).unwrap_err().why,
            "a vault plaintext is v 2: the root, or the record"
        );
        assert_eq!(seal("correct horse", &json!({"roots": []}), Some(small()), None, None).unwrap_err().code, "bad_request");
        // A document an earlier wallet wrote: it decrypts, and is still not opened.
        let old =
            seal_any("correct horse", &json!({"v": 1, "roots": [], "ledger": [], "contacts": []}), Some(small()), None, None).unwrap();
        let e = open("correct horse", &old).unwrap_err();
        assert_eq!(e.code, "vault");
        assert_eq!(e.why, "this vault was written by an earlier wallet and is not opened: there is no conversion");
        // The control: a wrong passphrase on that same document is still the one message.
        assert_eq!(open("wrong", &old).unwrap_err().why, "the passphrase is wrong or the vault is damaged");
    }

    /// SPEC §2.2 on the software path (TC-8): `wallet_issue` signs only with a key that is the root the
    /// identity is known by, whose certificate is that key's and signs a challenge under it, and
    /// returns only a chain that validates to that root at the endpoint. It signed with whatever key sat
    /// beside the fingerprint, and a leaf that failed chain rule 3 came back.
    #[test]
    fn a_vault_root_proves_itself_before_it_signs() {
        let root = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/root")).unwrap();
        let other = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/other")).unwrap();
        let now = 1_789_214_400;
        let cert = x509::build_root("Alina Rao", &root, now, &x509::serial_of("vault/root")).unwrap();
        let other_cert = x509::build_root("Mallory", &other, now, &x509::serial_of("vault/other")).unwrap();
        let fp = root.public().fingerprint();
        let endpoint = "https://agent.alina.example/mcp";
        // A certificate of the root's own key that is no root: a leaf, under the root.
        let (issuer, subject) = (root.public(), root.public());
        let no_root = x509::build_leaf(
            &x509::LeafSpec {
                cn: "Alina Rao",
                root_cn: "Alina Rao",
                issuer: &issuer,
                host_key: &subject,
                uris: vec![endpoint.into()],
                dns_name: None,
                not_before: now - 3600,
                not_after: now + 86_400,
                serial: x509::serial_of("vault/no-root"),
                ca: false,
                usage: None,
                aki: None,
            },
            &root,
        )
        .unwrap();
        let vault = |key: &PrivateKey, cert: &[u8]| json!({"v": 2, "roots": [{"fingerprint": fp, "cn": "Alina Rao", "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(cert), "created": format_rfc3339(now)}]});
        let record = json!({"v": 2, "ledger": [], "contacts": []});
        let host = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/host")).unwrap();
        let req = csr::csr_new("Alina Rao", &host, endpoint, None).unwrap();
        let issue = |v: &Value| wallet_issue(v, &record, &fp, &req, now, 365, false);
        assert_eq!(issue(&vault(&other, &cert)).unwrap_err().why, "the vault's root key is not the root it is filed under");
        assert_eq!(issue(&vault(&root, &other_cert)).unwrap_err().why, "the vault's root certificate is not its key's");
        let refused = issue(&vault(&root, &no_root)).unwrap_err();
        assert!(refused.why.starts_with("the chain it issued does not validate: chain rule "), "{}", refused.why);
        assert_eq!(ROOT_PROOF, b"PACT root proof v1\n");
        // The control: the root, its certificate, and a chain that validates to it at the endpoint.
        let out = issue(&vault(&root, &cert)).unwrap();
        let leaf = from_b64u(out["der"].as_str().unwrap()).unwrap();
        assert!(matches!(x509::validate_chain(&[leaf, cert], now, Some(&fp), Some(endpoint)), x509::ChainResult::Ok(_)));
    }

    #[test]
    fn issues_from_the_vault() {
        let root = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/root")).unwrap();
        let now = 1_789_214_400;
        let cert = x509::build_root("Alina Rao", &root, now, &x509::serial_of("vault/root")).unwrap();
        let fp = root.public().fingerprint();
        let plaintext = json!({"v": 2, "roots": [{"fingerprint": fp, "cn": "Alina Rao", "pkcs8": b64u(&root.to_pkcs8()), "cert": b64u(&cert), "created": format_rfc3339(now)}]});
        let record = json!({"v": 2, "ledger": [], "contacts": []});
        let host = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/host")).unwrap();
        let req = csr::csr_new("Alina Rao", &host, "https://agent.alina.example/mcp", None).unwrap();
        let out = wallet_issue(&plaintext, &record, &fp, &req, now, 365, false).unwrap();
        assert_eq!(out["new_host"], true);
        // The entry is the endpoint and the dates: no leaf in it.
        assert_eq!(
            out["ledger_entry"].as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
            ["root", "endpoint", "not_before", "not_after", "issued_at"]
        );
        // A vault that carries what belongs in the record, and a missing record, are refused.
        let mut old = plaintext.clone();
        old["ledger"] = json!([]);
        assert_eq!(
            wallet_issue(&old, &record, &fp, &req, now, 365, false).unwrap_err().why,
            "a vault holds the root and nothing else: its ledger and contacts belong in the record"
        );
        assert_eq!(wallet_issue(&plaintext, &Value::Null, &fp, &req, now, 365, false).unwrap_err().why, "record_plaintext is required");
        assert_eq!(
            wallet_issue(&plaintext, &json!("x"), &fp, &req, now, 365, false).unwrap_err().why,
            "record_plaintext is required: the ledger lives there"
        );
        let leaf = from_b64u(out["der"].as_str().unwrap()).unwrap();
        assert!(matches!(
            x509::validate_chain(&[leaf, cert.clone()], now, Some(&fp), Some("https://agent.alina.example/mcp")),
            x509::ChainResult::Ok(_)
        ));
        // A second endpoint while one is live is a move, refused without the flag.
        let mut with = record.clone();
        with["ledger"] = json!([out["ledger_entry"].clone()]);
        let host2 = PrivateKey::from_seed(Alg::P256, &seed("vault/host2")).unwrap();
        let req2 = csr::csr_new("Alina Rao", &host2, "https://alina.host.example/alina/mcp", None).unwrap();
        assert!(wallet_issue(&plaintext, &with, &fp, &req2, now + 10, 365, false).is_err());
        let moved = wallet_issue(&plaintext, &with, &fp, &req2, now + 10, 365, true).unwrap();
        assert_eq!(moved["not_before"], format_rfc3339(now + 10 - 3600)); // an hour before issuance, later than the previous leaf plus one second
                                                                          // After the move the new address is the live one: a renewal there is not a second home,
                                                                          // and a leaf for the old address now is the move back, refused without the flag.
        with["ledger"] = json!([out["ledger_entry"].clone(), moved["ledger_entry"].clone()]);
        let host3 = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/host3")).unwrap();
        let req3 = csr::csr_new("Alina Rao", &host3, "https://alina.host.example/alina/mcp", None).unwrap();
        let renewed = wallet_issue(&plaintext, &with, &fp, &req3, now + 20, 365, false).unwrap();
        assert_eq!(renewed["new_host"], false);
        assert!(wallet_issue(&plaintext, &with, &fp, &req, now + 20, 365, false).is_err());
        // The root's own key in a request is refused by the wallet.
        let bad = csr::csr_new("Alina Rao", &root, "https://x.example/mcp", None).unwrap();
        assert_eq!(wallet_issue(&plaintext, &record, &fp, &bad, now, 365, false).unwrap_err().why, "the request's key is a root");
    }
}
