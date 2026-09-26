//! The vault (SPEC §9; CONTRACT §6): the root keys, the issued-leaf ledger and the contact book,
//! under Argon2id and AES-256-GCM with the document's header as AAD. Shared by the sign-up
//! ceremony and the CLI.
use crate::canonical::canonical;
use crate::csr;
use crate::keys::PrivateKey;
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{b64u, err, from_b64u, Error, Result};
use crate::x509;
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
/// real caller asks for moves. The Go port carries the same four numbers.
const MAX_M_KIB: u32 = 1 << 21; // 2 GiB
const MIN_M_KIB: u32 = 8 * 1024; // 8 MiB: enough to be worth doing, low enough for a test
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;

impl Kdf {
    fn from_value(v: Option<&Value>) -> Result<Kdf> {
        let Some(v) = v else { return Ok(Kdf::default()) };
        if v.get("name").and_then(|n| n.as_str()).unwrap_or("argon2id") != "argon2id" {
            return err("vault", "unknown kdf");
        }
        let d = Kdf::default();
        // `u32::try_from`, not `as`: a truncating cast turned `m_kib: 4294967304` (2^32 + 8) into 8,
        // so a caller asking for more than it could express got the weakest KDF that is legal, and
        // was told nothing.
        let g = |k: &str, dflt: u32| -> Result<u32> {
            match v.get(k) {
                None | Some(Value::Null) => Ok(dflt),
                Some(x) => x.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| Error::new("vault", "kdf parameters out of range")),
            }
        };
        let kdf = Kdf { m_kib: g("m_kib", d.m_kib)?, t: g("t", d.t)?, p: g("p", d.p)? };
        if !(MIN_M_KIB..=MAX_M_KIB).contains(&kdf.m_kib) || kdf.t < 1 || kdf.t > MAX_T || kdf.p < 1 || kdf.p > MAX_P {
            return err("vault", "kdf parameters out of range");
        }
        Ok(kdf)
    }
    fn to_value(self) -> Value {
        json!({ "name": "argon2id", "m_kib": self.m_kib, "t": self.t, "p": self.p })
    }
}

/// The KDF a caller named, parsed and bounded exactly as `vault_open` parses the document's own —
/// so `vault_seal` cannot write a document that `vault_open` would refuse, and neither end has a
/// range the other does not.
pub fn kdf_from_args(v: Option<&Value>) -> Result<Kdf> {
    Kdf::from_value(v)
}

fn derive(passphrase: &str, salt: &[u8], kdf: Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|e| Error::new("vault", e.to_string()))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key[..]).map_err(|e| Error::new("vault", e.to_string()))?;
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
    if passphrase.is_empty() {
        return err("bad_request", "empty passphrase");
    }
    if plaintext_v(plaintext) != Some(PLAINTEXT_V) {
        return err("bad_request", "a vault plaintext is v 2: the root, or the record");
    }
    seal_any(passphrase, plaintext, kdf, salt, nonce)
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
    let pt = Zeroizing::new(serde_json::to_vec(plaintext).map_err(|e| Error::new("internal", e.to_string()))?);
    let ct = aes_gcm::Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| Error::new("internal", "key length"))?
        .encrypt(nonce.as_slice().into(), Payload { msg: &pt, aad: aad.as_bytes() })
        .map_err(|_| Error::new("internal", "AEAD failure"))?;
    let mut doc = h;
    doc.insert("ct".into(), json!(b64u(&ct)));
    Ok(Value::Object(doc))
}

/// A wrong passphrase and a tampered document are one message: nothing distinguishes them.
pub fn open(passphrase: &str, vault: &Value) -> Result<Value> {
    let fail = || Error::new("vault", "the passphrase is wrong or the vault is damaged");
    let Some(doc) = vault.as_object() else { return Err(fail()) };
    if doc.get("format").and_then(|f| f.as_str()) != Some(FORMAT) {
        return err("vault", "not a pact-vault/1 document");
    }
    let kdf = Kdf::from_value(doc.get("kdf"))?;
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
pub fn wallet_issue(
    vault: &Value,
    record: &Value,
    root_fingerprint: &str,
    csr_der: &[u8],
    now: i64,
    valid_days: i64,
    moving: bool,
) -> Result<Value> {
    if vault.get("ledger").is_some() || vault.get("contacts").is_some() {
        return err("bad_request", "a vault holds the root and nothing else: its ledger and contacts belong in the record");
    }
    if !record.is_object() {
        return err("bad_request", "record_plaintext is required: the ledger lives there");
    }
    let roots = vault.get("roots").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let ledger = record.get("ledger").and_then(|r| r.as_array()).cloned().unwrap_or_default();
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
    let root_key = PrivateKey::from_pkcs8(&Zeroizing::new(from_b64u(root.get("pkcs8").and_then(|p| p.as_str()).unwrap_or(""))?))?;
    let root_cn = root.get("cn").and_then(|c| c.as_str()).unwrap_or("");
    let request = csr::check(csr_der, &root_spkis)?;
    let host = x509::host_of(&request.endpoint).to_string();
    let mine: Vec<&Value> = ledger.iter().filter(|l| l.get("root").and_then(|r| r.as_str()) == Some(root_fingerprint)).collect();
    let mut warnings = Vec::new();
    let new_host = !mine.iter().any(|l| l.get("endpoint").and_then(|e| e.as_str()).map(|e| x509::host_of(e) == host).unwrap_or(false));
    if new_host {
        warnings.push(json!("new host: this endpoint's host has never been issued to"));
    }
    // The live leaf is the newest one issued (§14.3: a later notBefore supersedes every earlier
    // leaf the instant it is seen), if it has not expired. Earlier entries are history.
    let newest = mine
        .iter()
        .filter_map(|l| l.get("not_before").and_then(|t| t.as_str()).and_then(|t| parse_rfc3339(t).ok()).map(|t| (t, *l)))
        .max_by_key(|(t, _)| *t)
        .map(|(_, l)| l);
    let live = newest
        .filter(|l| l.get("not_after").and_then(|t| t.as_str()).and_then(|t| parse_rfc3339(t).ok()).map(|t| t > now).unwrap_or(false));
    if let Some(other) = live.filter(|l| l.get("endpoint").and_then(|e| e.as_str()) != Some(request.endpoint.as_str())) {
        if !moving {
            return err(
                "bad_request",
                format!(
                    "a leaf is live for {}: a second endpoint is a move, not a second home",
                    other.get("endpoint").and_then(|e| e.as_str()).unwrap_or("?")
                ),
            );
        }
        warnings.push(json!("move: the live leaf at the previous endpoint is superseded once contacts see this one"));
    }
    let previous = mine.iter().filter_map(|l| l.get("not_before").and_then(|t| t.as_str()).and_then(|t| parse_rfc3339(t).ok())).max();
    let issued = csr::issue(&request, root_cn, &root_key, now, previous, valid_days)?;
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

    fn small() -> Kdf {
        Kdf { m_kib: 8192, t: 1, p: 1 }
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
        assert_eq!(
            wallet_issue(&plaintext, &Value::Null, &fp, &req, now, 365, false).unwrap_err().why,
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
        let req2 = csr::csr_new("Alina Rao", &host2, "https://alina.pact.contact/alina/mcp", None).unwrap();
        assert!(wallet_issue(&plaintext, &with, &fp, &req2, now + 10, 365, false).is_err());
        let moved = wallet_issue(&plaintext, &with, &fp, &req2, now + 10, 365, true).unwrap();
        assert_eq!(moved["not_before"], format_rfc3339(now + 10 - 3600)); // an hour before issuance, later than the previous leaf plus one second
                                                                          // After the move the new address is the live one: a renewal there is not a second home,
                                                                          // and a leaf for the old address now is the move back, refused without the flag.
        with["ledger"] = json!([out["ledger_entry"].clone(), moved["ledger_entry"].clone()]);
        let host3 = PrivateKey::from_seed(Alg::Ed25519, &seed("vault/host3")).unwrap();
        let req3 = csr::csr_new("Alina Rao", &host3, "https://alina.pact.contact/alina/mcp", None).unwrap();
        let renewed = wallet_issue(&plaintext, &with, &fp, &req3, now + 20, 365, false).unwrap();
        assert_eq!(renewed["new_host"], false);
        assert!(wallet_issue(&plaintext, &with, &fp, &req, now + 20, 365, false).is_err());
        // The root's own key in a request is refused by the wallet.
        let bad = csr::csr_new("Alina Rao", &root, "https://x.example/mcp", None).unwrap();
        assert_eq!(wallet_issue(&plaintext, &record, &fp, &bad, now, 365, false).unwrap_err().why, "the request's key is a root");
    }
}
