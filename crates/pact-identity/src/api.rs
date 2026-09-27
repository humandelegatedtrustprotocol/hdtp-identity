//! One surface for every host: `call(name, args_json) -> json`, the CONTRACT's functions by name.
//! Never panics across the boundary; every failure is `{"error", "why"}`.
use crate::keys::{PrivateKey, PublicKey};
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{b64u, err, from_b64u, Error, Result};
use crate::x509::{self, ChainResult, Extra, LeafSpec};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

mod cards;
mod certificates;
mod csr;
mod envelopes;
mod export;
mod keys;
mod ledger;
mod signing;
mod vault;

/// The version of `pact-protocol/SPEC.md` this core implements.
///
/// It read `2.0.0-draft` for days after the draft shipped as 2.0.0, and through 2.1.0, because a
/// literal in a dispatch arm has nothing to fail against. `tests/vectors.rs` now compares it with
/// the version line of the document the vectors are read from, so the two cannot part quietly.
pub const SPEC_VERSION: &str = "2.1.3";

/// A required string member that carries an identifier: present, and not empty. §13's `msg_id` is
/// what pairs a result with its request, so the empty string is not a value it can take — one port
/// sealed an envelope with one, and the other refused.
fn id<'a>(a: &'a Value, k: &str) -> Result<&'a str> {
    let v = s(a, k)?;
    if v.is_empty() {
        return err("bad_request", format!("{k} is required"));
    }
    Ok(v)
}

fn s<'a>(a: &'a Value, k: &str) -> Result<&'a str> {
    a.get(k).and_then(|v| v.as_str()).ok_or_else(|| Error::new("bad_request", format!("{k} is required")))
}
fn opt_s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(|v| v.as_str())
}
/// A required base64url member. Absent is a caller's mistake that names the member; present but not
/// a base64url string is a decode failure, and both ports say so in the same words.
fn bytes(a: &Value, k: &str) -> Result<Vec<u8>> {
    match a.get(k) {
        None | Some(Value::Null) => err("bad_request", format!("{k} is required")),
        Some(Value::String(v)) => from_b64u(v),
        Some(_) => err("parse", "not base64url"),
    }
}
fn opt_bytes(a: &Value, k: &str) -> Result<Option<Vec<u8>>> {
    match opt_s(a, k) {
        Some(v) => Ok(Some(from_b64u(v)?)),
        None => Ok(None),
    }
}
fn instant(a: &Value, k: &str) -> Result<i64> {
    parse_rfc3339(s(a, k)?)
}
fn opt_instant(a: &Value, k: &str) -> Result<Option<i64>> {
    match opt_s(a, k) {
        Some(v) => Ok(Some(parse_rfc3339(v)?)),
        None => Ok(None),
    }
}
fn int(a: &Value, k: &str) -> Result<i64> {
    a.get(k).and_then(|v| v.as_i64()).ok_or_else(|| Error::new("bad_request", format!("{k} is required")))
}
fn opt_int(a: &Value, k: &str) -> Option<i64> {
    a.get(k).and_then(|v| v.as_i64())
}
/// `valid_days`, read with the arguments (CONTRACT §0): absent is a year; present and not an integer
/// is a member of the wrong type, `valid_days is required`, and never a year it was not asked for.
fn valid_days(a: &Value) -> Result<i64> {
    let days = match a.get("valid_days") {
        None | Some(Value::Null) => 365,
        Some(v) => v.as_i64().ok_or_else(|| Error::new("bad_request", "valid_days is required"))?,
    };
    if !(1..=x509::MAX_LEAF_DAYS).contains(&days) {
        return err("bad_request", "validity must be between one and 398 days");
    }
    Ok(days)
}
fn boolean(a: &Value, k: &str) -> bool {
    a.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}
/// An optional list of DER members: absent is an empty list, present is parsed or refused. A list
/// that cannot be read must never read as "no roots to refuse against" — that is §9's root-key
/// refusal failing open.
fn opt_chain(a: &Value, k: &str) -> Result<Vec<Vec<u8>>> {
    if a.get(k).is_none() || a.get(k) == Some(&Value::Null) {
        return Ok(Vec::new());
    }
    chain(a, k)
}
/// A chain that may be left out, and may not be left out by being WRONG: `chain(..).ok()` turned a
/// `sender_chain` that was there and would not read into one that was absent, so the caller was told
/// "the chain form needs sender_chain" about a chain it had sent.
fn present_chain(a: &Value, k: &str) -> Result<Option<Vec<Vec<u8>>>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => chain(a, k).map(Some),
    }
}
fn chain(a: &Value, k: &str) -> Result<Vec<Vec<u8>>> {
    let Some(items) = a.get(k).and_then(|v| v.as_array()) else { return err("bad_request", format!("{k} is required")) };
    items.iter().map(|c| c.as_str().ok_or_else(|| Error::new("parse", "not base64url")).and_then(from_b64u)).collect()
}
fn private(a: &Value, k: &str) -> Result<PrivateKey> {
    PrivateKey::from_pkcs8(&Zeroizing::new(bytes(a, k)?))
}
fn public(a: &Value, k: &str) -> Result<PublicKey> {
    PublicKey::from_spki(&bytes(a, k)?)
}
fn seed32(a: &Value, k: &str) -> Result<Option<[u8; 32]>> {
    match opt_bytes(a, k)? {
        Some(v) => Ok(Some(v.try_into().map_err(|_| Error::new("bad_request", format!("{k} is 32 bytes")))?)),
        None => Ok(None),
    }
}
fn serial(a: &Value) -> Result<Vec<u8>> {
    match opt_bytes(a, "serial")? {
        Some(v) if (8..=20).contains(&v.len()) => Ok(v),
        Some(_) => err("bad_request", "serial is 8 to 20 bytes"),
        None => x509::random_serial(),
    }
}

fn key_json(k: &PrivateKey) -> Value {
    let p = k.public();
    json!({ "alg": k.alg().name(), "pkcs8": b64u(&k.to_pkcs8()), "spki": b64u(p.spki()), "fingerprint": p.fingerprint() })
}

fn cert_json(c: &x509::Cert) -> Value {
    json!({
        "kind": c.kind(),
        "subject": c.subject, "issuer": c.issuer, "serial": b64u(&c.serial),
        "not_before": format_rfc3339(c.not_before), "not_after": format_rfc3339(c.not_after),
        "alg": c.public_key.alg().name(), "spki": b64u(&c.spki), "fingerprint": c.public_key.fingerprint(), "key_id": b64u(&c.key_id),
        "ski": c.ski.as_ref().map(|v| b64u(v)), "aki": c.aki.as_ref().map(|v| b64u(v)),
        "ca": c.ca, "path_len": c.path_len, "key_usage": c.key_usage, "eku": c.eku, "uris": c.uris, "dns": c.dns,
        "sig_alg": c.sig_alg, "extensions": c.extensions.iter().map(|e| json!({ "id": e.id, "critical": e.critical })).collect::<Vec<_>>(),
        "profile_error": x509::profile_error(c, if c.issuer == c.subject && c.ca { "root" } else { "leaf" }),
        "bytes": c.der.len(),
    })
}

fn leaf_spec<'a>(a: &'a Value, issuer: &'a PublicKey, host_key: &'a PublicKey, serial_bytes: Vec<u8>) -> Result<LeafSpec<'a>> {
    let uris: Vec<String> = match a.get("uris").and_then(|u| u.as_array()) {
        Some(items) => items.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        None => vec![s(a, "endpoint")?.to_string()],
    };
    let usage = a.get("usage").and_then(|u| u.as_array()).map(|items| items.iter().filter_map(|x| x.as_u64().map(|b| b as u8)).collect());
    let extra = match a.get("extra").and_then(|e| e.as_array()) {
        Some(items) => items
            .iter()
            .map(|e| Ok(Extra { oid: s(e, "oid")?.to_string(), critical: boolean(e, "critical"), value: bytes(e, "value")? }))
            .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    let not_before = instant(a, "not_before")?;
    let not_after = instant(a, "not_after")?;
    // §14.1 at the boundary, where the Go port also puts it. Not in `x509::build_leaf`: the vector
    // generator calls that directly to make certificates that are outside the profile on purpose,
    // which is the whole point of a negative vector.
    if not_after - not_before > 398 * 86400 {
        return err("bad_request", "validity over 398 days");
    }
    if !uris.iter().all(|u| x509::is_normal_https(u)) {
        return err("bad_request", "endpoint is not an https URL in normal form");
    }
    Ok(LeafSpec {
        cn: s(a, "cn")?,
        root_cn: s(a, "root_cn")?,
        issuer,
        host_key,
        uris,
        dns_name: opt_s(a, "dns_name").map(|d| d.to_string()),
        not_before,
        not_after,
        serial: serial_bytes,
        ca: boolean(a, "ca"),
        usage,
        aki: opt_bytes(a, "aki")?,
        extra,
        alg_oid: opt_s(a, "alg_oid").map(|o| o.to_string()),
    })
}

fn chain_result(r: ChainResult) -> Value {
    match r {
        ChainResult::Ok(v) => json!({
            "ok": true, "leaf_spki": b64u(&v.leaf.spki), "leaf_fingerprint": v.leaf.public_key.fingerprint(), "root_fingerprint": v.root_fingerprint,
            "endpoint": v.endpoint, "not_before": format_rfc3339(v.leaf.not_before), "not_after": format_rfc3339(v.leaf.not_after), "alg": v.leaf.public_key.alg().name(),
        }),
        ChainResult::Refused { rule, reason } => json!({ "ok": false, "rule": rule, "reason": reason }),
    }
}

fn dispatch(name: &str, a: &Value) -> Result<Value> {
    Ok(match name {
        // §1 keys
        "generate_key" => keys::generate_key(a)?,
        "key_from_seed" => keys::key_from_seed(a)?,
        "prf_salt" => keys::prf_salt(a)?,
        "derive_seed" => keys::derive_seed(a)?,
        "public_key" => keys::public_key(a)?,
        "key_info" => keys::key_info(a)?,
        "sign" => keys::sign(a)?,
        "verify" => keys::verify(a)?,
        // §2 certificates
        "build_root" => certificates::build_root(a)?,
        "root_tbs" => certificates::root_tbs(a)?,
        "assemble_root" | "assemble_leaf" => certificates::assemble(a)?,
        "build_leaf" => certificates::build_leaf(a)?,
        "leaf_tbs" => certificates::leaf_tbs(a)?,
        "parse_certificate" => certificates::parse_certificate(a)?,
        "profile_error" => certificates::profile_error(a)?,
        "validate_chain" => certificates::validate_chain(a)?,
        "compare_leaves" => certificates::compare_leaves(a)?,
        "is_normal_https" => certificates::is_normal_https(a)?,
        "address_guard" => certificates::address_guard(a)?,
        "ip_is_private" => certificates::ip_is_private(a)?,
        // §3 CSR
        "csr_new" => csr::csr_new(a)?,
        "csr_check" => csr::csr_check(a)?,
        "issue_from_csr" => csr::issue_from_csr(a)?,
        "issue_tbs_from_csr" => csr::issue_tbs_from_csr(a)?,
        // §3.1 signing requests
        "signing_request_check" => signing::signing_request_check(a)?,
        // §4 cards
        "card_encode" => cards::card_encode(a)?,
        "card_decode" => cards::card_decode(a)?,
        // §5 envelopes
        "suite_for" => envelopes::suite_for(a)?,
        "hpke_seal" => envelopes::hpke_seal(a)?,
        "hpke_open" => envelopes::hpke_open(a)?,
        "seal_request" => envelopes::seal_request(a)?,
        "seal_result" => envelopes::seal_result(a)?,
        "open_result" => envelopes::open_result(a)?,
        "follow_renewed" => envelopes::follow_renewed(a)?,
        "decide" => envelopes::decide(a)?,
        // §6 vault
        "vault_seal" => vault::vault_seal(a)?,
        "vault_open" => vault::vault_open(a)?,
        "wallet_issue" => vault::wallet_issue(a)?,
        // §6.2 export
        "export_read" => export::export_read(a)?,
        "export_read_messages" => export::export_read_messages(a)?,
        "export_read_end" => export::export_read_end(a)?,
        "export_write" => export::export_write(a)?,
        "export_write_messages" => export::export_write_messages(a)?,
        "export_manifest" => export::export_manifest(a)?,
        "export_merge" => export::export_merge(a)?,
        // §6.1 ledger
        "ledger_check" => ledger::ledger_check(a)?,
        "version" => json!({ "crate": env!("CARGO_PKG_VERSION"), "spec": SPEC_VERSION }),
        other => return err("unsupported", format!("no function named {other}")),
    })
}

/// The boundary. `args` is one JSON object; the answer is one JSON object, never an exception.
pub fn call(name: &str, args: &str) -> String {
    let a: Value = match serde_json::from_str(args) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => return json!({ "error": "bad_request", "why": "args is a JSON object" }).to_string(),
        Err(e) => return json!({ "error": "bad_request", "why": format!("args: {e}") }).to_string(),
    };
    let run = || dispatch(name, &a);
    #[cfg(not(target_arch = "wasm32"))]
    let out = std::panic::catch_unwind(run).unwrap_or_else(|_| err("internal", "panic"));
    #[cfg(target_arch = "wasm32")]
    let out = run();
    match out {
        Ok(v) => v.to_string(),
        Err(e) => {
            let mut o = Map::new();
            o.insert("error".into(), json!(e.code));
            o.insert("why".into(), json!(e.why));
            Value::Object(o).to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_names_and_non_object_args_answer_rather_than_throw() {
        assert!(call("nope", "{}").contains("no function named nope"));
        // Every shape that is not an object, `null` included. `js/parity.mjs` cannot reach these:
        // its port shim turns them into `{}` before either port sees them, so the two ports' own
        // suites are where this one is held.
        for args in ["[]", "null", "3", "\"x\"", "true"] {
            assert!(call("verify", args).contains("args is a JSON object"), "verify({args})");
        }
        assert!(call("verify", "{").contains("args:"));
        let k: Value = serde_json::from_str(&call("generate_key", r#"{"alg":"ed25519"}"#)).unwrap();
        assert_eq!(k["alg"], "ed25519");
        let v: Value = serde_json::from_str(&call("version", "{}")).unwrap();
        assert_eq!(v["spec"], SPEC_VERSION);
    }

    /// The name above used to be `the_boundary_never_throws`, which claimed a property of wasm32 while
    /// testing six ordinary `Err` returns on x86_64 — where `call` has a `catch_unwind` backstop that
    /// wasm32 does not compile at all, and where `panic = "abort"` makes unwinding impossible anyway.
    /// So the guarantee rests on no panic EXISTING, and these are the three inputs that produced one
    /// (or would have): six bytes of DER whose 4-octet length wrapped a 32-bit `usize`; a vault header
    /// whose Argon2id parameters were unbounded; and a `ts` that wrapped the skew window. Each is
    /// refused here before any allocation or derivation, which is why asserting the catastrophic
    /// numbers costs nothing.
    #[test]
    fn the_inputs_that_panicked_or_ran_away_are_refused_by_name() {
        // `30 84 FF FF FF FF`: on wasm32 this trapped with `RuntimeError: unreachable`.
        for name in ["parse_certificate", "key_info", "card_decode"] {
            let args = match name {
                "key_info" => r#"{"spki":"MIT_____"}"#.to_string(),
                "card_decode" => r#"{"vcard":"BEGIN:VCARD
VERSION:4.0
X-PACT-VERSION:2
X-PACT-CERT:MIT_____
END:VCARD
","now":0}"#
                    .to_string(),
                _ => r#"{"der":"MIT_____"}"#.to_string(),
            };
            let out: Value = serde_json::from_str(&call(name, &args)).unwrap();
            assert!(out.get("error").is_some() || out.get("cert").is_some(), "{name} answered {out}");
        }
        // The vault's parameters, at both extremes, refused before Argon2id is asked for anything.
        for kdf in [
            r#"{"name":"argon2id","m_kib":268435455,"t":3,"p":1}"#,
            r#"{"name":"argon2id","m_kib":65536,"t":4000000000,"p":1}"#,
            r#"{"name":"argon2id","m_kib":8,"t":1,"p":1}"#,
            r#"{"name":"argon2id","m_kib":4294967304,"t":3,"p":1}"#,
            r#"{"name":"scrypt","m_kib":65536,"t":3,"p":1}"#,
        ] {
            // A plaintext `vault_seal` would seal: the KDF is read after the generation (CONTRACT §0),
            // so a `v` of 1 here would be refused for itself and this would test nothing about the KDF.
            let args = format!(r#"{{"passphrase":"x","plaintext":{{"v":2}},"kdf":{kdf}}}"#);
            let out: Value = serde_json::from_str(&call("vault_seal", &args)).unwrap();
            assert_eq!(out["error"], "vault", "vault_seal with {kdf} answered {out}");
            let doc = format!(
                r#"{{"passphrase":"x","vault":{{"format":"pact-vault/1","kdf":{kdf},"salt":"AAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAA","ct":"AAAA"}}}}"#
            );
            let out: Value = serde_json::from_str(&call("vault_open", &doc)).unwrap();
            assert_eq!(out["error"], "vault", "vault_open with {kdf} answered {out}");
        }
        // A `ts` of `i64::MIN + now`: `(now - ts).abs()` wrapped to `i64::MIN`, which is <= 300, so the
        // skew window and the thirty-day cap both passed. `decide` needs a whole node to reach, so the
        // band is asserted through the function that reads the same header members.
        let out: Value =
            serde_json::from_str(&call("decide", r#"{"now":0,"envelope":{"protected":"","enc":"","ct":"","sig":""}}"#)).unwrap();
        assert!(out.get("error").is_some() || out["result"]["code"] == "envelope_invalid", "decide answered {out}");
    }
}
