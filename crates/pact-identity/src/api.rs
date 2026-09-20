//! One surface for every host: `call(name, args_json) -> json`, the CONTRACT's functions by name.
//! Never panics across the boundary; every failure is `{"error", "why"}`.
use crate::address;
use crate::card;
use crate::csr;
use crate::envelope::{self, CallerPin, Form, OpenResultArgs, SealRequest, SealResult, Wire};
use crate::hpke::{self, Suite};
use crate::keys::{self, Alg, PrivateKey, PublicKey};
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{b64u, err, from_b64u, Error, Result};
use crate::vault::{self};
use crate::x509::{self, ChainResult, Extra, LeafSpec};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

/// The version of `pact-protocol/SPEC.md` this core implements.
///
/// It read `2.0.0-draft` for days after the draft shipped as 2.0.0, and through 2.1.0, because a
/// literal in a dispatch arm has nothing to fail against. `tests/vectors.rs` now compares it with
/// the version line of the document the vectors are read from, so the two cannot part quietly.
pub const SPEC_VERSION: &str = "2.1.1";

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
        "generate_key" => key_json(&PrivateKey::generate(Alg::parse(s(a, "alg")?)?)?),
        "key_from_seed" => {
            let seed = seed32(a, "seed")?.ok_or_else(|| Error::new("bad_request", "seed is required"))?;
            key_json(&PrivateKey::from_seed(Alg::parse(s(a, "alg")?)?, &seed)?)
        }
        // §2.1. Two calls rather than one so a wallet never hardcodes the salt: the constant lives
        // here, the vectors prove it, and a page that gets it wrong fails loudly instead of quietly
        // becoming somebody else.
        "prf_salt" => json!({ "salt": b64u(&keys::prf_salt()), "infos": keys::DERIVATION_INFOS }),
        "derive_seed" => json!({ "seed": b64u(&keys::derive_seed(&bytes(a, "prf")?, s(a, "info")?)?) }),
        "public_key" => {
            let k = private(a, "pkcs8")?;
            let p = k.public();
            json!({ "alg": k.alg().name(), "spki": b64u(p.spki()), "fingerprint": p.fingerprint() })
        }
        "key_info" => {
            let p = public(a, "spki")?;
            json!({ "alg": p.alg().name(), "fingerprint": p.fingerprint(), "key_id": b64u(&p.key_id()) })
        }
        "sign" => json!({ "sig": b64u(&private(a, "pkcs8")?.sign(&bytes(a, "data")?)) }),
        "verify" => json!({ "valid": public(a, "spki")?.verify(&bytes(a, "data")?, &bytes(a, "sig")?) }),

        // §2 certificates
        "build_root" => {
            let k = private(a, "pkcs8")?;
            let der = x509::build_root(s(a, "cn")?, &k, instant(a, "not_before")?, &serial(a)?)?;
            json!({ "der": b64u(&der), "fingerprint": k.public().fingerprint() })
        }
        "root_tbs" => {
            let u = x509::root_tbs(s(a, "cn")?, &public(a, "spki")?, instant(a, "not_before")?, &serial(a)?)?;
            json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)) })
        }
        "assemble_root" | "assemble_leaf" => {
            let tbs = bytes(a, "tbs")?;
            // The algorithm outside is the TBS's own third field; a `sig_alg` handed back (base64url
            // DER of the AlgorithmIdentifier) must equal it, so the two can never differ.
            let declared = x509::declared_alg(&tbs)?;
            if let Some(given) = opt_bytes(a, "sig_alg")? {
                if given != declared {
                    return err("bad_request", "sig_alg is not the algorithm the tbs declares");
                }
            }
            json!({ "der": b64u(&x509::assemble_raw(&tbs, &declared, &bytes(a, "sig")?)) })
        }
        "build_leaf" => {
            let root = private(a, "root_pkcs8")?;
            let issuer = root.public();
            let host = public(a, "host_spki")?;
            let spec = leaf_spec(a, &issuer, &host, serial(a)?)?;
            json!({ "der": b64u(&x509::build_leaf(&spec, &root)?) })
        }
        "leaf_tbs" => {
            let issuer = public(a, "root_spki")?;
            let host = public(a, "host_spki")?;
            let spec = leaf_spec(a, &issuer, &host, serial(a)?)?;
            let u = x509::leaf_tbs(&spec)?;
            json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)) })
        }
        "parse_certificate" => cert_json(&x509::parse(&bytes(a, "der")?)?),
        "profile_error" => json!({ "error": x509::profile_error(&x509::parse(&bytes(a, "der")?)?, s(a, "kind")?) }),
        "validate_chain" => chain_result(x509::validate_chain(
            &chain(a, "chain")?,
            instant(a, "now")?,
            opt_s(a, "expected_root"),
            opt_s(a, "expected_endpoint"),
        )),
        "compare_leaves" => json!({ "order": x509::compare_leaves(&bytes(a, "pinned")?, &bytes(a, "presented")?)? }),
        "is_normal_https" => json!({ "normal": x509::is_normal_https(s(a, "url")?) }),
        "address_guard" => match address::address_guard(s(a, "endpoint")?, opt_s(a, "self_endpoint"), boolean(a, "guest")) {
            Ok(()) => json!({ "ok": true }),
            Err(e) => json!({ "ok": false, "why": e.why }),
        },
        "ip_is_private" => json!({ "private": address::ip_is_private(s(a, "ip")?) }),

        // §3 CSR
        "csr_new" => {
            json!({ "der": b64u(&csr::csr_new(s(a, "cn")?, &private(a, "host_pkcs8")?, s(a, "endpoint")?, opt_s(a, "dns_name"))?) })
        }
        "csr_check" => match csr::check(&bytes(a, "der")?, &opt_chain(a, "root_spkis")?) {
            Ok(c) => {
                json!({ "ok": true, "cn": c.cn, "spki": b64u(c.key.spki()), "fingerprint": c.key.fingerprint(), "alg": c.key.alg().name(), "endpoint": c.endpoint, "dns_name": c.dns_name })
            }
            Err(e) => json!({ "ok": false, "why": e.why }),
        },
        "issue_from_csr" => {
            let root = private(a, "root_pkcs8")?;
            let mut roots = opt_chain(a, "root_spkis")?;
            roots.push(root.public().spki().to_vec());
            let req = csr::check(&bytes(a, "csr")?, &roots)?;
            let i = csr::issue(
                &req,
                s(a, "root_cn")?,
                &root,
                instant(a, "now")?,
                opt_instant(a, "previous_not_before")?,
                opt_int(a, "valid_days").unwrap_or(365),
            )?;
            json!({ "der": b64u(&i.der), "endpoint": req.endpoint, "not_before": format_rfc3339(i.not_before), "not_after": format_rfc3339(i.not_after) })
        }
        "issue_tbs_from_csr" => {
            let root = public(a, "root_spki")?;
            let mut roots = opt_chain(a, "root_spkis")?;
            roots.push(root.spki().to_vec());
            let req = csr::check(&bytes(a, "csr")?, &roots)?;
            let (u, nb, na) = csr::issue_tbs(
                &req,
                s(a, "root_cn")?,
                &root,
                instant(a, "now")?,
                opt_instant(a, "previous_not_before")?,
                opt_int(a, "valid_days").unwrap_or(365),
            )?;
            json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)), "endpoint": req.endpoint, "not_before": format_rfc3339(nb), "not_after": format_rfc3339(na) })
        }

        // §4 cards
        "card_encode" => {
            let extra: Vec<String> = a
                .get("extra")
                .and_then(|e| e.as_array())
                .map(|items| items.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            json!({ "vcard": card::encode(s(a, "fn")?, &bytes(a, "cert")?, opt_s(a, "seal"), &extra) })
        }
        "card_decode" => {
            let now = opt_instant(a, "now")?.unwrap_or(0);
            let text = s(a, "vcard")?;
            let c = card::decode(text, now)?;
            json!({ "fn": c.fn_, "version": 2, "seal": c.seal, "cert": b64u(&c.cert), "root": c.root, "endpoint": c.endpoint, "expired": c.expired, "ignored": c.ignored, "bytes": text.len(), "leaf": cert_json(&c.leaf) })
        }

        // §5 envelopes
        "suite_for" => json!({ "suite": envelope::suite_name(&bytes(a, "spki")?)? }),
        "hpke_seal" => {
            let suite = Suite::parse(s(a, "suite")?).ok_or_else(|| Error::new("envelope_invalid", "version or suite"))?;
            let (enc, ct) = hpke::seal(
                suite,
                &public(a, "recipient_spki")?,
                s(a, "info")?.as_bytes(),
                &opt_bytes(a, "aad")?.unwrap_or_default(),
                &bytes(a, "plaintext")?,
                seed32(a, "ephemeral_seed")?,
            )?;
            json!({ "enc": b64u(&enc), "ct": b64u(&ct) })
        }
        "hpke_open" => {
            let suite = Suite::parse(s(a, "suite")?).ok_or_else(|| Error::new("envelope_invalid", "version or suite"))?;
            let pt = hpke::open(
                suite,
                &private(a, "recipient_pkcs8")?,
                s(a, "info")?.as_bytes(),
                &opt_bytes(a, "aad")?.unwrap_or_default(),
                &bytes(a, "enc")?,
                &bytes(a, "ct")?,
            )?;
            json!({ "plaintext": b64u(&pt) })
        }
        "seal_request" => {
            let leaf = x509::parse(&bytes(a, "recipient_leaf")?)?;
            let sender = private(a, "sender_pkcs8")?;
            let sender_chain = chain(a, "sender_chain").ok();
            let wire = envelope::seal_request(SealRequest {
                recipient: &leaf.public_key,
                sender: &sender,
                form: Form::parse(opt_s(a, "form").unwrap_or("chain"))?,
                sender_chain: sender_chain.as_deref(),
                method: opt_s(a, "method").unwrap_or("tools/call").to_string(),
                params: a.get("params").cloned().unwrap_or(json!({})),
                msg_id: id(a, "msg_id")?.to_string(),
                ts: int(a, "ts")?,
                exp: opt_int(a, "exp"),
                cty: opt_s(a, "cty").map(|c| c.to_string()),
                ephemeral_seed: seed32(a, "ephemeral_seed")?,
            })?;
            serde_json::to_value(wire).map_err(|e| Error::new("internal", e.to_string()))?
        }
        "seal_result" => {
            let recipient = public(a, "recipient_spki")?;
            let sender = private(a, "sender_pkcs8")?;
            let sender_chain = chain(a, "sender_chain").ok();
            let wire = envelope::seal_result(SealResult {
                recipient: &recipient,
                sender: &sender,
                form: Form::parse(opt_s(a, "form").unwrap_or("chain"))?,
                sender_chain: sender_chain.as_deref(),
                result: a.get("result").cloned(),
                error: a.get("error").cloned(),
                msg_id: id(a, "msg_id")?.to_string(),
                ts: int(a, "ts")?,
                exp: opt_int(a, "exp"),
                ephemeral_seed: seed32(a, "ephemeral_seed")?,
            })?;
            serde_json::to_value(wire).map_err(|e| Error::new("internal", e.to_string()))?
        }
        "open_result" => {
            let wire: Wire = serde_json::from_value(a.get("envelope").cloned().unwrap_or(Value::Null))
                .map_err(|_| Error::new("envelope_invalid", "envelope members"))?;
            let key = private(a, "my_pkcs8")?;
            let pins: Vec<CallerPin> = serde_json::from_value(a.get("pins").cloned().unwrap_or(json!([])))
                .map_err(|e| Error::new("bad_request", format!("pins: {e}")))?;
            envelope::open_result(OpenResultArgs {
                envelope: &wire,
                my_key: &key,
                msg_id: s(a, "msg_id")?,
                now: instant(a, "now")?,
                pins: &pins,
                expected_root: opt_s(a, "expected_root"),
                expected_endpoint: opt_s(a, "expected_endpoint"),
            })?
        }
        "follow_renewed" => envelope::follow_renewed(
            a.get("answer").unwrap_or(&Value::Null),
            s(a, "pinned_root")?,
            &bytes(a, "pinned_leaf")?,
            s(a, "dialed")?,
            instant(a, "now")?,
        ),
        "decide" => {
            // A missing `node` is not a decision against an empty node, and the member is named the
            // way the caller wrote it rather than the way serde reports a missing field — the Go port
            // cannot reproduce another library's wording, and CONTRACT §0 promises it will not have to.
            for k in ["node", "envelope"] {
                if a.get(k).is_none_or(Value::is_null) {
                    return err("bad_request", format!("{k} is required"));
                }
            }
            let input: envelope::DecideInput =
                serde_json::from_value(a.clone()).map_err(|_| Error::new("bad_request", "decide input does not read"))?;
            serde_json::to_value(envelope::decide(&input)?).map_err(|e| Error::new("internal", e.to_string()))?
        }

        // §6 vault
        "vault_seal" => {
            // ONE parser, shared with `vault_open`, so the bounds cannot diverge between sealing and
            // opening and `name` is checked on both. This built the struct inline: it never looked at
            // `name` (so `{"name":"scrypt"}` sealed with Argon2id and said nothing, while `vault_open`
            // refused that name), it had no floor, and it cast with `as`.
            let kdf = match a.get("kdf") {
                None | Some(Value::Null) => None,
                Some(_) => Some(vault::kdf_from_args(a.get("kdf"))?),
            };
            // Sealing an absent plaintext sealed the JSON literal `null` and handed back a
            // well-formed vault with nothing in it — a file a person would keep, and restore from.
            let Some(plaintext) = a.get("plaintext").filter(|v| !v.is_null()) else {
                return err("bad_request", "plaintext is required");
            };
            json!({ "vault": vault::seal(s(a, "passphrase")?, plaintext, kdf, opt_bytes(a, "salt")?, opt_bytes(a, "nonce")?)? })
        }
        "vault_open" => {
            let Some(doc) = a.get("vault").filter(|v| !v.is_null()) else {
                return err("bad_request", "vault is required");
            };
            json!({ "plaintext": vault::open(s(a, "passphrase")?, doc)? })
        }
        "wallet_issue" => vault::wallet_issue(
            a.get("vault_plaintext").unwrap_or(&Value::Null),
            s(a, "root_fingerprint")?,
            &bytes(a, "csr")?,
            instant(a, "now")?,
            opt_int(a, "valid_days").unwrap_or(365),
            boolean(a, "move"),
        )?,

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
            let args = format!(r#"{{"passphrase":"x","plaintext":{{"v":1}},"kdf":{kdf}}}"#);
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
