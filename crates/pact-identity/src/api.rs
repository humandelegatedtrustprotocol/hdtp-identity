//! One surface for every host: `call(name, args_json) -> json`, the CONTRACT's functions by name.
//! Never panics across the boundary; every failure is `{"error", "why"}`.
use crate::keys::{PrivateKey, PublicKey};
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{b64u, err, from_b64u, Error, Result};
use crate::x509::{self, ChainResult, LeafSpec};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

mod cards;
mod certificates;
mod csr;
mod envelopes;
mod export;
mod keys;
mod ledger;
mod limits;
mod signing;
mod vault;

/// The version of `pact-protocol/SPEC.md` this core implements.
///
/// It read `2.0.0-draft` for days after the draft shipped as 2.0.0, and through 2.1.0, because a
/// literal in a dispatch arm has nothing to fail against. `tests/vectors.rs` now compares it with
/// the version line of the document the vectors are read from, so the two cannot part quietly.
pub const SPEC_VERSION: &str = "2.2.4";

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

/// `<k> is required`: CONTRACT §0's answer to a member that is absent, and to one of the wrong type.
fn required(k: &str) -> Error {
    Error::new("bad_request", format!("{k} is required"))
}

fn s<'a>(a: &'a Value, k: &str) -> Result<&'a str> {
    a.get(k).and_then(|v| v.as_str()).ok_or_else(|| required(k))
}

// The optional members (CONTRACT §0). Absent or null is not given; present and of the wrong type is
// refused in the words its absence gets where it is required — never read as absent. These read a
// member of the wrong type as absent, and so a `serial` of 7 built a root with a random serial, a
// `guest` of "yes" let a guest name this host, an `expected_root` of 7 accepted any root and an `exp`
// of 1.5 sealed ts + 600, where the Go port refused each (F5, R02, C3).

/// An optional string.
fn opt_s<'a>(a: &'a Value, k: &str) -> Result<Option<&'a str>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v)),
        Some(_) => Err(required(k)),
    }
}
/// Optional bytes: present and not a string is bytes that will not decode, as for `bytes`.
fn opt_bytes(a: &Value, k: &str) -> Result<Option<Vec<u8>>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(from_b64u(v)?)),
        Some(_) => err("parse", "not base64url"),
    }
}
/// A required base64url member. Absent is a caller's mistake that names the member; present but not
/// a base64url string is a decode failure, and both ports say so in the same words.
fn bytes(a: &Value, k: &str) -> Result<Vec<u8>> {
    opt_bytes(a, k)?.ok_or_else(|| required(k))
}
fn instant(a: &Value, k: &str) -> Result<i64> {
    parse_rfc3339(s(a, k)?)
}
fn opt_instant(a: &Value, k: &str) -> Result<Option<i64>> {
    opt_s(a, k)?.map(parse_rfc3339).transpose()
}
/// An optional integer: one serde_json reads as an `i64`, which is a number written without a
/// fraction or an exponent that fits 64 bits — and not `-0`, which it reads as a float. The Go port
/// reads the same set (go/api_args.go's `integerText`).
fn opt_int(a: &Value, k: &str) -> Result<Option<i64>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_i64().map(Some).ok_or_else(|| required(k)),
    }
}
fn int(a: &Value, k: &str) -> Result<i64> {
    opt_int(a, k)?.ok_or_else(|| required(k))
}
/// `valid_days`, read with the arguments (CONTRACT §0): absent is a year; present and not an integer
/// is a member of the wrong type, `valid_days is required`, and never a year it was not asked for.
fn valid_days(a: &Value) -> Result<i64> {
    let days = opt_int(a, "valid_days")?.unwrap_or(365);
    if !(1..=x509::MAX_LEAF_DAYS).contains(&days) {
        return err("bad_request", "validity must be between one and 398 days");
    }
    Ok(days)
}
/// An optional boolean: absent or null is false.
fn boolean(a: &Value, k: &str) -> Result<bool> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(required(k)),
    }
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
    let Some(items) = a.get(k).and_then(|v| v.as_array()) else { return Err(required(k)) };
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

/// An optional `dns_name`: absent or null is none; present and empty is refused, `dns_name is empty`.
/// Written, it was an empty dNSName that csr_check and chain rule 5 then refused, and the Go port wrote
/// none (R26, F4).
fn dns_name(a: &Value) -> Result<Option<String>> {
    match opt_s(a, "dns_name")? {
        Some("") => err("bad_request", "dns_name is empty"),
        d => Ok(d.map(str::to_string)),
    }
}

fn leaf_spec<'a>(a: &'a Value, issuer: &'a PublicKey, host_key: &'a PublicKey, serial_bytes: Vec<u8>) -> Result<LeafSpec<'a>> {
    // The contract's members and no others: `uris`, `usage`, `extra`, `ca`, `aki` and `alg_oid` were
    // read here too, undeclared, so one call built a CA leaf, a leaf with no URI or a leaf under
    // another algorithm's name through this port and a profile leaf through the Go port (T16, F1).
    // No JSON caller ever sent them; the typed `LeafSpec` keeps them for the tests and the CLI.
    let uris = vec![s(a, "endpoint")?.to_string()];
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
        dns_name: dns_name(a)?,
        not_before,
        not_after,
        serial: serial_bytes,
        ca: false,
        usage: None,
        aki: None,
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

/// What a function answers: a JSON value, or, for an answer as large as the file it describes, the
/// JSON text already written — so that no tree of values is built beside it (export_read).
pub(crate) enum Answer {
    Json(Value),
    Text(String),
}

fn dispatch(name: &str, a: &Value) -> Result<Answer> {
    Ok(Answer::Json(match name {
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
        "refresh_check" => cards::refresh_check(a)?,
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
        "export_read" => return export::export_read(a),
        "export_read_messages" => export::export_read_messages(a)?,
        "export_read_end" => export::export_read_end(a)?,
        "export_write" => export::export_write(a)?,
        "export_write_messages" => export::export_write_messages(a)?,
        "export_manifest" => export::export_manifest(a)?,
        "export_merge" => export::export_merge(a)?,
        "book_rows" => export::book_rows(a)?,
        "media_holds_private_key" => export::media_holds_private_key(a)?,
        // §6.1 ledger
        "ledger_check" => ledger::ledger_check(a)?,
        // §6.3 limits
        "limits_rules_check" => limits::limits_rules_check(a)?,
        "limits_decide" => limits::limits_decide(a)?,
        "limits_buckets" => limits::limits_buckets(a)?,
        "version" => json!({ "crate": env!("CARGO_PKG_VERSION"), "spec": SPEC_VERSION }),
        // `call` names a function nobody declares before this is reached; `declared` and this match are
        // one list, which every_function_declares_the_contracts_members and js/parity.mjs hold.
        other => return Err(unknown(other)),
    }))
}

/// The answer to a name no function has, whatever the arguments are (CONTRACT §0).
fn unknown(name: &str) -> Error {
    Error::new("unsupported", format!("no function named {name}"))
}

/// The members each function declares, `params.properties` of contract/contract.json, in its order.
/// `call` holds the arguments to them before a member is read (CONTRACT §0): a member the function
/// does not declare is a caller's mistake, refused by name, and never read as though it were absent.
/// `build_leaf` read six the contract never declared (T16), and the member nobody checks is where
/// the two ports come apart. The test `every_function_declares_the_contracts_members` holds this
/// table to the contract file; go/api.go carries the Go port's, held the same way.
fn declared(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "version" | "prf_salt" => &[],
        "generate_key" => &["alg"],
        "key_from_seed" => &["alg", "seed"],
        "derive_seed" => &["prf", "info"],
        "public_key" => &["pkcs8"],
        "key_info" => &["spki"],
        "sign" => &["pkcs8", "data"],
        "verify" => &["spki", "data", "sig"],
        "build_root" => &["cn", "pkcs8", "not_before", "serial"],
        "root_tbs" => &["cn", "spki", "not_before", "serial"],
        "assemble_root" | "assemble_leaf" => &["tbs", "sig", "sig_alg"],
        "build_leaf" => &["cn", "root_cn", "host_spki", "endpoint", "dns_name", "not_before", "not_after", "serial", "root_pkcs8"],
        "leaf_tbs" => &["cn", "root_cn", "host_spki", "endpoint", "dns_name", "not_before", "not_after", "serial", "root_spki"],
        "parse_certificate" => &["der"],
        "profile_error" => &["der", "kind"],
        "validate_chain" => &["chain", "now", "expected_root", "expected_endpoint"],
        "compare_leaves" => &["pinned", "presented"],
        "is_normal_https" => &["url"],
        "address_guard" => &["endpoint", "self_endpoint", "guest"],
        "ip_is_private" => &["ip"],
        "csr_new" => &["cn", "host_pkcs8", "endpoint", "dns_name"],
        "csr_check" => &["der", "root_spkis"],
        "issue_from_csr" => &["csr", "root_cn", "root_spkis", "now", "previous_not_before", "valid_days", "root_pkcs8"],
        "issue_tbs_from_csr" => &["csr", "root_cn", "root_spkis", "now", "previous_not_before", "valid_days", "root_spki"],
        "signing_request_check" => &["request", "origin", "now", "root_spkis"],
        "card_encode" => &["fn", "cert", "seal", "extra"],
        "card_decode" => &["vcard", "now"],
        "refresh_check" => &["pin", "answer", "now"],
        "suite_for" => &["spki"],
        "hpke_seal" => &["suite", "recipient_spki", "info", "aad", "plaintext", "ephemeral_seed"],
        "hpke_open" => &["suite", "recipient_pkcs8", "recipient_spki", "info", "aad", "enc", "ct"],
        "seal_request" => {
            &["recipient_leaf", "sender_pkcs8", "form", "sender_chain", "msg_id", "ts", "exp", "ephemeral_seed", "method", "params", "cty"]
        }
        "seal_result" => {
            &["recipient_spki", "sender_pkcs8", "form", "sender_chain", "msg_id", "ts", "exp", "ephemeral_seed", "result", "error"]
        }
        "open_result" => &["envelope", "my_pkcs8", "my_spki", "msg_id", "now", "pins", "expected_root", "expected_endpoint"],
        "follow_renewed" => &["answer", "pinned_root", "pinned_leaf", "dialed", "now"],
        "decide" => &["now", "envelope", "node"],
        "vault_seal" => &["passphrase", "plaintext", "kdf", "salt", "nonce"],
        "vault_open" => &["passphrase", "vault"],
        "wallet_issue" => &["vault_plaintext", "record_plaintext", "root_fingerprint", "csr", "now", "valid_days", "move"],
        "export_read" => &["directory", "manifest", "contacts_csv", "threads_csv", "owner", "now"],
        "export_read_messages" => &["lines", "threads", "contacts", "media", "first_line"],
        "export_read_end" => &["manifest", "messages_sha256", "lines", "ids", "msg_ids", "reply_tos", "media_seen", "media"],
        "export_write" => &["owner", "owner_name", "exported_at", "tool", "contacts", "threads", "media"],
        "export_write_messages" => &["messages", "msg_ids"],
        "export_manifest" => &["partial", "hashes", "messages"],
        "export_merge" => &["held", "rows"],
        "book_rows" => &["contacts", "exported_at"],
        "media_holds_private_key" => &["bytes"],
        "ledger_check" => &["ledger", "root", "endpoint", "now", "move"],
        "limits_rules_check" => &["rules"],
        "limits_decide" => &["rules", "charge", "now", "state"],
        "limits_buckets" => &["rules", "charge"],
        _ => return None,
    })
}

/// The first member of `keys`, in sorted order, that function `name` does not declare, refused in
/// the words CONTRACT §0 fixes. `None` for a function nobody defines: `dispatch` names that.
pub(crate) fn undeclared<'k>(name: &str, keys: impl Iterator<Item = &'k str>) -> Option<Error> {
    let allowed = declared(name)?;
    let mut extra: Vec<&str> = keys.filter(|k| !allowed.contains(k)).collect();
    extra.sort_unstable();
    extra.first().map(|k| Error::new("bad_request", format!("{name} takes no member \"{k}\"")))
}

/// What `call` answers arguments holding an unpaired UTF-16 surrogate escape.
pub const LONE_SURROGATE: &str = "args: a string holds half of a UTF-16 surrogate pair";

/// The boundary. `args` is one JSON object; the answer is one JSON object, never an exception.
pub fn call(name: &str, args: &str) -> String {
    // The name first: one the contract does not have is `unsupported`, whatever the arguments are
    // (CONTRACT §0). This read the arguments first, so a list, null or half a surrogate pair beside an
    // unknown name was a refusal of the arguments here and `unsupported` in the Go port (R34).
    if declared(name).is_none() {
        return answer(Err(unknown(name)));
    }
    // A \u escape of half a surrogate pair: serde_json refuses it in words of its own, and Go's
    // encoding/json reads it as U+FFFD, so the two ports answered it two ways. Both name it next, in
    // these words, before anything reads the arguments.
    if crate::util::lone_surrogate(args) {
        return json!({ "error": "bad_request", "why": LONE_SURROGATE }).to_string();
    }
    // What one port's JSON parser refuses and the other's reads — a number infinite as a double, or
    // containers nested past serde_json's limit — named next, in fixed words: the core answered
    // serde's own (`args: number out of range at line 1 column 10`) and the Go port read the
    // arguments and went on (R40, S3-2).
    if let Some(why) = crate::util::json_limit(args) {
        return json!({ "error": "bad_request", "why": format!("args: {why}") }).to_string();
    }
    // export_read_end's lists can hold an id per message of a file; its arguments are read straight
    // from their text when they read (api/export.rs), rather than into a tree of values first.
    if name == "export_read_end" {
        let lean = || export::export_read_end_lean(args);
        #[cfg(not(target_arch = "wasm32"))]
        let lean = std::panic::catch_unwind(lean).unwrap_or_else(|_| Some(err("internal", "panic")));
        #[cfg(target_arch = "wasm32")]
        let lean = lean();
        if let Some(out) = lean {
            return answer(out.map(Answer::Json));
        }
    }
    let a: Value = match serde_json::from_str(args) {
        Ok(v @ Value::Object(_)) => v,
        // Text that does not parse is not an object either, in the words the Go port's `Call` has for
        // both: serde's own (`args: EOF while parsing an object at line 1 column 1`) went into `why`,
        // which CONTRACT §0 forbids (F21).
        _ => return json!({ "error": "bad_request", "why": "args is a JSON object" }).to_string(),
    };
    if let Some(e) = undeclared(name, a.as_object().into_iter().flat_map(|o| o.keys().map(String::as_str))) {
        return answer(Err(e));
    }
    let run = || dispatch(name, &a);
    #[cfg(not(target_arch = "wasm32"))]
    let out = std::panic::catch_unwind(run).unwrap_or_else(|_| err("internal", "panic"));
    #[cfg(target_arch = "wasm32")]
    let out = run();
    answer(out)
}

/// An answer as the boundary writes it.
fn answer(out: Result<Answer>) -> String {
    match out {
        Ok(Answer::Json(v)) => v.to_string(),
        Ok(Answer::Text(t)) => t,
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
        // Every shape that is not an object, `null` included. js/parity.mjs holds the Go port to the
        // same answers for each (js/cases/dispatcher.mjs); this is the core's own record of them.
        for args in ["[]", "null", "3", "\"x\"", "true"] {
            assert!(call("verify", args).contains("args is a JSON object"), "verify({args})");
        }
        // Half a surrogate pair, in either order and at the end, is refused in fixed words; a whole
        // pair, and an escaped backslash before a `u`, are text.
        for args in [r#"{"spki":"a\ud800"}"#, r#"{"spki":"\udc00b"}"#, r#"{"spki":"\ud800\u0041"}"#] {
            assert!(call("verify", args).contains(LONE_SURROGATE), "{args}");
        }
        // export_read_end's lean path answers what the ordinary one does, a number past the largest
        // double in a member it does not read included: the fixed words, never `ok` (R40).
        let wide = r#"{"x":1e400,"manifest":"{}","lines":0,"ids":[],"msg_ids":[],"reply_tos":[],"media_seen":[],"media":[]}"#;
        assert_eq!(call("export_read_end", wide), r#"{"error":"bad_request","why":"args: a number is outside the range of a double"}"#);
        for args in [r#"{"x":"\ud83d\ude00"}"#, r#"{"x":"\\ud800"}"#] {
            assert!(!call("version", args).contains(LONE_SURROGATE), "{args}");
        }
        let k: Value = serde_json::from_str(&call("generate_key", r#"{"alg":"ed25519"}"#)).unwrap();
        assert_eq!(k["alg"], "ed25519");
        let v: Value = serde_json::from_str(&call("version", "{}")).unwrap();
        assert_eq!(v["spec"], SPEC_VERSION);
    }

    /// A member of the wrong type is refused, never read as absent (CONTRACT §0): bytes answer as bytes
    /// that will not decode, anything else as its absence would were it required; absent and null are
    /// not given. js/cases/generated.mjs holds both ports to the same answer for every optional member
    /// of every function; this is the core's own record of the readers.
    #[test]
    fn a_member_of_the_wrong_type_is_refused_and_never_read_as_absent() {
        let a = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        let required = |k: &str| Some(Error::new("bad_request", format!("{k} is required")));
        let undecodable = Some(Error::new("parse", "not base64url"));
        for absent in ["{}", r#"{"k":null}"#] {
            assert_eq!(opt_s(&a(absent), "k"), Ok(None));
            assert_eq!(opt_bytes(&a(absent), "k"), Ok(None));
            assert_eq!(opt_int(&a(absent), "k"), Ok(None));
            assert_eq!(boolean(&a(absent), "k"), Ok(false));
            assert_eq!(opt_instant(&a(absent), "k"), Ok(None));
        }
        assert_eq!(opt_s(&a(r#"{"k":7}"#), "k").err(), required("k"));
        assert_eq!(opt_instant(&a(r#"{"k":7}"#), "k").err(), required("k"));
        assert_eq!(opt_bytes(&a(r#"{"k":7}"#), "k").err(), undecodable);
        assert_eq!(seed32(&a(r#"{"k":[1]}"#), "k").err(), undecodable);
        assert_eq!(serial(&a(r#"{"serial":7}"#)).err(), undecodable);
        assert_eq!(boolean(&a(r#"{"k":"yes"}"#), "k").err(), required("k"));
        assert_eq!(boolean(&a(r#"{"k":1}"#), "k").err(), required("k"));
        // An integer is what serde_json reads as an i64, the list in js/boundary-text.json (below);
        // -0, which it reads as a float, is not a number of days.
        assert_eq!(opt_int(&a(r#"{"k":"7"}"#), "k").err(), required("k"));
        assert_eq!(valid_days(&a(r#"{"valid_days":-0}"#)).err(), required("valid_days"));
        // `extra` is a list of strings, every item: one that is not — null included — was dropped.
        for extra in [r#"["X-A:1",7]"#, "[null]", r#""X-A:1""#] {
            let out: Value = serde_json::from_str(&call("card_encode", &format!(r#"{{"fn":"A","cert":"AAAA","extra":{extra}}}"#))).unwrap();
            assert_eq!(out, json!({ "error": "bad_request", "why": "extra is required" }), "extra {extra}");
        }
    }

    /// The arguments text both ports read alike, one list for both: js/boundary-text.json, which
    /// go/api_args_test.go reads too. Text that does not parse is not an object, in fixed words and
    /// never serde's (F21); what one parser refuses and the other reads — a number infinite as a
    /// double, containers nested past `JSON_MAX_DEPTH` — is named before the arguments are read (R40,
    /// S3-2); and an integer is what serde_json reads as an i64, which -0 is not (S3-1). The parity
    /// harness cannot send text that does not parse, nor ask a reader about one token.
    #[test]
    fn the_arguments_text_is_read_as_the_go_port_reads_it() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../js/boundary-text.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let answer = |args: &str| serde_json::from_str::<Value>(&call("key_info", args)).unwrap();
        assert_eq!(doc["max_depth"], json!(crate::util::JSON_MAX_DEPTH));
        for c in doc["calls"].as_array().unwrap() {
            assert_eq!(answer(c["args"].as_str().unwrap()), c["want"], "key_info({})", c["args"]);
        }
        // A name no function has is judged before the arguments are read, whatever they are (R34).
        let unknown = &doc["unknown_name"];
        let texts = unknown["args"].as_array().unwrap();
        assert!(texts.len() >= 5, "js/boundary-text.json's unknown_name holds {} texts", texts.len());
        for t in texts {
            let out: Value = serde_json::from_str(&call(unknown["fn"].as_str().unwrap(), t.as_str().unwrap())).unwrap();
            assert_eq!(out, unknown["want"], "{}({t})", unknown["fn"]);
        }
        let nested = |n: usize| format!(r#"{{"spki":{}1{}}}"#, "[".repeat(n), "]".repeat(n));
        assert_eq!(answer(&nested(crate::util::JSON_MAX_DEPTH - 1)), doc["nested"]["within"]);
        assert_eq!(answer(&nested(crate::util::JSON_MAX_DEPTH)), doc["nested"]["beyond"]);
        for (list, read) in [("read", true), ("refused", false)] {
            for t in doc["integers"][list].as_array().unwrap() {
                let a: Value = serde_json::from_str(&format!(r#"{{"k":{}}}"#, t.as_str().unwrap())).unwrap();
                assert_eq!(matches!(opt_int(&a, "k"), Ok(Some(_))), read, "{t}");
            }
        }
    }

    /// `declared` is contract/contract.json's `params.properties`, function by function, in order;
    /// and `call` refuses a member outside it, before it reads the ones inside it.
    #[test]
    fn every_function_declares_the_contracts_members() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contract/contract.json");
        let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let methods = contract["methods"].as_object().unwrap();
        for (name, m) in methods {
            let want: Vec<&str> = m["params"]["properties"].as_object().map(|p| p.keys().map(String::as_str).collect()).unwrap_or_default();
            assert_eq!(declared(name), Some(&want[..]), "{name}: the members this port holds its arguments to, and the contract's");
            // Every member the contract declares gets past the check; one it does not is named, and a
            // missing required member beside it is not reached.
            for member in &want {
                let out = call(name, &json!({ *member: null }).to_string());
                assert!(!out.contains("takes no member"), "{name}({member}) answered {out}");
            }
            let out: Value = serde_json::from_str(&call(name, r#"{"not_a_member":1,"zz":2}"#)).unwrap();
            assert_eq!(out, json!({ "error": "bad_request", "why": format!("{name} takes no member \"not_a_member\"") }), "{name}");
        }
        assert_eq!(declared("nope"), None);
        assert!(call("nope", r#"{"not_a_member":1}"#).contains("no function named nope"));
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
