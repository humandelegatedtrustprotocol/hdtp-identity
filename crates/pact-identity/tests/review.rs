//! The cryptography review of 2026-09-14, as tests: each finding it made against the core is a case
//! here that failed before the fix and passes after it. Everything goes through the JSON boundary
//! where it can, so the shapes the review read are the shapes proven.
use pact_identity::der;
use pact_identity::keys::{Alg, PrivateKey};
use pact_identity::x509::{self, ChainResult};
use serde_json::{json, Value};

const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ED25519: &str = "1.3.101.112";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_SKI: &str = "2.5.29.14";
const E_A: &str = "https://agent.alina.example/mcp";
const NOW_RFC: &str = "2026-09-13T12:00:00Z";

fn now_s() -> i64 {
    pact_identity::time::parse_rfc3339(NOW_RFC).unwrap()
}
fn call(name: &str, args: Value) -> Value {
    serde_json::from_str(&pact_identity::call(name, &args.to_string())).unwrap()
}
fn b64u(b: &[u8]) -> String {
    pact_identity::util::b64u(b)
}
fn from_b64u(s: &str) -> Vec<u8> {
    pact_identity::util::from_b64u(s).unwrap()
}
fn key(alg: &str) -> Value {
    call("generate_key", json!({ "alg": alg }))
}

/// A root and a leaf for alina, Ed25519, through the boundary.
struct Pair {
    root_key: Value,
    root: Vec<u8>,
    leaf_key: Value,
    leaf: Vec<u8>,
    root_fp: String,
}
fn pair(alg: &str, endpoint: &str) -> Pair {
    let root_key = key(alg);
    let root = call("build_root", json!({ "cn": "Alina Rao", "pkcs8": root_key["pkcs8"], "not_before": "2026-09-01T00:00:00Z" }));
    let leaf_key = key(alg);
    let leaf = call(
        "build_leaf",
        json!({ "cn": "Alina Rao", "root_cn": "Alina Rao", "root_pkcs8": root_key["pkcs8"], "host_spki": leaf_key["spki"], "endpoint": endpoint, "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z" }),
    );
    assert!(leaf["der"].is_string(), "{leaf}");
    Pair {
        root_fp: root["fingerprint"].as_str().unwrap().to_string(),
        root: from_b64u(root["der"].as_str().unwrap()),
        leaf_key,
        leaf: from_b64u(leaf["der"].as_str().unwrap()),
        root_key,
    }
}
fn refusal(chain: &[Vec<u8>]) -> (u32, String) {
    match x509::validate_chain(chain, now_s(), None, None) {
        ChainResult::Ok(_) => panic!("accepted"),
        ChainResult::Refused { rule, reason } => (rule as u32, reason),
    }
}
/// Rebuild a certificate's TBS with one of its eight fields replaced, re-sign it with `signer`, and
/// assemble it with the algorithm the TBS declares — so only the deviation under test differs.
fn with_field(cert_der: &[u8], index: usize, field: Vec<u8>, signer: &PrivateKey) -> Vec<u8> {
    let c = x509::parse(cert_der).unwrap();
    let tbs = der::read(&c.tbs, 0).unwrap();
    let mut fields: Vec<Vec<u8>> = der::children(&tbs).unwrap().iter().map(|n| n.raw.to_vec()).collect();
    fields[index] = field;
    let tbs = der::seq(&fields);
    let alg = x509::declared_alg(&tbs).unwrap();
    x509::assemble_raw(&tbs, &alg, &signer.sign(&tbs))
}
fn ext(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![der::oid(oid)];
    if critical {
        parts.push(der::boolean(true));
    }
    parts.push(der::octet(value));
    der::seq(&parts)
}
fn root_extensions(id: &[u8], basic: Vec<u8>, usage: Vec<u8>) -> Vec<u8> {
    der::explicit(
        3,
        &der::seq(&[ext(OID_BASIC_CONSTRAINTS, true, &basic), ext(OID_KEY_USAGE, true, &usage), ext(OID_SKI, false, &der::octet(id))]),
    )
}

// ── MEDIUM 2: the seam assembles with the algorithm the TBS declares, for a P-256 root too ──
#[test]
fn a_p256_root_signs_through_the_seam() {
    let root = key("p256");
    let u = call("root_tbs", json!({ "cn": "Bharat Mehta", "spki": root["spki"], "not_before": "2026-09-01T00:00:00Z" }));
    let alg_der = from_b64u(u["sig_alg"].as_str().unwrap());
    assert_eq!(alg_der, der::seq(&[der::oid(OID_ECDSA_SHA256)]), "the seam hands out the AlgorithmIdentifier as DER");
    let sig = call("sign", json!({ "pkcs8": root["pkcs8"], "data": u["tbs"] }));
    // The algorithm handed back must be the TBS's own; an Ed25519 one is refused.
    let wrong = call("assemble_root", json!({ "tbs": u["tbs"], "sig": sig["sig"], "sig_alg": b64u(&der::seq(&[der::oid(OID_ED25519)])) }));
    assert_eq!(wrong["error"], "bad_request", "{wrong}");
    let assembled = call("assemble_root", json!({ "tbs": u["tbs"], "sig": sig["sig"] }));
    let root_der = from_b64u(assembled["der"].as_str().unwrap());
    let parsed = call("parse_certificate", json!({ "der": assembled["der"] }));
    assert_eq!(parsed["kind"], "root", "{parsed}");
    assert_eq!(parsed["sig_alg"], OID_ECDSA_SHA256);
    // And a leaf under it, signed outside the core the same way.
    let host = key("p256");
    let lu = call(
        "leaf_tbs",
        json!({ "cn": "Bharat Mehta", "root_cn": "Bharat Mehta", "root_spki": root["spki"], "host_spki": host["spki"], "endpoint": "https://agent.bharat.example/mcp", "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z" }),
    );
    let lsig = call("sign", json!({ "pkcs8": root["pkcs8"], "data": lu["tbs"] }));
    let leaf = call("assemble_leaf", json!({ "tbs": lu["tbs"], "sig": lsig["sig"], "sig_alg": lu["sig_alg"] }));
    let v = call(
        "validate_chain",
        json!({ "chain": [leaf["der"], b64u(&root_der)], "now": NOW_RFC, "expected_root": root["fingerprint"], "expected_endpoint": "https://agent.bharat.example/mcp" }),
    );
    assert_eq!(v["ok"], true, "{v}");
}

// ── MEDIUM 4: one algorithm inside the TBS, another outside ──
#[test]
fn inner_and_outer_algorithm_must_agree() {
    let p = pair("ed25519", E_A);
    let c = x509::parse(&p.leaf).unwrap();
    let mismatched = x509::assemble_raw(&c.tbs, &x509::sig_alg(OID_ECDSA_SHA256), &c.sig);
    let (rule, reason) = refusal(&[mismatched, p.root.clone()]);
    assert_eq!((rule, reason.as_str()), (1, "signature algorithm inside and outside differ"));
    // The same through the boundary, the way a card is read.
    let c2 = call("parse_certificate", json!({ "der": b64u(&x509::assemble_raw(&c.tbs, &x509::sig_alg(OID_ECDSA_SHA256), &c.sig)) }));
    assert_eq!(c2["error"], "parse", "{c2}");
    // An AlgorithmIdentifier with parameters is not the profile's either.
    let with_params = der::seq(&[der::oid(OID_ED25519), der::null()]);
    let tbs_fields: Vec<Vec<u8>> = der::children(&der::read(&c.tbs, 0).unwrap()).unwrap().iter().map(|n| n.raw.to_vec()).collect();
    let mut f = tbs_fields.clone();
    f[2] = with_params.clone();
    let tbs = der::seq(&f);
    let signer = PrivateKey::from_pkcs8(&from_b64u(p.root_key["pkcs8"].as_str().unwrap())).unwrap();
    let (rule, _) = refusal(&[x509::assemble_raw(&tbs, &with_params, &signer.sign(&tbs)), p.root.clone()]);
    assert_eq!(rule, 1);
}

// ── LOW 7: DER strictness the exact profile relies on ──
#[test]
fn der_deviations_are_refused() {
    let p = pair("ed25519", E_A);
    let root_key = PrivateKey::from_pkcs8(&from_b64u(p.root_key["pkcs8"].as_str().unwrap())).unwrap();
    let root = x509::parse(&p.root).unwrap();
    let id = root.key_id.to_vec();
    let reason = |chain: &[Vec<u8>]| refusal(chain).1;
    // An explicit BOOLEAN FALSE (DER never encodes a DEFAULT) — as cA in a root.
    let r = with_field(&p.root, 7, root_extensions(&id, der::seq(&[der::boolean(false), der::int(0)]), der::bitstr(&[0x04], 2)), &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "BOOLEAN not in the DER form");
    // TRUE encoded as 0x01 instead of 0xFF (BER), as the critical flag.
    let r = with_field(
        &p.root,
        7,
        der::explicit(
            3,
            &der::seq(&[
                der::seq(&[
                    der::oid(OID_BASIC_CONSTRAINTS),
                    der::tlv(0x01, &[0x01]),
                    der::octet(&der::seq(&[der::boolean(true), der::int(0)])),
                ]),
                ext(OID_KEY_USAGE, true, &der::bitstr(&[0x04], 2)),
                ext(OID_SKI, false, &der::octet(&id)),
            ]),
        ),
        &root_key,
    );
    assert_eq!(reason(&[p.leaf.clone(), r]), "BOOLEAN not in the DER form");
    // A serial with a needless leading zero.
    let r = with_field(&p.root, 1, der::tlv(0x02, &[0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]), &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "INTEGER not minimal");
    // pathLenConstraint 128, whose first content byte is 0x00: read in full, it is not 0.
    let r =
        with_field(&p.root, 7, root_extensions(&id, der::seq(&[der::boolean(true), der::int(128)]), der::bitstr(&[0x04], 2)), &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "root basicConstraints");
    // keyUsage with a second byte (decipherOnly) hidden behind keyCertSign.
    let r = with_field(
        &p.root,
        7,
        root_extensions(&id, der::seq(&[der::boolean(true), der::int(0)]), der::bitstr(&[0x04, 0x80], 7)),
        &root_key,
    );
    assert_eq!(reason(&[p.leaf.clone(), r]), "root keyUsage is not keyCertSign alone");
    // Unused bits that are not zero.
    let r = with_field(&p.root, 7, root_extensions(&id, der::seq(&[der::boolean(true), der::int(0)]), der::bitstr(&[0x05], 2)), &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "BIT STRING not in the DER form");
    // A validity with three times.
    let validity = der::children(&der::read(&root.tbs, 0).unwrap()).unwrap()[4].raw.to_vec();
    let three = {
        let v = der::read(&validity, 0).unwrap();
        let kids: Vec<Vec<u8>> = der::children(&v).unwrap().iter().map(|n| n.raw.to_vec()).collect();
        der::seq(&[kids[0].clone(), kids[1].clone(), kids[1].clone()])
    };
    let r = with_field(&p.root, 4, three, &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "time not in the DER form");
    // An extension value with a byte after its one TLV.
    let mut padded = der::seq(&[der::boolean(true), der::int(0)]);
    padded.push(0x00);
    let r = with_field(&p.root, 7, root_extensions(&id, padded, der::bitstr(&[0x04], 2)), &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "extension value has trailing bytes");
    // The version INTEGER written non-minimally.
    let r = with_field(&p.root, 0, der::explicit(0, &der::tlv(0x02, &[0x00, 0x02])), &root_key);
    assert_eq!(reason(&[p.leaf.clone(), r]), "not a v3 certificate with extensions");
    // And the untouched pair still validates, so the harness above is sound.
    assert!(matches!(x509::validate_chain(&[p.leaf.clone(), p.root.clone()], now_s(), Some(&p.root_fp), Some(E_A)), ChainResult::Ok(_)));
}

// ── LOW 11: only the uncompressed P-256 point, in a key and in an encapsulated key ──
#[test]
fn compressed_p256_points_are_refused() {
    let k = key("p256");
    let spki = from_b64u(k["spki"].as_str().unwrap());
    let point = &spki[spki.len() - 65..];
    assert_eq!(point[0], 0x04);
    let mut compressed = vec![0x02 | (point[64] & 1)];
    compressed.extend_from_slice(&point[1..33]);
    let alg = der::seq(&[der::oid("1.2.840.10045.2.1"), der::oid("1.2.840.10045.3.1.7")]);
    let compressed_spki = der::seq(&[alg, der::bitstr(&compressed, 0)]);
    let r = call("key_info", json!({ "spki": b64u(&compressed_spki) }));
    assert_eq!(r["error"], "parse", "{r}");
    // A sealed message whose enc is compressed does not open.
    let sealed = call(
        "hpke_seal",
        json!({ "suite": "PACT-SEAL-P256", "recipient_spki": k["spki"], "info": b64u(b"PACT-SEAL-v2"), "aad": b64u(b"h"), "plaintext": b64u(b"hi") }),
    );
    let enc = from_b64u(sealed["enc"].as_str().unwrap());
    assert_eq!(enc.len(), 65);
    let mut enc_c = vec![0x02 | (enc[64] & 1)];
    enc_c.extend_from_slice(&enc[1..33]);
    let opened = call(
        "hpke_open",
        json!({ "suite": "PACT-SEAL-P256", "recipient_pkcs8": k["pkcs8"], "recipient_spki": k["spki"], "info": b64u(b"PACT-SEAL-v2"), "aad": b64u(b"h"), "enc": b64u(&enc_c), "ct": sealed["ct"] }),
    );
    assert!(opened["error"].is_string(), "{opened}");
    let ok = call(
        "hpke_open",
        json!({ "suite": "PACT-SEAL-P256", "recipient_pkcs8": k["pkcs8"], "recipient_spki": k["spki"], "info": b64u(b"PACT-SEAL-v2"), "aad": b64u(b"h"), "enc": sealed["enc"], "ct": sealed["ct"] }),
    );
    assert_eq!(ok["plaintext"], b64u(b"hi"), "{ok}");
}

// ── HIGH 1 (the core's half): an empty passphrase seals nothing ──
#[test]
fn empty_passphrase_is_refused() {
    let r = call("vault_seal", json!({ "passphrase": "", "plaintext": { "v": 2, "roots": [] } }));
    assert_eq!(r["error"], "bad_request");
    assert_eq!(r["why"], "empty passphrase");
}

// ── LOW 8: exp − ts is bounded ──
#[test]
fn an_envelope_asking_to_be_remembered_for_a_year_is_refused() {
    let alina = pair("ed25519", E_A);
    let bharat = pair("ed25519", "https://agent.bharat.example/mcp");
    let bharat_leaf = x509::parse(&bharat.leaf).unwrap();
    let node = |seen: Vec<&str>| {
        json!({
            "endpoint": "https://agent.bharat.example/mcp", "accept_new_hosts": "auto",
            "chain": [b64u(&bharat.leaf), b64u(&bharat.root)],
            "keys": [{ "kid": bharat_leaf.public_key.fingerprint(), "leaf": b64u(&bharat.leaf), "pkcs8": bharat.leaf_key["pkcs8"], "current": true }],
            "former": [], "sibling_kids": [],
            "pins": [{ "root": alina.root_fp, "endpoint": E_A, "leaf": b64u(&alina.leaf), "state": "active" }],
            "tombstones": [], "former_endpoints": [], "seen": seen,
        })
    };
    let seal = |exp: i64, msg: &str| {
        call(
            "seal_request",
            json!({
                "recipient_leaf": b64u(&bharat.leaf), "sender_pkcs8": alina.leaf_key["pkcs8"], "form": "chain",
                "sender_chain": [b64u(&alina.leaf), b64u(&alina.root)], "method": "tools/call",
                "params": { "name": "send_message", "arguments": { "msg_id": "m", "text": "hello" } },
                "msg_id": msg, "ts": now_s(), "exp": exp,
            }),
        )
    };
    let fine = call("decide", json!({ "now": NOW_RFC, "envelope": seal(now_s() + 600, "m-1"), "node": node(vec![]) }));
    assert_eq!(fine["result"]["code"], "ok", "{fine}");
    assert_eq!(fine["result"]["tier"], "contact");
    let long = call("decide", json!({ "now": NOW_RFC, "envelope": seal(now_s() + 365 * 86_400, "m-2"), "node": node(vec![]) }));
    assert_eq!(long["result"]["code"], "envelope_invalid", "{long}");
    assert_eq!(long["result"]["why"], "exp too far from ts");
    // Exactly thirty days is still fine.
    let edge = call("decide", json!({ "now": NOW_RFC, "envelope": seal(now_s() + 30 * 86_400, "m-3"), "node": node(vec![]) }));
    assert_eq!(edge["result"]["code"], "ok", "{edge}");
}

/// A header's `ts` and `exp` are integers it carries as themselves (2^53 - 1 either way): RFC 8785 writes
/// the double, so past that the core sealed a header whose `ts` was not the one it was given, and a
/// `ts` of i64::MAX with no `exp` overflowed computing the default (a panic in this debug build, a
/// wrapped `exp` in the Wasm). go/review_test.go's TestTheTypedSealRefusesAHeaderIntegerItCannotCarry
/// is the Go port's twin; js/parity.mjs holds both at the JSON boundary.
#[test]
fn a_header_integer_the_header_cannot_carry_is_refused_before_the_default_is_computed() {
    let alina = pair("ed25519", E_A);
    let seal = |fn_: &str, ts: Value, exp: Option<i64>| {
        let mut args = json!({
            "sender_pkcs8": alina.leaf_key["pkcs8"], "sender_chain": [b64u(&alina.leaf), b64u(&alina.root)],
            "msg_id": "m", "ts": ts,
        });
        if fn_ == "seal_request" {
            args["recipient_leaf"] = json!(b64u(&alina.leaf));
        } else {
            args["recipient_spki"] = alina.leaf_key["spki"].clone();
            args["result"] = json!({});
        }
        if let Some(exp) = exp {
            args["exp"] = json!(exp);
        }
        call(fn_, args)
    };
    let out = |m: &str| json!({ "error": "bad_request", "why": format!("{m} is an integer from -(2^53 - 1) to 2^53 - 1") });
    const MAX: i64 = (1 << 53) - 1;
    for fn_ in ["seal_request", "seal_result"] {
        assert_eq!(seal(fn_, json!(i64::MAX), None), out("ts"), "{fn_}");
        assert_eq!(seal(fn_, json!(i64::MIN), None), out("ts"), "{fn_}");
        assert_eq!(seal(fn_, json!(MAX + 1), Some(1)), out("ts"), "{fn_}");
        assert_eq!(seal(fn_, json!(MAX), None), out("exp"), "{fn_}");
        assert_eq!(seal(fn_, json!(1), Some(-MAX - 1)), out("exp"), "{fn_}");
        assert!(seal(fn_, json!(MAX), Some(MAX))["protected"].is_string(), "{fn_} at the edge");
    }
}

// ── §13.1#1: `enc` is exactly the suite's Npk, under each suite, in both directions ──
/// `sig` covers `protected ‖ enc ‖ ct` with nothing between them, so a byte moved across the enc/ct
/// boundary leaves the signed bytes as they were: the forgery is signed, and the length is the one
/// thing that refuses it. go/review_test.go's TestAnEncapsulatedKeyOfTheWrongLengthIsRefused is the Go
/// port's twin, and js/parity.mjs holds both ports to it through `decide` and `open_result`.
#[test]
fn an_encapsulated_key_of_the_wrong_length_is_refused_under_each_suite() {
    let alina = pair("ed25519", E_A);
    for (alg, npk) in [("ed25519", 32), ("p256", 65)] {
        let me = key(alg);
        let sealed = call(
            "seal_result",
            json!({
                "recipient_spki": me["spki"], "sender_pkcs8": alina.leaf_key["pkcs8"], "form": "chain",
                "sender_chain": [b64u(&alina.leaf), b64u(&alina.root)], "result": { "ok": true }, "msg_id": "r-1", "ts": now_s(),
            }),
        );
        let (enc, ct) = (from_b64u(sealed["enc"].as_str().unwrap()), from_b64u(sealed["ct"].as_str().unwrap()));
        assert_eq!(enc.len(), npk, "{alg}");
        let open = |enc: &[u8], ct: &[u8]| {
            let envelope = json!({ "protected": sealed["protected"], "enc": b64u(enc), "ct": b64u(ct), "sig": sealed["sig"] });
            call(
                "open_result",
                json!({ "envelope": envelope, "my_pkcs8": me["pkcs8"], "my_spki": me["spki"], "msg_id": "r-1", "now": NOW_RFC, "pins": [] }),
            )
        };
        assert_eq!(open(&enc, &ct)["ok"], true, "{alg}: the envelope as sealed opens, so the harness is sound");
        let short = open(&enc[..npk - 1], &[&enc[npk - 1..], &ct[..]].concat());
        let long = open(&[&enc[..], &ct[..1]].concat(), &ct[1..]);
        for (what, got) in [("one byte short", short), ("one byte long", long)] {
            assert_eq!(got, json!({ "error": "envelope_invalid", "why": "encapsulated key is not the suite's length" }), "{alg}, {what}");
        }
    }
}

// ── MEDIUM 3: the address guard takes the normal form first ──
#[test]
fn the_address_guard_refuses_every_other_spelling_of_loopback() {
    for bad in [
        "https://127.1/mcp",
        "https://2130706433/mcp",
        "https://0x7f000001/mcp",
        "https://0177.0.0.1/mcp",
        "https://localhost./mcp",
        "https://LOCALHOST/mcp",
        "https://[::1]/mcp",
    ] {
        let r = call("address_guard", json!({ "endpoint": bad, "guest": true }));
        assert_eq!(r["ok"], false, "{bad}: {r}");
    }
    let r = call("address_guard", json!({ "endpoint": "https://agent.alina.example/mcp", "guest": true }));
    assert_eq!(r["ok"], true);
}

#[test]
fn keys_still_generate_for_both_algorithms() {
    for alg in [Alg::Ed25519, Alg::P256] {
        let k = PrivateKey::generate(alg).unwrap();
        assert_eq!(k.alg(), alg);
    }
}

// ── 0.4.1: an open with no public key is refused by name, never a panic ──
// The Rust API cannot be handed a missing key (`&PublicKey`); the boundary is where one can be
// missing, and both functions that take it name the member. The Go port's library API, which can
// be handed nil, is held in go/unit_test.go.
#[test]
fn an_open_with_no_public_key_is_refused_by_name() {
    let k = key("ed25519");
    let sealed = call(
        "hpke_seal",
        json!({ "suite": "PACT-SEAL-X25519", "recipient_spki": k["spki"], "info": b64u(b"PACT-SEAL-v2"), "aad": b64u(b"h"), "plaintext": b64u(b"hi") }),
    );
    let open = |spki: Option<Value>| {
        let mut a = json!({ "suite": "PACT-SEAL-X25519", "recipient_pkcs8": k["pkcs8"], "info": b64u(b"PACT-SEAL-v2"), "aad": b64u(b"h"), "enc": sealed["enc"], "ct": sealed["ct"] });
        if let Some(v) = spki {
            a["recipient_spki"] = v;
        }
        call("hpke_open", a)
    };
    assert_eq!(open(None), json!({ "error": "bad_request", "why": "recipient_spki is required" }), "absent");
    assert_eq!(open(Some(Value::Null)), json!({ "error": "bad_request", "why": "recipient_spki is required" }), "null");
    assert_eq!(open(Some(k["spki"].clone()))["plaintext"], b64u(b"hi"), "the control");
    let r = call(
        "open_result",
        json!({ "envelope": { "protected": "", "enc": "", "ct": "", "sig": "" }, "my_pkcs8": k["pkcs8"], "msg_id": "m", "now": "2026-09-13T12:00:00Z" }),
    );
    assert_eq!(r, json!({ "error": "bad_request", "why": "my_spki is required" }));
}

/// The typed `decide`, `decide_chain` and `open_result` hold every root the host hands them to a
/// fingerprint first, as the Go port's typed `Decide`, `DecideChain` and `OpenResult` do (its
/// `hostRoots`), in the same words. Only the JSON reader asked it here, so a typed caller's pin whose
/// root was `abc` was a root nothing matched: `decide_chain` answered `chain rule 1` where Go answered
/// `node.pins[0].root is not a fingerprint` (the hunt of 2026-09-30). The control, the same state with
/// a real fingerprint, gets past the check to the chain.
#[test]
fn typed_decisions_refuse_a_host_root_that_is_not_a_fingerprint() {
    use pact_identity::envelope::{self, CallerPin, DecideInput, FormerEndpoint, HeldKey, NodeState, OpenResultArgs, Pin, Tombstone, Wire};
    let fp = format!("sha256:{}", "A".repeat(43));
    let pin =
        |root: &str| Pin { root: root.into(), endpoint: E_A.into(), leaf: String::new(), state: "active".into(), leaf_fingerprint: None };
    let node = |pins: Vec<Pin>, tombstones: Vec<Tombstone>, former_endpoints: Vec<FormerEndpoint>| NodeState {
        endpoint: E_A.into(),
        accept_new_hosts: "auto".into(),
        chain: vec![],
        keys: vec![],
        former: vec![],
        sibling_kids: vec![],
        pins,
        tombstones,
        former_endpoints,
        seen: vec![],
    };
    let why = |r: pact_identity::Result<envelope::DecideOutput>| match r {
        Err(e) => format!("{}: {}", e.code, e.why),
        Ok(d) => d.result.to_string(),
    };
    let stone = |root: &str| Tombstone { root: root.into(), leaf: String::new(), at: NOW_RFC.into() };
    let former = |root: &str| FormerEndpoint { root: root.into(), endpoint: E_A.into(), at: NOW_RFC.into() };
    for (state, want) in [
        (node(vec![pin(&fp), pin("abc")], vec![], vec![]), "bad_request: node.pins[1].root is not a fingerprint"),
        (node(vec![], vec![stone("")], vec![]), "bad_request: node.tombstones[0].root is not a fingerprint"),
        (node(vec![pin(&fp)], vec![stone(&fp)], vec![former("abc")]), "bad_request: node.former_endpoints[0].root is not a fingerprint"),
        // pins before tombstones, as the reader and the Go port read them
        (node(vec![pin("abc")], vec![stone("abc")], vec![]), "bad_request: node.pins[0].root is not a fingerprint"),
        // And, in the reader's order, a held key's kid first, then each pin's state and leaf fingerprint
        // beside its root (the review of 2026-09-30: S1, S2, and the kid).
        (
            NodeState {
                keys: vec![HeldKey { kid: "abc".into(), leaf: String::new(), pkcs8: String::new(), current: true }],
                ..node(vec![pin("abc")], vec![], vec![])
            },
            "bad_request: node.keys[0].kid is not a fingerprint",
        ),
        (
            node(vec![Pin { state: "Blocked".into(), ..pin(&fp) }], vec![], vec![]),
            "bad_request: node.pins[0].state is active, pending_out or blocked",
        ),
        (
            node(vec![Pin { leaf_fingerprint: Some(String::new()), ..pin(&fp) }], vec![], vec![]),
            "bad_request: node.pins[0].leaf_fingerprint is not a fingerprint",
        ),
    ] {
        assert_eq!(why(envelope::decide_chain(&state, &[], now_s())), want);
        let input = DecideInput {
            now: NOW_RFC.into(),
            envelope: Wire { protected: String::new(), enc: String::new(), ct: String::new(), sig: String::new() },
            node: state,
        };
        assert_eq!(why(envelope::decide(&input)), want, "decide asks it before anything else");
    }
    // The control: every root a fingerprint, and the call reaches what it was asked.
    let good = node(vec![pin(&fp)], vec![stone(&fp)], vec![former(&fp)]);
    assert_eq!(
        why(envelope::decide_chain(&good, &[], now_s())),
        json!({ "code": "envelope_invalid", "why": "chain rule 1: chain of 0" }).to_string()
    );

    let me = PrivateKey::generate(Alg::Ed25519).unwrap();
    let me_pub = me.public();
    let wire = Wire { protected: String::new(), enc: String::new(), ct: String::new(), sig: String::new() };
    let open = |pins: &[CallerPin]| match envelope::open_result(OpenResultArgs {
        envelope: &wire,
        my_key: &me,
        my_public: &me_pub,
        msg_id: "m",
        now: now_s(),
        pins,
        expected_root: None,
        expected_endpoint: None,
    }) {
        Err(e) => format!("{}: {}", e.code, e.why),
        Ok(v) => v.to_string(),
    };
    let caller = |root: &str| CallerPin {
        root: root.into(),
        endpoint: E_A.into(),
        leaf: String::new(),
        state: "active".into(),
        leaf_fingerprint: None,
    };
    assert_eq!(open(&[caller(&fp), caller("abc")]), "bad_request: pins[1].root is not a fingerprint");
    assert_eq!(
        open(&[CallerPin { state: "removed".into(), ..caller(&fp) }]),
        "bad_request: pins[0].state is active, pending_out or blocked"
    );
    assert_eq!(
        open(&[CallerPin { leaf_fingerprint: Some("x".into()), ..caller(&fp) }]),
        "bad_request: pins[0].leaf_fingerprint is not a fingerprint"
    );
    // The control: past the pins, the empty envelope is refused for itself.
    assert!(!open(&[caller(&fp)]).contains("root is not a fingerprint"));
}
