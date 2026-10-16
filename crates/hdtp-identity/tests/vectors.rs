//! Appendix B, proven from the core: the seven certificates it builds rebuilt (byte for byte where the
//! issuer is Ed25519; the TBS, and the vector's signature verified, where it is P-256, whose ECDSA is
//! not reproducible), the three marked `refused` refused, every chain, newest-leaf and
//! certificate_renewed case, every envelope opened and re-sealed from its ephemeral seed,
//! `decide` on the vector envelopes, a result sealed back and opened, and the derivation vectors.
use hdtp_identity::envelope::{self, DecideInput, Form, SealRequest};
use hdtp_identity::hpke::{self, suite_for, Suite};
use hdtp_identity::keys::{self, Alg, PrivateKey, PublicKey};
use hdtp_identity::time::parse_rfc3339;
use hdtp_identity::util::{b64u, from_b64u, from_hex, hex, seed};
use hdtp_identity::x509::{self, compare_leaves, fingerprint_of, parse, serial_of, validate_chain, ChainResult, LeafSpec};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn vectors() -> Value {
    let path =
        std::env::var("HDTP_VECTORS").map(PathBuf::from).unwrap_or_else(|_| root_dir().join("hdtp-spec/vectors/hdtp-1.0-vectors.json"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

/// The newest released version of hdtp-spec's specification, as one document: `index.md` followed
/// by the pages its table of contents links, in that order (hdtp-spec's `site/spec-source.mjs`).
/// `HDTP_SPEC` names a version directory instead.
fn spec() -> String {
    let dir = std::env::var("HDTP_SPEC").map(PathBuf::from).unwrap_or_else(|_| {
        let base = root_dir().join("hdtp-spec/docs/specification");
        let released = |p: &PathBuf| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            name.split_once('.').and_then(|(x, y)| Some((x.parse::<u64>().ok()?, y.parse::<u64>().ok()?)))
        };
        std::fs::read_dir(&base)
            .unwrap_or_else(|e| panic!("{}: {e}", base.display()))
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter_map(|p| released(&p).map(|n| (n, p)))
            .max_by_key(|(n, _)| *n)
            .map(|(_, p)| p)
            .expect("a released version of the specification")
    });
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{}: {e}", dir.join(name).display()));
    let index = read("index.md");
    let toc = &index[index.find("\n## Table of contents").expect("the index has a table of contents")..];
    let mut out = index.clone();
    for part in toc.split("](").skip(1) {
        if let Some(end) = part.find(".md)") {
            out += &read(&part[..end + 3]);
        }
    }
    out
}

/// The JSON blocks of a document's Appendix B: everything fenced as ```json between the heading
/// `## Appendix B` and the first `*End of HDTP` after it. Both markers must be there, every fence
/// must close and every block must be JSON — held to js/appendix-b-reader.json's cases, as the other
/// three readers are. (It found the end marker from the start of the file, so a marker quoted before
/// the heading sliced nothing, and it had no test.)
fn appendix_b(spec: &str) -> Result<Vec<Value>, String> {
    let start = spec.find("## Appendix B").ok_or("the document has no Appendix B")?;
    let end = spec[start..].find("*End of HDTP").map(|i| start + i).ok_or("Appendix B has no end marker (*End of HDTP)")?;
    let mut out = Vec::new();
    let mut rest = &spec[start..end];
    while let Some(i) = rest.find("```json\n") {
        let after = &rest[i + 8..];
        let j = after.find("\n```").ok_or("an unterminated json fence in Appendix B")?;
        let n = out.len() + 1;
        out.push(serde_json::from_str(&after[..j]).map_err(|_| format!("Appendix B block {n} is not JSON"))?);
        rest = &after[j + 4..];
    }
    Ok(out)
}

fn appendix_b_blocks() -> Vec<Value> {
    appendix_b(&spec()).unwrap()
}

#[test]
fn appendix_b_is_read_as_the_shared_cases_say_refusals_word_for_word() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../js/appendix-b-reader.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for c in cases {
        let (name, doc) = (c["name"].as_str().unwrap(), c["doc"].as_str().unwrap());
        match c["refused"].as_str() {
            Some(why) => assert_eq!(appendix_b(doc).unwrap_err(), why, "{name}"),
            None => assert_eq!(json!(appendix_b(doc).unwrap()), c["blocks"], "{name}"),
        }
    }
}

const NOW: &str = "2026-09-13T12:00:00Z";
const ENDPOINT_A: &str = "https://agent.alina.example/mcp";
const ENDPOINT_B: &str = "https://agent.bharat.example/mcp";
const ENDPOINT_C: &str = "https://agent.chandra.example/mcp";
const ROOT_C_ENDS: &str = "2028-01-01T00:00:00Z";

struct Cast {
    root_a: PrivateKey,
    root_b: PrivateKey,
    root_c: PrivateKey,
    hosts: HashMap<&'static str, PrivateKey>,
}

fn cast() -> Cast {
    let mut hosts = HashMap::new();
    hosts.insert("leaf_a", PrivateKey::from_seed(Alg::Ed25519, &seed("host/alina/2026")).unwrap());
    hosts.insert("leaf_a_next", PrivateKey::from_seed(Alg::Ed25519, &seed("host/alina/2027")).unwrap());
    hosts.insert("leaf_b", PrivateKey::from_seed(Alg::P256, &seed("host/bharat/2026")).unwrap());
    hosts.insert("leaf_c", PrivateKey::from_seed(Alg::Ed25519, &seed("host/chandra/2026")).unwrap());
    Cast {
        root_a: PrivateKey::from_seed(Alg::Ed25519, &seed("root/alina")).unwrap(),
        root_b: PrivateKey::from_seed(Alg::P256, &seed("root/bharat")).unwrap(),
        root_c: PrivateKey::from_seed(Alg::Ed25519, &seed("root/chandra")).unwrap(),
        hosts,
    }
}

fn at(s: &str) -> i64 {
    parse_rfc3339(s).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn leaf<'a>(
    c: &'a Cast,
    cn: &'a str,
    root: &'a PrivateKey,
    issuer: &'a PublicKey,
    host: &'a PublicKey,
    endpoint: &str,
    dns: Option<&str>,
    nb: &str,
    na: &str,
    label: &str,
) -> Vec<u8> {
    let _ = c;
    let spec = LeafSpec {
        cn,
        root_cn: cn,
        issuer,
        host_key: host,
        uris: vec![endpoint.to_string()],
        dns_name: dns.map(|d| d.to_string()),
        not_before: at(nb),
        not_after: at(na),
        serial: serial_of(label),
        ca: false,
        usage: None,
        aki: None,
    };
    x509::build_leaf(&spec, root).unwrap()
}

fn der_of(v: &Value) -> HashMap<String, Vec<u8>> {
    v["certificates"].as_object().unwrap().iter().map(|(k, c)| (k.clone(), from_hex(c["der_hex"].as_str().unwrap()).unwrap())).collect()
}

#[test]
fn the_certificates_reproduce() {
    let v = vectors();
    let der = der_of(&v);
    let c = cast();
    let (pub_a, pub_b) = (c.root_a.public(), c.root_b.public());
    let h = |n: &str| c.hosts[n].public();

    let root_a = x509::build_root("Alina Rao", &c.root_a, at("2026-09-01T00:00:00Z"), None, &serial_of("root_a")).unwrap();
    assert_eq!(hex(&root_a), hex(&der["root_a"]), "root_a byte for byte");
    let root_b = x509::build_root("Bharat Mehta", &c.root_b, at("2026-09-01T00:00:00Z"), None, &serial_of("root_b")).unwrap();
    assert_eq!(parse(&root_b).unwrap().tbs, parse(&der["root_b"]).unwrap().tbs, "root_b TBS");
    assert!(x509::verify_cert(&parse(&der["root_b"]).unwrap(), &pub_b), "root_b verifies under its key");

    let leaf_a = leaf(
        &c,
        "Alina Rao",
        &c.root_a,
        &pub_a,
        &h("leaf_a"),
        ENDPOINT_A,
        Some("agent.alina.example"),
        "2026-09-01T00:00:00Z",
        "2027-09-01T00:00:00Z",
        "leaf_a",
    );
    assert_eq!(hex(&leaf_a), hex(&der["leaf_a"]), "leaf_a byte for byte");
    let leaf_b = leaf(
        &c,
        "Bharat Mehta",
        &c.root_b,
        &pub_b,
        &h("leaf_b"),
        ENDPOINT_B,
        None,
        "2026-09-01T00:00:00Z",
        "2027-09-01T00:00:00Z",
        "leaf_b",
    );
    assert_eq!(parse(&leaf_b).unwrap().tbs, parse(&der["leaf_b"]).unwrap().tbs, "leaf_b TBS");
    assert!(x509::verify_cert(&parse(&der["leaf_b"]).unwrap(), &pub_b), "leaf_b verifies under root_b");
    let expired = leaf(
        &c,
        "Alina Rao",
        &c.root_a,
        &pub_a,
        &h("leaf_a"),
        ENDPOINT_A,
        None,
        "2025-06-01T00:00:00Z",
        "2026-06-01T00:00:00Z",
        "leaf_a_expired",
    );
    assert_eq!(hex(&expired), hex(&der["leaf_a_expired"]));
    let long = leaf(
        &c,
        "Alina Rao",
        &c.root_a,
        &pub_a,
        &h("leaf_a"),
        ENDPOINT_A,
        None,
        "2026-09-01T00:00:00Z",
        "2027-10-10T00:00:00Z",
        "leaf_a_long",
    );
    assert_eq!(hex(&long), hex(&der["leaf_a_long"]));
    let next = leaf(
        &c,
        "Alina Rao",
        &c.root_a,
        &pub_a,
        &h("leaf_a_next"),
        ENDPOINT_A,
        None,
        "2027-08-02T00:00:00Z",
        "2028-08-01T00:00:00Z",
        "leaf_a_next",
    );
    assert_eq!(hex(&next), hex(&der["leaf_a_next"]));
    // Chandra's root carries the end date its person chose (SPEC 14.1); its leaves end before it,
    // with it, and after it.
    let root_c =
        x509::build_root("Chandra Iyer", &c.root_c, at("2026-09-01T00:00:00Z"), Some(at(ROOT_C_ENDS)), &serial_of("root_c")).unwrap();
    assert_eq!(hex(&root_c), hex(&der["root_c"]), "root_c byte for byte");
    let pub_c = c.root_c.public();
    for (label, nb, na) in [
        ("leaf_c", "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z"),
        ("leaf_c_last", "2027-01-01T00:00:00Z", ROOT_C_ENDS),
        ("leaf_c_outlives", "2027-06-01T00:00:00Z", "2028-06-01T00:00:00Z"),
    ] {
        let l = leaf(&c, "Chandra Iyer", &c.root_c, &pub_c, &h("leaf_c"), ENDPOINT_C, None, nb, na, label);
        assert_eq!(hex(&l), hex(&der[label]), "{label} byte for byte");
    }

    for (name, pkcs8_hex) in v["leaf_keys_pkcs8_hex"].as_object().unwrap() {
        let k = PrivateKey::from_pkcs8(&from_hex(pkcs8_hex.as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(k.public().spki(), c.hosts[name.as_str()].public().spki(), "{name}: key");
        if k.alg() == Alg::Ed25519 {
            assert_eq!(hex(&k.to_pkcs8()), pkcs8_hex.as_str().unwrap(), "{name}: PKCS #8 byte for byte");
        }
    }
    for (name, bytes) in &der {
        assert!(bytes.len() <= 4096, "{name} under 4 KiB");
        // A certificate the appendix marks `refused` exists to be refused (SPEC 14.1): it must not
        // come out of parse and the profile check clean.
        if v["certificates"][name.as_str()]["refused"].as_bool() == Some(true) {
            let why = match parse(bytes) {
                Ok(c) => x509::profile_error(&c, if name.starts_with("root") { "root" } else { "leaf" }),
                Err(e) => Some(e.why),
            };
            assert!(why.is_some(), "{name} is marked refused, and parse + the profile let it through");
            continue;
        }
        let c = parse(bytes).unwrap();
        assert_eq!(c.kind(), if name.starts_with("root") { "root" } else { "leaf" }, "{name}");
    }
}

#[test]
fn the_core_reports_the_version_of_the_document_it_is_proven_against() {
    // The first `**Version X` of the specification is the document's own number; the core's constant is a
    // claim about it, and a claim nothing checks is how `2.0.0-draft` outlived the draft by two
    // releases.
    let text = spec();
    let line = text.lines().find(|l| l.starts_with("**Version ")).expect("the specification has a version line");
    let version = line.trim_start_matches("**Version ").split_whitespace().next().unwrap();
    assert_eq!(hdtp_identity::api::SPEC_VERSION, version, "the core says one spec version and the specification another");
}

#[test]
fn spec_carries_the_generated_vectors_unchanged() {
    let blocks = appendix_b_blocks();
    assert!(!blocks.is_empty(), "Appendix B has the vector block");
    assert_eq!(blocks[0].to_string(), vectors().to_string());
}

#[test]
fn chain_cases() {
    let v = vectors();
    let der = der_of(&v);
    let mut n = 0;
    for c in v["chain_cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let chain: Vec<Vec<u8>> = c["chain"].as_array().unwrap().iter().map(|x| der[x.as_str().unwrap()].clone()).collect();
        let r = validate_chain(&chain, at(c["now"].as_str().unwrap()), c["expected_root"].as_str(), c["expected_endpoint"].as_str());
        match (c["expect"].as_str().unwrap(), r) {
            ("accept", ChainResult::Ok(_)) => {}
            // A case that names its reason is held to it: rule 4 refuses for four reasons, and a guard
            // that went missing would still refuse by rule 4 for another one.
            ("refuse", ChainResult::Refused { rule, reason })
                if rule as u64 == c["rule"].as_u64().unwrap() && c["reason"].as_str().is_none_or(|want| want == reason) => {}
            (want, ChainResult::Ok(_)) => panic!("{name}: expected {want}, got accept"),
            (want, ChainResult::Refused { rule, reason }) => {
                panic!("{name}: expected {want} rule {}, got rule {rule} ({reason})", c["rule"])
            }
        }
        n += 1;
    }
    // A floor, not a count: `== 12` went stale the day Appendix B gained two cases, and failed a run
    // in which every case had passed. What a number here is for is noticing the suite SHRINK.
    assert!(n >= 20, "Appendix B has carried 20 chain cases; this run saw {n}");
}

#[test]
fn newest_leaf_cases() {
    let v = vectors();
    let der = der_of(&v);
    for c in v["newest_leaf_cases"].as_array().unwrap() {
        let got = compare_leaves(&der[c["pinned"].as_str().unwrap()], &der[c["presented"].as_str().unwrap()]).unwrap();
        assert_eq!(got, c["expect"].as_str().unwrap(), "{} then {}", c["pinned"], c["presented"]);
    }
}

#[test]
fn certificate_renewed_cases() {
    let v = vectors();
    let der = der_of(&v);
    for c in v["certificate_renewed_cases"].as_array().unwrap() {
        let pinned = &der[c["pinned_leaf"].as_str().unwrap()];
        let pinned_root = hdtp_identity::keys::fingerprint_of_id(parse(pinned).unwrap().aki.as_ref().unwrap());
        let r = envelope::follow_renewed(&c["answer"], &pinned_root, pinned, c["dialed"].as_str().unwrap(), at(c["now"].as_str().unwrap()));
        assert_eq!(r["follow"].as_bool().unwrap(), c["expect"] == "follow", "{}: {r}", c["name"]);
    }
}

#[test]
fn envelopes_open_and_reproduce() {
    let v = vectors();
    let der = der_of(&v);
    let c = cast();
    let ts = at(NOW);
    let mut seen = 0;
    for e in v["envelopes"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let form = e["form"].as_str().unwrap();
        let recipient_name = e["recipient_chain"][0].as_str().unwrap();
        let sender_name = e["sender_chain"][0].as_str().unwrap();
        let recipient_leaf = parse(&der[recipient_name]).unwrap();
        let recipient = PrivateKey::from_pkcs8(&from_hex(v["leaf_keys_pkcs8_hex"][recipient_name].as_str().unwrap()).unwrap()).unwrap();
        let aad = from_b64u(e["protected"].as_str().unwrap()).unwrap();
        let enc = from_b64u(e["enc"].as_str().unwrap()).unwrap();
        let ct = from_b64u(e["ct"].as_str().unwrap()).unwrap();
        let sig = from_b64u(e["sig"].as_str().unwrap()).unwrap();
        let header: Value = serde_json::from_slice(&aad).unwrap();
        assert!(envelope::members_are(header.as_object().unwrap(), envelope::HEADER_MEMBERS), "{name}: header members");
        let suite = Suite::parse(e["suite"].as_str().unwrap()).unwrap();
        assert_eq!(header["v"], 1);
        assert_eq!(header["suite"], e["suite"]);
        assert_eq!(suite_for(&recipient_leaf.public_key), suite, "{name}: suite follows the recipient key");
        assert_eq!(header["kid"], recipient_leaf.public_key.fingerprint(), "{name}: kid is the recipient leaf key");
        assert_eq!(recipient.public().spki(), &recipient_leaf.spki[..], "{name}: the recipient key is the leaf's");
        let pt = hpke::open(suite, &recipient, &recipient_leaf.public_key, b"HDTP-SEAL-v1", &aad, &enc, &ct)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(hex(&pt), e["plaintext_hex"].as_str().unwrap(), "{name}: plaintext");
        let body: Value = serde_json::from_slice(&pt).unwrap();
        let mut signed = aad.clone();
        signed.extend_from_slice(&enc);
        signed.extend_from_slice(&ct);
        let sender_leaf = parse(&der[sender_name]).unwrap();
        let mut bm: Vec<&str> = body.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        bm.sort();
        if form == "leaf" {
            assert_eq!(bm.join(","), "leaf,method,params");
            assert_eq!(body["leaf"], sender_leaf.public_key.fingerprint(), "{name}: leaf names the sender's held leaf");
            assert!(sender_leaf.public_key.verify(&signed, &sig), "{name}: signature under the held leaf's key");
            assert!(ct.len() < 400, "{name}: small form stays small ({} bytes sealed)", ct.len());
        } else {
            assert_eq!(bm.join(","), "chain,method,params");
            let chain: Vec<Vec<u8>> = body["chain"].as_array().unwrap().iter().map(|x| from_b64u(x.as_str().unwrap()).unwrap()).collect();
            let r = validate_chain(&chain, at(v["now"].as_str().unwrap()), None, None);
            let ChainResult::Ok(ok) = r else { panic!("{name}: chain inside validates") };
            assert_eq!(chain[0], der[sender_name], "{name}: chain inside is the sender's");
            assert!(ok.leaf.public_key.verify(&signed, &sig), "{name}: signature under the chain's leaf key");
        }

        // Re-seal from the same inputs and the vector's ephemeral seed: enc and ct reproduce.
        let sender = &c.hosts[sender_name];
        let chain: Vec<Vec<u8>> = e["sender_chain"].as_array().unwrap().iter().map(|x| der[x.as_str().unwrap()].clone()).collect();
        let wire = envelope::seal_request(SealRequest {
            recipient: &recipient_leaf.public_key,
            sender,
            form: Form::parse(form).unwrap(),
            sender_chain: Some(&chain),
            method: "tools/call".into(),
            params: body["params"].clone(),
            msg_id: header["msg_id"].as_str().unwrap().into(),
            ts,
            exp: Some(ts + 600),
            cty: None,
            ephemeral_seed: Some(seed(&format!("ephemeral/{name}"))),
        })
        .unwrap();
        assert_eq!(wire.protected, e["protected"], "{name}: protected reproduces");
        assert_eq!(wire.enc, e["enc"], "{name}: enc reproduces");
        assert_eq!(wire.ct, e["ct"], "{name}: ct reproduces");
        if sender.alg() == Alg::Ed25519 {
            assert_eq!(wire.sig, e["sig"], "{name}: Ed25519 signature reproduces");
        }
        seen += 1;
    }
    assert_eq!(seen, 3);
}

fn node_for(v: &Value, der: &HashMap<String, Vec<u8>>, me: &str, root_cert: &str, pins: Vec<Value>) -> Value {
    let leaf = parse(&der[me]).unwrap();
    json!({
        "endpoint": leaf.uris[0],
        "accept_new_hosts": "auto",
        "chain": [b64u(&der[me]), b64u(&der[root_cert])],
        "keys": [{ "kid": leaf.public_key.fingerprint(), "leaf": b64u(&der[me]), "pkcs8": b64u(&from_hex(v["leaf_keys_pkcs8_hex"][me].as_str().unwrap()).unwrap()), "current": true }],
        "former": [], "sibling_kids": [], "pins": pins, "tombstones": [], "former_endpoints": [], "seen": []
    })
}

#[test]
fn decide_on_the_vector_envelopes() {
    let v = vectors();
    let der = der_of(&v);
    let envelopes = v["envelopes"].as_array().unwrap();
    let full = &envelopes[0]; // alina → bharat, chain form, send_message
    let small = &envelopes[2]; // alina → bharat, leaf form
    let root_a = fingerprint_of(&parse(&der["root_a"]).unwrap());
    let pin_a = json!({ "root": root_a, "endpoint": ENDPOINT_A, "leaf": b64u(&der["leaf_a"]), "state": "active" });
    let wire = |e: &Value| json!({ "protected": e["protected"], "enc": e["enc"], "ct": e["ct"], "sig": e["sig"] });

    // A stranger with a chain calling send_message: the guest binding refuses it.
    let input =
        DecideInput::read(&json!({ "now": NOW, "envelope": wire(full), "node": node_for(&v, &der, "leaf_b", "root_b", vec![]) })).unwrap();
    let out = envelope::decide(&input).unwrap();
    assert_eq!(out.result["code"], "envelope_invalid");
    assert_eq!(out.result["why"], "guest may only redeem or request");
    assert!(out.effects.is_empty());

    // The same envelope from a pinned contact is a contact-tier call, with the message id recorded.
    let input = DecideInput::read(
        &json!({ "now": NOW, "envelope": wire(full), "node": node_for(&v, &der, "leaf_b", "root_b", vec![pin_a.clone()]) }),
    )
    .unwrap();
    let out = envelope::decide(&input).unwrap();
    assert_eq!(out.result["code"], "ok", "{}", out.result);
    assert_eq!(out.result["tier"], "contact");
    assert_eq!(out.result["form"], "chain");
    assert_eq!(out.result["root"], root_a);
    assert_eq!(out.result["endpoint"], ENDPOINT_A);
    assert_eq!(out.result["tool"], "send_message");
    assert_eq!(out.result["params"]["arguments"]["text"], "hello from the HDTP test vectors");
    assert_eq!(out.effects, vec![json!({ "op": "seen", "msg_id": "vec-v1-alina-to-bharat" })]);

    // The small form: chain_required for a stranger, contact for a pinned leaf.
    let input =
        DecideInput::read(&json!({ "now": NOW, "envelope": wire(small), "node": node_for(&v, &der, "leaf_b", "root_b", vec![]) })).unwrap();
    assert_eq!(envelope::decide(&input).unwrap().result, json!({ "code": "chain_required" }));
    let input = DecideInput::read(
        &json!({ "now": NOW, "envelope": wire(small), "node": node_for(&v, &der, "leaf_b", "root_b", vec![pin_a.clone()]) }),
    )
    .unwrap();
    let out = envelope::decide(&input).unwrap();
    assert_eq!(out.result["tier"], "contact");
    assert_eq!(out.result["form"], "leaf");

    // A replay is acknowledged, not re-executed.
    let mut node = node_for(&v, &der, "leaf_b", "root_b", vec![pin_a.clone()]);
    node["seen"] = json!(["vec-v1-alina-to-bharat"]);
    let input = DecideInput::read(&json!({ "now": NOW, "envelope": wire(full), "node": node })).unwrap();
    assert_eq!(envelope::decide(&input).unwrap().result, json!({ "code": "ok", "replayed": true }));

    // The same through the boundary.
    let out: Value = serde_json::from_str(&hdtp_identity::call(
        "decide",
        &json!({ "now": NOW, "envelope": wire(full), "node": node_for(&v, &der, "leaf_b", "root_b", vec![pin_a]) }).to_string(),
    ))
    .unwrap();
    assert_eq!(out["result"]["tier"], "contact");
}

/// A `sig` not in the one spelling (§13.1) is `envelope_invalid` before the form decides anything.
/// The small form from a pinned contact answered `chain_required` to every one of them, while the
/// chain form refused them: the same envelope, two answers, by form alone. An empty `sig` is the one
/// spelling of zero bytes and is not refused for its spelling: it fails as a signature (§13.3 step 7).
#[test]
fn a_sig_not_in_the_one_spelling_is_refused_in_either_form() {
    let v = vectors();
    let der = der_of(&v);
    let envelopes = v["envelopes"].as_array().unwrap();
    let full = &envelopes[0];
    let small = &envelopes[2];
    let root_a = fingerprint_of(&parse(&der["root_a"]).unwrap());
    let pin_a = json!({ "root": root_a, "endpoint": ENDPOINT_A, "leaf": b64u(&der["leaf_a"]), "state": "active" });
    let with_sig = |e: &Value, sig: Value| json!({ "protected": e["protected"], "enc": e["enc"], "ct": e["ct"], "sig": sig });
    let decide = |envelope: Value, pins: Vec<Value>| {
        let input = DecideInput::read(&json!({ "now": NOW, "envelope": envelope, "node": node_for(&v, &der, "leaf_b", "root_b", pins) }));
        envelope::decide(&input.unwrap()).unwrap()
    };
    const A64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (form, e) in [("chain", full), ("small", small)] {
        let good = e["sig"].as_str().unwrap();
        let last = A64.find(good.chars().last().unwrap()).unwrap();
        assert_eq!(good.len() % 4, 2, "{form}: a 64-byte signature leaves four spare bits in its last character");
        let spare = format!("{}{}", &good[..good.len() - 1], &A64[last | 1..(last | 1) + 1]);
        let mut standard = good.replace('-', "+").replace('_', "/");
        if standard == good {
            standard = format!("{}+", &good[..good.len() - 1]);
        }
        for (what, sig, why) in [
            ("not base64url at all", "!!!".to_string(), "sig is not base64url"),
            ("padded", format!("{good}=="), "sig is not base64url"),
            ("in the standard alphabet", standard, "sig is not base64url"),
            ("with a line break", format!("{}\n{}", &good[..8], &good[8..]), "sig is not base64url"),
            ("with its spare bits set", spare, "sig is not base64url"),
        ] {
            for (whom, pins) in [("a pinned contact", vec![pin_a.clone()]), ("a stranger", vec![])] {
                let out = decide(with_sig(e, json!(sig)), pins);
                assert_eq!(out.result, json!({ "code": "envelope_invalid", "why": why }), "{form} form from {whom}, sig {what}");
                assert!(out.effects.is_empty(), "{form} form from {whom}, sig {what}");
            }
        }
        // An empty `sig` reads, and fails where any signature that does not verify fails: the small
        // form's `chain_required` (§13.2), the chain form's refusal of the signature.
        let failed = if form == "small" {
            json!({ "code": "chain_required" })
        } else {
            json!({ "code": "envelope_invalid", "why": "signature is not the chain's leaf key" })
        };
        for (whom, pins) in [("a pinned contact", vec![pin_a.clone()]), ("a stranger", vec![])] {
            let out = decide(with_sig(e, json!("")), pins);
            assert_eq!(out.result, failed, "{form} form from {whom}, sig empty");
            assert!(out.effects.is_empty(), "{form} form from {whom}, sig empty");
        }
        // Absent or null is step 1 failing (§13.1): a decision, `envelope members` for an absent member and
        // `envelope member types` for a null one, with no effect.
        for (sig, why) in [(None, "envelope members"), (Some(Value::Null), "envelope member types")] {
            let mut envelope = with_sig(e, Value::Null);
            if sig.is_none() {
                envelope.as_object_mut().unwrap().remove("sig");
            }
            let node = node_for(&v, &der, "leaf_b", "root_b", vec![pin_a.clone()]);
            let out: Value = serde_json::from_str(&hdtp_identity::call(
                "decide",
                &json!({ "now": NOW, "envelope": envelope, "node": node }).to_string(),
            ))
            .unwrap();
            assert_eq!(out, json!({ "result": { "code": "envelope_invalid", "why": why }, "effects": [] }), "{form} form, sig {sig:?}");
        }
    }

    // The controls: the vector's own signature passes in both forms, and a signature in the one
    // spelling that is not the leaf's is still the small form's `chain_required` (§13.2).
    let out = decide(with_sig(full, full["sig"].clone()), vec![pin_a.clone()]);
    assert_eq!((out.result["code"].as_str(), out.result["form"].as_str()), (Some("ok"), Some("chain")), "{}", out.result);
    let out = decide(with_sig(small, small["sig"].clone()), vec![pin_a.clone()]);
    assert_eq!((out.result["code"].as_str(), out.result["form"].as_str()), (Some("ok"), Some("leaf")), "{}", out.result);
    let out = decide(with_sig(small, json!(b64u(&[0u8; 64]))), vec![pin_a.clone()]);
    assert_eq!(out.result, json!({ "code": "chain_required" }));
    let out = decide(with_sig(full, json!(b64u(&[0u8; 64]))), vec![pin_a]);
    assert_eq!(out.result, json!({ "code": "envelope_invalid", "why": "signature is not the chain's leaf key" }));
}

#[test]
fn a_result_seals_back_and_opens_on_the_caller_side() {
    let v = vectors();
    let der = der_of(&v);
    let c = cast();
    let ts = at(NOW);
    let alina = &c.hosts["leaf_a"];
    let bharat = &c.hosts["leaf_b"];
    let chain_b = vec![der["leaf_b"].clone(), der["root_b"].clone()];
    let root_b = fingerprint_of(&parse(&der["root_b"]).unwrap());
    let wire = envelope::seal_result(envelope::SealResult {
        recipient: &alina.public(),
        sender: bharat,
        form: Form::Chain,
        sender_chain: Some(&chain_b),
        result: Some(json!({ "content": [{ "type": "text", "text": "ok" }] })),
        error: None,
        msg_id: "m-1".into(),
        ts,
        exp: None,
        ephemeral_seed: None,
    })
    .unwrap();
    let out = envelope::open_result(envelope::OpenResultArgs {
        envelope: &wire,
        my_key: alina,
        my_public: &alina.public(),
        msg_id: "m-1",
        now: ts + 5,
        pins: &[],
        expected_root: Some(&root_b),
        expected_endpoint: Some(ENDPOINT_B),
    })
    .unwrap();
    assert_eq!(out["ok"], true);
    assert_eq!(out["result"]["content"][0]["text"], "ok");
    assert_eq!(out["root"], root_b);
    assert_eq!(out["leaf_update"], b64u(&der["leaf_b"]));
    // The wrong msg_id does not correlate; a request envelope is not a result.
    let bad = envelope::open_result(envelope::OpenResultArgs {
        envelope: &wire,
        my_key: alina,
        my_public: &alina.public(),
        msg_id: "m-2",
        now: ts,
        pins: &[],
        expected_root: None,
        expected_endpoint: None,
    });
    assert_eq!(bad.unwrap_err().why, "msg_id does not correlate");
    let pins = vec![envelope::CallerPin {
        root: root_b.clone(),
        endpoint: ENDPOINT_B.into(),
        leaf: b64u(&der["leaf_b"]),
        state: "active".into(),
        leaf_fingerprint: None,
    }];
    let small = envelope::seal_result(envelope::SealResult {
        recipient: &alina.public(),
        sender: bharat,
        form: Form::Leaf,
        sender_chain: None,
        result: None,
        error: Some(json!({ "code": "permission_denied", "message": "no" })),
        msg_id: "m-3".into(),
        ts,
        exp: None,
        ephemeral_seed: None,
    })
    .unwrap();
    let out = envelope::open_result(envelope::OpenResultArgs {
        envelope: &small,
        my_key: alina,
        my_public: &alina.public(),
        msg_id: "m-3",
        now: ts,
        pins: &pins,
        expected_root: Some(&root_b),
        expected_endpoint: Some(ENDPOINT_B),
    })
    .unwrap();
    assert_eq!(out["form"], "leaf");
    assert_eq!(out["error"]["code"], "permission_denied");
}

/// An envelope's four members as JSON text, `sig` written as each of `sigs` in turn: text, because a
/// parsed value cannot hold a member written twice.
fn sig_text(e: &Value, sigs: &[&str]) -> String {
    let m = |k: &str| serde_json::to_string(&e[k]).unwrap();
    let sigs: Vec<String> = sigs.iter().map(|s| format!(r#""sig":{s}"#)).collect();
    format!(r#"{{"protected":{},"enc":{},"ct":{},{}}}"#, m("protected"), m("enc"), m("ct"), sigs.join(","))
}

/// The answer `call` gives to `function` with `envelope` spliced into `rest` as it is written.
fn call_with_envelope(function: &str, rest: Value, envelope: &str) -> Value {
    let rest = rest.to_string();
    let args = format!(r#"{{"envelope":{envelope},{}"#, &rest[1..]);
    serde_json::from_str(&hdtp_identity::call(function, &args)).unwrap()
}

/// `serde_json` reads a member written twice at its last occurrence, and never refuses it: what the
/// closed reader (`Wire::read`) relies on for §13.1's repeated member, measured here so it cannot move
/// under it with a dependency.
#[test]
fn a_repeated_member_is_read_at_its_last_occurrence() {
    let v: Value = serde_json::from_str(r#"{"sig":5,"sig":"real"}"#).unwrap();
    assert_eq!(v, json!({ "sig": "real" }));
    let v: Value = serde_json::from_str(r#"{"sig":"real","sig":null}"#).unwrap();
    assert_eq!(v, json!({ "sig": null }));
}

/// §13.1 of the draft (SEP-0005): an envelope is exactly its four members, each a string, names
/// compared byte for byte, a repeated member read at its last occurrence; and step 1 of §13.3 reads all
/// four in their one spelling before the key is resolved. Each envelope reaches `decide` as text, the
/// way a host hands it over, and each case is an Appendix B envelope with one change, the answers the
/// seed's (vectors/lib/envelope.mjs `receive`, vectors/lib/invalid-envelopes.mjs).
#[test]
fn decide_reads_an_envelope_of_exactly_four_string_members() {
    let v = vectors();
    let der = der_of(&v);
    let envelopes = v["envelopes"].as_array().unwrap();
    let full = &envelopes[0];
    let small = &envelopes[2];
    let root_a = fingerprint_of(&parse(&der["root_a"]).unwrap());
    let pin_a = json!({ "root": root_a, "endpoint": ENDPOINT_A, "leaf": b64u(&der["leaf_a"]), "state": "active" });
    let node = node_for(&v, &der, "leaf_b", "root_b", vec![pin_a]);
    let decide = |text: &str| call_with_envelope("decide", json!({ "now": NOW, "node": node }), text);
    let refused = |why: &str| json!({ "result": { "code": "envelope_invalid", "why": why }, "effects": [] });
    let real = |e: &Value| serde_json::to_string(&e["sig"]).unwrap();
    let (real_full, real_small) = (real(full), real(small));
    let without = |e: &Value, k: &str| {
        let mut o = json!({ "protected": e["protected"], "enc": e["enc"], "ct": e["ct"], "sig": e["sig"] });
        o.as_object_mut().unwrap().remove(k);
        o
    };
    let with = |e: &Value, k: &str, x: Value| {
        let mut o = json!({ "protected": e["protected"], "enc": e["enc"], "ct": e["ct"], "sig": e["sig"] });
        o.as_object_mut().unwrap().insert(k.into(), x);
        o.to_string()
    };
    for (what, text, why) in [
        ("a fifth member", with(full, "note", json!("x")), "envelope members"),
        ("sig spelled SIG", with(&without(full, "sig"), "SIG", full["sig"].clone()), "envelope members"),
        ("Protected beside protected", with(full, "Protected", full["protected"].clone()), "envelope members"),
        (
            "a member named ct,enc for ct and enc",
            json!({ "ct,enc": full["ct"], "protected": full["protected"], "sig": full["sig"] }).to_string(),
            "envelope members",
        ),
        ("sig absent, in the small form", without(small, "sig").to_string(), "envelope members"),
        (
            "an array in place of the object",
            json!([full["protected"], full["enc"], full["ct"], full["sig"]]).to_string(),
            "envelope members",
        ),
        ("a string in place of the object", json!("x").to_string(), "envelope members"),
        ("sig null, in the small form", with(small, "sig", Value::Null), "envelope member types"),
        ("sig a number", with(full, "sig", json!(5)), "envelope member types"),
        ("enc an object", with(full, "enc", json!({})), "envelope member types"),
        ("sig not base64url, in the small form", with(small, "sig", json!("!!!!")), "sig is not base64url"),
        ("sig twice, the real one then AAAA", sig_text(full, &[&real_full, r#""AAAA""#]), "signature is not the chain's leaf key"),
        // Step 1 reads every spelling before the header is parsed: a `protected` that decodes to bytes
        // that are not JSON, beside a `sig` that does not read, is refused for the `sig`.
        (
            "protected not JSON and sig not base64url",
            with(&serde_json::from_str(&with(full, "protected", json!(b64u(b"nope")))).unwrap(), "sig", json!("!!!!")),
            "sig is not base64url",
        ),
    ] {
        assert_eq!(decide(&text), refused(why), "{what}");
    }
    // The controls that must get through: each member once, and the real `sig` last after an earlier
    // one that is not even a string, which is never read or judged.
    for (what, e, text) in [
        ("each member once", full, sig_text(full, &[&real_full])),
        ("sig twice, AAAA then the real one", full, sig_text(full, &[r#""AAAA""#, &real_full])),
        ("sig twice, 5 then the real one", full, sig_text(full, &[r#"5"#, &real_full])),
        ("sig twice in the small form, null then the real one", small, sig_text(small, &["null", &real_small])),
    ] {
        let out = decide(&text);
        assert_eq!((out["result"]["code"].as_str(), out["result"]["tier"].as_str()), (Some("ok"), Some("contact")), "{what}: {out}");
        assert_eq!(out["result"]["form"], if std::ptr::eq(e, small) { "leaf" } else { "chain" }, "{what}");
    }
    // Absent or null is the host's omission (CONTRACT §0); a host's own fault is its answer whatever the
    // envelope is.
    let out: Value =
        serde_json::from_str(&hdtp_identity::call("decide", &json!({ "now": NOW, "node": node, "envelope": null }).to_string())).unwrap();
    assert_eq!(out, json!({ "error": "bad_request", "why": "envelope is required" }));
    let out = call_with_envelope("decide", json!({ "now": "yesterday", "node": node }), &with(full, "note", json!("x")));
    assert_eq!(out["error"], "parse", "{out}");
}

/// Step 1 comes before the key is resolved (§13.3): an envelope sealed to a key this endpoint once held
/// and no longer does is `certificate_renewed`, and the same envelope with a `sig` that does not read is
/// `envelope_invalid`, never answered with the current chain.
#[test]
fn a_misspelled_member_to_a_former_key_is_refused_before_the_key_is_resolved() {
    let v = vectors();
    let der = der_of(&v);
    let full = &v["envelopes"].as_array().unwrap()[0];
    let mut node = node_for(&v, &der, "leaf_b", "root_b", vec![]);
    let kid = node["keys"][0]["kid"].clone();
    node["keys"] = json!([]);
    node["former"] = json!([kid]);
    let decide = |text: &str| call_with_envelope("decide", json!({ "now": NOW, "node": node }), text);
    let real = serde_json::to_string(&full["sig"]).unwrap();
    assert_eq!(decide(&sig_text(full, &[&real]))["result"]["code"], "certificate_renewed");
    for (what, sig, why) in [("!!!!", r#""!!!!""#, "sig is not base64url"), ("null", "null", "envelope member types")] {
        assert_eq!(
            decide(&sig_text(full, &[sig])),
            json!({ "result": { "code": "envelope_invalid", "why": why }, "effects": [] }),
            "sig {what}"
        );
    }
}

/// `open_result` reads a result envelope as `decide` reads a request (§13.2, §13.1): the same reader,
/// the same step 1, the same words, as `{error: envelope_invalid}`.
#[test]
fn open_result_reads_an_envelope_of_exactly_four_string_members() {
    let v = vectors();
    let der = der_of(&v);
    let c = cast();
    let ts = at(NOW);
    let alina = &c.hosts["leaf_a"];
    let chain_b = vec![der["leaf_b"].clone(), der["root_b"].clone()];
    let wire = envelope::seal_result(envelope::SealResult {
        recipient: &alina.public(),
        sender: &c.hosts["leaf_b"],
        form: Form::Chain,
        sender_chain: Some(&chain_b),
        result: Some(json!({ "ok": 1 })),
        error: None,
        msg_id: "m-1".into(),
        ts,
        exp: None,
        ephemeral_seed: None,
    })
    .unwrap();
    let e = serde_json::to_value(&wire).unwrap();
    let rest = json!({ "my_pkcs8": b64u(&alina.to_pkcs8()), "my_spki": b64u(alina.public().spki()), "msg_id": "m-1", "now": NOW });
    let open = |text: &str| call_with_envelope("open_result", rest.clone(), text);
    let real = serde_json::to_string(&e["sig"]).unwrap();
    let with = |k: &str, x: Value| {
        let mut o = e.clone();
        o.as_object_mut().unwrap().insert(k.into(), x);
        o.to_string()
    };
    let mut no_ct = e.clone();
    no_ct.as_object_mut().unwrap().remove("ct");
    for (what, text, why) in [
        ("a fifth member", with("note", json!("x")), "envelope members"),
        ("CT beside ct", with("CT", e["ct"].clone()), "envelope members"),
        ("ct absent", no_ct.to_string(), "envelope members"),
        ("a string in place of the object", json!("x").to_string(), "envelope members"),
        ("sig null", with("sig", Value::Null), "envelope member types"),
        ("sig not base64url", with("sig", json!("!!!!")), "sig is not base64url"),
        ("sig twice, the real one then AAAA", sig_text(&e, &[&real, r#""AAAA""#]), "signature is not the chain's leaf key"),
    ] {
        assert_eq!(open(&text), json!({ "error": "envelope_invalid", "why": why }), "{what}");
    }
    for (what, text) in [("each member once", sig_text(&e, &[&real])), ("sig twice, 5 then the real one", sig_text(&e, &["5", &real]))] {
        let out = open(&text);
        assert_eq!(out["ok"], true, "{what}: {out}");
        assert_eq!(out["result"], json!({ "ok": 1 }), "{what}");
    }
}

/// §2.1, recomputed from the published `prf` alone — so what passes is what a third implementation
/// reading Appendix B would have to reproduce, not what this crate happened to write.
#[test]
fn derivation_vectors() {
    let v = appendix_b_blocks().remove(0);
    let entries = v["derivation"].as_array().expect("derivation block").clone();
    assert!(entries.len() >= 3, "all three info strings are covered");
    let mut seen: Vec<String> = Vec::new();
    for d in &entries {
        let info = d["info"].as_str().unwrap();
        assert_eq!(d["salt"].as_str().unwrap(), b64u(&keys::prf_salt()), "{info}: the salt is SHA-256(\"hdtp/vault/1\")");
        let seed = keys::derive_seed(&from_b64u(d["prf"].as_str().unwrap()).unwrap(), info).unwrap();
        assert_eq!(b64u(&seed), d["seed"].as_str().unwrap(), "{info}: HKDF-SHA256 over an empty salt");
        if let Some(alg) = d["alg"].as_str() {
            assert_eq!(alg, "ed25519", "a derived root is Ed25519");
            let k = PrivateKey::from_seed(Alg::Ed25519, &seed).unwrap();
            assert_eq!(b64u(k.public().spki()), d["spki"].as_str().unwrap(), "{info}: the key the seed makes");
            assert_eq!(k.public().fingerprint(), d["fingerprint"].as_str().unwrap(), "{info}: the identity that key is");
        }
        // The property the info strings exist for: one credential, three unrelated secrets. A port
        // that dropped `info` from the expand step passes everything above and fails here.
        assert!(!seen.contains(&b64u(&seed)), "{info}: a different info gives a different seed");
        seen.push(b64u(&seed));
    }
}

/// The two refusals §2.1 leans on. A mistyped domain separator would otherwise return 32 perfectly
/// good bytes belonging to nobody, which is this design's whole failure mode.
#[test]
fn derivation_refuses_what_would_silently_differ() {
    let prf = [7u8; 32];
    assert!(keys::derive_seed(&prf, "hdtp/root/2").is_err(), "an info string that is not one of the three");
    assert!(keys::derive_seed(&prf, "hdtp/Root/1").is_err(), "case matters in a domain separator");
    assert!(keys::derive_seed(&prf[..31], "hdtp/root/1").is_err(), "a prf output is 32 bytes");
    assert!(keys::derive_seed(&prf, "hdtp/root/1").is_ok());
}
