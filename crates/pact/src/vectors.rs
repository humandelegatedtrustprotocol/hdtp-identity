//! The implementer's proofs: regenerate Appendix B's 2.0 vectors from their labelled seeds, prove a
//! document's vectors natively, and aim the black-box intrusion scenarios at a live endpoint.
use crate::io::{core, fail, instant, now_or, read_input, write_output, Fail, Res};
use pact_identity::envelope::{self, Form, SealRequest};
use pact_identity::hpke::{self, suite_for, Suite};
use pact_identity::keys::{Alg, PrivateKey, PublicKey};
use pact_identity::time::parse_rfc3339;
use pact_identity::util::{b64u, from_b64u, from_hex, hex, seed};
use pact_identity::x509::{self, fingerprint_of, parse, serial_of, validate_chain, ChainResult, LeafSpec};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const NOW: &str = "2026-09-13T12:00:00Z";
const ENDPOINT_A: &str = "https://agent.alina.example/mcp";
const ENDPOINT_B: &str = "https://agent.bharat.example/mcp";
const TEXT: &str = "hello from the PACT test vectors";

fn at(s: &str) -> i64 {
    parse_rfc3339(s).expect("a literal instant")
}

struct Cast {
    root_a: PrivateKey,
    root_b: PrivateKey,
    hosts: BTreeMap<&'static str, PrivateKey>,
}

fn cast() -> Res<Cast> {
    let k = |alg, label: &str| PrivateKey::from_seed(alg, &seed(label)).map_err(|e| Fail(e.why));
    let mut hosts = BTreeMap::new();
    hosts.insert("leaf_a", k(Alg::Ed25519, "host/alina/2026")?);
    hosts.insert("leaf_a_next", k(Alg::Ed25519, "host/alina/2027")?);
    hosts.insert("leaf_b", k(Alg::P256, "host/bharat/2026")?);
    Ok(Cast { root_a: k(Alg::Ed25519, "root/alina")?, root_b: k(Alg::P256, "root/bharat")?, hosts })
}

#[allow(clippy::too_many_arguments)]
fn leaf(cn: &str, root: &PrivateKey, host: &PublicKey, endpoint: &str, dns: Option<&str>, nb: &str, na: &str, label: &str) -> Res<Vec<u8>> {
    let issuer = root.public();
    let spec = LeafSpec {
        cn,
        root_cn: cn,
        issuer: &issuer,
        host_key: host,
        uris: vec![endpoint.to_string()],
        dns_name: dns.map(String::from),
        not_before: at(nb),
        not_after: at(na),
        serial: serial_of(label),
        ca: false,
        usage: None,
        aki: None,
        extra: Vec::new(),
        alg_oid: None,
    };
    x509::build_leaf(&spec, root).map_err(|e| Fail(e.why))
}

/// The seven certificates of Appendix B, in the generator's order, from their labelled seeds.
fn certificates(c: &Cast) -> Res<Vec<(&'static str, Vec<u8>, String)>> {
    let a = |n: &str| c.hosts[n].public();
    Ok(vec![
        ("root_a", x509::build_root("Alina Rao", &c.root_a, at("2026-09-01T00:00:00Z"), &serial_of("root_a")).map_err(|e| Fail(e.why))?, "Ed25519 root, self-signed, CN \"Alina Rao\", notAfter 9999-12-31".into()),
        ("root_b", x509::build_root("Bharat Mehta", &c.root_b, at("2026-09-01T00:00:00Z"), &serial_of("root_b")).map_err(|e| Fail(e.why))?, "P-256 root, self-signed, CN \"Bharat Mehta\"".into()),
        ("leaf_a", leaf("Alina Rao", &c.root_a, &a("leaf_a"), ENDPOINT_A, Some("agent.alina.example"), "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z", "leaf_a")?, format!("Ed25519 leaf under root_a for {ENDPOINT_A}, 2026-09-01 to 2027-09-01, with a dNSName beside the URI")),
        ("leaf_b", leaf("Bharat Mehta", &c.root_b, &a("leaf_b"), ENDPOINT_B, None, "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z", "leaf_b")?, format!("P-256 leaf under root_b for {ENDPOINT_B}, 2026-09-01 to 2027-09-01, keyUsage digitalSignature+keyAgreement")),
        ("leaf_a_expired", leaf("Alina Rao", &c.root_a, &a("leaf_a"), ENDPOINT_A, None, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", "leaf_a_expired")?, "leaf_a's key and endpoint, 2025-06-01 to 2026-06-01: expired at NOW".into()),
        ("leaf_a_long", leaf("Alina Rao", &c.root_a, &a("leaf_a"), ENDPOINT_A, None, "2026-09-01T00:00:00Z", "2027-10-10T00:00:00Z", "leaf_a_long")?, "leaf_a's key and endpoint, 2026-09-01 to 2027-10-10: 404 days".into()),
        ("leaf_a_next", leaf("Alina Rao", &c.root_a, &a("leaf_a_next"), ENDPOINT_A, None, "2027-08-02T00:00:00Z", "2028-08-01T00:00:00Z", "leaf_a_next")?, "a fresh key for the same endpoint, 2027-08-02 to 2028-08-01: the renewal that supersedes leaf_a".into()),
    ])
}

fn chain_case(name: &str, chain: &[&str], expected_root: Option<String>, expected_endpoint: Option<&str>, expect: &str, rule: Option<u8>) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), json!(name));
    m.insert("chain".into(), json!(chain));
    if let Some(r) = expected_root {
        m.insert("expected_root".into(), json!(r));
    }
    if let Some(e) = expected_endpoint {
        m.insert("expected_endpoint".into(), json!(e));
    }
    m.insert("now".into(), json!(NOW));
    m.insert("expect".into(), json!(expect));
    if let Some(r) = rule {
        m.insert("rule".into(), json!(r));
    }
    Value::Object(m)
}

pub fn gen(out: Option<&str>) -> Res<i32> {
    let c = cast()?;
    let certs = certificates(&c)?;
    let der: BTreeMap<&str, &Vec<u8>> = certs.iter().map(|(n, d, _)| (*n, d)).collect();
    let fp = |n: &str| fingerprint_of(&parse(der[n]).expect("a built certificate parses"));
    let chain_b64 = |names: &[&str]| -> Vec<String> { names.iter().map(|n| b64u(der[*n])).collect() };

    let chain_cases = vec![
        chain_case("alina valid", &["leaf_a", "root_a"], Some(fp("root_a")), Some(ENDPOINT_A), "accept", None),
        chain_case("bharat valid", &["leaf_b", "root_b"], Some(fp("root_b")), Some(ENDPOINT_B), "accept", None),
        chain_case("first contact, no expectation", &["leaf_a", "root_a"], None, None, "accept", None),
        chain_case("chain of three", &["leaf_a", "root_a", "root_a"], None, None, "refuse", Some(1)),
        chain_case("single certificate is not a chain", &["root_a"], None, None, "refuse", Some(1)),
        chain_case("leaf presented as root", &["leaf_a", "leaf_a"], None, None, "refuse", Some(1)),
        chain_case("root is not the one pinned", &["leaf_a", "root_a"], Some(fp("root_b")), None, "refuse", Some(2)),
        chain_case("leaf under the wrong root", &["leaf_a", "root_b"], None, None, "refuse", Some(3)),
        chain_case("expired leaf", &["leaf_a_expired", "root_a"], None, None, "refuse", Some(4)),
        chain_case("leaf not yet valid", &["leaf_a_next", "root_a"], None, None, "refuse", Some(4)),
        chain_case("leaf longer than 398 days", &["leaf_a_long", "root_a"], None, None, "refuse", Some(4)),
        chain_case("endpoint mismatch", &["leaf_a", "root_a"], None, Some(&format!("{ENDPOINT_A}/")), "refuse", Some(5)),
    ];
    let newest = json!([
        { "pinned": "leaf_a", "presented": "leaf_a", "expect": "same" },
        { "pinned": "leaf_a", "presented": "leaf_a_next", "expect": "newer" },
        { "pinned": "leaf_a_next", "presented": "leaf_a", "expect": "superseded" },
        { "pinned": "leaf_a", "presented": "leaf_a_long", "expect": "conflict" },
    ]);
    let renewed = json!([
        { "name": "renewal followed", "pinned_leaf": "leaf_a", "dialed": ENDPOINT_A, "now": "2027-08-15T12:00:00Z", "answer": { "code": "certificate_renewed", "data": { "chain": chain_b64(&["leaf_a_next", "root_a"]) } }, "expect": "follow" },
        { "name": "older chain discarded", "pinned_leaf": "leaf_a_next", "dialed": ENDPOINT_A, "now": "2027-08-15T12:00:00Z", "answer": { "code": "certificate_renewed", "data": { "chain": chain_b64(&["leaf_a", "root_a"]) } }, "expect": "discard" },
        { "name": "another root discarded", "pinned_leaf": "leaf_a", "dialed": ENDPOINT_A, "now": NOW, "answer": { "code": "certificate_renewed", "data": { "chain": chain_b64(&["leaf_b", "root_b"]) } }, "expect": "discard" },
    ]);

    let ts = at(NOW);
    let envelope = |name: &str, sender: &str, sender_chain: &[&str], recipient_chain: &[&str], msg_id: &str, form: &str| -> Res<Value> {
        let recipient_leaf = parse(der[recipient_chain[0]]).map_err(|e| Fail(e.why))?;
        let chain: Vec<Vec<u8>> = sender_chain.iter().map(|n| der[*n].clone()).collect();
        let params = json!({ "name": "send_message", "arguments": { "msg_id": "vec-1", "text": TEXT } });
        let wire = envelope::seal_request(SealRequest {
            recipient: &recipient_leaf.public_key,
            sender: &c.hosts[sender],
            form: Form::parse(form).map_err(|e| Fail(e.why))?,
            sender_chain: Some(&chain),
            method: "tools/call".into(),
            params,
            msg_id: msg_id.into(),
            ts,
            exp: Some(ts + 600),
            cty: None,
            ephemeral_seed: Some(seed(&format!("ephemeral/{name}"))),
        })
        .map_err(|e| Fail(e.why))?;
        // The plaintext bytes are what the recipient reads back; opening is how the generator learns them.
        let recipient = &c.hosts[recipient_chain[0]];
        let suite = suite_for(&recipient_leaf.public_key);
        let pt = hpke::open(suite, recipient, envelope::INFO_V2, &from_b64u(&wire.protected).map_err(|e| Fail(e.why))?, &from_b64u(&wire.enc).map_err(|e| Fail(e.why))?, &from_b64u(&wire.ct).map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.why))?;
        Ok(json!({ "name": name, "form": form, "suite": suite.id(), "sender_chain": sender_chain, "recipient_chain": recipient_chain, "plaintext_hex": hex(&pt), "protected": wire.protected, "enc": wire.enc, "ct": wire.ct, "sig": wire.sig }))
    };
    let envelopes = vec![
        envelope("alina-to-bharat", "leaf_a", &["leaf_a", "root_a"], &["leaf_b", "root_b"], "vec-v2-alina-to-bharat", "chain")?,
        envelope("bharat-to-alina", "leaf_b", &["leaf_b", "root_b"], &["leaf_a", "root_a"], "vec-v2-bharat-to-alina", "chain")?,
        envelope("alina-to-bharat-by-reference", "leaf_a", &["leaf_a", "root_a"], &["leaf_b", "root_b"], "vec-v2-alina-to-bharat-ref", "leaf")?,
    ];

    let mut cert_map = Map::new();
    for (n, d, note) in &certs {
        cert_map.insert((*n).into(), json!({ "der_hex": hex(d), "note": note }));
    }
    let mut keys = Map::new();
    for (n, k) in &c.hosts {
        keys.insert((*n).into(), json!(hex(&k.to_pkcs8())));
    }
    let doc = json!({
        "generated_by": "pact vectors gen (deterministic; Ed25519 signatures and every certificate reproduce byte for byte, ECDSA signatures are one valid signature)",
        "now": NOW,
        "certificates": cert_map,
        "leaf_keys_pkcs8_hex": keys,
        "chain_cases": chain_cases,
        "newest_leaf_cases": newest,
        "certificate_renewed_cases": renewed,
        "envelopes": envelopes,
    });
    write_output(out, &format!("{}\n", serde_json::to_string_pretty(&doc)?))?;
    eprintln!("{} certificates, {} chain cases, {} envelopes", certs.len(), doc["chain_cases"].as_array().map_or(0, |a| a.len()), envelopes.len());
    Ok(0)
}

/// The JSON blocks of a document's Appendix B: the `v: 1` vectors first, the 2.0 vectors second.
fn appendix_b(spec: &str) -> Res<Vec<Value>> {
    let start = spec.find("## Appendix B").ok_or_else(|| Fail("no Appendix B in the document".into()))?;
    let end = spec[start..].find("## Appendix C").map(|i| start + i).unwrap_or(spec.len());
    let b = &spec[start..end];
    let mut out = Vec::new();
    let mut rest = b;
    while let Some(i) = rest.find("```json\n") {
        let after = &rest[i + 8..];
        let j = after.find("\n```").ok_or_else(|| Fail("an unterminated json fence in Appendix B".into()))?;
        out.push(serde_json::from_str(&after[..j]).map_err(|e| Fail(format!("Appendix B block: {e}")))?);
        rest = &after[j + 4..];
    }
    Ok(out)
}

struct Tally {
    checks: usize,
    failures: usize,
}

impl Tally {
    fn ok(&mut self, cond: bool, what: impl AsRef<str>) {
        self.checks += 1;
        if !cond {
            self.failures += 1;
            println!("  FAIL {}", what.as_ref());
        }
    }
}

pub fn check(spec: Option<&str>, file: Option<&str>) -> Res<i32> {
    let (v1, v2): (Option<Value>, Value) = match (spec, file) {
        (Some(s), _) => {
            let text = String::from_utf8(read_input(s)?).map_err(|_| Fail("the document is not UTF-8".into()))?;
            let mut blocks = appendix_b(&text)?;
            if blocks.is_empty() {
                return fail("Appendix B has no vector blocks");
            }
            let v2 = if blocks.len() > 1 { blocks.remove(1) } else { return fail("Appendix B has no 2.0 block") };
            (Some(blocks.remove(0)), v2)
        }
        (None, Some(f)) => (None, serde_json::from_slice(&read_input(f)?).map_err(|e| Fail(format!("{f}: {e}")))?),
        (None, None) => {
            let candidates = [std::env::var("PACT_SPEC").unwrap_or_default(), "pact-protocol/SPEC.md".into(), "SPEC.md".into()];
            match candidates.iter().find(|p| !p.is_empty() && std::path::Path::new(p).exists()) {
                Some(p) => return check(Some(p), None),
                None => return fail("give --spec SPEC.md or --file vectors.json"),
            }
        }
    };
    let mut t = Tally { checks: 0, failures: 0 };

    if let Some(v1) = &v1 {
        println!("v1 envelopes");
        for v in v1.as_array().cloned().unwrap_or_default() {
            let name = v["name"].as_str().unwrap_or("?");
            let mut go = || -> Result<(), String> {
                let suite = Suite::parse(v["suite"].as_str().unwrap_or("")).ok_or("suite")?;
                let recipient = PrivateKey::from_pkcs8(&from_hex(v["recipient_key_pkcs8_hex"].as_str().unwrap_or("")).map_err(|e| e.why)?).map_err(|e| e.why)?;
                let sender = PrivateKey::from_pkcs8(&from_hex(v["sender_key_pkcs8_hex"].as_str().unwrap_or("")).map_err(|e| e.why)?).map_err(|e| e.why)?;
                let aad = from_b64u(v["protected"].as_str().unwrap_or("")).map_err(|e| e.why)?;
                let enc = from_b64u(v["enc"].as_str().unwrap_or("")).map_err(|e| e.why)?;
                let ct = from_b64u(v["ct"].as_str().unwrap_or("")).map_err(|e| e.why)?;
                let pt = hpke::open(suite, &recipient, b"PACT-SEAL-v1", &aad, &enc, &ct).map_err(|e| e.why)?;
                t.ok(hex(&pt) == v["plaintext_hex"].as_str().unwrap_or(""), format!("{name}: plaintext"));
                let mut signed = aad.clone();
                signed.extend_from_slice(&enc);
                signed.extend_from_slice(&ct);
                t.ok(sender.public().verify(&signed, &from_b64u(v["sig"].as_str().unwrap_or("")).map_err(|e| e.why)?), format!("{name}: signature"));
                t.ok(hpke::open(suite, &recipient, b"PACT-SEAL-v2", &aad, &enc, &ct).is_err(), format!("{name}: never opens as 2.0"));
                Ok(())
            };
            match go() {
                Ok(()) => println!("  {name}: opened"),
                Err(e) => t.ok(false, format!("{name}: {e}")),
            }
        }
    }

    let der: BTreeMap<String, Vec<u8>> = v2["certificates"].as_object().map(|o| o.iter().filter_map(|(k, c)| from_hex(c["der_hex"].as_str()?).ok().map(|d| (k.clone(), d))).collect()).unwrap_or_default();
    let get = |n: &str| der.get(n).cloned().unwrap_or_default();

    println!("certificates rebuild from their seeds");
    let c = cast()?;
    let mine: BTreeMap<&str, Vec<u8>> = certificates(&c)?.into_iter().map(|(n, d, _)| (n, d)).collect();
    for (name, bytes) in &der {
        match parse(bytes) {
            Ok(cert) => {
                let kind = if name.starts_with("root") { "root" } else { "leaf" };
                t.ok(cert.kind() == kind, format!("{name}: in the profile as a {kind}"));
                t.ok(bytes.len() <= 4096, format!("{name}: under 4 KiB"));
                match mine.get(name.as_str()) {
                    Some(rebuilt) => {
                        let same_tbs = parse(rebuilt).map(|r| r.tbs == cert.tbs).unwrap_or(false);
                        let issuer = if name.ends_with("_b") { c.root_b.public() } else { c.root_a.public() };
                        let signed = x509::verify_cert(&cert, &issuer);
                        t.ok(same_tbs && signed && (cert.public_key.alg() == Alg::P256 || rebuilt == bytes), format!("{name}: rebuilt from the labelled seeds"));
                    }
                    None => t.ok(false, format!("{name}: not one the generator knows")),
                }
            }
            Err(e) => t.ok(false, format!("{name}: {}", e.why)),
        }
    }
    for (name, k) in v2["leaf_keys_pkcs8_hex"].as_object().cloned().unwrap_or_default() {
        let parsed = from_hex(k.as_str().unwrap_or("")).ok().and_then(|b| PrivateKey::from_pkcs8(&b).ok());
        let mine_spki = c.hosts.get(name.as_str()).map(|h| h.public().spki().to_vec());
        t.ok(parsed.as_ref().map(|p| p.public().spki().to_vec()) == mine_spki && mine_spki.is_some(), format!("{name}: leaf key is the seed's"));
    }

    println!("chain cases (§14.2)");
    for case in v2["chain_cases"].as_array().cloned().unwrap_or_default() {
        let name = case["name"].as_str().unwrap_or("?");
        let chain: Vec<Vec<u8>> = case["chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(get).collect()).unwrap_or_default();
        let now = case["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(0);
        let r = validate_chain(&chain, now, case["expected_root"].as_str(), case["expected_endpoint"].as_str());
        let want = case["expect"].as_str().unwrap_or("");
        match &r {
            ChainResult::Ok(_) => t.ok(want == "accept", format!("{name}: expected {want}, got accept")),
            ChainResult::Refused { rule, reason } => t.ok(want == "refuse" && Some(*rule as u64) == case["rule"].as_u64(), format!("{name}: expected {want} rule {}, got rule {rule} ({reason})", case["rule"])),
        }
        println!("  {name}: {}", match r { ChainResult::Ok(_) => "accepted".to_string(), ChainResult::Refused { rule, .. } => format!("refused by rule {rule}") });
    }

    println!("newest leaf (§14.3)");
    for case in v2["newest_leaf_cases"].as_array().cloned().unwrap_or_default() {
        let (p, q) = (case["pinned"].as_str().unwrap_or(""), case["presented"].as_str().unwrap_or(""));
        let got = x509::compare_leaves(&get(p), &get(q)).unwrap_or("error");
        t.ok(got == case["expect"].as_str().unwrap_or(""), format!("{p} vs {q}: expected {}, got {got}", case["expect"]));
        println!("  {p} then {q}: {got}");
    }

    println!("certificate_renewed (§14.4)");
    for case in v2["certificate_renewed_cases"].as_array().cloned().unwrap_or_default() {
        let name = case["name"].as_str().unwrap_or("?");
        let pinned = get(case["pinned_leaf"].as_str().unwrap_or(""));
        let root = parse(&pinned).ok().and_then(|c| c.aki.map(|a| pact_identity::keys::fingerprint_of_id(&a))).unwrap_or_default();
        let now = case["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(0);
        let r = envelope::follow_renewed(&case["answer"], &root, &pinned, case["dialed"].as_str().unwrap_or(""), now);
        let follow = r["follow"].as_bool().unwrap_or(false);
        t.ok(follow == (case["expect"] == "follow"), format!("{name}: expected {}, got {r}", case["expect"]));
        println!("  {name}: {}", if follow { "followed" } else { "discarded" });
    }

    println!("v2 envelopes (§13)");
    let now2 = v2["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(at(NOW));
    for e in v2["envelopes"].as_array().cloned().unwrap_or_default() {
        let name = e["name"].as_str().unwrap_or("?");
        let form = e["form"].as_str().unwrap_or("chain");
        let mut go = || -> Result<(), String> {
            let rn = e["recipient_chain"][0].as_str().ok_or("recipient_chain")?;
            let sn = e["sender_chain"][0].as_str().ok_or("sender_chain")?;
            let recipient_leaf = parse(&get(rn)).map_err(|e| e.why)?;
            let recipient = PrivateKey::from_pkcs8(&from_hex(v2["leaf_keys_pkcs8_hex"][rn].as_str().unwrap_or("")).map_err(|e| e.why)?).map_err(|e| e.why)?;
            let aad = from_b64u(e["protected"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let enc = from_b64u(e["enc"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let ct = from_b64u(e["ct"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let sig = from_b64u(e["sig"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let header: Value = serde_json::from_slice(&aad).map_err(|e| e.to_string())?;
            let mut members: Vec<&str> = header.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
            members.sort_unstable();
            t.ok(members.join(",") == envelope::HEADER_MEMBERS, format!("{name}: header members"));
            let suite = suite_for(&recipient_leaf.public_key);
            t.ok(header["v"] == 2 && header["suite"] == e["suite"] && Suite::parse(e["suite"].as_str().unwrap_or("")) == Some(suite), format!("{name}: version and suite"));
            t.ok(header["kid"] == recipient_leaf.public_key.fingerprint(), format!("{name}: kid is the recipient leaf key"));
            t.ok(recipient.public().spki() == &recipient_leaf.spki[..], format!("{name}: the recipient key is the leaf's"));
            let pt = hpke::open(suite, &recipient, envelope::INFO_V2, &aad, &enc, &ct).map_err(|e| e.why)?;
            t.ok(hex(&pt) == e["plaintext_hex"].as_str().unwrap_or(""), format!("{name}: plaintext"));
            let body: Value = serde_json::from_slice(&pt).map_err(|e| e.to_string())?;
            let mut signed = aad.clone();
            signed.extend_from_slice(&enc);
            signed.extend_from_slice(&ct);
            let sender_leaf = parse(&get(sn)).map_err(|e| e.why)?;
            let mut bm: Vec<&str> = body.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
            bm.sort_unstable();
            if form == "leaf" {
                t.ok(bm.join(",") == "leaf,method,params", format!("{name}: small form carries leaf, method, params"));
                t.ok(body["leaf"] == sender_leaf.public_key.fingerprint(), format!("{name}: leaf names the sender's held leaf"));
                t.ok(sender_leaf.public_key.verify(&signed, &sig), format!("{name}: signature under the held leaf's key"));
                t.ok(ct.len() < 400, format!("{name}: small form stays small ({} bytes sealed)", ct.len()));
            } else {
                t.ok(bm.join(",") == "chain,method,params", format!("{name}: full form carries chain, method, params"));
                let chain: Vec<Vec<u8>> = body["chain"].as_array().map(|a| a.iter().filter_map(|x| from_b64u(x.as_str()?).ok()).collect()).unwrap_or_default();
                match validate_chain(&chain, now2, None, None) {
                    ChainResult::Ok(ok) => {
                        t.ok(true, "");
                        t.ok(chain.first() == Some(&get(sn)), format!("{name}: chain inside is the sender's"));
                        t.ok(ok.leaf.public_key.verify(&signed, &sig), format!("{name}: signature under the chain's leaf key"));
                    }
                    ChainResult::Refused { rule, reason } => t.ok(false, format!("{name}: chain inside validates (rule {rule}: {reason})")),
                }
            }
            // Re-sealed from the same inputs and the vector's ephemeral seed: enc and ct reproduce.
            let sender = PrivateKey::from_pkcs8(&from_hex(v2["leaf_keys_pkcs8_hex"][sn].as_str().unwrap_or("")).map_err(|e| e.why)?).map_err(|e| e.why)?;
            let chain: Vec<Vec<u8>> = e["sender_chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(get).collect()).unwrap_or_default();
            let wire = envelope::seal_request(SealRequest {
                recipient: &recipient_leaf.public_key,
                sender: &sender,
                form: Form::parse(form).map_err(|e| e.why)?,
                sender_chain: Some(&chain),
                method: body["method"].as_str().unwrap_or("tools/call").into(),
                params: body["params"].clone(),
                msg_id: header["msg_id"].as_str().unwrap_or("").into(),
                ts: header["ts"].as_i64().unwrap_or(0),
                exp: header["exp"].as_i64(),
                cty: None,
                ephemeral_seed: Some(seed(&format!("ephemeral/{name}"))),
            })
            .map_err(|e| e.why)?;
            t.ok(wire.protected == e["protected"] && wire.enc == e["enc"] && wire.ct == e["ct"], format!("{name}: re-sealed from the seed, enc and ct reproduce"));
            Ok(())
        };
        match go() {
            Ok(()) => println!("  {name}: opened{}", if form == "leaf" { " (by reference)" } else { "" }),
            Err(err) => t.ok(false, format!("{name}: {err}")),
        }
    }

    println!("{}/{} checks passed", t.checks - t.failures, t.checks);
    Ok(if t.failures > 0 { 1 } else { 0 })
}

// ── The black-box intrusion run ─────────────────────────────────────────────────────────────

/// What a JSON-RPC answer says, reduced to the one word the scenarios judge by: a spec error code,
/// `sealed` for a result envelope, or `unknown:<shape>`.
pub fn answer_code(text: &str) -> String {
    let payload = if text.trim_start().starts_with("event:") || text.trim_start().starts_with("data:") {
        text.lines().filter_map(|l| l.strip_prefix("data:")).map(|l| l.trim()).collect::<Vec<_>>().join("")
    } else {
        text.to_string()
    };
    let Ok(v) = serde_json::from_str::<Value>(&payload) else { return format!("unknown:not-json({})", payload.chars().take(60).collect::<String>()) };
    if let Some(code) = v["error"]["data"]["code"].as_str() {
        return code.into();
    }
    if let Some(code) = v["error"]["code"].as_str() {
        return code.into();
    }
    let texts: Vec<Value> = v["result"]["content"].as_array().map(|a| a.iter().filter_map(|c| c["text"].as_str()).filter_map(|t| serde_json::from_str(t).ok()).collect()).unwrap_or_default();
    for inner in texts {
        if inner.get("protected").is_some() && inner.get("ct").is_some() {
            return "sealed".into();
        }
        if let Some(code) = inner["code"].as_str() {
            return code.into();
        }
        if let Some(code) = inner["error"]["code"].as_str() {
            return code.into();
        }
    }
    if let Some(code) = v["result"]["code"].as_str() {
        return code.into();
    }
    if v["result"]["isError"].as_bool() == Some(true) {
        return "unknown:isError".into();
    }
    format!("unknown:{}", v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(",")).unwrap_or_default())
}

fn post(endpoint: &str, body: &str) -> Res<String> {
    let mut resp = ureq::post(endpoint)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .config()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .send(body)
        .map_err(|e| Fail(format!("{endpoint}: {e}")))?;
    resp.body_mut().read_to_string().map_err(|e| Fail(format!("{endpoint}: {e}")))
}

fn sealed_call(endpoint: &str, wire: &Value, id: u32) -> Res<String> {
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": "sealed_call", "arguments": wire } });
    Ok(answer_code(&post(endpoint, &body.to_string())?))
}

pub fn intrude(against: &str, now: Option<&str>) -> Res<i32> {
    let now = now_or(now)?;
    let endpoint = against.trim_end_matches('/').to_string();
    let card_text = ureq::get(format!("{endpoint}/card.vcf"))
        .call()
        .and_then(|mut r| r.body_mut().read_to_string())
        .map_err(|e| Fail(format!("{endpoint}/card.vcf: {e}")))?;
    let card = match core("card_decode", json!({ "vcard": card_text, "now": instant(now) })) {
        Ok(c) => c,
        Err(e) => {
            println!("the target's card is not a 2.0 card ({}): nothing to aim at", e.0);
            return Ok(2);
        }
    };
    let recipient_leaf = from_b64u(card["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let recipient = parse(&recipient_leaf).map_err(|e| Fail(e.why))?;
    println!("target      {} root {} leaf {}", card["endpoint"].as_str().unwrap_or(""), card["root"].as_str().unwrap_or(""), recipient.public_key.fingerprint());

    // Mallory: her own root, her own host, a leaf for an address of her own.
    let root_m = PrivateKey::generate(Alg::Ed25519).map_err(|e| Fail(e.why))?;
    let host_m = PrivateKey::generate(Alg::Ed25519).map_err(|e| Fail(e.why))?;
    let root_m_der = x509::build_root("Alina Rao", &root_m, now - 3600, &x509::random_serial().map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.why))?;
    let issuer = root_m.public();
    let host_pub = host_m.public();
    let mut spec = LeafSpec { cn: "Alina Rao", root_cn: "Alina Rao", issuer: &issuer, host_key: &host_pub, uris: vec!["https://mallory.example/mcp".into()], dns_name: None, not_before: now - 3600, not_after: now + 365 * 86_400, serial: x509::random_serial().map_err(|e| Fail(e.why))?, ca: false, usage: None, aki: None, extra: Vec::new(), alg_oid: None };
    let leaf_m = x509::build_leaf(&spec, &root_m).map_err(|e| Fail(e.why))?;
    spec.not_before = now - 400 * 86_400;
    spec.not_after = now - 2 * 86_400;
    let leaf_m_expired = x509::build_leaf(&spec, &root_m).map_err(|e| Fail(e.why))?;
    let chain_m = vec![leaf_m.clone(), root_m_der.clone()];
    let ts = now;
    let mut sealed = 0u32;
    let mut seal = |form: Form, chain: &[Vec<u8>], params: Value| -> Res<Value> {
        sealed += 1;
        let wire = envelope::seal_request(SealRequest { recipient: &recipient.public_key, sender: &host_m, form, sender_chain: Some(chain), method: "tools/call".into(), params, msg_id: format!("intrude-{}-{sealed}", now), ts, exp: Some(ts + 600), cty: None, ephemeral_seed: None }).map_err(|e| Fail(e.why))?;
        serde_json::to_value(wire).map_err(|e| Fail(e.to_string()))
    };
    let message = json!({ "name": "send_message", "arguments": { "msg_id": "m", "text": "hello" } });
    let listing = json!({});

    let mut results: Vec<(String, String, bool)> = Vec::new();
    let mut posted = 0u32;
    let mut run = |name: &str, wire: Value, expect: &[&str]| -> Res<()> {
        posted += 1;
        let got = sealed_call(&endpoint, &wire, posted)?;
        let blocked = expect.contains(&got.as_str());
        println!("  {:<10} {name}: {got}", if blocked { "blocked" } else { "REPRODUCES" });
        results.push((name.into(), got, blocked));
        Ok(())
    };

    println!("scenarios (judged by the answer's code only)");
    let small = seal(Form::Leaf, &chain_m, message.clone())?;
    run("a stranger in the small form", small.clone(), &["chain_required"])?;
    run("the same small envelope again (a replay proves nothing)", small, &["chain_required"])?;
    run("a stranger with a chain calling send_message", seal(Form::Chain, &chain_m, message.clone())?, &["envelope_invalid"])?;
    let mut tampered = seal(Form::Chain, &chain_m, message.clone())?;
    tampered["sig"] = json!(b64u(&[0u8; 64]));
    run("a chain envelope with a forged signature", tampered, &["envelope_invalid"])?;
    let mut unknown_kid = seal(Form::Chain, &chain_m, message.clone())?;
    let header: Value = serde_json::from_slice(&from_b64u(unknown_kid["protected"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.to_string()))?;
    let mut h2 = header.clone();
    h2["kid"] = json!(host_pub.fingerprint());
    unknown_kid["protected"] = json!(b64u(pact_identity::canonical::canonical(&h2).as_bytes()));
    run("an envelope sealed to a key the endpoint never held", unknown_kid, &["envelope_invalid"])?;
    let mut with_from = seal(Form::Chain, &chain_m, message.clone())?;
    let mut h3 = header.clone();
    h3["from"] = json!(host_pub.fingerprint());
    with_from["protected"] = json!(b64u(pact_identity::canonical::canonical(&h3).as_bytes()));
    run("a header carrying a member the version does not list", with_from, &["envelope_invalid"])?;
    let mut wrong_suite = seal(Form::Chain, &chain_m, message.clone())?;
    let mut h4 = header.clone();
    h4["suite"] = json!(if header["suite"] == "PACT-SEAL-X25519" { "PACT-SEAL-P256" } else { "PACT-SEAL-X25519" });
    wrong_suite["protected"] = json!(b64u(pact_identity::canonical::canonical(&h4).as_bytes()));
    run("a suite that is not the one the recipient key takes", wrong_suite, &["envelope_invalid"])?;
    run("an expired leaf in the chain", seal(Form::Chain, &[leaf_m_expired.clone(), root_m_der.clone()], message.clone())?, &["envelope_invalid"])?;
    run("a chain of one certificate", seal(Form::Chain, std::slice::from_ref(&leaf_m), message.clone())?, &["envelope_invalid"])?;
    run("a sealed tools/list from a stranger (no card to bind)", seal(Form::Chain, &chain_m, listing)?, &["envelope_invalid"])?;
    let stale = envelope::seal_request(SealRequest { recipient: &recipient.public_key, sender: &host_m, form: Form::Chain, sender_chain: Some(&chain_m), method: "tools/call".into(), params: message.clone(), msg_id: "intrude-stale".into(), ts: ts - 3600, exp: Some(ts - 3000), cty: None, ephemeral_seed: None }).map_err(|e| Fail(e.why))?;
    run("an envelope an hour old", serde_json::to_value(stale)?, &["envelope_invalid"])?;

    let bad = results.iter().filter(|(_, _, ok)| !ok).count();
    println!("{} scenarios: {} blocked, {} reproduce", results.len(), results.len() - bad, bad);
    Ok(if bad > 0 { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_reduce_to_one_word() {
        assert_eq!(answer_code(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"code":"envelope_invalid"}}}"#), "envelope_invalid");
        assert_eq!(answer_code(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"chain_required\"}"}]}}"#), "chain_required");
        assert_eq!(answer_code(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"protected\":\"a\",\"enc\":\"b\",\"ct\":\"c\",\"sig\":\"d\"}"}]}}"#), "sealed");
        assert_eq!(answer_code("event: message\ndata: {\"result\":{\"code\":\"certificate_renewed\"}}\n\n"), "certificate_renewed");
        assert!(answer_code("<html>").starts_with("unknown:"));
    }

    #[test]
    fn the_generator_agrees_with_the_core_tests() {
        let c = cast().unwrap();
        let certs = certificates(&c).unwrap();
        assert_eq!(certs.len(), 7);
        for (name, der, _) in &certs {
            let parsed = parse(der).unwrap();
            assert_eq!(parsed.kind(), if name.starts_with("root") { "root" } else { "leaf" });
        }
    }
}
