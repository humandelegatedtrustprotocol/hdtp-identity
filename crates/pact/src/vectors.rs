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
        (
            "root_a",
            x509::build_root("Alina Rao", &c.root_a, at("2026-09-01T00:00:00Z"), &serial_of("root_a")).map_err(|e| Fail(e.why))?,
            "Ed25519 root, self-signed, CN \"Alina Rao\", notAfter 9999-12-31".into(),
        ),
        (
            "root_b",
            x509::build_root("Bharat Mehta", &c.root_b, at("2026-09-01T00:00:00Z"), &serial_of("root_b")).map_err(|e| Fail(e.why))?,
            "P-256 root, self-signed, CN \"Bharat Mehta\"".into(),
        ),
        (
            "leaf_a",
            leaf(
                "Alina Rao",
                &c.root_a,
                &a("leaf_a"),
                ENDPOINT_A,
                Some("agent.alina.example"),
                "2026-09-01T00:00:00Z",
                "2027-09-01T00:00:00Z",
                "leaf_a",
            )?,
            format!("Ed25519 leaf under root_a for {ENDPOINT_A}, 2026-09-01 to 2027-09-01, with a dNSName beside the URI"),
        ),
        (
            "leaf_b",
            leaf("Bharat Mehta", &c.root_b, &a("leaf_b"), ENDPOINT_B, None, "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z", "leaf_b")?,
            format!("P-256 leaf under root_b for {ENDPOINT_B}, 2026-09-01 to 2027-09-01, keyUsage digitalSignature+keyAgreement"),
        ),
        (
            "leaf_a_expired",
            leaf("Alina Rao", &c.root_a, &a("leaf_a"), ENDPOINT_A, None, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", "leaf_a_expired")?,
            "leaf_a's key and endpoint, 2025-06-01 to 2026-06-01: expired at NOW".into(),
        ),
        (
            "leaf_a_long",
            leaf("Alina Rao", &c.root_a, &a("leaf_a"), ENDPOINT_A, None, "2026-09-01T00:00:00Z", "2027-10-10T00:00:00Z", "leaf_a_long")?,
            "leaf_a's key and endpoint, 2026-09-01 to 2027-10-10: 404 days".into(),
        ),
        (
            "leaf_a_next",
            leaf(
                "Alina Rao",
                &c.root_a,
                &a("leaf_a_next"),
                ENDPOINT_A,
                None,
                "2027-08-02T00:00:00Z",
                "2028-08-01T00:00:00Z",
                "leaf_a_next",
            )?,
            "a fresh key for the same endpoint, 2027-08-02 to 2028-08-01: the renewal that supersedes leaf_a".into(),
        ),
    ])
}

fn chain_case(
    name: &str,
    chain: &[&str],
    expected_root: Option<String>,
    expected_endpoint: Option<&str>,
    expect: &str,
    rule: Option<u8>,
) -> Value {
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
        let pt = hpke::open(
            suite,
            recipient,
            envelope::INFO_V2,
            &from_b64u(&wire.protected).map_err(|e| Fail(e.why))?,
            &from_b64u(&wire.enc).map_err(|e| Fail(e.why))?,
            &from_b64u(&wire.ct).map_err(|e| Fail(e.why))?,
        )
        .map_err(|e| Fail(e.why))?;
        Ok(
            json!({ "name": name, "form": form, "suite": suite.id(), "sender_chain": sender_chain, "recipient_chain": recipient_chain, "plaintext_hex": hex(&pt), "protected": wire.protected, "enc": wire.enc, "ct": wire.ct, "sig": wire.sig }),
        )
    };
    let envelopes = vec![
        envelope("alina-to-bharat", "leaf_a", &["leaf_a", "root_a"], &["leaf_b", "root_b"], "vec-v2-alina-to-bharat", "chain")?,
        envelope("bharat-to-alina", "leaf_b", &["leaf_b", "root_b"], &["leaf_a", "root_a"], "vec-v2-bharat-to-alina", "chain")?,
        envelope(
            "alina-to-bharat-by-reference",
            "leaf_a",
            &["leaf_a", "root_a"],
            &["leaf_b", "root_b"],
            "vec-v2-alina-to-bharat-ref",
            "leaf",
        )?,
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
    eprintln!(
        "{} certificates, {} chain cases, {} envelopes",
        certs.len(),
        doc["chain_cases"].as_array().map_or(0, |a| a.len()),
        envelopes.len()
    );
    Ok(0)
}

/// The JSON blocks of a document's Appendix B.
fn appendix_b(spec: &str) -> Res<Vec<Value>> {
    let start = spec.find("## Appendix B").ok_or_else(|| Fail("no Appendix B in the document".into()))?;
    let end = spec[start..].find("*End of PACT").map(|i| start + i).unwrap_or(spec.len());
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
    let v2: Value = match (spec, file) {
        (Some(s), _) => {
            let text = String::from_utf8(read_input(s)?).map_err(|_| Fail("the document is not UTF-8".into()))?;
            let mut blocks = appendix_b(&text)?;
            if blocks.is_empty() {
                return fail("Appendix B has no vector blocks");
            }
            blocks.remove(0)
        }
        (None, Some(f)) => serde_json::from_slice(&read_input(f)?).map_err(|e| Fail(format!("{f}: {e}")))?,
        (None, None) => {
            let candidates = [std::env::var("PACT_SPEC").unwrap_or_default(), "pact-protocol/SPEC.md".into(), "SPEC.md".into()];
            match candidates.iter().find(|p| !p.is_empty() && std::path::Path::new(p).exists()) {
                Some(p) => return check(Some(p), None),
                None => return fail("give --spec SPEC.md or --file vectors.json"),
            }
        }
    };
    // EVERY section, or this proves nothing. Each loop below reads its section with
    // `unwrap_or_default()` and records a failure only for an item that is PRESENT, so deleting
    // `chain_cases` from Appendix B left the checker printing a smaller `N/N checks passed` and
    // exiting 0 — with SPEC 14.2's twelve cases no longer proven and nothing in the tree noticing.
    // `{}` passed too, as `0/0`. The names are asserted rather than counted, so the guard cannot
    // itself go stale as the suite grows.
    for section in ["certificates", "chain_cases", "newest_leaf_cases", "certificate_renewed_cases", "envelopes"] {
        if v2.get(section).is_none() {
            return fail(format!("the document has no `{section}`: a vector suite missing a section proves less than it says"));
        }
    }

    let mut t = Tally { checks: 0, failures: 0 };

    let der: BTreeMap<String, Vec<u8>> = v2["certificates"]
        .as_object()
        .map(|o| o.iter().filter_map(|(k, c)| from_hex(c["der_hex"].as_str()?).ok().map(|d| (k.clone(), d))).collect())
        .unwrap_or_default();
    let get = |n: &str| der.get(n).cloned().unwrap_or_default();

    println!("certificates rebuild from their seeds");
    let c = cast()?;
    let mine: BTreeMap<&str, Vec<u8>> = certificates(&c)?.into_iter().map(|(n, d, _)| (n, d)).collect();
    for (name, bytes) in &der {
        // A certificate the appendix marks `refused` exists to be refused (SPEC 14.1): it must not
        // come out of parse and the profile check clean. It is not one the generator rebuilds, and
        // it is not "in the profile as a leaf" — asserting either of those about it is the mistake
        // this branch is here to avoid.
        if v2["certificates"][name.as_str()]["refused"].as_bool() == Some(true) {
            let why = match parse(bytes) {
                Ok(cert) => x509::profile_error(&cert, "leaf"),
                Err(e) => Some(e.why),
            };
            t.ok(why.is_some(), format!("{name}: marked refused, and parse + profile let it through"));
            continue;
        }
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
                        t.ok(
                            same_tbs && signed && (cert.public_key.alg() == Alg::P256 || rebuilt == bytes),
                            format!("{name}: rebuilt from the labelled seeds"),
                        );
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
        t.ok(
            parsed.as_ref().map(|p| p.public().spki().to_vec()) == mine_spki && mine_spki.is_some(),
            format!("{name}: leaf key is the seed's"),
        );
    }

    println!("chain cases (§14.2)");
    for case in v2["chain_cases"].as_array().cloned().unwrap_or_default() {
        let name = case["name"].as_str().unwrap_or("?");
        let chain: Vec<Vec<u8>> =
            case["chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(get).collect()).unwrap_or_default();
        let now = case["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(0);
        let r = validate_chain(&chain, now, case["expected_root"].as_str(), case["expected_endpoint"].as_str());
        let want = case["expect"].as_str().unwrap_or("");
        match &r {
            ChainResult::Ok(_) => t.ok(want == "accept", format!("{name}: expected {want}, got accept")),
            ChainResult::Refused { rule, reason } => t.ok(
                want == "refuse" && Some(*rule as u64) == case["rule"].as_u64(),
                format!("{name}: expected {want} rule {}, got rule {rule} ({reason})", case["rule"]),
            ),
        }
        println!(
            "  {name}: {}",
            match r {
                ChainResult::Ok(_) => "accepted".to_string(),
                ChainResult::Refused { rule, .. } => format!("refused by rule {rule}"),
            }
        );
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
            let recipient = PrivateKey::from_pkcs8(&from_hex(v2["leaf_keys_pkcs8_hex"][rn].as_str().unwrap_or("")).map_err(|e| e.why)?)
                .map_err(|e| e.why)?;
            let aad = from_b64u(e["protected"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let enc = from_b64u(e["enc"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let ct = from_b64u(e["ct"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let sig = from_b64u(e["sig"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let header: Value = serde_json::from_slice(&aad).map_err(|e| e.to_string())?;
            let mut members: Vec<&str> = header.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
            members.sort_unstable();
            t.ok(members.join(",") == envelope::HEADER_MEMBERS, format!("{name}: header members"));
            let suite = suite_for(&recipient_leaf.public_key);
            t.ok(
                header["v"] == 2 && header["suite"] == e["suite"] && Suite::parse(e["suite"].as_str().unwrap_or("")) == Some(suite),
                format!("{name}: version and suite"),
            );
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
                let chain: Vec<Vec<u8>> =
                    body["chain"].as_array().map(|a| a.iter().filter_map(|x| from_b64u(x.as_str()?).ok()).collect()).unwrap_or_default();
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
            let sender = PrivateKey::from_pkcs8(&from_hex(v2["leaf_keys_pkcs8_hex"][sn].as_str().unwrap_or("")).map_err(|e| e.why)?)
                .map_err(|e| e.why)?;
            let chain: Vec<Vec<u8>> =
                e["sender_chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(get).collect()).unwrap_or_default();
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
            t.ok(
                wire.protected == e["protected"] && wire.enc == e["enc"] && wire.ct == e["ct"],
                format!("{name}: re-sealed from the seed, enc and ct reproduce"),
            );
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
/// The JSON-RPC body of an answer, whether it came as JSON or as an event stream's `data:` lines.
fn rpc_body(text: &str) -> std::result::Result<Value, String> {
    let payload = if text.trim_start().starts_with("event:") || text.trim_start().starts_with("data:") {
        text.lines().filter_map(|l| l.strip_prefix("data:")).map(|l| l.trim()).collect::<Vec<_>>().join("")
    } else {
        text.to_string()
    };
    serde_json::from_str::<Value>(&payload).map_err(|_| payload.chars().take(60).collect::<String>())
}

/// Every content item of a tool answer that is itself JSON.
fn tool_texts(v: &Value) -> Vec<Value> {
    v["result"]["content"]
        .as_array()
        .map(|a| a.iter().filter_map(|c| c["text"].as_str()).filter_map(|t| serde_json::from_str(t).ok()).collect())
        .unwrap_or_default()
}

/// What the CONTROL has to show. `answer_code` says `sealed` for anything SHAPED like an envelope —
/// four non-empty strings — which is the right price for twenty-seven scenarios where a false
/// "sealed" costs nothing. For the one call that must get THROUGH it is no evidence at all: a
/// receiver, or a carrier in front of it, answering `{"protected":"a","enc":"b","ct":"c","sig":"d"}`
/// scored the control as passed, and the driver was holding the key that would have said otherwise.
///
/// So the control OPENS what it is answered with, as any caller would (§13.2): sealed to Mallory's
/// leaf key, a result, for THIS call, inside the window, signed by a leaf that chains to the
/// target's root at the target's address — and carrying a result, not a sealed refusal.
pub fn control_opened(
    text: &str,
    my_key: &PrivateKey,
    msg_id: &str,
    now: i64,
    root: &str,
    endpoint: &str,
) -> std::result::Result<(), String> {
    let v = rpc_body(text).map_err(|s| format!("the answer is not JSON ({s})"))?;
    let Some(wire) = tool_texts(&v).into_iter().find_map(|inner| serde_json::from_value::<envelope::Wire>(inner).ok()) else {
        return Err("the answer carries no envelope".into());
    };
    let opened = envelope::open_result(envelope::OpenResultArgs {
        envelope: &wire,
        my_key,
        msg_id,
        now,
        pins: &[],
        expected_root: Some(root),
        expected_endpoint: Some(endpoint),
    })
    .map_err(|e| format!("{}: {}", e.code, e.why))?;
    match opened.get("error") {
        Some(e) => Err(format!("it opens, and what is inside is a refusal: {e}")),
        None => Ok(()),
    }
}

pub fn answer_code(text: &str) -> String {
    let v = match rpc_body(text) {
        Ok(v) => v,
        Err(start) => return format!("unknown:not-json({start})"),
    };
    if let Some(code) = v["error"]["data"]["code"].as_str() {
        return code.into();
    }
    if let Some(code) = v["error"]["code"].as_str() {
        return code.into();
    }
    for inner in tool_texts(&v) {
        // All FOUR members, each a non-empty string. This asked only whether `protected` and `ct`
        // existed, so `{"protected":"","ct":""}` scored the CONTROL as passed -- and the control is
        // the one scenario whose whole job is to prove a well-formed call gets through.
        let full = ["protected", "enc", "ct", "sig"].iter().all(|k| inner.get(*k).and_then(|v| v.as_str()).is_some_and(|v| !v.is_empty()));
        if full {
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

/// How the target is dialled. `--allow-insecure` means BOTH things a node on your own machine
/// needs: the address guard stands aside, and so does WebPKI.
///
/// It used to mean only the first. A node in direct mode serves TLS under its own chain — a root
/// no public authority signed — so the flag that promised "a node on your own machine" got past
/// the guard and stopped at `invalid peer certificate: UnknownIssuer`, having posted nothing. On
/// 2026-09-18 nobody noticed, because the rig this was aimed at sat behind Cloudflare, whose
/// certificates WebPKI does accept.
///
/// **With the card from a FILE, what the battery measures does not rest on the transport**: every
/// envelope is sealed to the key in that card, which no carrier can open or answer for. Without
/// `--card` the sentence is false, and that is why `--card` is now required alongside this flag:
/// the card was fetched over the very channel the flag stopped authenticating, so a carrier could
/// hand over its own card, hold the key all 28 envelopes were sealed to, answer `envelope_invalid`
/// 27 times and a stub once, and the tool printed `28 blocked, 0 reproduce` and exited 0. A
/// fabricated clean security report is worse than a crash.
fn tls(insecure: bool) -> ureq::tls::TlsConfig {
    ureq::tls::TlsConfig::builder().disable_verification(insecure).build()
}

fn post(endpoint: &str, body: &str, session: Option<&str>, insecure: bool) -> Res<(String, Option<String>, u16)> {
    let mut req = ureq::post(endpoint).header("content-type", "application/json").header("accept", "application/json, text/event-stream");
    if let Some(id) = session {
        req = req.header("mcp-session-id", id);
    }
    let mut resp = req
        .config()
        .tls_config(tls(insecure))
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .send(body)
        .map_err(|e| Fail(format!("{endpoint}: {e}")))?;
    let status = resp.status().as_u16();
    let given = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let text = resp.body_mut().read_to_string().map_err(|e| Fail(format!("{endpoint}: {e}")))?;
    Ok((text, given, status))
}

/// The MCP handshake, before any scenario.
///
/// Without it this whole battery measured nothing. A receiver that keeps sessions answers
/// `tools/call` with `method "tools/call" is invalid during session initialization` — a JSON-RPC
/// error whose code is the NUMBER 0, which `answer_code` reads as `unknown:jsonrpc,id,error`, and
/// which every scenario then reports as a REPRODUCTION. Eight scenarios said the reference node was
/// vulnerable to eight things it had never been asked about. A security instrument that answers
/// "vulnerable" when it never reached the code under test is worse than one that refuses to run.
///
/// A stateless receiver hands back no session id, and then this changes nothing: the scenarios post
/// exactly as they did before.
fn initialize(endpoint: &str, insecure: bool) -> Res<Option<String>> {
    let body = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": { "name": "pact vectors intrude", "version": env!("CARGO_PKG_VERSION") },
    }});
    let (text, session, _) = post(endpoint, &body.to_string(), None, insecure)?;
    if session.is_none() && !text.contains("\"result\"") {
        return fail(format!(
            "{endpoint}: initialize was refused, so no scenario could be posted: {}",
            text.chars().take(200).collect::<String>()
        ));
    }
    if session.is_some() {
        // The notification the protocol requires before any call; a receiver that gates on it
        // answers everything else with the same session error the scenarios used to collect.
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let _ = post(endpoint, &note.to_string(), session.as_deref(), insecure)?;
    }
    Ok(session)
}

fn sealed_call(endpoint: &str, wire: &Value, id: u32, session: Option<&str>, insecure: bool) -> Res<(String, String)> {
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": "sealed_call", "arguments": wire } });
    let (text, _, status) = post(endpoint, &body.to_string(), session, insecure)?;
    let code = answer_code(&text);
    // A door that refuses before PACT sees anything is `http_<n>`, as the JS driver has always
    // reported it. This dropped the status, so an HTTP 403 at the edge arrived as
    // `unknown:not-json(...)` -- classified UNREACHED correctly, but unable to say why, and the
    // `http_` arm of the verdict test below was dead code in this port.
    if code.starts_with("unknown:not-json") && status >= 400 {
        return Ok((format!("http_{status}"), text));
    }
    Ok((code, text))
}

pub fn intrude(against: &str, card_file: Option<&str>, allow_insecure: bool, now: Option<&str>) -> Res<i32> {
    let now = now_or(now)?;
    let endpoint = against.trim_end_matches('/').to_string();
    // This command dials what it is given and posts sealed envelopes there. The same guard a
    // receiver applies to a card's endpoint (§3, §14.2) applies to the target, so `--against` can
    // never be talked into reaching a loopback or a metadata address; a node on your own machine
    // is the one case worth an explicit flag.
    // One guard, and its words are the answer. The core's `address_guard` applies the normal form
    // of §14.1 as its own first rule, so asking `is_normal_https` first only took the refusal away
    // from the guard that owns it — and gave two different sentences for one rule, which is how a
    // guard and its message drift apart.
    // The card must come from DISK when verification is off, or the run's verdict is the carrier's.
    // See `tls` above: this is the whole of the flag's safety argument.
    if allow_insecure && card_file.is_none() {
        return fail(format!(
            "{endpoint}: --allow-insecure turns off certificate verification, so the card must come from a file: pass --card <file>. \
             Fetched over an unverified channel the card is whatever answered, every envelope is sealed to ITS key, and a clean \
             `28 blocked` would say nothing about the target."
        ));
    }
    if !allow_insecure {
        let guard = core("address_guard", json!({ "endpoint": &endpoint, "guest": false }))?;
        if guard["ok"].as_bool() != Some(true) {
            return fail(format!(
                "{endpoint}: {} (pass --allow-insecure for a node on your own machine)",
                guard["why"].as_str().unwrap_or("the address guard refuses this endpoint")
            ));
        }
    }
    // The card comes from a file when one is given, and from `<endpoint>/card.vcf` otherwise.
    // That URL is NOT something a target must serve: SPEC §9 puts the card on the invite landing
    // page, and the reference node serves exactly three public routes — `/a/{slug}/mcp`,
    // `/i/{token}` and `/mcp`. Aimed at one with no `--card`, this command used to stop at a 404
    // with nothing to say about what to do instead, which is how the battery came to be something
    // only the hosted platform could be measured with.
    let card_text = match card_file {
        Some(path) => std::fs::read_to_string(path).map_err(|e| Fail(format!("{path}: {e}")))?,
        None => ureq::get(format!("{endpoint}/card.vcf"))
            .config()
            .tls_config(tls(allow_insecure))
            .build()
            .call()
            .and_then(|mut r| r.body_mut().read_to_string())
            .map_err(|e| Fail(format!("{endpoint}/card.vcf: {e} — a host need not serve a card at a URL of its own (SPEC §9 puts it on the invite landing page); save the target's card and pass --card <file>")))?,
    };
    let card = match core("card_decode", json!({ "vcard": card_text, "now": instant(now) })) {
        Ok(c) => c,
        Err(e) => {
            println!("the target's card is not a 2.0 card ({}): nothing to aim at", e.0);
            return Ok(2);
        }
    };
    let recipient_leaf = from_b64u(card["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let recipient = parse(&recipient_leaf).map_err(|e| Fail(e.why))?;
    println!(
        "target      {} root {} leaf {}",
        card["endpoint"].as_str().unwrap_or(""),
        card["root"].as_str().unwrap_or(""),
        recipient.public_key.fingerprint()
    );

    // Mallory: her own root, her own host, a leaf for an address of her own.
    let root_m = PrivateKey::generate(Alg::Ed25519).map_err(|e| Fail(e.why))?;
    let host_m = PrivateKey::generate(Alg::Ed25519).map_err(|e| Fail(e.why))?;
    let root_m_der =
        x509::build_root("Alina Rao", &root_m, now - 3600, &x509::random_serial().map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.why))?;
    let issuer = root_m.public();
    let host_pub = host_m.public();
    let mut spec = LeafSpec {
        cn: "Alina Rao",
        root_cn: "Alina Rao",
        issuer: &issuer,
        host_key: &host_pub,
        uris: vec!["https://mallory.example/mcp".into()],
        dns_name: None,
        not_before: now - 3600,
        not_after: now + 365 * 86_400,
        serial: x509::random_serial().map_err(|e| Fail(e.why))?,
        ca: false,
        usage: None,
        aki: None,
        extra: Vec::new(),
        alg_oid: None,
    };
    let leaf_m = x509::build_leaf(&spec, &root_m).map_err(|e| Fail(e.why))?;
    spec.not_before = now - 400 * 86_400;
    spec.not_after = now - 2 * 86_400;
    let leaf_m_expired = x509::build_leaf(&spec, &root_m).map_err(|e| Fail(e.why))?;
    let chain_m = vec![leaf_m.clone(), root_m_der.clone()];
    let ts = now;
    let mut sealed = 0u32;
    let mut seal = |form: Form, chain: &[Vec<u8>], params: Value| -> Res<Value> {
        sealed += 1;
        let wire = envelope::seal_request(SealRequest {
            recipient: &recipient.public_key,
            sender: &host_m,
            form,
            sender_chain: Some(chain),
            method: "tools/call".into(),
            params,
            msg_id: format!("intrude-{}-{sealed}", now),
            ts,
            exp: Some(ts + 600),
            cty: None,
            ephemeral_seed: None,
        })
        .map_err(|e| Fail(e.why))?;
        serde_json::to_value(wire).map_err(|e| Fail(e.to_string()))
    };
    let message = json!({ "name": "send_message", "arguments": { "msg_id": "m", "text": "hello" } });

    // The handshake first: a receiver that keeps MCP sessions refuses every `tools/call` before it,
    // and the refusal looks nothing like a security answer.
    let session = initialize(&endpoint, allow_insecure)?;
    match session.as_deref() {
        Some(id) => println!("session     {id}"),
        None => println!("session     none (the receiver is stateless)"),
    }

    // An answer that is no PACT answer at all — a transport error, a body that is not JSON — means
    // the scenario never reached the layer it tests. That is a failure of the RUN, and calling it
    // an intrusion that reproduces is how the JS driver once reported 27 of 27 against the
    // reference node, every one an `http_400` from a missing handshake.
    let mut results: Vec<(String, String, &'static str)> = Vec::new();
    let mut posted = 0u32;
    let mut run = |name: &str, wire: Value, expect: &str| -> Res<String> {
        posted += 1;
        let (got, raw) = sealed_call(&endpoint, &wire, posted, session.as_deref(), allow_insecure)?;
        let verdict = if got == expect {
            "blocked"
        } else if got.starts_with("unknown") || got.starts_with("http_") {
            "UNREACHED"
        } else if expect == "sealed" {
            // The control is the one scenario that must get THROUGH, so its failure is the opposite
            // of an intrusion: a receiver refusing everything -- exactly what the control exists to
            // catch -- was reported as `REPRODUCES`, i.e. "something got in", while what happened
            // was that the legitimate call was blocked.
            "CONTROL REFUSED"
        } else {
            "REPRODUCES"
        };
        println!("  {verdict:<10} {name}: {got}");
        results.push((name.into(), got, verdict));
        Ok(raw)
    };

    // Everything an honest sealer will not build, hand-rolled — and SEALED UNDER what it forges.
    //
    // `seal_request` refuses a chain that is not exactly a leaf and a root, a version it does not
    // speak, a header member it does not know: right for a sender, useless for an intruder. So this
    // assembles the envelope from the same public parts `seal_body` uses — the canonical header as
    // AAD, one HPKE seal to the recipient's leaf key, a signature over protected||enc||ct — with
    // `patch` laid over the honest header BEFORE any of it is computed.
    //
    // Rewriting `protected` after sealing proves nothing: the AAD stops matching, and the envelope
    // is refused for that alone whatever the header says. Three scenarios here did exactly that
    // until 2026-09-20 (an unknown `kid`, an unlisted member, the wrong suite) and so could not
    // fail: a receiver that never checked the suite would still have answered `envelope_invalid`,
    // for the broken AAD, and been scored as blocking it.
    const CALL: &str = "application/pact-call+json";
    const INVALID: &str = "envelope_invalid";
    let mut forged = 0u32;
    let mut forge = |chain: &[Vec<u8>], patch: Value, method: &str, params: Value| -> Res<Value> {
        forged += 1;
        let suite = suite_for(&recipient.public_key);
        let mut header = json!({ "v": 2, "suite": suite.id(), "kid": recipient.public_key.fingerprint(),
            "msg_id": format!("intrude-{now}-forge{forged}"), "ts": ts, "exp": ts + 600, "cty": CALL });
        if let (Some(h), Some(p)) = (header.as_object_mut(), patch.as_object()) {
            for (k, v) in p {
                h.insert(k.clone(), v.clone());
            }
        }
        let aad = pact_identity::canonical::canonical(&header).into_bytes();
        let chain_b64: Vec<Value> = chain.iter().map(|c| json!(b64u(c))).collect();
        let body = json!({ "method": method, "params": params, "chain": chain_b64 });
        let plaintext = serde_json::to_vec(&body).map_err(|e| Fail(e.to_string()))?;
        let (enc, ct) = hpke::seal(suite, &recipient.public_key, envelope::INFO_V2, &aad, &plaintext, None).map_err(|e| Fail(e.why))?;
        let mut signed = aad.clone();
        signed.extend_from_slice(&enc);
        signed.extend_from_slice(&ct);
        let sig = host_m.sign(&signed);
        Ok(json!({ "protected": b64u(&aad), "enc": b64u(&enc), "ct": b64u(&ct), "sig": b64u(&sig) }))
    };

    // The scenarios, in an order that matters; their names are js/live.mjs's too, and
    // js/live.test.mjs holds the two lists to each other.
    println!("scenarios (judged by the answer's code only)");
    let small = seal(Form::Leaf, &chain_m, message.clone())?;
    run("a stranger in the small form, naming a leaf nobody holds", small.clone(), "chain_required")?;
    run("the same small-form envelope replayed", small, "chain_required")?;
    run("a stranger in the full form calling a contact tool", seal(Form::Chain, &chain_m, message.clone())?, INVALID)?;
    let mut tampered = seal(Form::Chain, &chain_m, message.clone())?;
    tampered["sig"] = json!(b64u(&[0u8; 64]));
    run("a full-form envelope whose signature was tampered", tampered, INVALID)?;

    // Headers no honest sealer writes.
    let unknown_kid = forge(&chain_m, json!({ "kid": host_pub.fingerprint() }), "tools/call", message.clone())?;
    run("an envelope sealed to a key this endpoint never held", unknown_kid, INVALID)?;
    let with_from = forge(&chain_m, json!({ "from": host_pub.fingerprint() }), "tools/call", message.clone())?;
    run("a header carrying a member the protocol does not list", with_from, INVALID)?;
    let other = if suite_for(&recipient.public_key).id() == "PACT-SEAL-X25519" { "PACT-SEAL-P256" } else { "PACT-SEAL-X25519" };
    let wrong_suite = forge(&chain_m, json!({ "suite": other }), "tools/call", message.clone())?;
    run("a suite that is not the one the recipient key takes", wrong_suite, INVALID)?;

    // §14.2 takes exactly two certificates, in one order, the second self-signed. Every
    // shape below is a path a general X.509 verifier would happily walk.
    run("a chain of one certificate", forge(std::slice::from_ref(&leaf_m), json!({}), "tools/call", message.clone())?, INVALID)?;
    run("an empty chain", forge(&[], json!({}), "tools/call", message.clone())?, INVALID)?;
    let three = [leaf_m.clone(), root_m_der.clone(), root_m_der.clone()];
    run("a chain of three certificates", forge(&three, json!({}), "tools/call", message.clone())?, INVALID)?;
    run("the chain in reverse order", forge(&[root_m_der.clone(), leaf_m.clone()], json!({}), "tools/call", message.clone())?, INVALID)?;
    let root_twice = [root_m_der.clone(), root_m_der.clone()];
    run("the root presented as its own leaf", forge(&root_twice, json!({}), "tools/call", message.clone())?, INVALID)?;
    run(
        "the leaf presented as its own root",
        forge(&[leaf_m.clone(), leaf_m.clone()], json!({}), "tools/call", message.clone())?,
        INVALID,
    )?;
    // A CA-signed intermediate in the root slot is WebPKI asking to be let in: accept it and
    // any public CA could mint an identity. Rule 2 wants the root self-signed, so there is no
    // hierarchy to climb and no authority above the person.
    let intermediate = {
        let mut ispec = LeafSpec {
            cn: "Alina Rao",
            root_cn: "Alina Rao",
            issuer: &issuer,
            host_key: &issuer,
            uris: vec!["https://mallory.example/mcp".into()],
            dns_name: None,
            not_before: now - 3600,
            not_after: now + 365 * 86_400,
            serial: x509::random_serial().map_err(|e| Fail(e.why))?,
            ca: true,
            usage: Some(vec![5]),
            aki: None,
            extra: Vec::new(),
            alg_oid: None,
        };
        ispec.ca = true;
        x509::build_leaf(&ispec, &root_m).map_err(|e| Fail(e.why))?
    };
    run("an intermediate posing as the root", forge(&[leaf_m.clone(), intermediate], json!({}), "tools/call", message.clone())?, INVALID)?;

    // Time, WELL outside the edges the receiver holds. Rule 4 checks the leaf's dates and only
    // the leaf's: a leaf not valid yet is refused exactly as an expired one is.
    let leaf_m_future = {
        let mut fspec = LeafSpec {
            cn: "Alina Rao",
            root_cn: "Alina Rao",
            issuer: &issuer,
            host_key: &host_pub,
            uris: vec!["https://mallory.example/mcp".into()],
            dns_name: None,
            not_before: now + 3600,
            not_after: now + 300 * 86_400,
            serial: x509::random_serial().map_err(|e| Fail(e.why))?,
            ca: false,
            usage: None,
            aki: None,
            extra: Vec::new(),
            alg_oid: None,
        };
        fspec.not_before = now + 3600;
        x509::build_leaf(&fspec, &root_m).map_err(|e| Fail(e.why))?
    };
    run("a leaf that is not valid yet", seal(Form::Chain, &[leaf_m_future, root_m_der.clone()], message.clone())?, INVALID)?;
    run("an expired leaf", seal(Form::Chain, &[leaf_m_expired.clone(), root_m_der.clone()], message.clone())?, INVALID)?;
    run("an envelope an hour old", forge(&chain_m, json!({ "ts": ts - 3600, "exp": ts - 3000 }), "tools/call", message.clone())?, INVALID)?;
    // §13.3's window is 300 seconds either way, and the EXACT boundary — 300 in, 301 out — is the
    // offline suite's, where there is no transit and one clock. These said 301 until 2026-09-20.
    // Over a network that is a coin toss: an envelope sealed 301 seconds ahead and posted two
    // seconds later is 299 ahead and inside the window, and a receiver that accepts it is right
    // (the JS driver reported exactly that as an intrusion). A live run can honestly claim "well
    // outside the window is refused", so the margin is thirty seconds.
    const WINDOW: i64 = 300;
    const MARGIN: i64 = 30;
    let old = forge(&chain_m, json!({ "ts": ts - WINDOW - MARGIN, "exp": ts + 300 }), "tools/call", message.clone())?;
    run(&format!("an envelope {} seconds old", WINDOW + MARGIN), old, INVALID)?;
    let ahead = forge(&chain_m, json!({ "ts": ts + WINDOW + MARGIN, "exp": ts + 900 }), "tools/call", message.clone())?;
    run(&format!("an envelope {} seconds in the future", WINDOW + MARGIN), ahead, INVALID)?;
    // §13.3 caps a lifetime at thirty days, because `exp` is how long a receiver must remember.
    let forever = forge(&chain_m, json!({ "exp": ts + 365 * 86_400 }), "tools/call", message.clone())?;
    run("an envelope asking to be remembered for a year", forever, INVALID)?;

    // The retired generation, refused by a node that no longer implements it, and a version
    // that does not exist yet.
    run("a v: 1 header, the retired generation", forge(&chain_m, json!({ "v": 1 }), "tools/call", message.clone())?, INVALID)?;
    run(
        "a header claiming a version that does not exist yet",
        forge(&chain_m, json!({ "v": 3 }), "tools/call", message.clone())?,
        INVALID,
    )?;
    // A `ts` of "1757000000" is not the same bytes as one of 1757000000 (§13.1).
    let strings = forge(&chain_m, json!({ "ts": ts.to_string(), "exp": (ts + 600).to_string() }), "tools/call", message.clone())?;
    run("a header whose ts and exp are strings", strings, INVALID)?;
    // Idempotency keyed on an empty string protects nothing (§13.1).
    run("an empty msg_id", forge(&chain_m, json!({ "msg_id": "" }), "tools/call", message.clone())?, INVALID)?;
    // `cty` is what binds direction: a result envelope is never dispatched (§13.2).
    let as_result = forge(&chain_m, json!({ "cty": "application/pact-result+json" }), "tools/call", message.clone())?;
    run("a result envelope dispatched as a request", as_result, INVALID)?;
    // A real `tools/list`. Until 2026-09-20 this scenario sealed a `tools/call` with EMPTY params
    // and was named for a tools/list: refused, as any call with no tool name is, for a reason
    // that had nothing to do with listing.
    run("a sealed tools/list from a stranger", forge(&chain_m, json!({}), "tools/list", json!({}))?, INVALID)?;
    // `sig` covers protected||enc||ct with nothing between them, so a byte moved across the
    // enc/ct boundary leaves the signed bytes identical: what refuses it is `enc` being the
    // suite's own length (§13.1).
    let mut slid = seal(Form::Chain, &chain_m, message.clone())?;
    let mut enc = from_b64u(slid["enc"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let mut ct = from_b64u(slid["ct"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    if let Some(last) = enc.pop() {
        ct.insert(0, last);
    }
    slid["enc"] = json!(b64u(&enc));
    slid["ct"] = json!(b64u(&ct));
    run("a byte moved from the encapsulated key into the ciphertext", slid, INVALID)?;

    // THE CONTROL, and it is last on purpose. Twenty-seven refusals are also what a receiver that
    // refuses EVERYTHING gives, and until 2026-09-20 this battery had no scenario such a receiver
    // would fail. This is the one well-formed call from a stranger that must get through the same
    // door: sealed, by the target, to her key. It leaves a pending request behind — after it
    // Mallory is no stranger — which is why nothing may come after it, and why her keys are new
    // every run.
    let card_m = pact_identity::card::encode("Mallory", &leaf_m, Some("required"), &[]);
    let request = json!({ "name": "request_contact", "arguments": { "card": card_m, "note": "hi" } });
    let control_wire = seal(Form::Chain, &chain_m, request)?;
    let control_id = from_b64u(control_wire["protected"].as_str().unwrap_or(""))
        .ok()
        .and_then(|h| serde_json::from_slice::<Value>(&h).ok())
        .and_then(|h| h["msg_id"].as_str().map(String::from))
        .unwrap_or_default();
    let raw = run("CONTROL: a stranger asking for contact with a card that is her leaf", control_wire, "sealed")?;
    // …and an answer that LOOKS sealed is opened, with the key this driver has been holding all
    // along. Only a verdict of `blocked` (the expected `sealed`) is worth opening: a refusal and an
    // unreached run have said what they are already.
    if results.last().is_some_and(|(_, _, v)| *v == "blocked") {
        let (root, at) = (card["root"].as_str().unwrap_or(""), card["endpoint"].as_str().unwrap_or(""));
        if let Err(why) = control_opened(&raw, &host_m, &control_id, now, root, at) {
            println!("  {:<10} …and what it was answered with does not open: {why}", "");
            if let Some(last) = results.last_mut() {
                last.2 = "CONTROL UNOPENED";
            }
        }
    }

    let reproduce = results.iter().filter(|(_, _, v)| *v == "REPRODUCES").count();
    let unreached = results.iter().filter(|(_, _, v)| *v == "UNREACHED").count();
    let control = results.iter().filter(|(_, _, v)| *v == "CONTROL REFUSED").count();
    let unopened = results.iter().filter(|(_, _, v)| *v == "CONTROL UNOPENED").count();
    println!(
        "{} scenarios: {} blocked, {} reproduce, {} never reached a PACT answer{}{}",
        results.len(),
        results.len() - reproduce - unreached - control - unopened,
        reproduce,
        unreached,
        if control > 0 { ", and the CONTROL was refused: this receiver refuses a legitimate call too" } else { "" },
        if unopened > 0 {
            ", and the CONTROL's answer looked sealed and did not open: nothing here shows a call can get through"
        } else {
            ""
        }
    );
    Ok(if reproduce + unreached + control + unopened > 0 { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_reduce_to_one_word() {
        assert_eq!(
            answer_code(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"code":"envelope_invalid"}}}"#),
            "envelope_invalid"
        );
        assert_eq!(
            answer_code(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"chain_required\"}"}]}}"#),
            "chain_required"
        );
        assert_eq!(
            answer_code(
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"protected\":\"a\",\"enc\":\"b\",\"ct\":\"c\",\"sig\":\"d\"}"}]}}"#
            ),
            "sealed"
        );
        assert_eq!(answer_code("event: message\ndata: {\"result\":{\"code\":\"certificate_renewed\"}}\n\n"), "certificate_renewed");
        assert!(answer_code("<html>").starts_with("unknown:"));
    }

    // The control is the one scenario that must get THROUGH, and it was judged by the look of its
    // answer. The first case below is the very stub `answers_reduce_to_one_word` calls "sealed".
    #[test]
    fn the_control_is_passed_by_an_envelope_that_opens_and_by_nothing_that_only_looks_like_one() {
        const NOW: i64 = 1_789_000_000;
        const AT: &str = "https://target.example/mcp";
        let wrap = |inner: &Value| {
            json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": [{ "type": "text", "text": inner.to_string() }] } }).to_string()
        };

        // The target, and Mallory's host key: the control's call is sealed to the target, and its
        // answer is sealed back to her.
        let (root_t, host_t, host_m) = (
            PrivateKey::generate(Alg::Ed25519).unwrap(),
            PrivateKey::generate(Alg::Ed25519).unwrap(),
            PrivateKey::generate(Alg::Ed25519).unwrap(),
        );
        let root_t_der = x509::build_root("Target", &root_t, NOW - 3600, &x509::serial_of("control/root")).unwrap();
        let (issuer, host_pub) = (root_t.public(), host_t.public());
        let leaf_t = x509::build_leaf(
            &LeafSpec {
                cn: "Target",
                root_cn: "Target",
                issuer: &issuer,
                host_key: &host_pub,
                uris: vec![AT.into()],
                dns_name: None,
                not_before: NOW - 3600,
                not_after: NOW + 86_400,
                serial: x509::serial_of("control/leaf"),
                ca: false,
                usage: None,
                aki: None,
                extra: Vec::new(),
                alg_oid: None,
            },
            &root_t,
        )
        .unwrap();
        let root_fp = issuer.fingerprint();
        let answer = |msg_id: &str, result: Option<Value>, error: Option<Value>, to: &PrivateKey| {
            let wire = envelope::seal_result(envelope::SealResult {
                recipient: &to.public(),
                sender: &host_t,
                form: Form::Chain,
                sender_chain: Some(&[leaf_t.clone(), root_t_der.clone()]),
                result,
                error,
                msg_id: msg_id.into(),
                ts: NOW,
                exp: Some(NOW + 600),
                ephemeral_seed: None,
            })
            .unwrap();
            wrap(&serde_json::to_value(wire).unwrap())
        };

        // What passed before: four non-empty strings.
        let stub = wrap(&json!({ "protected": "a", "enc": "b", "ct": "c", "sig": "d" }));
        assert_eq!(answer_code(&stub), "sealed", "the cheap reading still calls this sealed, which is why the control cannot use it");
        assert!(control_opened(&stub, &host_m, "c1", NOW, &root_fp, AT).is_err());

        // What must pass: a result, for this call, sealed to her, from the target.
        let good = answer("c1", Some(json!({ "status": "pending" })), None, &host_m);
        control_opened(&good, &host_m, "c1", NOW, &root_fp, AT).expect("a real sealed result opens");

        // And each way a REAL envelope can still be the wrong one.
        let refuses = |text: &str, id: &str, root: &str, at: &str, what: &str| {
            assert!(control_opened(text, &host_m, id, NOW, root, at).is_err(), "{what} was accepted as the control's answer");
        };
        refuses(&good, "another-call", &root_fp, AT, "an answer to a different call");
        refuses(&good, "c1", &host_m.public().fingerprint(), AT, "an answer from somebody who is not the target's root");
        refuses(&good, "c1", &root_fp, "https://elsewhere.example/mcp", "an answer from a leaf for another address");
        refuses(
            &answer("c1", Some(json!({ "status": "pending" })), None, &host_t),
            "c1",
            &root_fp,
            AT,
            "an answer sealed to somebody else",
        );
        refuses(&answer("c1", None, Some(json!({ "code": "rate_limited" })), &host_m), "c1", &root_fp, AT, "a sealed REFUSAL");
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
