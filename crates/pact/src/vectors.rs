//! The implementer's proofs: regenerate Appendix B's 2.0 vectors from their labelled seeds, prove a
//! document's vectors natively, and aim the black-box intrusion scenarios at a live endpoint.
//!
//! The generator is here; `check` proves a document and `intrude` is the live run.
use crate::io::{write_output, Fail, Res};
use pact_identity::envelope::{self, Form, SealRequest};
use pact_identity::hpke::{self, suite_for};
use pact_identity::keys::{Alg, PrivateKey, PublicKey};
use pact_identity::time::parse_rfc3339;
use pact_identity::util::{b64u, from_b64u, hex, seed};
use pact_identity::x509::{self, fingerprint_of, parse, serial_of, LeafSpec};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

mod check;
pub(crate) mod corpus;
mod intrude;

pub use check::check;
pub use corpus::corpus;
pub use intrude::intrude;

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
            &recipient_leaf.public_key,
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

/// The live battery as data: every scenario, its order, the code it must be answered with, the one
/// CONTROL and the skew window. js/live.mjs reads the same file; this driver and that one only build
/// the envelope for an id. `battery()` refuses a file whose ids repeat or whose control is not
/// exactly one and last, so a run can never post the control before a scenario that needs a stranger.
const LIVE_SCENARIOS: &str = include_str!("../../../js/live-scenarios.json");

#[cfg(test)]
mod tests {
    use super::*;

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
