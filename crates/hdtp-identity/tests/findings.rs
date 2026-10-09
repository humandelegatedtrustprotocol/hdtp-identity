//! The review findings that reached the pinned core — those of 2026-09-20 (the review-findings plan,
//! C) and, since, P-21 of 2026-09-23 — each held at the boundary a host actually calls. Every test
//! here was RED against the core as it was.

use hdtp_identity::keys::{Alg, PrivateKey};
use hdtp_identity::x509::{self, LeafSpec};
use serde_json::{json, Value};

const E_A: &str = "https://agent.alina.example/mcp";
const NOW: i64 = 1_789_000_000;
const NOW_RFC: &str = "2026-09-10T00:26:40Z";

fn call(name: &str, args: Value) -> Value {
    serde_json::from_str(&hdtp_identity::call(name, &args.to_string())).expect("the boundary answers JSON")
}
fn b64u(b: &[u8]) -> String {
    hdtp_identity::util::b64u(b)
}

struct Cast {
    root: PrivateKey,
    host: PrivateKey,
    root_der: Vec<u8>,
}
fn cast() -> Cast {
    let root = PrivateKey::generate(Alg::Ed25519).unwrap();
    let host = PrivateKey::generate(Alg::Ed25519).unwrap();
    let root_der = x509::build_root("Alina Rao", &root, NOW - 3600, None, &x509::serial_of("findings/root")).unwrap();
    Cast { root, host, root_der }
}
fn leaf(c: &Cast, endpoint: &str, dns: Option<&str>, aki: Option<Vec<u8>>) -> Vec<u8> {
    let (issuer, host_pub) = (c.root.public(), c.host.public());
    x509::build_leaf(
        &LeafSpec {
            cn: "Alina Rao",
            root_cn: "Alina Rao",
            issuer: &issuer,
            host_key: &host_pub,
            uris: vec![endpoint.into()],
            dns_name: dns.map(String::from),
            not_before: NOW - 3600,
            not_after: NOW + 86_400,
            serial: x509::serial_of("findings/leaf"),
            ca: false,
            usage: None,
            aki,
        },
        &c.root,
    )
    .unwrap()
}

// C1 — §14.1: "a key identifier is the 32-byte SHA-256 of the SubjectPublicKeyInfo". The profile held
// the SUBJECT key identifier to that and asked of the AUTHORITY one only that it be there. A card then
// turned whatever it found into the identity shown to the person: `sha256:AQID`, three bytes, which no
// chain can ever satisfy — a contact dead on arrival, under a "fingerprint" that is not one.
#[test]
fn an_authority_key_identifier_is_thirty_two_bytes_or_the_leaf_is_outside_the_profile() {
    let c = cast();
    let short = leaf(&c, E_A, None, Some(vec![1, 2, 3]));
    let parsed = call("parse_certificate", json!({ "der": b64u(&short) }));
    assert_eq!(parsed["profile_error"], "leaf authorityKeyIdentifier is not a key identifier alone", "{parsed}");

    let chain = call("validate_chain", json!({ "chain": [b64u(&short), b64u(&c.root_der)], "now": NOW_RFC }));
    assert_eq!((chain["ok"].as_bool(), chain["rule"].as_i64()), (Some(false), Some(1)), "{chain}");

    let card = hdtp_identity::card::encode("Alina Rao", &short, Some("required"), &[]).expect("a card");
    let intake = call("card_decode", json!({ "vcard": card, "now": NOW_RFC }));
    assert!(intake.get("error").is_some(), "a card was taken in, and would show the person {}: {intake}", intake["root"]);

    // …and the honest one is untouched.
    let good = leaf(&c, E_A, None, None);
    assert_eq!(call("parse_certificate", json!({ "der": b64u(&good) }))["profile_error"], Value::Null);
}

// C2 — an IPv6 literal that EMBEDS an IPv4 address a translator will dial. On a NAT64 network
// `[64:ff9b::7f00:1]` is 127.0.0.1, and for a literal there is nothing to resolve: this predicate is
// the whole guard. The test beside the old one was named "every other spelling of loopback".
#[test]
fn an_ipv6_literal_is_judged_by_the_ipv4_address_inside_it() {
    for (ip, private) in [
        ("64:ff9b::7f00:1", true),       // NAT64 well-known prefix → 127.0.0.1
        ("64:ff9b::a00:1", true),        // → 10.0.0.1
        ("64:ff9b::a9fe:a9fe", true),    // → 169.254.169.254, the metadata address
        ("64:ff9b::808:808", false),     // → 8.8.8.8: a translator reaching a public address is fine
        ("64:ff9b:1::1", true),          // RFC 8215's LOCAL-use NAT64 prefix: never a public address
        ("2002:7f00:1::1", true),        // 6to4 → 127.0.0.1
        ("2002:c0a8:101::1", true),      // 6to4 → 192.168.1.1
        ("2002:808:808::1", false),      // 6to4 → 8.8.8.8
        ("fec0::1", true),               // deprecated site-local
        ("::7f00:1", true),              // IPv4-compatible (deprecated) → 127.0.0.1
        ("2606:4700:4700::1111", false), // an ordinary public address
    ] {
        let r = call("ip_is_private", json!({ "ip": ip }));
        assert_eq!(r["private"].as_bool(), Some(private), "{ip}: {r}");
    }
    for bad in ["https://[64:ff9b::7f00:1]/mcp", "https://[2002:7f00:1::1]/mcp", "https://[64:ff9b::a9fe:a9fe]/mcp"] {
        let r = call("address_guard", json!({ "endpoint": bad, "guest": true }));
        assert_eq!(r["ok"], false, "{bad}: {r}");
    }
}

// C3 — §14.1 lets a leaf carry the dNSName of its URI's host. `host_of` kept the PORT, so on any
// address but :443 the wallet refused the request ("dNSName differs from the URI host") and rule 5
// would have refused the leaf: a dNSName cannot carry a port, so the feature did not exist there.
#[test]
fn a_leaf_on_another_port_may_carry_its_hosts_dns_name() {
    const E: &str = "https://agent.alina.example:8443/mcp";
    assert_eq!(x509::host_of(E), "agent.alina.example");
    assert_eq!(x509::host_of("https://[2606:4700::1]:8443/mcp"), "[2606:4700::1]");
    assert_eq!(x509::host_of(E_A), "agent.alina.example");

    let c = cast();
    let csr = call(
        "csr_new",
        json!({ "cn": "Alina Rao", "host_pkcs8": b64u(&c.host.to_pkcs8()), "endpoint": E, "dns_name": "agent.alina.example" }),
    );
    let checked = call("csr_check", json!({ "der": csr["der"] }));
    assert_eq!(checked["ok"], true, "{checked}");

    let with_dns = leaf(&c, E, Some("agent.alina.example"), None);
    let chain = call("validate_chain", json!({ "chain": [b64u(&with_dns), b64u(&c.root_der)], "now": NOW_RFC, "expected_endpoint": E }));
    assert_eq!(chain["ok"], true, "{chain}");

    // A dNSName for some OTHER host is still refused, on any port.
    let lying = leaf(&c, E, Some("agent.mallory.example"), None);
    let chain = call("validate_chain", json!({ "chain": [b64u(&lying), b64u(&c.root_der)], "now": NOW_RFC }));
    assert_eq!((chain["ok"].as_bool(), chain["rule"].as_i64()), (Some(false), Some(5)), "{chain}");
}

// C4 — a card is lines. A name, a seal policy or an extra line holding a line break writes a property
// of the attacker's choosing, and the decoder reads the FIRST of a name: `FN` "x\r\nX-HDTP-SEAL:none"
// turned a card that requires sealing into one that does not.
#[test]
fn nothing_that_goes_into_a_card_may_carry_a_line_break() {
    let c = cast();
    let good = leaf(&c, E_A, None, None);
    for (what, args) in [
        ("fn with CR LF", json!({ "fn": "x\r\nX-HDTP-SEAL:none", "cert": b64u(&good), "seal": "required" })),
        ("fn with a bare LF", json!({ "fn": "x\nX-HDTP-SEAL:none", "cert": b64u(&good) })),
        ("fn with a NUL", json!({ "fn": "x\u{0}y", "cert": b64u(&good) })),
        ("seal with CR LF", json!({ "fn": "x", "cert": b64u(&good), "seal": "required\r\nX-HDTP-VERSION:3" })),
        ("an extra line with CR LF", json!({ "fn": "x", "cert": b64u(&good), "extra": ["X-A:1\r\nX-HDTP-SEAL:none"] })),
    ] {
        let r = call("card_encode", args);
        assert_eq!(r["error"], "bad_request", "{what}: {r}");
    }
    let honest = call("card_encode", json!({ "fn": "Alina Rao, of Pune", "cert": b64u(&good), "seal": "required" }));
    assert!(honest["vcard"].as_str().is_some_and(|v| v.contains("FN:Alina Rao, of Pune\r\n")), "{honest}");
}

// C5 — `now` is what `expired` MEANS. Without it the core decoded against 1970 and answered
// `expired: false` for every card ever made; the Go port refused.
#[test]
fn a_card_is_not_decoded_without_the_instant_it_is_judged_at() {
    let c = cast();
    let card = hdtp_identity::card::encode("Alina Rao", &leaf(&c, E_A, None, None), None, &[]).expect("a card");
    let r = call("card_decode", json!({ "vcard": card }));
    assert_eq!((r["error"].as_str(), r.get("expired")), (Some("bad_request"), None), "{r}");
    assert_eq!(call("card_decode", json!({ "vcard": card, "now": NOW_RFC }))["expired"], false);
}

// C9 — a chain that is THERE and will not read is not a chain that is absent.
#[test]
fn a_sender_chain_that_will_not_read_is_said_to_be_that() {
    let c = cast();
    let good = leaf(&c, E_A, None, None);
    let base = json!({ "recipient_leaf": b64u(&good), "sender_pkcs8": b64u(&c.host.to_pkcs8()), "form": "chain", "method": "tools/call", "params": {}, "msg_id": "m-1", "ts": NOW });
    let mut absent = base.clone();
    absent.as_object_mut().unwrap().remove("sender_chain");
    let absent = call("seal_request", absent);
    let mut broken = base.clone();
    broken["sender_chain"] = json!(["!!!", "!!!"]);
    let broken = call("seal_request", broken);
    assert!(absent.get("error").is_some() && broken.get("error").is_some(), "{absent} {broken}");
    assert_ne!(absent["why"], broken["why"], "one answer for a chain that is missing and a chain that is not base64url");
    assert_eq!(broken["error"], "parse", "{broken}");
}

// C11 — §9: a wallet refuses a request whose key is a root. `wallet_issue` gathered root keys from
// `pkcs8` alone, so a CARD-held sibling — a certificate and no private key — was not among them.
#[test]
fn a_request_carrying_a_card_held_siblings_key_is_refused_on_the_software_path() {
    let c = cast();
    let sibling = PrivateKey::generate(Alg::P256).unwrap();
    let sibling_der = x509::build_root("Alina at work", &sibling, NOW - 3600, None, &x509::serial_of("findings/sibling")).unwrap();
    let plaintext = json!({
        "v": 1,
        "roots": [
            { "fingerprint": c.root.public().fingerprint(), "cn": "Alina Rao", "pkcs8": b64u(&c.root.to_pkcs8()), "cert": b64u(&c.root_der), "created": NOW_RFC },
            { "fingerprint": sibling.public().fingerprint(), "cn": "Alina at work", "cert": b64u(&sibling_der), "created": NOW_RFC, "holder": { "kind": "piv" } },
        ],
    });
    let csr = call("csr_new", json!({ "cn": "A Host", "host_pkcs8": b64u(&sibling.to_pkcs8()), "endpoint": E_A }));
    let r = call(
        "wallet_issue",
        json!({ "vault_plaintext": plaintext, "record_plaintext": { "v": 1, "ledger": [] }, "root_fingerprint": c.root.public().fingerprint(), "csr": csr["der"], "now": NOW_RFC }),
    );
    assert_eq!(r["why"], "the request's key is a root", "{r}");
}

// C6 — a small-form envelope names a leaf, and its sender has proved nothing yet. Finding the pin that
// holds it meant parsing EVERY pinned leaf. A pin may now say which leaf it holds; then only the pin
// that matches is parsed — shown here by a pin that CANNOT be parsed and is never asked to be.
#[test]
fn a_pin_that_names_its_leaf_is_matched_by_name_and_only_the_match_is_parsed() {
    let (me, them) = (cast(), cast());
    let (my_leaf, their_leaf) = (leaf(&me, E_A, None, None), leaf(&them, "https://agent.bharat.example/mcp", None, None));
    let their_fp = them.host.public().fingerprint();
    let small = call(
        "seal_request",
        json!({ "recipient_leaf": b64u(&my_leaf), "sender_pkcs8": b64u(&them.host.to_pkcs8()), "form": "leaf", "method": "tools/call",
                "params": { "name": "send_message" }, "msg_id": "c6", "ts": NOW }),
    );
    let node = |pins: Value| {
        json!({ "endpoint": E_A, "accept_new_hosts": "auto", "chain": [b64u(&my_leaf), b64u(&me.root_der)],
                "keys": [{ "kid": me.host.public().fingerprint(), "leaf": b64u(&my_leaf), "pkcs8": b64u(&me.host.to_pkcs8()), "current": true }],
                "former": [], "sibling_kids": [], "pins": pins, "tombstones": [], "former_endpoints": [], "seen": [] })
    };
    let theirs = |fp: Option<&str>| {
        let mut p = json!({ "root": them.root.public().fingerprint(), "endpoint": "https://agent.bharat.example/mcp", "leaf": b64u(&their_leaf), "state": "active" });
        if let Some(fp) = fp {
            p["leaf_fingerprint"] = json!(fp);
        }
        p
    };
    // Its root is a fingerprint, as every root a host holds must be (a root that is not one is refused
    // by the reader, whatever the pin says it holds); its leaf is what has gone bad.
    let unreadable = |fp: Option<&str>| {
        let mut p = json!({ "root": format!("sha256:{}A", "G".repeat(42)), "endpoint": "https://ghost.example/mcp", "leaf": "AAAA", "state": "active" });
        if let Some(fp) = fp {
            p["leaf_fingerprint"] = json!(fp);
        }
        p
    };
    let decide = |pins: Value| call("decide", json!({ "now": NOW_RFC, "envelope": small, "node": node(pins) }));

    // Named or not, the contact is found.
    for pins in [json!([theirs(None)]), json!([theirs(Some(&their_fp))])] {
        let d = decide(pins);
        assert_eq!((d["result"]["code"].as_str(), d["result"]["tier"].as_str()), (Some("ok"), Some("contact")), "{d}");
    }
    // An unreadable pin that does NOT say which leaf it holds has to be parsed to find out, and is an error…
    assert_eq!(decide(json!([unreadable(None), theirs(Some(&their_fp))]))["error"], "parse");
    // …and one that says it holds some OTHER leaf is never parsed at all. The other leaf is named by a
    // fingerprint: a leaf_fingerprint that is not one is the host's damaged state, refused where it is
    // read (the review of 2026-09-30, S1), as `sha256:somebody-else` now is.
    let d = decide(json!([unreadable(Some(&format!("sha256:{}A", "H".repeat(42)))), theirs(Some(&their_fp))]));
    assert_eq!(d["result"]["code"], "ok", "{d}");
    let d = decide(json!([unreadable(Some("sha256:somebody-else")), theirs(Some(&their_fp))]));
    assert_eq!(
        (d["error"].as_str(), d["why"].as_str()),
        (Some("bad_request"), Some("node.pins[0].leaf_fingerprint is not a fingerprint")),
        "{d}"
    );

    // The name is a claim about the certificate beside it, and is held to it.
    let lying = {
        let mut p = theirs(Some(&their_fp));
        p["leaf"] = json!(b64u(&my_leaf));
        p
    };
    let d = decide(json!([lying]));
    assert_eq!((d["error"].as_str(), d["why"].as_str()), (Some("parse"), Some("a pin's leaf_fingerprint is not its leaf's")), "{d}");
}

// P-21 (review of 2026-09-23) — a contact I asked, still `pending_out`, lists my tools: `tools/list`
// returns what the caller's tier may use (§6) and a sealed call is dispatched in the tier the proven
// identity earns (§13.2). A listing names no tool, so it never matched `contact_accepted` or
// `contact_rejected` and was answered `pending_approval` — in the small form, in the chain form, and
// on the path where the pin moves on the way through. The controls are the calls that must still wait.
#[test]
fn a_pending_contacts_sealed_listing_answers_at_the_pending_tier() {
    const E_B: &str = "https://agent.bharat.example/mcp";
    const E_N: &str = "https://alina.host.example/alina/mcp";
    let (me, them) = (cast(), cast());
    let (my_leaf, their_leaf) = (leaf(&me, E_B, None, None), leaf(&them, E_A, None, None));
    // Their next host: the same root, a newer leaf, another address (§5.3 under `auto`).
    let (issuer, host_pub) = (them.root.public(), them.host.public());
    let moved_leaf = x509::build_leaf(
        &LeafSpec {
            cn: "Alina Rao",
            root_cn: "Alina Rao",
            issuer: &issuer,
            host_key: &host_pub,
            uris: vec![E_N.into()],
            dns_name: None,
            not_before: NOW - 1800,
            not_after: NOW + 86_400,
            serial: x509::serial_of("findings/p21/moved"),
            ca: false,
            usage: None,
            aki: None,
        },
        &them.root,
    )
    .unwrap();
    let node = json!({ "endpoint": E_B, "accept_new_hosts": "auto", "chain": [b64u(&my_leaf), b64u(&me.root_der)],
        "keys": [{ "kid": me.host.public().fingerprint(), "leaf": b64u(&my_leaf), "pkcs8": b64u(&me.host.to_pkcs8()), "current": true }],
        "former": [], "sibling_kids": [], "tombstones": [], "former_endpoints": [], "seen": [],
        "pins": [{ "root": them.root.public().fingerprint(), "endpoint": E_A, "leaf": b64u(&their_leaf), "state": "pending_out" }] });
    let decide = |sender_leaf: Option<&[u8]>, method: &str, params: Value| {
        let mut args = json!({ "recipient_leaf": b64u(&my_leaf), "sender_pkcs8": b64u(&them.host.to_pkcs8()), "form": "leaf",
            "method": method, "params": params, "msg_id": "p21", "ts": NOW });
        if let Some(l) = sender_leaf {
            args["form"] = json!("chain");
            args["sender_chain"] = json!([b64u(l), b64u(&them.root_der)]);
        }
        let d = call("decide", json!({ "now": NOW_RFC, "envelope": call("seal_request", args), "node": node }));
        (d["result"]["code"].as_str().map(String::from), d["result"]["tier"].as_str().map(String::from), d)
    };
    let pending = (Some("ok".to_string()), Some("pending".to_string()));
    let waits = (Some("pending_approval".to_string()), None);
    for (sender, what) in [(None, "small form"), (Some(&their_leaf[..]), "chain form"), (Some(&moved_leaf[..]), "chain form, moved")] {
        let (code, tier, d) = decide(sender, "tools/list", json!({}));
        assert_eq!((code, tier), pending, "{what}, tools/list: {d}");
        // The moved case really took the path where the pin moves: the answer is at the new address.
        let at = if what.ends_with("moved") { E_N } else { E_A };
        assert_eq!(d["result"]["endpoint"], at, "{what}: {d}");
        let (code, tier, d) = decide(sender, "tools/call", json!({ "name": "contact_accepted" }));
        assert_eq!((code, tier), pending, "{what}, contact_accepted: {d}");
        // The controls: what the pending tier does not have still waits.
        let (code, tier, d) = decide(sender, "tools/call", json!({ "name": "send_message" }));
        assert_eq!((code, tier), waits, "{what}, send_message: {d}");
        let (code, tier, d) = decide(sender, "tools/call", json!({}));
        assert_eq!((code, tier), waits, "{what}, a call that names no tool: {d}");
    }
}
