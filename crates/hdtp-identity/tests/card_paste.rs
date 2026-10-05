//! §3, Reading a card, at the boundary a host calls (`card_decode`): a card whose folding a paste
//! damaged reads, a property after the certificate is not swallowed into it, and damage that is not
//! whitespace is still caught — a cut certificate by the DER parse, a changed character by chain
//! validation. The Go port's `TestCardAsAChatDeliversIt` and the seed's vectors/check.mjs damage their
//! cards the same way.

use hdtp_identity::keys::{Alg, PrivateKey};
use hdtp_identity::x509::{self, LeafSpec};
use serde_json::{json, Value};

const NOW: i64 = 1_789_000_000;
const NOW_RFC: &str = "2026-09-10T00:26:40Z";

fn call(name: &str, args: Value) -> Value {
    serde_json::from_str(&hdtp_identity::call(name, &args.to_string())).expect("the boundary answers JSON")
}

fn b64u(b: &[u8]) -> String {
    hdtp_identity::util::b64u(b)
}

fn chain() -> (Vec<u8>, Vec<u8>) {
    let root = PrivateKey::generate(Alg::Ed25519).unwrap();
    let host = PrivateKey::generate(Alg::Ed25519).unwrap();
    let root_der = x509::build_root("Alina Rao", &root, NOW - 3600, None, &x509::serial_of("card-paste/root")).unwrap();
    let (issuer, host_pub) = (root.public(), host.public());
    let leaf = x509::build_leaf(
        &LeafSpec {
            cn: "Alina Rao",
            root_cn: "Alina Rao",
            issuer: &issuer,
            host_key: &host_pub,
            uris: vec!["https://agent.alina.example/mcp".into()],
            dns_name: None,
            not_before: NOW - 3600,
            not_after: NOW + 86_400,
            serial: x509::serial_of("card-paste/leaf"),
            ca: false,
            usage: None,
            aki: None,
        },
        &root,
    )
    .unwrap();
    (leaf, root_der)
}

/// The owner's paste of 2026-10-05: every continuation of X-HDTP-CERT without its leading space but
/// the third, a blank line after the first and the fourth, LF line ends.
fn pasted(card: &str) -> String {
    let mut lines: Vec<String> = card.split("\r\n").map(String::from).collect();
    let first = lines.iter().position(|l| l.starts_with("X-HDTP-CERT:")).expect("a certificate");
    let conts = lines[first + 1..].iter().filter(|l| l.starts_with(' ')).count();
    assert!(conts >= 4, "the certificate is folded over {} lines, too few to damage", conts + 1);
    for k in 1..=conts {
        let l = &mut lines[first + k];
        if k != 3 {
            l.remove(0);
        }
        if k == 1 || k == 4 {
            l.push('\n');
        }
    }
    lines.join("\n")
}

/// The card with its certificate's value replaced, unfolded.
fn with_cert(card: &str, value: &str) -> String {
    let start = card.find("X-HDTP-CERT:").unwrap();
    let end = card.find("\r\nX-HDTP-SEAL").unwrap();
    format!("{}X-HDTP-CERT:{value}{}", &card[..start], &card[end..])
}

fn decode(text: &str) -> Value {
    call("card_decode", json!({ "vcard": text, "now": NOW_RFC }))
}

#[test]
fn a_card_as_a_chat_delivers_it_reads() {
    let (leaf, _) = chain();
    let card = hdtp_identity::card::encode("Alina Rao", &leaf, Some("required"), &[]).expect("a card");
    let b64 = b64u(&leaf);
    let paste = pasted(&card);
    for (what, text, seal) in [
        ("as the owner pasted it", paste.clone(), "required"),
        ("folded correctly (the control)", card.clone(), "required"),
        ("not folded at all", card.replace("\r\n ", ""), "required"),
        ("with a space and a tab inside", with_cert(&card, &format!("{} \t{}", &b64[..9], &b64[9..])), "required"),
        ("pasted, then X-HDTP-SEAL:none", paste.replace("X-HDTP-SEAL:required", "X-HDTP-SEAL:none"), "none"),
        (
            "pasted, then a group-prefixed property and the seal",
            paste.replace("X-HDTP-SEAL:required", "item1.EMAIL;type=INTERNET:a@example.com\nX-HDTP-SEAL:optional"),
            "optional",
        ),
    ] {
        let r = decode(&text);
        assert_eq!((r["cert"].as_str(), r["seal"].as_str()), (Some(b64.as_str()), Some(seal)), "a card {what}: {r}");
    }
    // A vertical tab and a no-break space are not what a fold or a paste writes: still refused.
    for bad in ["\u{b}", "\u{a0}"] {
        let r = decode(&with_cert(&card, &format!("{}{bad}{}", &b64[..9], &b64[9..])));
        assert_eq!(r["why"], "certificate does not parse: not base64url", "{bad:?}: {r}");
    }
}

#[test]
fn damage_that_is_not_whitespace_is_still_caught() {
    let (leaf, root) = chain();
    let card = hdtp_identity::card::encode("Alina Rao", &leaf, Some("required"), &[]).expect("a card");
    let b64 = b64u(&leaf);
    // Cut at 120 characters, a multiple of four: the base64url reads, the DER does not.
    let cut = decode(&with_cert(&card, &b64[..120]));
    assert!(cut["why"].as_str().is_some_and(|w| w.starts_with("certificate does not parse: ")), "{cut}");
    // One character of the signature changed, the value broken over two lines with no fold: the card
    // reads, its certificate is another leaf, and the chain does not validate.
    let mid = b64.len() - 30;
    let swap = if &b64[mid..=mid] == "A" { "B" } else { "A" };
    let changed = format!("{}{swap}{}", &b64[..mid], &b64[mid + 1..]);
    let r = decode(&with_cert(&card, &format!("{}\n{}", &changed[..60], &changed[60..])));
    let cert = r["cert"].as_str().unwrap_or_else(|| panic!("a changed character is read: {r}"));
    assert_ne!(cert, b64);
    let refused = call("validate_chain", json!({ "chain": [cert, b64u(&root)], "now": NOW_RFC }));
    assert_eq!((refused["ok"].as_bool(), refused["rule"].as_i64()), (Some(false), Some(3)), "{refused}");
    let control = call("validate_chain", json!({ "chain": [b64, b64u(&root)], "now": NOW_RFC }));
    assert_eq!(control["ok"], true, "{control}");
}
