//! A root held on a PIV card: the card checked against the root it is supposed to be, root and leaf
//! certificates signed through the core's seam, and the commands that make such a root
//! (`id create --piv`), look at a card (`card-status`) and hand a vault's root to one
//! (`card-attach`).
use super::files::{empty_record, land_all, open_vault, pick_root, real, record_of, roots, save_vault, sealed_bytes};
use crate::io::{check_writable, core, fail, instant, now_or, passphrase, Fail, Res};
use crate::piv::{digest_of, CardSigner};
use pact_identity::time::parse_rfc3339;
use pact_identity::util::{b64u, from_b64u};
use pact_identity::x509;
use serde_json::{json, Value};
use std::path::Path;

/// How a root is held. A vault entry with a `pkcs8` alone is software. One with a `holder` signs on
/// a card: generated there (`id create --piv`), the entry has the certificate and no key at all —
/// there is nothing to hold, which is the whole point of that arrangement; imported (`card-attach`),
/// the vault keeps the key as well, and the card is a way to sign rather than the identity.
pub fn card_holder(root: &Value) -> Option<&Value> {
    root.get("holder").filter(|h| h["kind"].as_str() == Some("piv"))
}

/// The card a root names, opened and checked against the root it is supposed to be. A different
/// card, or a slot regenerated since, is the one mistake that would otherwise produce certificates
/// under a root nobody pinned.
pub(super) fn card_for(root: &Value, reader: Option<&str>) -> Res<Box<dyn CardSigner>> {
    let holder = card_holder(root).ok_or_else(|| Fail("this root is not held on a card".into()))?;
    let slot = holder["slot"].as_str().unwrap_or(crate::piv::DEFAULT_SLOT);
    let card = crate::piv::open(reader.or_else(|| holder["reader"].as_str()), slot)?;
    match_root(root, card.as_ref())?;
    Ok(card)
}

/// The card in hand is the one this identity's root lives on — or nothing is signed. A different
/// card, or a slot generated again since, would otherwise mint certificates under a root no
/// contact has ever pinned.
fn match_root(root: &Value, card: &dyn CardSigner) -> Res<()> {
    let on_card = card.public_key()?.fingerprint();
    let wanted = root["fingerprint"].as_str().unwrap_or("");
    if on_card != wanted {
        return fail(format!(
            "the key in slot {} is {on_card}, and this identity's root is {wanted}: a different card, or that slot has been generated again. Nothing signed.",
            card.describe().slot
        ));
    }
    Ok(())
}

/// A card proves it can *sign* under the key it shows, before a vault records it as this root's
/// card. Reading the slot's certificate is not that proof: PIV keeps the certificate and the key in
/// two separate objects and nothing makes them agree, so a slot can show exactly the right
/// certificate over a key that is not this root's. An attach that believed the certificate would
/// record a card that then fails at every issuance, burning a PIN try each time, for a reason
/// nobody could see.
///
/// The challenge is domain-separated and carries fresh randomness, so this signature is not a
/// certificate signature and no captured signature is this one: it begins with ASCII text, and a
/// TBSCertificate begins with 0x30.
fn card_proves_it_holds(card: &dyn CardSigner, key: &pact_identity::keys::PublicKey) -> Res<()> {
    // 32 random bytes of its own, as §2.2 asks of the analogous root-possession proof. It used to
    // borrow the certificate-SERIAL generator, which makes 8: enough here, since the domain prefix
    // does the real work, and the wrong number to have on loan.
    let nonce = pact_identity::util::random(32).map_err(|e| Fail(e.why))?;
    let mut challenge = b"PACT card-attach proof v1\n".to_vec();
    challenge.extend_from_slice(key.fingerprint().as_bytes());
    challenge.push(b'\n');
    challenge.extend_from_slice(&nonce);
    let sig = card.sign_digest(&digest_of(&challenge))?;
    if !key.verify(&challenge, &sig) {
        return fail("the card's signature does not verify under this identity's root: the slot holds this root's certificate over a different key, so it could show the right key and sign with the wrong one. Nothing written.");
    }
    Ok(())
}

/// The root certificate a card's key signs for itself, through the seam: the core builds the bytes,
/// the card signs them, the core assembles, and the signature is checked here before a vault is
/// written — a card that signed with another key must not become an identity on disk.
fn root_from_card(card: &dyn CardSigner, name: &str, now: i64) -> Res<(Vec<u8>, pact_identity::keys::PublicKey)> {
    let key = card.public_key()?;
    if key.alg().name() != "p256" {
        return fail(format!(
            "that slot holds a {} key; a card-held root is P-256 (SPEC §14.1 allows Ed25519 or P-256, and PIV's Ed25519 is too new to rely on)",
            key.alg().name()
        ));
    }
    let serial = x509::random_serial().map_err(|e| Fail(e.why))?;
    let u = core("root_tbs", json!({ "cn": name, "spki": b64u(key.spki()), "not_before": instant(now), "serial": b64u(&serial) }))?;
    let tbs = from_b64u(u["tbs"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let sig = card.sign_digest(&digest_of(&tbs))?;
    if !key.verify(&tbs, &sig) {
        return fail("the card's signature does not verify under the slot's key: nothing written");
    }
    let cert = from_b64u(
        core("assemble_root", json!({ "tbs": u["tbs"], "sig": b64u(&sig), "sig_alg": u["sig_alg"] }))?["der"].as_str().unwrap_or(""),
    )
    .map_err(|e| Fail(e.why))?;
    Ok((cert, key))
}

/// SPEC §9's one-live-leaf rule, which the core applies for a software root inside `wallet_issue`
/// and which the card path must apply for itself — the core cannot, because there is no key to hand
/// it. `live_leaf_refusal` and the core's rule are held to the same behaviour by a test that runs a
/// software root and a card-held root through the same vault and expects the same refusal.
pub(super) fn live_leaf_refusal(mine: &[&Value], endpoint: &str, now: i64, moving: bool) -> Option<String> {
    let newest = mine.iter().max_by_key(|l| l["not_before"].as_str().and_then(|t| parse_rfc3339(t).ok()).unwrap_or(0))?;
    let live = newest["not_after"].as_str().and_then(|t| parse_rfc3339(t).ok()).is_some_and(|t| t > now);
    let elsewhere = newest["endpoint"].as_str() != Some(endpoint);
    if live && elsewhere && !moving {
        return Some(format!(
            "a leaf is live for {}: a second endpoint is a move, not a second home",
            newest["endpoint"].as_str().unwrap_or("?")
        ));
    }
    None
}

/// The key this identity *is*: read out of the root certificate the vault holds, which is the
/// certificate a contact pinned. Everything a card signs is checked against this and never against
/// what the card says about itself, because the card is the thing that might be lying — or might
/// simply have been swapped for another since the last question. The entry's own fingerprint is
/// checked against its certificate on the way past: a vault whose two halves disagree is a vault
/// that would issue under a root nobody has.
pub(super) fn root_key(root: &Value) -> Res<pact_identity::keys::PublicKey> {
    let der = from_b64u(root["cert"].as_str().unwrap_or("")).map_err(|e| Fail(format!("this identity's root certificate: {}", e.why)))?;
    let cert = x509::parse(&der).map_err(|e| Fail(format!("this identity's root certificate: {}", e.why)))?;
    let fp = cert.public_key.fingerprint();
    if root["fingerprint"].as_str() != Some(fp.as_str()) {
        return fail(format!(
            "this vault's entry says the root is {}, and the certificate it keeps is for {fp}: the vault has been edited, and nothing is signed under it",
            root["fingerprint"].as_str().unwrap_or("nothing")
        ));
    }
    Ok(cert.public_key)
}

/// A leaf signed by a card, through the core's seam: the core makes the bytes and checks the
/// request, the card makes the signature, the core puts the certificate together — and the
/// signature is verified under the pinned root before any of it is assembled. The verification is
/// not a formality: a PIV slot's certificate and its key are not made to agree by anything, so a
/// card can pass the check with one key and sign with another, and what would come back is a leaf
/// naming this root as its issuer that no contact could ever validate.
pub(super) fn issue_on_card(
    card: &dyn CardSigner,
    root: &Value,
    vault_roots: &[Value],
    csr_der: &[u8],
    now: i64,
    previous: Option<i64>,
    valid_days: i64,
) -> Res<Value> {
    let pinned = root_key(root)?;
    // The card in hand is this root's card. `id_issue` asked already; asking here too is what makes
    // this function safe to call from anywhere, which is how the gap above it arrived.
    match_root(root, card)?;
    // §9 refuses a request whose key is a root — ANY root this wallet holds, not only the one that
    // is issuing. The software path hands the core every root in the vault; this one handed it only
    // `root_spki`, so a request carrying a sibling identity's root key was given a leaf. Each root's
    // key is read from its certificate, which a card-held root has and a private key it has not.
    let every_root = vault_roots.iter().map(|r| root_key(r).map(|k| b64u(k.spki()))).collect::<Res<Vec<String>>>()?;
    let mut args = json!({
        "csr": b64u(csr_der),
        "root_cn": root["cn"].as_str().unwrap_or(""),
        "root_spki": b64u(pinned.spki()),
        "root_spkis": every_root,
        "now": instant(now),
        "valid_days": valid_days,
    });
    if let Some(p) = previous {
        args["previous_not_before"] = json!(instant(p));
    }
    let u = core("issue_tbs_from_csr", args)?;
    let tbs = from_b64u(u["tbs"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let sig = card.sign_digest(&digest_of(&tbs))?;
    if !pinned.verify(&tbs, &sig) {
        return fail("the card's signature does not verify under this identity's root: the slot's certificate and its key are for different keys, or the card was changed mid-ceremony. Nothing signed, nothing written.");
    }
    let der = core("assemble_leaf", json!({ "tbs": u["tbs"], "sig": b64u(&sig), "sig_alg": u["sig_alg"] }))?["der"].clone();
    Ok(json!({
        "der": der,
        "endpoint": u["endpoint"],
        "not_before": u["not_before"],
        "not_after": u["not_after"],
    }))
}

/// An identity whose root is a card: the certificate is built from the slot's public key and signed
/// by the slot, so no private key exists anywhere but the card, including here.
pub fn id_create_piv(name: &str, slot: &str, reader: Option<&str>, vault: &str) -> Res<i32> {
    let (record, record_real) = record_of(vault);
    for (taken, really) in [(vault, real(vault)), (record.as_str(), record_real.clone())] {
        if Path::new(&really).exists() {
            return fail(format!("{taken} exists; a second identity goes in with --vault pointing elsewhere, or is a decision for later"));
        }
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let card = crate::piv::open(reader, slot)?;
    let info = card.describe();
    eprintln!("reader      {}", info.reader);
    eprintln!("card        {}", info.serial.clone().unwrap_or_else(|| "serial unknown".into()));
    eprintln!("slot        {}", info.slot);
    let pass = passphrase(true)?;
    let now = now_or(None)?;
    let (cert, key) = root_from_card(card.as_ref(), name, now)?;
    eprintln!("root        {}", key.fingerprint());
    let plaintext = json!({
        "v": 2,
        "roots": [{
            "fingerprint": key.fingerprint(),
            "cn": name,
            "cert": b64u(&cert),
            "created": instant(now),
            "holder": { "kind": "piv", "mode": "generated", "slot": info.slot, "serial": info.serial, "reader": info.reader },
        }],
    });
    let vault_real = real(vault);
    let files = [
        (vault, vault_real.as_str(), sealed_bytes(&pass, &plaintext)?),
        (record.as_str(), record_real.as_str(), sealed_bytes(&pass, &empty_record())?),
    ];
    land_all(&files, &pass, false)?.iter_mut().for_each(crate::io::wipe);
    println!("{}", key.fingerprint());
    eprintln!("wrote {vault} (mode 0600) — the certificate; the key stays on the card. {record}: the ledger and the contact book");
    eprintln!("This card is the identity. The vault cannot hold the key and there is no export: lose the card and the identity is gone, exactly as a lost vault ends a software one. A second card is a second identity, not a copy.");
    Ok(0)
}

pub fn card_status(vault: Option<&str>, slot: &str, reader: Option<&str>) -> Res<i32> {
    let card = crate::piv::open(reader, slot)?;
    let info = card.describe();
    let key = card.public_key()?;
    println!("reader      {}", info.reader);
    println!("card        {}", info.serial.unwrap_or_else(|| "serial unknown".into()));
    println!("slot        {}", info.slot);
    println!("algorithm   {}", key.alg().name());
    println!("key         {}", key.fingerprint());
    let Some(path) = vault else { return Ok(0) };
    let v = open_vault(path, false)?;
    let matching = roots(&v.plaintext).into_iter().find(|r| r["fingerprint"].as_str() == Some(&key.fingerprint()));
    match matching {
        Some(r) => {
            // The same question every signing path asks: is this entry and the certificate it keeps
            // one key? A person asking "is this card my identity?" gets the whole answer or none.
            root_key(&r)?;
            println!("identity    {} ({})", r["fingerprint"].as_str().unwrap_or(""), r["cn"].as_str().unwrap_or(""));
            println!(
                "held        {}",
                match card_holder(&r).and_then(|h| h["mode"].as_str()) {
                    Some("generated") => "on this card, generated there: the vault has no key and there is no backup",
                    Some("imported") => "on this card, imported: the vault keeps the key too, so a lost card is not a lost identity",
                    Some(_) | None => "as a key in the vault; this card signs nothing for it",
                }
            );
            Ok(0)
        }
        None => {
            println!("identity    none in {path} has this key");
            Ok(1)
        }
    }
}

/// Hands a vault's own root over to a card that has been given a copy of its key. The card is
/// proved to hold that very key before anything is written — an attach that recorded a card holding
/// some other key would send every later signature somewhere nobody pinned.
pub fn card_attach(vault: &str, slot: &str, reader: Option<&str>, root: Option<&str>) -> Res<i32> {
    let mut v = open_vault(vault, false)?;
    let chosen = pick_root(&v.plaintext, root)?;
    let fp = chosen["fingerprint"].as_str().unwrap_or("").to_string();
    let pinned = root_key(&chosen)?;
    let card = crate::piv::open(reader, slot)?;
    let info = card.describe();
    let on_card = card.public_key()?.fingerprint();
    if on_card != fp {
        return fail(format!(
            "the key in slot {slot} is {on_card}, and this identity's root is {fp}: import the right key, or attach the right identity"
        ));
    }
    // One signature now, and the PIN it costs, in exchange for never recording a card that cannot
    // sign for this root.
    card_proves_it_holds(card.as_ref(), &pinned)?;
    let roots = v.plaintext["roots"].as_array_mut().ok_or_else(|| Fail("vault roots".into()))?;
    let entry = roots.iter_mut().find(|r| r["fingerprint"].as_str() == Some(&fp)).ok_or_else(|| Fail("the root went missing".into()))?;
    entry["holder"] = json!({ "kind": "piv", "mode": "imported", "slot": info.slot, "serial": info.serial, "reader": info.reader });
    save_vault(&v)?;
    eprintln!("{fp} now signs on card {} slot {}", info.serial.unwrap_or_else(|| "?".into()), info.slot);
    eprintln!("The vault still holds this root's key, so this is a card that signs rather than a card that is the identity: a lost card is an inconvenience, and a copied vault is still a copied identity. `pact id create --piv` is the other arrangement.");
    Ok(0)
}

#[cfg(test)]
mod card_tests {
    //! A card-held root, proven without a card: the fake signs a digest exactly as PIV's GENERAL
    //! AUTHENTICATE does, so everything above the trait — the seam, the profile, the rules, the
    //! refusals — is the real thing.
    use super::*;
    use crate::piv::fake::FakeCard;
    use pact_identity::csr as csr_mod;
    use pact_identity::keys::{Alg, PrivateKey};

    const NOW: i64 = 1_789_000_000;
    const ENDPOINT: &str = "https://agent.alina.example/mcp";

    fn root_of(card: &FakeCard) -> Res<(Vec<u8>, Value)> {
        let (cert, key) = root_from_card(card, "Alina Rao", NOW)?;
        let root = json!({
            "fingerprint": key.fingerprint(),
            "cn": "Alina Rao",
            "cert": b64u(&cert),
            "created": instant(NOW),
            "holder": { "kind": "piv", "mode": "generated", "slot": "9c", "serial": "1", "reader": "Fake Reader" },
        });
        Ok((cert, root))
    }

    fn a_request(endpoint: &str) -> Vec<u8> {
        let host = PrivateKey::generate(Alg::Ed25519).expect("a host key");
        csr_mod::csr_new("A Host", &host, endpoint, None).expect("a request")
    }

    #[test]
    fn a_root_the_card_signed_is_a_root() {
        let card = FakeCard::p256("7777");
        let (cert, root) = root_of(&card).expect("a root");
        // §14.2 rule 1 refuses a single self-signed certificate as a chain, so a chain of it
        // twice is what asks "is this a root of the profile?": rule 2 is where a bad one would die.
        let r = core("validate_chain", json!({ "chain": [b64u(&cert), b64u(&cert)], "now": instant(NOW) })).expect("an answer");
        assert_eq!(r["ok"], json!(false), "a root is not a chain");
        assert_eq!(r["rule"], json!(1), "it fails for being one certificate, not for its profile: {r}");
        let parsed = core("parse_certificate", json!({ "der": b64u(&cert) })).expect("parsed");
        assert_eq!(parsed["kind"], json!("root"), "the profile accepts it: {parsed}");
        assert_eq!(parsed["profile_error"], json!(null));
        assert_eq!(parsed["fingerprint"].as_str(), root["fingerprint"].as_str());
    }

    #[test]
    fn a_leaf_the_card_signed_validates_to_that_root_at_its_endpoint() {
        let card = FakeCard::p256("7777");
        let (cert, root) = root_of(&card).expect("a root");
        let out = issue_on_card(&card, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365).expect("a leaf");
        let r = core(
            "validate_chain",
            json!({ "chain": [out["der"].clone(), b64u(&cert)], "now": instant(NOW), "expected_root": root["fingerprint"], "expected_endpoint": ENDPOINT }),
        )
        .expect("an answer");
        assert_eq!(r["ok"], json!(true), "the chain validates: {r}");
        assert_eq!(r["endpoint"].as_str(), Some(ENDPOINT));
    }

    #[test]
    fn a_card_that_refuses_says_which_refusal_it_was() {
        let honest = FakeCard::p256("7777");
        let root = root_of(&honest).expect("a root").1;
        let csr = a_request(ENDPOINT);

        // An empty slot cannot even be read.
        let e = root_from_card(&FakeCard::empty_slot(), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no certificate"), "{}", e.0);

        // A slot holding an RSA key: the CARD refuses the parameters (6A80), and that message says
        // the profile signs with P-256. This is not the wallet's own guard — see the test below.
        let e = root_from_card(&FakeCard::rsa(), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("P-256"), "{}", e.0);

        // A wrong PIN comes back with the tries left, because that is what a person needs next.
        let e = issue_on_card(&FakeCard::wrong_pin_for(&honest), &root, std::slice::from_ref(&root), &csr, NOW, None, 365).unwrap_err();
        assert!(e.0.contains("wrong PIN") && e.0.contains("2 tries left"), "{}", e.0);
    }

    // The guard on a card-held root's algorithm had no test. The one above that names P-256 passes
    // on the CARD's refusal of RSA parameters (status 6A80, whose text also says P-256) and never
    // reaches the guard; a slot that reports an Ed25519 key — which a newer PIV token can — does.
    #[test]
    fn a_card_reporting_an_ed25519_key_is_refused_by_the_guard_itself() {
        let e = root_from_card(&FakeCard::reports_ed25519(), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("that slot holds a ed25519 key") && e.0.contains("a card-held root is P-256"), "{}", e.0);
    }

    // §9: a wallet refuses a request whose key is a root. The software path hands the core every
    // root in the vault; the card path handed it only the root that was issuing, so on a card-held
    // identity a request carrying a SIBLING root's key was given a leaf.
    #[test]
    fn a_request_carrying_a_sibling_roots_key_is_refused_on_the_card_path_too() {
        let card = FakeCard::p256("7777");
        let root = root_of(&card).expect("a root").1;
        let sibling_key = PrivateKey::generate(Alg::Ed25519).expect("a key");
        let sibling_cert = x509::build_root("Alina at work", &sibling_key, NOW, &x509::serial_of("sibling")).expect("a root");
        let sibling = json!({ "fingerprint": sibling_key.public().fingerprint(), "cn": "Alina at work", "cert": b64u(&sibling_cert) });
        let csr = csr_mod::csr_new("A Host", &sibling_key, ENDPOINT, None).expect("a request");

        let e = issue_on_card(&card, &root, &[root.clone(), sibling], &csr, NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("the request's key is a root"), "{}", e.0);
    }

    #[test]
    fn another_card_signs_nothing_for_this_identity() {
        let root = root_of(&FakeCard::p256("7777")).expect("a root").1;
        // A second card, or the same slot generated again: a different key, and the check is the
        // fingerprint rather than the serial, which a card need not even report.
        let e = match_root(&root, &FakeCard::p256("8888")).unwrap_err();
        assert!(e.0.contains("a different card, or that slot has been generated again"), "{}", e.0);
        assert!(match_root(&root, &FakeCard::p256("7777")).is_err(), "a fake card's key is fresh each time, so this too is a mismatch");
    }

    #[test]
    fn a_card_held_identity_writes_no_key_into_the_vault() {
        let card = FakeCard::p256("7777");
        let (_, root) = root_of(&card).expect("a root");
        let plaintext = json!({ "v": 2, "roots": [root.clone()] });
        let text = serde_json::to_string(&plaintext).expect("json");
        assert!(!text.contains("pkcs8"), "no key material anywhere in the vault: {text}");
        assert_eq!(card_holder(&root).and_then(|h| h["mode"].as_str()), Some("generated"));
        // And the thing it does keep is the certificate, which is public.
        assert!(root["cert"].as_str().is_some());
    }

    #[test]
    fn one_live_leaf_is_refused_the_same_way_on_both_paths() {
        // The core applies this rule for a software root inside `wallet_issue`; the card path
        // applies it in `live_leaf_refusal`, because there is no key to hand the core. The two must
        // not drift, so here they are asked the same question about the same ledger.
        let key = PrivateKey::generate(Alg::P256).expect("a key");
        let cert = x509::build_root("Alina Rao", &key, NOW, &x509::serial_of("both-paths")).expect("a root");
        let fp = key.public().fingerprint();
        let software =
            json!({ "fingerprint": fp, "cn": "Alina Rao", "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(&cert), "created": instant(NOW) });
        let first = core(
            "wallet_issue",
            json!({ "vault_plaintext": { "v": 2, "roots": [software.clone()] }, "record_plaintext": { "v": 2, "ledger": [] }, "root_fingerprint": fp, "csr": b64u(&a_request(ENDPOINT)), "now": instant(NOW), "valid_days": 365 }),
        )
        .expect("a first leaf");
        let ledger = vec![first["ledger_entry"].clone()];
        let mine: Vec<&Value> = ledger.iter().collect();

        let elsewhere = "https://agent.alina.example/second/mcp";
        let core_says = core(
            "wallet_issue",
            json!({ "vault_plaintext": { "v": 2, "roots": [software] }, "record_plaintext": { "v": 2, "ledger": ledger.clone() }, "root_fingerprint": fp, "csr": b64u(&a_request(elsewhere)), "now": instant(NOW + 10), "valid_days": 365 }),
        )
        .unwrap_err();
        let cli_says = live_leaf_refusal(&mine, elsewhere, NOW + 10, false).expect("the card path refuses too");
        assert!(core_says.0.contains(&cli_says), "the same words on both paths:\n  core: {}\n  card: {cli_says}", core_says.0);
        // And a move says so on both.
        assert!(live_leaf_refusal(&mine, elsewhere, NOW + 10, true).is_none(), "--move allows it, as the core does");
        // A renewal at the same endpoint is never a second home.
        assert!(live_leaf_refusal(&mine, ENDPOINT, NOW + 10, false).is_none());
    }

    /// A card whose certificate names one key and whose slot holds another. Nothing it signs may
    /// become a certificate: the leaf would carry the pinned root as its issuer and a stranger's
    /// signature, and no contact could ever validate it.
    #[test]
    fn a_card_whose_certificate_and_key_disagree_gets_no_leaf() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let hostile = FakeCard::signs_with_another_key(&honest, "7777");
        // Every check that reads the certificate passes: the certificate is this root's.
        match_root(&root, &hostile).expect("the certificate in the slot is this identity's root");
        // The signature is the only thing that tells, and it is checked before anything is built.
        let e = issue_on_card(&hostile, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("does not verify"), "{}", e.0);
    }

    /// The check passes and the signature is a stranger's: the card was pulled and replaced, or the
    /// slot was generated again, between the two. This is the one that ends in an artefact if the
    /// signature is not verified — a leaf in the ledger that no contact can validate.
    #[test]
    fn a_card_that_swaps_its_key_after_the_check_signs_nothing_that_is_kept() {
        let honest = FakeCard::p256("7777");
        let (cert, root) = root_of(&honest).expect("a root");
        let hostile = FakeCard::swapped_after(&honest, 1);
        match issue_on_card(&hostile, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365) {
            Err(e) => assert!(e.0.contains("does not verify"), "{}", e.0),
            Ok(out) => {
                // What was assembled, and what it is worth, before failing — the defect is the
                // artefact, not the exit code.
                let r = core(
                    "validate_chain",
                    json!({ "chain": [out["der"].clone(), b64u(&cert)], "now": instant(NOW), "expected_root": root["fingerprint"] }),
                )
                .expect("an answer");
                panic!("a leaf was assembled from a card that swapped its key after the check; against the pinned root it is {r}");
            }
        }
    }

    /// Taken out of the reader between the check and the signature: the refusal says so, and
    /// nothing is assembled from a signature that never came.
    #[test]
    fn a_card_that_leaves_the_reader_mid_ceremony_says_so() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let gone = FakeCard::vanishes_after(1);
        let e = issue_on_card(&gone, &root, std::slice::from_ref(&root), &a_request(ENDPOINT), NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no longer in") || e.0.contains("a different card"), "{}", e.0);
        // And a card gone before the first word is the same refusal, not a panic.
        let e = root_from_card(&FakeCard::vanishes_after(0), "Alina Rao", NOW).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no longer in"), "{}", e.0);
    }

    /// Attaching a card records that every later signature comes from it, so the card proves it can
    /// sign before that is written down. The certificate in the slot is not that proof: this is the
    /// card `card-attach` used to wave through, and the failure would then have arrived at the
    /// first issuance, one PIN try at a time.
    #[test]
    fn attaching_a_card_that_only_holds_the_certificate_is_refused() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let pinned = root_key(&root).expect("the pinned key");
        card_proves_it_holds(&honest, &pinned).expect("the card that made this root can sign for it");
        let e = card_proves_it_holds(&FakeCard::signs_with_another_key(&honest, "8888"), &pinned).map(|_| ()).unwrap_err();
        assert!(e.0.contains("does not verify"), "{}", e.0);
        let e = card_proves_it_holds(&FakeCard::vanishes_after(0), &pinned).map(|_| ()).unwrap_err();
        assert!(e.0.contains("no longer in"), "{}", e.0);
    }

    /// A vault whose entry and whose certificate are for different keys is not an identity: it
    /// would issue under a key no contact pinned, and print a certificate nobody can check against
    /// the fingerprint they were given. Both halves are read together, everywhere.
    #[test]
    fn a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing() {
        let honest = FakeCard::p256("7777");
        let (_, root) = root_of(&honest).expect("a root");
        let stranger = root_of(&FakeCard::p256("8888")).expect("another root").1;
        let mut edited = root.clone();
        edited["cert"] = stranger["cert"].clone();
        let e = root_key(&edited).map(|_| ()).unwrap_err();
        assert!(e.0.contains("the vault has been edited"), "{}", e.0);
        let e =
            issue_on_card(&honest, &edited, std::slice::from_ref(&edited), &a_request(ENDPOINT), NOW, None, 365).map(|_| ()).unwrap_err();
        assert!(e.0.contains("the vault has been edited"), "{}", e.0);
    }
}
