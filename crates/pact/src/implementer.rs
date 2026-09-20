//! The implementer's half: inspect a card, validate a chain, read a certificate, make and check a
//! request, mint a key. Every verdict is the core's; the terminal only formats it.
use crate::io::{core, fail, instant, now_or, pem, read_der, read_input, write_new_private, write_output, write_private, Res};
use pact_identity::keys::{Alg, PrivateKey, PublicKey};
use pact_identity::util::{b64u, from_b64u};
use pact_identity::x509;
use serde_json::{json, Value};
use std::path::Path;

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => "-".to_string(),
        Some(x) => x.to_string(),
    }
}

pub fn card_show(path: &str, now: Option<&str>, json: bool) -> Res<i32> {
    let text = String::from_utf8(read_input(path)?).map_err(|_| crate::io::Fail("the card is not UTF-8".into()))?;
    let now = now_or(now)?;
    let c = core("card_decode", json!({ "vcard": text, "now": instant(now) }))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&c)?);
        return Ok(0);
    }
    println!("name        {}", s(&c, "fn"));
    println!("root        {}", s(&c, "root"));
    println!("endpoint    {}", s(&c, "endpoint"));
    println!("leaf key    {} ({})", s(&c["leaf"], "fingerprint"), s(&c["leaf"], "alg"));
    println!(
        "valid       {} to {}{}",
        s(&c["leaf"], "not_before"),
        s(&c["leaf"], "not_after"),
        if c["expired"].as_bool().unwrap_or(false) { "  (expired: a bootstrap, not a proof)" } else { "" }
    );
    println!("seal        {}", s(&c, "seal"));
    let ignored: Vec<String> =
        c["ignored"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    println!("ignored     {}", if ignored.is_empty() { "none".to_string() } else { ignored.join(", ") });
    println!(
        "bytes       {}{}",
        s(&c, "bytes"),
        if c["bytes"].as_u64().unwrap_or(0) > 1024 { "  (over a kilobyte: too big for a QR)" } else { "" }
    );
    Ok(0)
}

pub fn card_check(path: &str, now: Option<&str>) -> Res<i32> {
    let text = String::from_utf8(read_input(path)?).map_err(|_| crate::io::Fail("the card is not UTF-8".into()))?;
    let now = now_or(now)?;
    match core("card_decode", json!({ "vcard": text, "now": instant(now) })) {
        Ok(c) => {
            println!(
                "accepted: root {} at {}{}",
                s(&c, "root"),
                s(&c, "endpoint"),
                if c["expired"].as_bool().unwrap_or(false) { " (leaf expired)" } else { "" }
            );
            Ok(0)
        }
        Err(e) => {
            println!("refused: {}", e.0);
            Ok(1)
        }
    }
}

pub fn chain_check(
    leaf: Option<&str>,
    root: Option<&str>,
    bundle: Option<&str>,
    expect_root: Option<&str>,
    expect_endpoint: Option<&str>,
    now: Option<&str>,
) -> Res<i32> {
    let chain: Vec<Vec<u8>> = match (bundle, leaf, root) {
        (Some(b), _, _) => {
            let raw = read_input(b)?;
            if raw.starts_with(b"-----BEGIN") {
                crate::io::pem_blocks(&raw)?.into_iter().map(|(_, d)| d).collect()
            } else {
                return fail("--chain wants a PEM bundle, leaf first; use --leaf and --root for DER files");
            }
        }
        (None, Some(l), Some(r)) => vec![read_der(l)?, read_der(r)?],
        _ => return fail("give --leaf and --root, or --chain with a PEM bundle"),
    };
    let now = now_or(now)?;
    let r = core(
        "validate_chain",
        json!({ "chain": chain.iter().map(|c| b64u(c)).collect::<Vec<_>>(), "now": instant(now), "expected_root": expect_root, "expected_endpoint": expect_endpoint }),
    )?;
    if r["ok"].as_bool().unwrap_or(false) {
        println!("accepted");
        println!("root        {}", s(&r, "root_fingerprint"));
        println!("endpoint    {}", s(&r, "endpoint"));
        println!("leaf key    {} ({})", s(&r, "leaf_fingerprint"), s(&r, "alg"));
        println!("valid       {} to {}", s(&r, "not_before"), s(&r, "not_after"));
        Ok(0)
    } else {
        println!("refused by rule {}: {}", r["rule"], s(&r, "reason"));
        Ok(1)
    }
}

pub fn cert_show(path: &str, json: bool) -> Res<i32> {
    let der = read_der(path)?;
    let c = core("parse_certificate", json!({ "der": b64u(&der) }))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&c)?);
        return Ok(0);
    }
    println!("kind        {}", s(&c, "kind"));
    println!("subject     {}", s(&c, "subject"));
    println!("issuer      {}", s(&c, "issuer"));
    println!("key         {} ({})", s(&c, "fingerprint"), s(&c, "alg"));
    println!("serial      {}", s(&c, "serial"));
    println!("valid       {} to {}", s(&c, "not_before"), s(&c, "not_after"));
    if let Some(u) = c["uris"].as_array().filter(|u| !u.is_empty()) {
        println!("endpoint    {}", u.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "));
    }
    if let Some(d) = c["dns"].as_array().filter(|d| !d.is_empty()) {
        println!("dns         {}", d.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "));
    }
    if let Some(aki) = c["aki"].as_str() {
        println!("issuer key  sha256:{aki}");
    }
    println!("bytes       {}", s(&c, "bytes"));
    match c["profile_error"].as_str() {
        None => println!("profile     exact (§14.1)"),
        Some(e) => println!("profile     NOT a PACT certificate: {e}"),
    }
    Ok(0)
}

pub fn csr_new(key: &str, endpoint: &str, cn: Option<&str>, dns: bool, out: Option<&str>) -> Res<i32> {
    let pkcs8 = read_der(key)?;
    let k = PrivateKey::from_pkcs8(&pkcs8).map_err(|e| crate::io::Fail(format!("{key}: {}", e.why)))?;
    let host = x509::host_of(endpoint).to_string();
    let cn = cn.map(String::from).unwrap_or(host.clone());
    let r = core(
        "csr_new",
        json!({ "cn": cn, "host_pkcs8": b64u(&k.to_pkcs8()), "endpoint": endpoint, "dns_name": if dns { Some(host.as_str()) } else { None } }),
    )?;
    let der = from_b64u(r["der"].as_str().unwrap_or("")).map_err(|e| crate::io::Fail(e.why))?;
    write_output(out, &pem("CERTIFICATE REQUEST", &der))?;
    eprintln!("request for {endpoint} by {}", k.public().fingerprint());
    Ok(0)
}

/// A root's public key from a file: an SPKI, or a certificate whose key it is.
fn spki_of_file(path: &str) -> Res<Vec<u8>> {
    let der = read_der(path)?;
    if let Ok(c) = x509::parse(&der) {
        return Ok(c.spki);
    }
    PublicKey::from_spki(&der)
        .map(|p| p.spki().to_vec())
        .map_err(|e| crate::io::Fail(format!("{path}: neither a certificate nor a public key ({})", e.why)))
}

pub fn csr_check(path: &str, root_spkis: &[String]) -> Res<i32> {
    let der = read_der(path)?;
    let roots: Vec<String> = root_spkis.iter().map(|p| spki_of_file(p).map(|s| b64u(&s))).collect::<Res<_>>()?;
    let r = core("csr_check", json!({ "der": b64u(&der), "root_spkis": roots }))?;
    if r["ok"].as_bool().unwrap_or(false) {
        println!("accepted");
        println!("name        {}", s(&r, "cn"));
        println!("endpoint    {}", s(&r, "endpoint"));
        println!("key         {} ({})", s(&r, "fingerprint"), s(&r, "alg"));
        if let Some(d) = r["dns_name"].as_str() {
            println!("dns         {d}");
        }
        Ok(0)
    } else {
        println!("refused: {}", s(&r, "why"));
        Ok(1)
    }
}

pub fn key_new(alg: &str, out: &str, force: bool) -> Res<i32> {
    // A host's leaf key is not written over. The leaf that is live was issued to *this* key, and a
    // fresh one at the same name would leave the host unable to serve it and unable to get it back
    // — the same rule `id create --key-out` has always had, on the command that makes keys.
    let alg = Alg::parse(alg).map_err(|e| crate::io::Fail(e.why))?;
    if !force && Path::new(out).exists() {
        return fail(format!("{out} exists: a live leaf was issued to the key that is there (pass --force to replace it)"));
    }
    crate::io::check_writable(Some(out))?;
    let k = PrivateKey::generate(alg).map_err(|e| crate::io::Fail(e.why))?;
    // Exclusive, because the check above is a moment old: the refusal has to still be true at the
    // moment the file appears.
    match force {
        false => write_new_private(Path::new(out), &k.to_pkcs8())?,
        true => write_private(Path::new(out), &k.to_pkcs8())?,
    }
    println!("{}", k.public().fingerprint());
    eprintln!("wrote {out} (PKCS #8 DER, mode 0600)");
    Ok(0)
}
