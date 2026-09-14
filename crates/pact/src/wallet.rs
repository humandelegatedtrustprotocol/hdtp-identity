//! The wallet half: a root in a vault, leaves issued from it under SPEC §9's rules, the ledger, the
//! contact book. The rules live in the core's `wallet_issue`; this file adds the terminal's
//! discipline — the passphrase from a prompt, the vault owner-only, nothing a root key ever printed.
use crate::io::{confirm, core, fail, instant, now_or, passphrase, pem, read_der, read_input, write_output, write_private, Fail, Res};
use pact_identity::csr;
use pact_identity::keys::{Alg, PrivateKey};
use pact_identity::time::parse_rfc3339;
use pact_identity::util::{b64u, from_b64u};
use pact_identity::x509;
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroize;

struct Vault {
    path: String,
    passphrase: String,
    plaintext: Value,
}

// What the vault held in memory is cleared when the command is done with it: the passphrase
// zeroized, the plaintext — root keys among it — dropped to Null so its buffers are freed.
impl Drop for Vault {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        self.plaintext = Value::Null;
    }
}

fn open_vault(path: &str, confirm_passphrase: bool) -> Res<Vault> {
    let raw = read_input(path)?;
    let doc: Value = serde_json::from_slice(&raw).map_err(|e| Fail(format!("{path}: not a vault document ({e})")))?;
    let passphrase = passphrase(confirm_passphrase)?;
    let plaintext = core("vault_open", json!({ "passphrase": passphrase, "vault": doc }))?["plaintext"].take();
    Ok(Vault { path: path.to_string(), passphrase, plaintext })
}

fn save_vault(v: &Vault) -> Res<()> {
    let sealed = core("vault_seal", json!({ "passphrase": v.passphrase, "plaintext": v.plaintext }))?["vault"].take();
    write_private(Path::new(&v.path), format!("{}\n", serde_json::to_string_pretty(&sealed)?).as_bytes())
}

fn roots(v: &Value) -> Vec<Value> {
    v.get("roots").and_then(|r| r.as_array()).cloned().unwrap_or_default()
}

/// The root a command works with: the named one, or the only one.
fn pick_root(v: &Value, wanted: Option<&str>) -> Res<Value> {
    let all = roots(v);
    match wanted {
        Some(fp) => all.into_iter().find(|r| r["fingerprint"].as_str() == Some(fp)).ok_or_else(|| Fail(format!("no root {fp} in this vault"))),
        None => match all.len() {
            0 => fail("the vault holds no identity yet: pact id create"),
            1 => Ok(all[0].clone()),
            n => fail(format!("the vault holds {n} identities: say which with --root <fingerprint>")),
        },
    }
}

pub fn id_create(name: &str, alg: &str, vault: &str) -> Res<i32> {
    if Path::new(vault).exists() {
        return fail(format!("{vault} exists; a second identity goes in with --vault pointing elsewhere, or is a decision for later"));
    }
    let alg = Alg::parse(alg).map_err(|e| Fail(e.why))?;
    let pass = passphrase(true)?;
    let now = now_or(None)?;
    let key = PrivateKey::generate(alg).map_err(|e| Fail(e.why))?;
    let cert = x509::build_root(name, &key, now, &x509::random_serial().map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.why))?;
    let fp = key.public().fingerprint();
    let plaintext = json!({
        "v": 1,
        "roots": [{ "fingerprint": fp, "cn": name, "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(&cert), "created": instant(now) }],
        "ledger": [],
        "contacts": [],
    });
    save_vault(&Vault { path: vault.to_string(), passphrase: pass, plaintext })?;
    println!("{fp}");
    eprintln!("wrote {vault} (mode 0600)");
    eprintln!("This vault is the identity. There is no recovery: a lost vault, or a forgotten passphrase, is a lost identity. Keep a copy somewhere else (pact id backup).");
    Ok(0)
}

pub struct IssueArgs<'a> {
    pub vault: &'a str,
    pub csr: &'a str,
    pub valid_days: i64,
    pub moving: bool,
    pub renew_only: bool,
    pub origin: Option<&'a str>,
    pub root: Option<&'a str>,
    pub yes: bool,
    pub out: Option<&'a str>,
    pub chain_out: Option<&'a str>,
    pub now: Option<&'a str>,
}

pub fn id_issue(a: IssueArgs<'_>) -> Res<i32> {
    let csr_der = read_der(a.csr)?;
    let request = csr::parse(&csr_der).map_err(|e| Fail(format!("{}: {}", a.csr, e.why)))?;
    let now = now_or(a.now)?;
    let mut v = open_vault(a.vault, false)?;
    let root = pick_root(&v.plaintext, a.root)?;
    let fp = root["fingerprint"].as_str().unwrap_or("").to_string();
    let ledger: Vec<Value> = v.plaintext["ledger"].as_array().cloned().unwrap_or_default();
    let mine: Vec<&Value> = ledger.iter().filter(|l| l["root"].as_str() == Some(&fp)).collect();
    let host = x509::host_of(&request.endpoint).to_string();
    let known_endpoint = mine.iter().any(|l| l["endpoint"].as_str() == Some(request.endpoint.as_str()));
    let new_host = !mine.iter().any(|l| l["endpoint"].as_str().map(|e| x509::host_of(e) == host).unwrap_or(false));
    if a.renew_only && !known_endpoint {
        return fail(format!("{} is not in the ledger: a renewal is for an endpoint already issued to; use pact id issue", request.endpoint));
    }
    let previous = mine.iter().filter_map(|l| l["not_before"].as_str().and_then(|t| parse_rfc3339(t).ok())).max();
    let (nb, na) = csr::validity(now, previous, a.valid_days).map_err(|e| Fail(e.why))?;

    eprintln!("identity    {} ({})", fp, root["cn"].as_str().unwrap_or(""));
    eprintln!("endpoint    {}{}", request.endpoint, if new_host { "  NEW HOST: never issued to before" } else if known_endpoint { "  (renewal)" } else { "  (a new address on a known host)" });
    eprintln!("origin      {}", a.origin.unwrap_or("(not given)"));
    eprintln!("host key    {} ({})", request.key.fingerprint(), request.key.alg().name());
    eprintln!("valid       {} to {}  ({} days)", instant(nb), instant(na), a.valid_days);
    if a.moving {
        eprintln!("move        the live leaf at the previous endpoint is superseded once contacts see this one");
    }
    if new_host && !a.yes {
        // SPEC §9: a new endpoint needs the passphrase again, even in an unlocked session. The
        // vault was just opened with it; asking once more is the deliberate friction.
        let again = passphrase(false)?;
        if again != v.passphrase {
            return fail("the passphrase does not match: nothing signed");
        }
    }
    if !confirm("Sign this leaf?", a.yes)? {
        eprintln!("nothing signed");
        return Ok(1);
    }
    let r = core("wallet_issue", json!({ "vault_plaintext": v.plaintext, "root_fingerprint": fp, "csr": b64u(&csr_der), "now": instant(now), "valid_days": a.valid_days, "move": a.moving }))?;
    for w in r["warnings"].as_array().cloned().unwrap_or_default() {
        eprintln!("note        {}", w.as_str().unwrap_or(""));
    }
    let mut entry = r["ledger_entry"].clone();
    if let Some(o) = a.origin {
        entry["origin"] = json!(o);
    }
    v.plaintext["ledger"].as_array_mut().ok_or_else(|| Fail("vault ledger".into()))?.push(entry);
    save_vault(&v)?;
    let leaf = from_b64u(r["der"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    write_output(a.out, &pem("CERTIFICATE", &leaf))?;
    if let Some(p) = a.chain_out {
        let root_der = from_b64u(root["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
        write_output(Some(p), &format!("{}{}", pem("CERTIFICATE", &leaf), pem("CERTIFICATE", &root_der)))?;
    }
    eprintln!("issued      {} for {}", x509::parse(&leaf).map(|c| c.public_key.fingerprint()).unwrap_or_default(), request.endpoint);
    Ok(0)
}

pub fn id_ledger(vault: &str, root: Option<&str>, json: bool) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let now = now_or(None)?;
    let ledger: Vec<Value> = v.plaintext["ledger"].as_array().cloned().unwrap_or_default();
    let filter = root.map(String::from);
    let rows: Vec<&Value> = ledger.iter().filter(|l| filter.as_deref().is_none_or(|f| l["root"].as_str() == Some(f))).collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(0);
    }
    if rows.is_empty() {
        println!("no leaves issued");
        return Ok(0);
    }
    // The current leaf of a root is the live one with the latest notBefore.
    let current: Vec<usize> = roots(&v.plaintext)
        .iter()
        .filter_map(|r| {
            let fp = r["fingerprint"].as_str()?;
            rows.iter()
                .enumerate()
                .filter(|(_, l)| l["root"].as_str() == Some(fp) && l["not_after"].as_str().and_then(|t| parse_rfc3339(t).ok()).is_some_and(|t| t > now))
                .max_by_key(|(_, l)| l["not_before"].as_str().and_then(|t| parse_rfc3339(t).ok()).unwrap_or(0))
                .map(|(i, _)| i)
        })
        .collect();
    for (i, l) in rows.iter().enumerate() {
        let leaf_fp = l["leaf"].as_str().and_then(|b| from_b64u(b).ok()).and_then(|d| x509::parse(&d).ok()).map(|c| c.public_key.fingerprint()).unwrap_or_else(|| "?".into());
        println!(
            "{} {}  {}  {} to {}  root {}  key {}{}",
            if current.contains(&i) { "*" } else { " " },
            l["issued_at"].as_str().unwrap_or("-"),
            l["endpoint"].as_str().unwrap_or("-"),
            l["not_before"].as_str().unwrap_or("-"),
            l["not_after"].as_str().unwrap_or("-"),
            l["root"].as_str().unwrap_or("-"),
            leaf_fp,
            l["origin"].as_str().map(|o| format!("  asked by {o}")).unwrap_or_default()
        );
    }
    println!("* current");
    Ok(0)
}

pub fn id_show(vault: &str, root: Option<&str>, out: Option<&str>) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let r = pick_root(&v.plaintext, root)?;
    let der = from_b64u(r["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    eprintln!("{}  {}  created {}", r["fingerprint"].as_str().unwrap_or(""), r["cn"].as_str().unwrap_or(""), r["created"].as_str().unwrap_or(""));
    write_output(out, &pem("CERTIFICATE", &der))?;
    Ok(0)
}

pub fn id_backup(vault: &str, to: &str) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let raw = read_input(vault)?;
    write_private(Path::new(to), &raw)?;
    let back = read_input(to)?;
    let doc: Value = serde_json::from_slice(&back)?;
    core("vault_open", json!({ "passphrase": v.passphrase, "vault": doc }))?;
    eprintln!("copied {vault} to {to}; the copy opens");
    Ok(0)
}

pub fn id_restore(from: &str, vault: &str) -> Res<i32> {
    if Path::new(vault).exists() {
        return fail(format!("{vault} exists: restore goes to a path that is empty"));
    }
    let v = open_vault(from, false)?;
    write_private(Path::new(vault), &read_input(from)?)?;
    let doc: Value = serde_json::from_slice(&read_input(vault)?)?;
    core("vault_open", json!({ "passphrase": v.passphrase, "vault": doc }))?;
    eprintln!("restored {from} to {vault}: {} identities, {} leaves, {} contacts", roots(&v.plaintext).len(), v.plaintext["ledger"].as_array().map_or(0, |a| a.len()), v.plaintext["contacts"].as_array().map_or(0, |a| a.len()));
    Ok(0)
}

pub fn contacts_export(vault: &str) -> Res<i32> {
    let v = open_vault(vault, false)?;
    println!("{}", serde_json::to_string_pretty(&v.plaintext["contacts"])?);
    Ok(0)
}

fn contact_line(c: &Value) -> String {
    format!("{}  {}  {}", c["root"].as_str().unwrap_or("?"), c["endpoint"].as_str().unwrap_or("?"), c["name"].as_str().unwrap_or(""))
}

pub fn contacts_import(vault: &str, file: &str, yes: bool) -> Res<i32> {
    let incoming: Vec<Value> = serde_json::from_slice(&read_input(file)?).map_err(|e| Fail(format!("{file}: a JSON array of contacts ({e})")))?;
    for c in &incoming {
        if c["root"].as_str().is_none_or(|r| !r.starts_with("sha256:")) || c["endpoint"].as_str().is_none() {
            return fail(format!("{file}: every contact needs a root fingerprint and an endpoint"));
        }
    }
    let mut v = open_vault(vault, false)?;
    let mine: Vec<Value> = v.plaintext["contacts"].as_array().cloned().unwrap_or_default();
    let mut added = 0;
    let mut removed = 0;
    let mut changed = 0;
    for c in &incoming {
        match mine.iter().find(|m| m["root"] == c["root"]) {
            None => {
                added += 1;
                eprintln!("+ {}", contact_line(c));
            }
            Some(m) if m["endpoint"] != c["endpoint"] || m["leaf"] != c["leaf"] => {
                changed += 1;
                eprintln!("~ {}", contact_line(m));
                eprintln!("  now {}{}", c["endpoint"].as_str().unwrap_or("?"), if m["leaf"] != c["leaf"] { " (leaf differs)" } else { "" });
            }
            Some(_) => {}
        }
    }
    for m in &mine {
        if !incoming.iter().any(|c| c["root"] == m["root"]) {
            removed += 1;
            eprintln!("- {}", contact_line(m));
        }
    }
    if added + removed + changed == 0 {
        eprintln!("no differences: the book already matches");
        return Ok(0);
    }
    eprintln!("{added} added, {removed} removed, {changed} changed");
    if !confirm("Make this the wallet's contact book?", yes)? {
        eprintln!("nothing written");
        return Ok(1);
    }
    let now = instant(now_or(None)?);
    let merged: Vec<Value> = incoming
        .into_iter()
        .map(|mut c| {
            if c.get("added").is_none() {
                c["added"] = json!(mine.iter().find(|m| m["root"] == c["root"]).and_then(|m| m["added"].as_str()).unwrap_or(&now));
            }
            c
        })
        .collect();
    v.plaintext["contacts"] = Value::Array(merged);
    save_vault(&v)?;
    eprintln!("written");
    Ok(0)
}
