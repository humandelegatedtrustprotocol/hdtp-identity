//! The identity commands but `id create --piv`, which makes a root on a card (card.rs): `id create`,
//! `id issue` and `id renew`, `id ledger`, `id show`, `id backup` and `id restore`.
use super::card::{card_for, card_holder, issue_on_card, root_key};
use super::files::{empty_record, land_all, open_record, open_vault, pick_root, real, record_of, roots, save_record, sealed_bytes};
use crate::io::{
    check_writable, confirm, core, fail, instant, now_or, passphrase, pem, read_der, read_input, write_new_private, write_output, Fail, Res,
};
use hdtp_identity::csr;
use hdtp_identity::keys::{Alg, PrivateKey};
use hdtp_identity::time::parse_rfc3339;
use hdtp_identity::util::{b64u, from_b64u};
use hdtp_identity::x509;
use serde_json::{json, Value};
use std::path::Path;

pub fn id_create(name: &str, alg: &str, vault: &str, key_out: Option<&str>) -> Res<i32> {
    // Every reason this command can refuse is found before a person is asked for a passphrase and
    // before a vault exists on disk. The `--key-out` check used to sit after the vault was
    // written, which left a made identity behind and told the person it had failed.
    let (record, record_real) = record_of(vault);
    for (taken, really) in [(vault, real(vault)), (record.as_str(), record_real.clone())] {
        if Path::new(&really).exists() {
            return fail(format!("{taken} exists; a second identity goes in with --vault pointing elsewhere, or is a decision for later"));
        }
    }
    if let Some(path) = key_out {
        if Path::new(path).exists() {
            return fail(format!("{path} exists: the key is not written over a file"));
        }
        check_writable(Some(path))?;
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let alg = Alg::parse(alg).map_err(|e| Fail(e.why))?;
    let pass = passphrase(true)?;
    let now = now_or(None)?;
    let key = PrivateKey::generate(alg).map_err(|e| Fail(e.why))?;
    let cert = x509::build_root(name, &key, now, &x509::random_serial().map_err(|e| Fail(e.why))?).map_err(|e| Fail(e.why))?;
    let fp = key.public().fingerprint();
    let mut plaintext = json!({
        "v": 1,
        "roots": [{ "fingerprint": fp, "cn": name, "pkcs8": b64u(&key.to_pkcs8()), "cert": b64u(&cert), "created": instant(now) }],
    });
    // Both files, or neither: a vault whose record could not be written is taken away again.
    let vault_real = real(vault);
    let files = [
        (vault, vault_real.as_str(), sealed_bytes(&pass, &plaintext)?),
        (record.as_str(), record_real.as_str(), sealed_bytes(&pass, &empty_record())?),
    ];
    crate::io::wipe(&mut plaintext);
    land_all(&files, &pass, false)?.iter_mut().for_each(crate::io::wipe);
    println!("{fp}");
    eprintln!("wrote {vault} (mode 0600): the root, and nothing else — written again only if a card takes the root");
    eprintln!("wrote {record} (mode 0600): the ledger and the contact book, under the same passphrase");
    eprintln!("The vault is the identity. There is no recovery: a lost vault, or a forgotten passphrase, is a lost identity. Keep a copy somewhere else (hdtp id backup).");
    if let Some(path) = key_out {
        // Exclusive, because the check above is a moment old by now: nothing else may have taken
        // this name, and nothing that did will be written over or followed.
        write_new_private(Path::new(path), pem("PRIVATE KEY", &key.to_pkcs8()).as_bytes())?;
        eprintln!();
        eprintln!("wrote {path} (mode 0600): this file IS the root key, in the clear.");
        eprintln!("  ykman piv keys import 9c {path}");
        eprintln!("  ykman piv certificates generate 9c --subject 'CN={name}'   # a certificate in the slot, so the key can be read back");
        eprintln!("  hdtp card-attach --vault {vault} --slot 9c");
        eprintln!("Destroy {path} once the card holds it. The vault keeps this key, which is what makes this arrangement recoverable and weaker than a root generated on the card.");
    }
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
    /// Which reader, when the root is held on a card and this machine has more than one.
    pub reader: Option<&'a str>,
}

pub fn id_issue(a: IssueArgs<'_>) -> Res<i32> {
    let csr_der = read_der(a.csr)?;
    let request = csr::parse(&csr_der).map_err(|e| Fail(format!("{}: {}", a.csr, e.why)))?;
    let now = now_or(a.now)?;
    let v = open_vault(a.vault, false)?;
    let mut rec = open_record(&v)?;
    // No record here means no ledger here: this vault cannot say which leaf is live, so what it signs
    // is a replacement of whatever is (owner, 2026-09-26) — said before the question, not after.
    let replacing = !rec.found;
    let root = pick_root(&v.plaintext, a.root)?;
    // The entry and the certificate it keeps must be for the same key on either path, software or
    // card: a vault edited between the two would issue under a root no contact has.
    root_key(&root)?;
    // And where the leaf is going is checked before it is signed. A leaf signed, written into the
    // ledger, and then lost to a directory that does not exist would leave this identity's one live
    // leaf spoken for by a certificate nobody has.
    check_writable(a.out)?;
    check_writable(a.chain_out)?;
    let fp = root["fingerprint"].as_str().unwrap_or("").to_string();
    // The ledger's rules, from the one place they are written (the core's `ledger_check`): the
    // software path's `wallet_issue` applies the same ones, and the card path has only this.
    let mut ask = json!({ "root": fp, "endpoint": request.endpoint, "now": instant(now), "move": a.moving });
    if !replacing {
        ask["ledger"] = rec.plaintext["ledger"].clone();
    }
    let facts = core("ledger_check", ask)?;
    let known_endpoint = facts["known_endpoint"].as_bool().unwrap_or(false);
    let new_host = facts["new_host"].as_bool().unwrap_or(true);
    let previous = facts["previous_not_before"].as_str().map(parse_rfc3339).transpose().map_err(|e| Fail(e.why))?;
    if a.renew_only && replacing {
        return fail(format!(
            "no record at {}: a renewal is for an endpoint the ledger knows, and the ledger is not here; restore the record, or issue a replacement with hdtp id issue",
            rec.path
        ));
    }
    if a.renew_only && !known_endpoint {
        return fail(format!(
            "{} is not in the ledger: a renewal is for an endpoint already issued to; use hdtp id issue",
            request.endpoint
        ));
    }
    let (nb, na) = csr::validity(now, previous, a.valid_days).map_err(|e| Fail(e.why))?;

    eprintln!("identity    {} ({})", fp, root["cn"].as_str().unwrap_or(""));
    eprintln!(
        "endpoint    {}{}",
        request.endpoint,
        if replacing {
            "  (no ledger here to compare it with)"
        } else if new_host {
            "  NEW HOST: never issued to before"
        } else if known_endpoint {
            "  (renewal)"
        } else {
            "  (a new address on a known host)"
        }
    );
    eprintln!("origin      {}", a.origin.unwrap_or("(not given)"));
    eprintln!("host key    {} ({})", request.key.fingerprint(), request.key.alg().name());
    eprintln!("valid       {} to {}  ({} days)", instant(nb), instant(na), a.valid_days);
    if let Some(why) = facts["refusal"].as_str() {
        return fail(format!("bad_request: {why}"));
    }
    let name = root["cn"].as_str().unwrap_or("this identity");
    if let Some(words) = move_notice(&facts, name, &request.endpoint) {
        eprintln!();
        eprintln!("{words}");
        eprintln!();
    }
    if replacing {
        eprintln!("record      none at {}: this vault's ledger is not here, so it cannot say which leaf is live", rec.path);
        eprintln!(
            "replaces    whatever leaf this identity has live, wherever it is — contacts take the newest — and {} is started with this one",
            rec.path
        );
    }
    if !known_endpoint {
        // SPEC §9: a NEW ENDPOINT needs the passphrase again, even in an unlocked session — a new
        // host is only the loudest case of one. The vault was just opened with it; asking once
        // more is the deliberate friction, and `--yes` does not skip it: `--yes` answers the
        // question below, not this one. With HDTP_PASSPHRASE_FILE the file is read again, so the
        // re-check proves the file still opens the vault rather than asking a person.
        let again = passphrase(false)?;
        if *again != *v.passphrase {
            return fail("the passphrase does not match: nothing signed");
        }
    }
    // The card is opened before the question, not after: a card that is absent, or holds another
    // key, is a thing to say now rather than after a person has agreed to a signature.
    let card = match card_holder(&root) {
        Some(h) => {
            let c = card_for(&root, a.reader)?;
            let i = c.describe();
            eprintln!(
                "held        on card {} slot {}{}",
                i.serial.clone().unwrap_or_else(|| "?".into()),
                i.slot,
                if h["serial"].as_str().is_some_and(|s| Some(s) != i.serial.as_deref()) {
                    "  (a different card from the one this identity was made on)"
                } else {
                    ""
                }
            );
            Some(c)
        }
        None => None,
    };
    if !confirm("Sign this leaf?", a.yes)? {
        eprintln!("nothing signed");
        return Ok(1);
    }
    let r = match &card {
        // A card-held root: the core checks the request and makes the bytes, the card signs them,
        // the core assembles. The one rule `wallet_issue` would have applied and cannot here —
        // one live leaf per identity — was applied above by `ledger_check`, against the same ledger.
        Some(c) => {
            let mut out = issue_on_card(c.as_ref(), &root, &roots(&v.plaintext), &csr_der, now, previous, a.valid_days)?;
            // The endpoint and the dates, as the core's entry: never the leaf.
            out["ledger_entry"] = json!({
                "root": fp,
                "endpoint": out["endpoint"].clone(),
                "not_before": out["not_before"].clone(),
                "not_after": out["not_after"].clone(),
                "issued_at": instant(now),
            });
            out
        }
        None => core(
            "wallet_issue",
            json!({ "vault_plaintext": v.plaintext, "record_plaintext": rec.plaintext, "root_fingerprint": fp, "csr": b64u(&csr_der), "now": instant(now), "valid_days": a.valid_days, "move": a.moving }),
        )?,
    };
    for w in r["warnings"].as_array().cloned().unwrap_or_default() {
        eprintln!("note        {}", w.as_str().unwrap_or(""));
    }
    let mut entry = r["ledger_entry"].clone();
    if let Some(o) = a.origin {
        entry["origin"] = json!(o);
    }
    // The record is what a signing writes; the vault is never touched. (`open_record` refused a
    // record without a ledger before anything was signed.)
    rec.plaintext["ledger"].as_array_mut().ok_or_else(|| Fail(format!("{}: the ledger went missing", rec.path)))?.push(entry);
    save_record(&v, &rec)?;
    if replacing {
        eprintln!("started     {}: the ledger begins with this leaf", rec.path);
    }
    let leaf = from_b64u(r["der"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    write_output(a.out, &pem("CERTIFICATE", &leaf))?;
    if let Some(p) = a.chain_out {
        let root_der = from_b64u(root["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
        write_output(Some(p), &format!("{}{}", pem("CERTIFICATE", &leaf), pem("CERTIFICATE", &root_der)))?;
    }
    eprintln!("issued      {} for {}", x509::parse(&leaf).map(|c| c.public_key.fingerprint()).unwrap_or_default(), request.endpoint);
    Ok(0)
}

/// The move notice (design §3), in the words a person reads before signing, from `ledger_check`'s
/// facts: for a move or a move back, and for a signer with no ledger, whose words say what it cannot
/// see. None for a renewal or a first leaf, which move nobody.
pub(super) fn move_notice(facts: &Value, name: &str, endpoint: &str) -> Option<String> {
    let notice = &facts["notice"];
    match notice["kind"].as_str()? {
        "move" | "move_back" => {
            let from = notice["from"].as_str().unwrap_or("?");
            let until = notice["until"].as_str().unwrap_or("?");
            let old_host = x509::host_of(from);
            Some(format!(
                "You are moving {name} to {endpoint}. Nothing cancels a certificate in HDTP. The one at {from} stays valid until {until}.\n\n\
                 Each contact switches to the new address the moment it sees this certificate. Your new host contacts each of them to show it. A contact it does not reach keeps using {from} until {until}.\n\n\
                 {old_host} is not told by this signature. It keeps serving and keeps its key until you delete the identity there. Do that after your new host reports your contacts reached. The address stays reserved until {until}.\n\n\
                 Renewing at {old_host} later would move your contacts back. This wallet refuses that unless you choose to move back."
            ))
        }
        "no_ledger" => Some(
            "This wallet cannot see the ledger your other wallet keeps. That wallet will not know about this certificate, and a renewal there would move your contacts back. Sign your moves in one wallet."
                .to_string(),
        ),
        _ => None,
    }
}

pub fn id_ledger(vault: &str, root: Option<&str>, json: bool) -> Res<i32> {
    // The vault first: it is what proves the passphrase (a record that is not there proves nothing)
    // and what refuses a mistyped path, which would otherwise read as an identity with no leaves.
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    if !r.found {
        eprintln!("no record at {}: this vault's ledger is not here", r.path);
    }
    let now = now_or(None)?;
    let ledger = &r.plaintext["ledger"];
    let filter = root.map(String::from);
    let rows: Vec<(usize, &Value)> = ledger
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
        .filter(|(_, l)| filter.as_deref().is_none_or(|f| l["root"].as_str() == Some(f)))
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows.iter().map(|(_, l)| l).collect::<Vec<_>>())?);
        return Ok(0);
    }
    if rows.is_empty() {
        println!("{}", if r.found { "no leaves issued" } else { "no ledger here" });
        return Ok(0);
    }
    let current = match current_entries(ledger, &rows, now) {
        Ok(current) => current,
        Err(why) => {
            eprintln!("the ledger does not read ({why}): no entry is marked current");
            Vec::new()
        }
    };
    for (i, l) in &rows {
        println!(
            "{} {}  {}  {} to {}  root {}{}",
            if current.contains(i) { "*" } else { " " },
            l["issued_at"].as_str().unwrap_or("-"),
            l["endpoint"].as_str().unwrap_or("-"),
            l["not_before"].as_str().unwrap_or("-"),
            l["not_after"].as_str().unwrap_or("-"),
            l["root"].as_str().unwrap_or("-"),
            l["origin"].as_str().map(|o| format!("  asked by {o}")).unwrap_or_default()
        );
    }
    println!("* current");
    Ok(0)
}

/// The entries of the listing that are current: each root's live leaf, as the core's ledger rules name
/// it (`ledger::live_entry`, what `ledger_check` reports as `live`) — its newest entry by notBefore,
/// the first of equals, if that has not expired. This picked the newest of the UNEXPIRED entries and
/// the last of equals, so the `*` could sit on an entry the rules treat as history (X8).
fn current_entries(ledger: &Value, rows: &[(usize, &Value)], now: i64) -> Result<Vec<usize>, String> {
    let mut roots: Vec<&str> = rows.iter().filter_map(|(_, l)| l["root"].as_str()).collect();
    roots.sort_unstable();
    roots.dedup();
    let mut current = Vec::new();
    for fp in roots {
        if let Some(i) = hdtp_identity::ledger::live_entry(ledger, fp, now).map_err(|e| e.why)? {
            current.push(i);
        }
    }
    Ok(current)
}

pub fn id_show(vault: &str, root: Option<&str>, out: Option<&str>) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let r = pick_root(&v.plaintext, root)?;
    // What is printed here is what a contact pins, so it is the entry's own key or nothing.
    root_key(&r)?;
    let der = from_b64u(r["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    eprintln!(
        "{}  {}  created {}",
        r["fingerprint"].as_str().unwrap_or(""),
        r["cn"].as_str().unwrap_or(""),
        r["created"].as_str().unwrap_or("")
    );
    write_output(out, &pem("CERTIFICATE", &der))?;
    Ok(0)
}

pub fn id_backup(vault: &str, to: &str, force: bool) -> Res<i32> {
    let v = open_vault(vault, false)?;
    let r = open_record(&v)?;
    let (record_to, record_to_real) = record_of(to);
    let dests = [(to, real(to)), (record_to.as_str(), record_to_real.clone())];
    // A backup onto either of its own sources would replace the identity with a copy of itself — or,
    // onto the record, with the vault's bytes, and the ledger and contacts gone with no copy anywhere.
    for (shown, really) in &dests {
        for source in [&v.real, &r.real] {
            if really == source {
                return fail(format!(
                    "{shown} is {}: a backup goes somewhere other than the identity it copies",
                    if *source == v.real { vault } else { &r.path }
                ));
            }
        }
    }
    for (shown, really) in &dests {
        if Path::new(really).exists() && !force {
            return fail(format!("{shown} exists: a backup never writes over a file (pass --force to replace it)"));
        }
    }
    check_writable(Some(to))?;
    check_writable(Some(&record_to))?;
    // Both copies or neither, each proven to open before it counts (`land_all`).
    let mut files = vec![(to, dests[0].1.as_str(), read_input(&v.real)?)];
    if r.found {
        files.push((record_to.as_str(), dests[1].1.as_str(), read_input(&r.real)?));
    }
    land_all(&files, &v.passphrase, force)?.iter_mut().for_each(crate::io::wipe);
    eprintln!("copied {vault} to {to}; the copy opens");
    if r.found {
        eprintln!("copied {} to {record_to}; the copy opens", r.path);
    } else {
        eprintln!("no record at {}: the ledger and the contacts were not there to copy", r.path);
    }
    Ok(0)
}

pub fn id_restore(from: &str, vault: &str) -> Res<i32> {
    let (record, record_real) = record_of(vault);
    for (taken, really) in [(vault, real(vault)), (record.as_str(), record_real.clone())] {
        if Path::new(&really).exists() {
            return fail(format!("{taken} exists: restore goes to a path that is empty"));
        }
    }
    check_writable(Some(vault))?;
    check_writable(Some(&record))?;
    let v = open_vault(from, false)?;
    let (record_from, record_from_real) = record_of(from);
    let with_record = Path::new(&record_from_real).exists();
    // Both, or neither: a vault landed without the record it came with would run on an empty ledger.
    let mut files = vec![(vault, real(vault), read_input(&v.real)?)];
    if with_record {
        files.push((record.as_str(), record_real.clone(), read_input(&record_from_real)?));
    }
    let files: Vec<(&str, &str, Vec<u8>)> = files.iter().map(|(a, b, c)| (*a, b.as_str(), c.clone())).collect();
    let mut landed = land_all(&files, &v.passphrase, false)?;
    eprint!("restored {from} to {vault}: {} identities", roots(&v.plaintext).len());
    if let Some(r) = landed.get(1) {
        eprintln!(
            "; and its record {record_from} to {record}: {} leaves, {} contacts",
            r["ledger"].as_array().map_or(0, |a| a.len()),
            r["contacts"].as_array().map_or(0, |a| a.len())
        );
    } else {
        eprintln!("; no record beside {from}, so the next leaf this vault issues replaces whatever was live");
    }
    landed.iter_mut().for_each(crate::io::wipe);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdtp_identity::time::format_rfc3339;

    const ROOT: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const A: &str = "https://agent.alina.example/mcp";
    const B: &str = "https://alina.host.example/alina/mcp";
    const NOW: i64 = 1_789_214_400; // 2026-09-12T12:00:00Z
    const DAY: i64 = 86_400;

    fn entry(root: &str, endpoint: &str, nb: i64, na: i64) -> Value {
        json!({ "root": root, "endpoint": endpoint, "not_before": format_rfc3339(nb), "not_after": format_rfc3339(na), "issued_at": format_rfc3339(nb) })
    }

    fn marked(ledger: &Value, root: Option<&str>) -> Result<Vec<usize>, String> {
        let rows: Vec<(usize, &Value)> =
            ledger.as_array().unwrap().iter().enumerate().filter(|(_, l)| root.is_none_or(|r| l["root"].as_str() == Some(r))).collect();
        current_entries(ledger, &rows, NOW)
    }

    /// The `*` of `hdtp id ledger` sits on the entry the ledger rules call live, and on no other (X8).
    #[test]
    fn the_listing_marks_the_leaf_the_rules_call_live() {
        // Two entries share the newest notBefore: the first of them, in ledger order, as the core
        // reads it — max_by_key marked the last.
        let tie = json!([
            entry(ROOT, A, NOW - 10 * DAY, NOW + 300 * DAY),
            entry(ROOT, B, NOW - DAY, NOW + 90 * DAY),
            entry(ROOT, A, NOW - DAY, NOW + 90 * DAY)
        ]);
        assert_eq!(marked(&tie, None), Ok(vec![1]));
        // The newest has expired and an older one has not: nothing is current. This marked the older
        // one, the newest of the unexpired, which the rules treat as history.
        let expired = json!([entry(ROOT, A, NOW - 10 * DAY, NOW + 300 * DAY), entry(ROOT, B, NOW - 2 * DAY, NOW - DAY)]);
        assert_eq!(marked(&expired, None), Ok(vec![]));
        // Each root's own, by its index in the ledger, whether or not the listing is filtered to it.
        let two = json!([entry(OTHER, B, NOW - DAY, NOW + 90 * DAY), entry(ROOT, A, NOW - 10 * DAY, NOW + 300 * DAY)]);
        assert_eq!(marked(&two, None), Ok(vec![1, 0]));
        assert_eq!(marked(&two, Some(ROOT)), Ok(vec![1]));
        // A ledger the rules refuse has no current entry to mark.
        assert!(marked(&json!([{ "root": ROOT, "endpoint": A }]), None).is_err());
    }
}
