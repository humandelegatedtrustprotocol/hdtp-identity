//! The binary end to end: a host's key and request, an identity in a vault, a leaf issued from it
//! that validates as a chain, the wallet's refusals, the Appendix B proof, a card read back.
use assert_cmd::Command;
use hdtp_identity::util::from_hex;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

fn hdtp() -> Command {
    Command::cargo_bin("hdtp").expect("the hdtp binary")
}

fn passphrase_file(dir: &Path, mode: u32) -> PathBuf {
    let p = dir.join("passphrase");
    fs::write(&p, "correct horse battery staple\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }
    p
}

/// The last line is `N/N checks passed` with the same N twice.
fn all_passed() -> impl Predicate<str> {
    predicate::function(|out: &str| {
        out.lines().rev().find(|l| l.ends_with("checks passed")).and_then(|l| {
            let (a, b) = l.split_once('/')?;
            let b = b.strip_suffix(" checks passed")?;
            Some(a == b && a.parse::<u32>().ok()? > 0)
        }) == Some(true)
    })
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Where the CLI keeps an identity's record: the rule `wallet::record_path` follows, held here so
/// that a change to it is seen.
fn record_of(vault: &std::path::Path) -> std::path::PathBuf {
    let name = vault.file_name().unwrap().to_string_lossy().to_string();
    let stem = name.strip_suffix(".json").unwrap_or(&name);
    let stem = stem.strip_suffix(".hdtp-vault").unwrap_or(stem);
    vault.with_file_name(format!("{stem}.hdtp-record.json"))
}

/// A sealed file opened as the core opens it, under the test's passphrase: what it holds, to judge.
fn open_sealed(path: &Path) -> serde_json::Value {
    let doc: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let answer: serde_json::Value = serde_json::from_str(&hdtp_identity::call(
        "vault_open",
        &serde_json::json!({ "passphrase": "correct horse battery staple", "vault": doc }).to_string(),
    ))
    .unwrap();
    assert!(answer.get("error").is_none(), "{} does not open: {answer}", path.display());
    answer["plaintext"].clone()
}

const CONTACT_HEADER: &str = "root,endpoint,name,display_name,status,was_active,permissions,their_permissions,leaf,root_cert,added";

/// The core's answer to one call, which must not be a refusal.
fn core_call(name: &str, args: serde_json::Value) -> serde_json::Value {
    let out: serde_json::Value = serde_json::from_str(&hdtp_identity::call(name, &args.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{name}: {out}");
    out
}

/// A vault's root, as its certificate: base64url DER.
fn root_cert_of_vault(pass: &Path, vault: &Path) -> String {
    let shown = hdtp().env("HDTP_PASSPHRASE_FILE", pass).args(["id", "show", "--vault"]).arg(vault).assert().success();
    let pem = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("").replace('+', "-").replace('/', "_").replace('=', "")
}

/// A vault's root fingerprint, read back through `cert show`.
fn fingerprint_of_vault(pass: &Path, vault: &Path, dir: &Path) -> String {
    let shown = hdtp().env("HDTP_PASSPHRASE_FILE", pass).args(["id", "show", "--vault"]).arg(vault).assert().success();
    let pem_path = dir.join("root.pem");
    fs::write(&pem_path, &shown.get_output().stdout).unwrap();
    let out = hdtp().args(["cert", "show", "--json"]).arg(&pem_path).assert().success();
    serde_json::from_slice::<serde_json::Value>(&out.get_output().stdout).unwrap()["fingerprint"].as_str().unwrap().to_string()
}

fn put(path: &Path, members: &[(&str, String)]) {
    let _ = fs::remove_file(path);
    let mut z = zip::ZipWriter::new(fs::File::create(path).unwrap());
    let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, text) in members {
        z.start_file(*name, opts).unwrap();
        std::io::Write::write_all(&mut z, text.as_bytes()).unwrap();
    }
    z.finish().unwrap();
}

/// A book as the core writes one, for `owner`.
fn write_book(path: &Path, owner: &str, rows: &[serde_json::Value]) {
    let w = core_call(
        "export_write",
        serde_json::json!({ "owner": owner, "owner_name": "", "exported_at": "2026-09-27T10:00:00Z", "tool": "cli.rs", "contacts": rows }),
    );
    let m = core_call("export_manifest", serde_json::json!({ "partial": w["partial"] }));
    put(
        path,
        &[
            ("contacts.csv", w["contacts_csv"].as_str().unwrap().to_string()),
            ("manifest.json", m["manifest"].as_str().unwrap().to_string()),
        ],
    );
}

/// A book around a contacts.csv written by hand, with a manifest that is true of it.
fn write_raw_book(path: &Path, owner: &str, contacts_csv: &str) {
    use sha2::Digest;
    let rows = contacts_csv.matches("\r\n").count() - 1;
    let manifest = serde_json::json!({
        "hdtp_export": 1, "owner": owner, "owner_name": "", "exported_at": "2026-09-27T10:00:00Z", "tool": "cli.rs",
        "counts": { "contacts": rows, "threads": 0, "messages": 0, "media": 0 },
        "files": { "contacts.csv": hdtp_identity::util::hex(&sha2::Sha256::digest(contacts_csv.as_bytes())) },
    });
    put(path, &[("contacts.csv", contacts_csv.to_string()), ("manifest.json", manifest.to_string())]);
}

fn zip_members(path: &Path) -> Vec<String> {
    let z = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
    let mut names: Vec<String> = z.file_names().map(String::from).collect();
    names.sort();
    names
}

fn zip_text(path: &Path, name: &str) -> String {
    let mut z = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut z.by_name(name).unwrap(), &mut text).unwrap();
    text
}

#[test]
fn a_host_key_a_request_an_identity_a_leaf_and_a_chain_that_validates() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = passphrase_file(d, 0o600);
    let key = d.join("host.key");
    let csr = d.join("host.csr");
    let vault = d.join("alina.hdtp-vault.json");
    let chain = d.join("chain.pem");

    // The host mints a key and a request for its address.
    hdtp().args(["key", "new", "--alg", "ed25519", "--out"]).arg(&key).assert().success().stdout(predicate::str::starts_with("sha256:"));
    hdtp()
        .args(["csr", "new", "--endpoint", "https://agent.alina.example/mcp", "--dns", "--key"])
        .arg(&key)
        .arg("--out")
        .arg(&csr)
        .assert()
        .success();
    hdtp()
        .args(["csr", "check"])
        .arg(&csr)
        .assert()
        .success()
        .stdout(predicate::str::contains("accepted").and(predicate::str::contains("https://agent.alina.example/mcp")));

    // The person makes an identity; the passphrase comes from the file, never the arguments.
    let out = hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "Alina Rao", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stderr(predicate::str::contains("lost identity"));
    let root_fp = String::from_utf8(out.get_output().stdout.clone()).unwrap().trim().to_string();
    assert!(root_fp.starts_with("sha256:"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&vault).unwrap().permissions().mode() & 0o777, 0o600, "the vault is owner-only");
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600, "the key is owner-only");
    }
    let text = fs::read_to_string(&vault).unwrap();
    assert!(text.contains("hdtp-vault/1") && !text.contains("pkcs8"), "the vault at rest shows no key material");
    // Two files: the vault, and its record beside it, named after it.
    let record = record_of(&vault);
    assert!(record.exists(), "the record is written with the vault, at {}", record.display());
    let vault_as_made = fs::read(&vault).unwrap();

    // The wallet issues; the leaf and the root validate as a chain for that address.
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--valid", "1y", "--origin", "https://wallet.example", "--csr"])
        .arg(&csr)
        .arg("--vault")
        .arg(&vault)
        .arg("--chain-out")
        .arg(&chain)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("-----BEGIN CERTIFICATE-----"))
        .stderr(predicate::str::contains("NEW HOST"));
    // The signing wrote the record and never the vault: the file a person keeps is the one they were given.
    assert_eq!(fs::read(&vault).unwrap(), vault_as_made, "the vault is written once");
    // What each file holds, opened (SPEC §9): the vault the root and nothing else, the record the
    // ledger and the contacts and no key. (A search of the ciphertext for "pkcs8" could not fail.)
    let held = open_sealed(&vault);
    let members: Vec<&str> = held.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(members, ["v", "roots"], "the vault is the root and nothing else");
    assert!(held["roots"][0]["pkcs8"].is_string(), "the vault carries the root's key");
    let kept = open_sealed(&record);
    assert!(kept["roots"].as_array().is_none_or(|r| r.iter().all(|e| e.get("pkcs8").is_none())), "the record holds no key: {kept}");
    assert_eq!(kept["ledger"].as_array().map(Vec::len), Some(1), "the record holds the signing's ledger entry");
    assert!(kept["ledger"][0].get("leaf").is_none(), "a ledger entry is the endpoint and the dates, never the leaf");
    hdtp()
        .args(["chain", "check", "--expect-endpoint", "https://agent.alina.example/mcp", "--expect-root", &root_fp, "--chain"])
        .arg(&chain)
        .assert()
        .success()
        .stdout(predicate::str::contains("accepted"));
    hdtp()
        .args(["chain", "check", "--expect-endpoint", "https://agent.alina.example/mcp/", "--chain"])
        .arg(&chain)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("refused by rule 5"));
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "ledger", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::contains("* ").and(predicate::str::contains("asked by https://wallet.example")));

    // A second endpoint while a leaf is live is a move, refused without saying so.
    let key2 = d.join("host2.key");
    let csr2 = d.join("host2.csr");
    hdtp().args(["key", "new", "--alg", "p256", "--out"]).arg(&key2).assert().success();
    hdtp()
        .args(["csr", "new", "--endpoint", "https://alina.host.example/alina/mcp", "--key"])
        .arg(&key2)
        .arg("--out")
        .arg(&csr2)
        .assert()
        .success();
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--csr"])
        .arg(&csr2)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("move"));
    // The same endpoint again is a renewal: a fresh key, no flag needed.
    let key3 = d.join("host3.key");
    let csr3 = d.join("host3.csr");
    hdtp().args(["key", "new", "--out"]).arg(&key3).assert().success();
    hdtp()
        .args(["csr", "new", "--endpoint", "https://agent.alina.example/mcp", "--key"])
        .arg(&key3)
        .arg("--out")
        .arg(&csr3)
        .assert()
        .success();
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "renew", "--yes", "--csr"])
        .arg(&csr3)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .success()
        .stderr(predicate::str::contains("(renewal)"));
    // A renewal for an endpoint never issued to is refused as such.
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "renew", "--yes", "--csr"])
        .arg(&csr2)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in the ledger"));
    // With --move the wallet issues for the new address.
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--move", "--csr"])
        .arg(&csr2)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .success()
        .stderr(predicate::str::contains("move"));
    let ledger = hdtp().env("HDTP_PASSPHRASE_FILE", &pass).args(["id", "ledger", "--json", "--vault"]).arg(&vault).assert().success();
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&ledger.get_output().stdout).unwrap();
    assert_eq!(rows.len(), 3);

    // The root's certificate is public; the root's key never leaves. A backup opens.
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "show", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("-----BEGIN CERTIFICATE-----"));
    let copy = d.join("copy.json");
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "backup", "--vault"])
        .arg(&vault)
        .arg("--to")
        .arg(&copy)
        .assert()
        .success()
        .stderr(predicate::str::contains("the copy opens"));
    let restored = d.join("restored.json");
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "restore", "--from"])
        .arg(&copy)
        .arg("--vault")
        .arg(&restored)
        .assert()
        .success()
        .stderr(predicate::str::contains("3 leaves"));
    assert!(record_of(&restored).exists(), "the record is restored beside the vault");

    let as_hdtp = || {
        let mut cmd = hdtp();
        cmd.env("HDTP_PASSPHRASE_FILE", &pass);
        cmd
    };
    // The contact book: export it as a book (SPEC §9.2), and import books with one more contact, one
    // changed, and ones a host must refuse.
    let out = d.join("alina-book.zip");
    // A book's notice says what a book holds, the contact list, and nothing it does not: no
    // conversations, no files.
    let notice = "This file is not encrypted. Anyone who gets it can read your contact list. It holds no keys, so it cannot be used to speak as you. Keep it where you keep private documents, and delete it once it has been imported.";
    let said = as_hdtp().args(["contacts", "export", "--vault"]).arg(&vault).arg("--out").arg(&out).assert().success().stderr(
        predicate::str::contains(notice).and(predicate::str::contains("0 contacts")).and(predicate::str::contains("conversations").not()),
    );
    // The notice comes BEFORE the file is written (SPEC 9.2#3): ahead of the line that says it was
    // written, and said when the write itself then fails. A dangling link passes every check made
    // before the vault is opened (no file there, its directory there) and refuses the create.
    let said = String::from_utf8_lossy(&said.get_output().stderr).into_owned();
    assert!(said.find(notice) < said.find("wrote "), "the notice is printed before the file is written: {said}");
    #[cfg(unix)]
    {
        let (link, target) = (d.join("dangling-book.zip"), d.join("nowhere-book.zip"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        as_hdtp()
            .args(["contacts", "export", "--vault"])
            .arg(&vault)
            .arg("--out")
            .arg(&link)
            .assert()
            .failure()
            .stderr(predicate::str::contains(notice));
        assert!(!target.exists(), "the write failed, and the notice was already given");
    }
    assert_eq!(zip_members(&out), ["contacts.csv", "manifest.json"], "a book is the manifest and contacts.csv only");
    as_hdtp()
        .args(["contacts", "export", "--vault"])
        .arg(&vault)
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("exists: a book is not written over a file"));
    as_hdtp()
        .args(["contacts", "import", "--yes", "--vault"])
        .arg(&vault)
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("no differences"));
    let alina_fp = fingerprint_of_vault(&pass, &vault, d);
    // Bharat, with a root of his own: a contact is pinned by a fingerprint, and a `root_cert` is worth
    // only its binding to it.
    let bharat_vault = d.join("bharat.json");
    as_hdtp().args(["id", "create", "--name", "Bharat", "--vault"]).arg(&bharat_vault).assert().success();
    let bharat_fp = fingerprint_of_vault(&pass, &bharat_vault, d);
    let bharat_der = root_cert_of_vault(&pass, &bharat_vault);
    let alina_der = root_cert_of_vault(&pass, &vault);
    let incoming = d.join("incoming.zip");
    let row = |endpoint: &str, root_cert: Option<&str>| {
        serde_json::json!({
            "root": bharat_fp, "endpoint": endpoint, "name": "Bharat", "display_name": "", "status": "active", "was_active": true,
            "permissions": [], "their_permissions": [], "leaf": null, "root_cert": root_cert, "added": "2026-09-27T10:00:00Z",
        })
    };
    let import = |book: &Path| {
        let mut cmd = as_hdtp();
        cmd.args(["contacts", "import", "--yes", "--vault"]).arg(&vault).arg(book);
        cmd
    };
    write_book(&incoming, &alina_fp, &[row("https://b.example/mcp", None)]);
    import(&incoming).assert().success().stderr(predicate::str::contains("1 added, 0 removed, 0 changed"));
    write_book(&incoming, &alina_fp, &[row("https://c.example/mcp", None)]);
    import(&incoming).assert().success().stderr(predicate::str::contains("0 added, 0 removed, 1 changed"));
    fs::remove_file(&out).unwrap();
    as_hdtp().args(["contacts", "export", "--vault"]).arg(&vault).arg("--out").arg(&out).assert().success();
    assert!(zip_text(&out, "contacts.csv").contains("https://c.example/mcp"));

    // A root certificate that is not the pinned root's is refused, and nothing is written: §14.5's
    // planted row, arriving through the book. Written by hand: no port writes a row it would refuse.
    let csv = |cells: &str| format!("{}\r\n{cells}\r\n", CONTACT_HEADER);
    write_raw_book(
        &incoming,
        &alina_fp,
        &csv(&format!("{bharat_fp},https://c.example/mcp,Bharat,,active,true,,,,{alina_der},2026-09-27T10:00:00Z")),
    );
    import(&incoming)
        .assert()
        .failure()
        .stderr(predicate::str::contains("contacts.csv: row 2, column root_cert: not the certificate of this row's root"));
    // A root that is not a fingerprint at all.
    write_raw_book(&incoming, &alina_fp, &csv("sha256:AAAA,https://c.example/mcp,Bharat,,active,true,,,,,2026-09-27T10:00:00Z"));
    import(&incoming).assert().failure().stderr(predicate::str::contains("contacts.csv: row 2, column root: not a fingerprint"));
    // A book that is someone else's: the owner is the importing identity's root, or nothing is read.
    write_book(&incoming, &bharat_fp, &[]);
    import(&incoming).assert().failure().stderr(predicate::str::contains("manifest.json: owner: the file is"));
    // Not a zip at all.
    fs::write(&incoming, "[]").unwrap();
    import(&incoming).assert().failure().stderr(predicate::str::contains("the file is not a zip"));

    // Bharat's own certificate under Bharat's fingerprint is a change, is kept, and is exported again.
    write_book(&incoming, &alina_fp, &[row("https://c.example/mcp", Some(&bharat_der))]);
    import(&incoming)
        .assert()
        .success()
        .stderr(predicate::str::contains("0 added, 0 removed, 1 changed").and(predicate::str::contains("root certificate differs")));
    fs::remove_file(&out).unwrap();
    as_hdtp().args(["contacts", "export", "--vault"]).arg(&vault).arg("--out").arg(&out).assert().success();
    assert!(zip_text(&out, "contacts.csv").contains(&bharat_der));
    // And a book the CLI wrote is one the core reads back whole: the same contact, the same bytes.
    import(&out).assert().success().stderr(predicate::str::contains("no differences"));

    // A backup never writes over a file that is there, unless it is told to.
    let occupied = d.join("occupied.json");
    fs::write(&occupied, "not a vault").unwrap();
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "backup", "--vault"])
        .arg(&vault)
        .arg("--to")
        .arg(&occupied)
        .assert()
        .failure()
        .stderr(predicate::str::contains("exists"));
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "backup", "--force", "--vault"])
        .arg(&vault)
        .arg("--to")
        .arg(&occupied)
        .assert()
        .success()
        .stderr(predicate::str::contains("the copy opens"));
}

/// Every reason a command has to refuse is found before it does the thing it cannot undo. These
/// used to run the other way round: `id create --key-out` wrote the vault, made the identity, told
/// the person it had succeeded, and only then noticed the key file was occupied and exited 1 — an
/// identity on disk that the person had been told did not exist.
#[test]
fn nothing_is_made_before_the_reasons_to_refuse_are_found() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = passphrase_file(d, 0o600);
    let vault = d.join("alina.hdtp-vault.json");
    let key_out = d.join("root.key");
    fs::write(&key_out, "something already here").unwrap();

    // The occupied key path is the refusal, and the vault is not made.
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "Alina Rao", "--vault"])
        .arg(&vault)
        .arg("--key-out")
        .arg(&key_out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("the key is not written over a file"));
    assert!(!vault.exists(), "no identity is left behind by a command that refused");
    assert_eq!(fs::read_to_string(&key_out).unwrap(), "something already here", "and nothing was written over");

    // A directory that does not exist is the same: said first, and nothing made.
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "Alina Rao", "--vault"])
        .arg(&vault)
        .arg("--key-out")
        .arg(d.join("nowhere/root.key"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("there is no directory"));
    assert!(!vault.exists());

    // With a free path it works, and the key it writes is owner-only.
    fs::remove_file(&key_out).unwrap();
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "Alina Rao", "--vault"])
        .arg(&vault)
        .arg("--key-out")
        .arg(&key_out)
        .assert()
        .success()
        .stderr(predicate::str::contains("hdtp card-attach"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&key_out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // A host's leaf key is not written over either: the live leaf was issued to the key that is
    // there, and a fresh one at the same name would strand the host.
    let host = d.join("host.key");
    let first = hdtp().args(["key", "new", "--out"]).arg(&host).assert().success();
    let first_fp = String::from_utf8(first.get_output().stdout.clone()).unwrap();
    let before = fs::read(&host).unwrap();
    hdtp()
        .args(["key", "new", "--out"])
        .arg(&host)
        .assert()
        .failure()
        .stderr(predicate::str::contains("a live leaf was issued to the key that is there"));
    assert_eq!(fs::read(&host).unwrap(), before, "the key that is there is the key that stays");
    let replaced = hdtp().args(["key", "new", "--force", "--out"]).arg(&host).assert().success();
    assert_ne!(String::from_utf8(replaced.get_output().stdout.clone()).unwrap(), first_fp, "--force says so and replaces it");

    // And a leaf is not signed into the ledger for an output that was never going to land.
    let csr = d.join("host.csr");
    hdtp()
        .args(["csr", "new", "--endpoint", "https://agent.alina.example/mcp", "--key"])
        .arg(&host)
        .arg("--out")
        .arg(&csr)
        .assert()
        .success();
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--csr"])
        .arg(&csr)
        .arg("--vault")
        .arg(&vault)
        .arg("--chain-out")
        .arg(d.join("nowhere/chain.pem"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("there is no directory"));
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "ledger", "--json", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::contains("[]"));

    // A restore never writes over a vault, and a backup needs --force to.
    let copy = d.join("copy.json");
    hdtp().env("HDTP_PASSPHRASE_FILE", &pass).args(["id", "backup", "--vault"]).arg(&vault).arg("--to").arg(&copy).assert().success();
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "restore", "--from"])
        .arg(&copy)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("exists"));
}

#[test]
fn a_passphrase_file_others_can_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pass = passphrase_file(dir.path(), 0o644);
    let vault = dir.path().join("v.json");
    hdtp()
        .env("HDTP_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "x", "--vault"])
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("readable by others"));
    assert!(!vault.exists());
}

#[test]
fn the_appendix_b_proof_passes_natively() {
    let spec = repo_root().join("hdtp-spec/docs/specification");
    if !spec.exists() {
        eprintln!("skipping: {} is not here", spec.display());
        return;
    }
    // With no --spec, the newest released version under hdtp-spec/docs/specification, found from
    // where it runs; and the same version named as a directory, and its appendix page alone.
    hdtp().current_dir(repo_root()).env_remove("HDTP_SPEC").args(["vectors", "check"]).assert().success().stdout(all_passed());
    let newest = std::fs::read_dir(&spec)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.split_once('.').is_some_and(|(x, y)| x.parse::<u64>().is_ok() && y.parse::<u64>().is_ok()))
        })
        .max()
        .expect("a released version");
    hdtp().args(["vectors", "check", "--spec"]).arg(&newest).assert().success().stdout(all_passed());
    hdtp().args(["vectors", "check", "--spec"]).arg(newest.join("appendix-b-test-vectors.md")).assert().success().stdout(all_passed());
    let file = repo_root().join("hdtp-spec/vectors/hdtp-1.0-vectors.json");
    hdtp().args(["vectors", "check", "--file"]).arg(&file).assert().success().stdout(predicate::str::contains("checks passed"));
}

#[test]
fn the_generator_writes_a_vector_file_the_checker_proves() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("vectors.json");
    hdtp().args(["vectors", "gen", "--out"]).arg(&out).assert().success();
    let v: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["certificates"].as_object().unwrap().len(), 7);
    assert_eq!(v["envelopes"].as_array().unwrap().len(), 3);
    hdtp().args(["vectors", "check", "--file"]).arg(&out).assert().success().stdout(all_passed());
    // The Ed25519 certificates are the committed vectors byte for byte.
    let committed = repo_root().join("hdtp-spec/vectors/hdtp-1.0-vectors.json");
    if committed.exists() {
        let c: serde_json::Value = serde_json::from_slice(&fs::read(&committed).unwrap()).unwrap();
        for name in ["root_a", "leaf_a", "leaf_a_expired", "leaf_a_long", "leaf_a_next"] {
            assert_eq!(v["certificates"][name]["der_hex"], c["certificates"][name]["der_hex"], "{name}");
        }
        assert_eq!(v["envelopes"][0]["ct"], c["envelopes"][0]["ct"], "alina-to-bharat reproduces");
    }
}

#[test]
fn a_card_and_a_certificate_read_back() {
    let committed = repo_root().join("hdtp-spec/vectors/hdtp-1.0-vectors.json");
    if !committed.exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let c: serde_json::Value = serde_json::from_slice(&fs::read(&committed).unwrap()).unwrap();
    let leaf = from_hex(c["certificates"]["leaf_a"]["der_hex"].as_str().unwrap()).unwrap();
    let leaf_path = dir.path().join("leaf_a.der");
    fs::write(&leaf_path, &leaf).unwrap();
    hdtp()
        .args(["cert", "show"])
        .arg(&leaf_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("kind        leaf").and(predicate::str::contains("profile     exact")));
    let card = hdtp_identity::card::encode("Alina Rao", &leaf, Some("required"), &["X-HDTP-FUTURE:1".to_string()]).expect("a card");
    let card_path = dir.path().join("alina.vcf");
    fs::write(&card_path, card).unwrap();
    hdtp().args(["card", "show", "--now", "2026-09-13T12:00:00Z"]).arg(&card_path).assert().success().stdout(
        predicate::str::contains("endpoint    https://agent.alina.example/mcp")
            .and(predicate::str::contains("ignored     X-HDTP-FUTURE"))
            .and(predicate::str::contains("name        Alina Rao")),
    );
    hdtp()
        .args(["card", "check", "--now", "2028-01-01T00:00:00Z"])
        .arg(&card_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("(leaf expired)"));
    let bad = dir.path().join("bad.vcf");
    fs::write(&bad, "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-HDTP-VERSION:2\r\nEND:VCARD\r\n").unwrap();
    hdtp().args(["card", "check"]).arg(&bad).assert().code(1).stdout(predicate::str::contains("refused"));
}

/// The one thing a fake cannot prove: that a real card answers these APDUs the way the standard
/// says. Needs hardware, so it asks for it by name rather than failing on a machine without one.
///
/// To set a card up (Yubico's tool, not this project's):
///   ykman piv keys generate --algorithm ECCP256 9c /tmp/pub.pem
///   ykman piv certificates generate --subject 'CN=HDTP root' 9c /tmp/pub.pem
/// then, with the PIN in a 0600 file:
///   HDTP_PIV_LIVE=1 HDTP_PIN_FILE=/tmp/pin HDTP_PASSPHRASE_FILE=/tmp/pass cargo test -p hdtp -- --ignored live_card
#[test]
#[ignore = "needs a smartcard: HDTP_PIV_LIVE=1"]
fn live_card_signs_a_root_and_a_leaf() {
    if std::env::var("HDTP_PIV_LIVE").is_err() {
        eprintln!("skipped: set HDTP_PIV_LIVE=1 with a PIV card in a reader");
        return;
    }
    let dir = tempfile::tempdir().expect("a directory");
    let vault = dir.path().join("card.hdtp-vault.json");
    let out = Command::cargo_bin("hdtp")
        .expect("the binary")
        .args(["id", "create", "--name", "Live Card", "--vault", vault.to_str().unwrap(), "--piv", "9c"])
        .output()
        .expect("it ran");
    assert!(out.status.success(), "create on the card: {}", String::from_utf8_lossy(&out.stderr));
    let fingerprint = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(fingerprint.starts_with("sha256:"), "the root's fingerprint: {fingerprint}");

    let key = dir.path().join("host.key");
    let csr = dir.path().join("req.pem");
    Command::cargo_bin("hdtp").unwrap().args(["key", "new", "--alg", "ed25519", "--out", key.to_str().unwrap()]).assert().success();
    Command::cargo_bin("hdtp")
        .unwrap()
        .args(["csr", "new", "--key", key.to_str().unwrap(), "--endpoint", "https://live.example/mcp", "--out", csr.to_str().unwrap()])
        .assert()
        .success();
    let chain = dir.path().join("chain.pem");
    Command::cargo_bin("hdtp")
        .unwrap()
        .args([
            "id",
            "issue",
            "--vault",
            vault.to_str().unwrap(),
            "--csr",
            csr.to_str().unwrap(),
            "--yes",
            "--chain-out",
            chain.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("hdtp")
        .unwrap()
        .args([
            "chain",
            "check",
            "--chain",
            chain.to_str().unwrap(),
            "--expect-root",
            &fingerprint,
            "--expect-endpoint",
            "https://live.example/mcp",
        ])
        .assert()
        .success();
    // And the vault never held the key.
    let text = std::fs::read_to_string(&vault).expect("the vault");
    assert!(!text.contains("pkcs8"), "a card-held root leaves no key in the vault");
}

/// The two files of one identity are found together, kept together and never taken for each other
/// (the review of PR #29: C1, C2, C3, C7, C21, S1, S2; the owner's D2).
#[test]
fn the_two_files_are_found_together_and_never_mistaken() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = passphrase_file(d, 0o600);
    let sub = |n: &str| {
        let p = d.join(n);
        fs::create_dir_all(&p).unwrap();
        p
    };
    let (a, b, c, e, f, g) = (sub("a"), sub("b"), sub("c"), sub("e"), sub("f"), sub("g"));
    let key = d.join("host.key");
    hdtp().args(["key", "new", "--alg", "ed25519", "--out"]).arg(&key).assert().success();
    let csr = |name: &str, endpoint: &str| {
        let p = d.join(name);
        hdtp().args(["csr", "new", "--endpoint", endpoint, "--dns", "--key"]).arg(&key).arg("--out").arg(&p).assert().success();
        p
    };
    let (home, away) = (csr("home.csr", "https://agent.alina.example/mcp"), csr("away.csr", "https://alina.host.example/alina/mcp"));
    let as_hdtp = || {
        let mut cmd = hdtp();
        cmd.env("HDTP_PASSPHRASE_FILE", &pass);
        cmd
    };
    let issue = |csr: &Path, vault: &Path| {
        let mut cmd = as_hdtp();
        cmd.args(["id", "issue", "--yes", "--csr"]).arg(csr).arg("--vault").arg(vault);
        cmd
    };

    let vault = a.join("alina.hdtp-vault.json");
    let record = record_of(&vault);
    as_hdtp().args(["id", "create", "--name", "Alina Rao", "--vault"]).arg(&vault).assert().success();
    issue(&home, &vault).assert().success();
    let record_bytes = fs::read(&record).unwrap();

    // S2, C21: through a link to the vault, the record is the one beside the file it leads to, so a
    // second endpoint is the move it is — not a second live leaf from an empty ledger at the link.
    #[cfg(unix)]
    {
        let link = b.join("alina.json");
        std::os::unix::fs::symlink(&vault, &link).unwrap();
        issue(&away, &link).assert().failure().stderr(predicate::str::contains("a leaf is live"));
        assert!(!record_of(&link).exists(), "a second record was started beside the link");
        as_hdtp().args(["id", "ledger", "--vault"]).arg(&link).assert().success().stdout(predicate::str::contains("agent.alina.example"));
    }

    // C2: a mistyped vault is not an identity with no leaves.
    as_hdtp()
        .args(["id", "ledger", "--vault"])
        .arg(a.join("alnia.hdtp-vault.json"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no vault there"));
    as_hdtp()
        .args(["contacts", "export", "--vault"])
        .arg(a.join("alnia.hdtp-vault.json"))
        .arg("--out")
        .arg(a.join("book.zip"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no vault there"));

    // C3: a backup onto the identity's own files is refused, even with --force, and nothing moves.
    for to in [&record, &vault] {
        as_hdtp()
            .args(["id", "backup", "--force", "--vault"])
            .arg(&vault)
            .arg("--to")
            .arg(to)
            .assert()
            .failure()
            .stderr(predicate::str::contains("a backup goes somewhere other"));
    }
    assert_eq!(fs::read(&record).unwrap(), record_bytes, "the record was replaced");

    // C7: a vault's bytes at the record's name are refused as not a record, before anything is signed.
    let cv = c.join("x.hdtp-vault.json");
    fs::copy(&vault, &cv).unwrap();
    fs::copy(&vault, record_of(&cv)).unwrap();
    issue(&away, &cv).assert().failure().stdout(predicate::str::is_empty()).stderr(predicate::str::contains("not a record"));

    // D2 (owner, 2026-09-26): a vault with no record beside it issues a replacement, says so before
    // it signs, and starts the record with that leaf.
    let alone = e.join("k.hdtp-vault.json");
    fs::copy(&vault, &alone).unwrap();
    issue(&away, &alone).assert().success().stderr(
        predicate::str::contains("replaces")
            .and(predicate::str::contains("no ledger here"))
            .and(predicate::str::contains("NEW HOST").not()),
    );
    assert_eq!(open_sealed(&record_of(&alone))["ledger"].as_array().map(Vec::len), Some(1), "the record starts with the leaf");

    // C1: a record is never started under a passphrase nothing checked.
    let other = f.join("other");
    fs::write(&other, "not the passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let lone = f.join("k.hdtp-vault.json");
    fs::copy(&vault, &lone).unwrap();
    let book = f.join("book.json");
    fs::write(&book, "[]").unwrap();
    hdtp().env("HDTP_PASSPHRASE_FILE", &other).args(["contacts", "import", "--yes", "--vault"]).arg(&lone).arg(&book).assert().failure();
    assert!(!record_of(&lone).exists(), "a record was sealed under the wrong passphrase");

    // S1: a record that cannot be written takes the vault with it, so the rerun is not refused.
    #[cfg(unix)]
    {
        let made = g.join("n.hdtp-vault.json");
        std::os::unix::fs::symlink(g.join("nowhere"), record_of(&made)).unwrap();
        as_hdtp().args(["id", "create", "--name", "N", "--vault"]).arg(&made).assert().failure();
        assert!(!made.exists(), "a vault was left without its record");
        fs::remove_file(record_of(&made)).unwrap();
        as_hdtp().args(["id", "create", "--name", "N", "--vault"]).arg(&made).assert().success();
    }
}

/// The one-live-leaf rule and the move notice come from the core's `ledger_check` on BOTH paths. A
/// card-held root has no key to hand `wallet_issue`, so the CLI's own copy of the rule used to hold
/// it there; that copy is gone, and this is the card path refusing through the one function — before
/// any card is looked for, which is why no card is needed here.
#[test]
fn a_card_held_root_is_held_to_the_ledger_by_the_core() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = passphrase_file(d, 0o600);
    let as_hdtp = || {
        let mut cmd = hdtp();
        cmd.env("HDTP_PASSPHRASE_FILE", &pass);
        cmd
    };
    let key = d.join("host.key");
    hdtp().args(["key", "new", "--alg", "ed25519", "--out"]).arg(&key).assert().success();
    let csr = |name: &str, endpoint: &str| {
        let p = d.join(name);
        hdtp().args(["csr", "new", "--endpoint", endpoint, "--key"]).arg(&key).arg("--out").arg(&p).assert().success();
        p
    };
    let (home, away) = (csr("home.csr", "https://agent.alina.example/mcp"), csr("away.csr", "https://alina.host.example/alina/mcp"));
    let vault = d.join("alina.hdtp-vault.json");
    as_hdtp().args(["id", "create", "--name", "Alina Rao", "--vault"]).arg(&vault).assert().success();
    as_hdtp().args(["id", "issue", "--yes", "--csr"]).arg(&home).arg("--vault").arg(&vault).assert().success();
    // The root moves to a card: its entry keeps the certificate and names the holder, and loses the key.
    let mut plaintext = open_sealed(&vault);
    let root = &mut plaintext["roots"][0];
    root.as_object_mut().unwrap().remove("pkcs8");
    root["holder"] = serde_json::json!({ "kind": "piv", "slot": "9c", "mode": "generated" });
    let sealed: serde_json::Value = serde_json::from_str(&hdtp_identity::call(
        "vault_seal",
        &serde_json::json!({ "passphrase": "correct horse battery staple", "plaintext": plaintext }).to_string(),
    ))
    .unwrap();
    fs::write(&vault, serde_json::to_string_pretty(&sealed["vault"]).unwrap()).unwrap();

    as_hdtp().args(["id", "issue", "--yes", "--csr"]).arg(&away).arg("--vault").arg(&vault).assert().failure().stderr(
        predicate::str::contains(
            "bad_request: a leaf is live for https://agent.alina.example/mcp: a second endpoint is a move, not a second home",
        ),
    );
    // Chosen, it is a move, and the person is told what a move does before anything is asked of a card.
    as_hdtp().args(["id", "issue", "--yes", "--move", "--csr"]).arg(&away).arg("--vault").arg(&vault).assert().stderr(
        predicate::str::contains(
            "You are moving Alina Rao to https://alina.host.example/alina/mcp. Nothing cancels a certificate in HDTP.",
        )
        .and(predicate::str::contains("agent.alina.example is not told by this signature"))
        .and(predicate::str::contains("a second endpoint is a move").not()),
    );
}
