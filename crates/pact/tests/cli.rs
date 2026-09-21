//! The binary end to end: a host's key and request, an identity in a vault, a leaf issued from it
//! that validates as a chain, the wallet's refusals, the Appendix B proof, a card read back.
use assert_cmd::Command;
use pact_identity::util::from_hex;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

fn pact() -> Command {
    Command::cargo_bin("pact").expect("the pact binary")
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

#[test]
fn a_host_key_a_request_an_identity_a_leaf_and_a_chain_that_validates() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = passphrase_file(d, 0o600);
    let key = d.join("host.key");
    let csr = d.join("host.csr");
    let vault = d.join("alina.pact-vault.json");
    let chain = d.join("chain.pem");

    // The host mints a key and a request for its address.
    pact().args(["key", "new", "--alg", "ed25519", "--out"]).arg(&key).assert().success().stdout(predicate::str::starts_with("sha256:"));
    pact()
        .args(["csr", "new", "--endpoint", "https://agent.alina.example/mcp", "--dns", "--key"])
        .arg(&key)
        .arg("--out")
        .arg(&csr)
        .assert()
        .success();
    pact()
        .args(["csr", "check"])
        .arg(&csr)
        .assert()
        .success()
        .stdout(predicate::str::contains("accepted").and(predicate::str::contains("https://agent.alina.example/mcp")));

    // The person makes an identity; the passphrase comes from the file, never the arguments.
    let out = pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
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
    assert!(text.contains("pact-vault/1") && !text.contains("pkcs8"), "the vault at rest shows no key material");

    // The wallet issues; the leaf and the root validate as a chain for that address.
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--valid", "1y", "--origin", "https://app.pact-cloud.com", "--csr"])
        .arg(&csr)
        .arg("--vault")
        .arg(&vault)
        .arg("--chain-out")
        .arg(&chain)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("-----BEGIN CERTIFICATE-----"))
        .stderr(predicate::str::contains("NEW HOST"));
    pact()
        .args(["chain", "check", "--expect-endpoint", "https://agent.alina.example/mcp", "--expect-root", &root_fp, "--chain"])
        .arg(&chain)
        .assert()
        .success()
        .stdout(predicate::str::contains("accepted"));
    pact()
        .args(["chain", "check", "--expect-endpoint", "https://agent.alina.example/mcp/", "--chain"])
        .arg(&chain)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("refused by rule 5"));
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "ledger", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::contains("* ").and(predicate::str::contains("asked by https://app.pact-cloud.com")));

    // A second endpoint while a leaf is live is a move, refused without saying so.
    let key2 = d.join("host2.key");
    let csr2 = d.join("host2.csr");
    pact().args(["key", "new", "--alg", "p256", "--out"]).arg(&key2).assert().success();
    pact()
        .args(["csr", "new", "--endpoint", "https://alina.pact.contact/alina/mcp", "--key"])
        .arg(&key2)
        .arg("--out")
        .arg(&csr2)
        .assert()
        .success();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
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
    pact().args(["key", "new", "--out"]).arg(&key3).assert().success();
    pact()
        .args(["csr", "new", "--endpoint", "https://agent.alina.example/mcp", "--key"])
        .arg(&key3)
        .arg("--out")
        .arg(&csr3)
        .assert()
        .success();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "renew", "--yes", "--csr"])
        .arg(&csr3)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .success()
        .stderr(predicate::str::contains("(renewal)"));
    // A renewal for an endpoint never issued to is refused as such.
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "renew", "--yes", "--csr"])
        .arg(&csr2)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in the ledger"));
    // With --move the wallet issues for the new address.
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--move", "--csr"])
        .arg(&csr2)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .success()
        .stderr(predicate::str::contains("move"));
    let ledger = pact().env("PACT_PASSPHRASE_FILE", &pass).args(["id", "ledger", "--json", "--vault"]).arg(&vault).assert().success();
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&ledger.get_output().stdout).unwrap();
    assert_eq!(rows.len(), 3);

    // The root's certificate is public; the root's key never leaves. A backup opens.
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "show", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("-----BEGIN CERTIFICATE-----"));
    let copy = d.join("copy.json");
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "backup", "--vault"])
        .arg(&vault)
        .arg("--to")
        .arg(&copy)
        .assert()
        .success()
        .stderr(predicate::str::contains("the copy opens"));
    let restored = d.join("restored.json");
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "restore", "--from"])
        .arg(&copy)
        .arg("--vault")
        .arg(&restored)
        .assert()
        .success()
        .stderr(predicate::str::contains("3 leaves"));

    // The contact book: export, then import a book with one more and one changed.
    let book = pact().env("PACT_PASSPHRASE_FILE", &pass).args(["contacts", "export", "--vault"]).arg(&vault).assert().success();
    assert_eq!(String::from_utf8(book.get_output().stdout.clone()).unwrap().trim(), "[]");
    let incoming = d.join("book.json");
    // Bharat, with a root of his own: a contact is pinned by a fingerprint, so the book carries one
    // that is the shape §2 defines, and a `root_cert` is worth only its binding to it.
    let bharat_vault = d.join("bharat.json");
    pact().env("PACT_PASSPHRASE_FILE", &pass).args(["id", "create", "--name", "Bharat", "--vault"]).arg(&bharat_vault).assert().success();
    let bharat_cert = pact().env("PACT_PASSPHRASE_FILE", &pass).args(["id", "show", "--vault"]).arg(&bharat_vault).assert().success();
    let bharat_pem = String::from_utf8(bharat_cert.get_output().stdout.clone()).unwrap();
    let bharat_der: String = bharat_pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("");
    let bharat_der_b64u = bharat_der.replace('+', "-").replace('/', "_").replace('=', "");
    // The fingerprint to pin is the root certificate's own, read back through `cert show`.
    let bharat_pem_path = d.join("bharat.pem");
    fs::write(&bharat_pem_path, &bharat_pem).unwrap();
    let shown = pact().args(["cert", "show", "--json"]).arg(&bharat_pem_path).assert().success();
    let bharat_fp =
        serde_json::from_slice::<serde_json::Value>(&shown.get_output().stdout).unwrap()["fingerprint"].as_str().unwrap().to_string();

    fs::write(&incoming, format!(r#"[{{"root":"{bharat_fp}","endpoint":"https://b.example/mcp","name":"Bharat"}}]"#)).unwrap();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["contacts", "import", "--yes", "--vault"])
        .arg(&vault)
        .arg(&incoming)
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added, 0 removed, 0 changed"));
    fs::write(&incoming, format!(r#"[{{"root":"{bharat_fp}","endpoint":"https://c.example/mcp","name":"Bharat"}}]"#)).unwrap();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["contacts", "import", "--yes", "--vault"])
        .arg(&vault)
        .arg(&incoming)
        .assert()
        .success()
        .stderr(predicate::str::contains("0 added, 0 removed, 1 changed"));
    let book = pact().env("PACT_PASSPHRASE_FILE", &pass).args(["contacts", "export", "--vault"]).arg(&vault).assert().success();
    assert!(String::from_utf8(book.get_output().stdout.clone()).unwrap().contains("https://c.example/mcp"));

    // A root certificate that is not the pinned root's is refused, and nothing is written: §14.5's
    // poisoned archive arriving through the book instead.
    let mine_cert = pact().env("PACT_PASSPHRASE_FILE", &pass).args(["id", "show", "--vault"]).arg(&vault).assert().success();
    let mine_der: String = String::from_utf8(mine_cert.get_output().stdout.clone())
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    fs::write(
        &incoming,
        format!(r#"[{{"root":"{bharat_fp}","endpoint":"https://c.example/mcp","name":"Bharat","root_cert":"{mine_der}"}}]"#),
    )
    .unwrap();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["contacts", "import", "--yes", "--vault"])
        .arg(&vault)
        .arg(&incoming)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not for the root this contact is pinned by"));
    // A book whose root is not a fingerprint at all is refused before anything is read.
    fs::write(&incoming, r#"[{"root":"sha256:AAAA","endpoint":"https://c.example/mcp","name":"Bharat"}]"#).unwrap();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["contacts", "import", "--yes", "--vault"])
        .arg(&vault)
        .arg(&incoming)
        .assert()
        .failure()
        .stderr(predicate::str::contains("root fingerprint"));

    // Bharat's own certificate under Bharat's fingerprint is a change, is kept, and is exported again.
    fs::write(
        &incoming,
        format!(r#"[{{"root":"{bharat_fp}","endpoint":"https://c.example/mcp","name":"Bharat","root_cert":"{bharat_der_b64u}"}}]"#),
    )
    .unwrap();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["contacts", "import", "--yes", "--vault"])
        .arg(&vault)
        .arg(&incoming)
        .assert()
        .success()
        .stderr(predicate::str::contains("0 added, 0 removed, 1 changed").and(predicate::str::contains("root certificate differs")));
    let book = pact().env("PACT_PASSPHRASE_FILE", &pass).args(["contacts", "export", "--vault"]).arg(&vault).assert().success();
    assert!(String::from_utf8(book.get_output().stdout.clone()).unwrap().contains(&bharat_der_b64u));

    // A backup never writes over a file that is there, unless it is told to.
    let occupied = d.join("occupied.json");
    fs::write(&occupied, "not a vault").unwrap();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "backup", "--vault"])
        .arg(&vault)
        .arg("--to")
        .arg(&occupied)
        .assert()
        .failure()
        .stderr(predicate::str::contains("exists"));
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
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
    let vault = d.join("alina.pact-vault.json");
    let key_out = d.join("root.key");
    fs::write(&key_out, "something already here").unwrap();

    // The occupied key path is the refusal, and the vault is not made.
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
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
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
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
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "Alina Rao", "--vault"])
        .arg(&vault)
        .arg("--key-out")
        .arg(&key_out)
        .assert()
        .success()
        .stderr(predicate::str::contains("pact card-attach"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&key_out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // A host's leaf key is not written over either: the live leaf was issued to the key that is
    // there, and a fresh one at the same name would strand the host.
    let host = d.join("host.key");
    let first = pact().args(["key", "new", "--out"]).arg(&host).assert().success();
    let first_fp = String::from_utf8(first.get_output().stdout.clone()).unwrap();
    let before = fs::read(&host).unwrap();
    pact()
        .args(["key", "new", "--out"])
        .arg(&host)
        .assert()
        .failure()
        .stderr(predicate::str::contains("a live leaf was issued to the key that is there"));
    assert_eq!(fs::read(&host).unwrap(), before, "the key that is there is the key that stays");
    let replaced = pact().args(["key", "new", "--force", "--out"]).arg(&host).assert().success();
    assert_ne!(String::from_utf8(replaced.get_output().stdout.clone()).unwrap(), first_fp, "--force says so and replaces it");

    // And a leaf is not signed into the ledger for an output that was never going to land.
    let csr = d.join("host.csr");
    pact()
        .args(["csr", "new", "--endpoint", "https://agent.alina.example/mcp", "--key"])
        .arg(&host)
        .arg("--out")
        .arg(&csr)
        .assert()
        .success();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "issue", "--yes", "--csr"])
        .arg(&csr)
        .arg("--vault")
        .arg(&vault)
        .arg("--chain-out")
        .arg(d.join("nowhere/chain.pem"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("there is no directory"));
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "ledger", "--json", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::contains("[]"));

    // A restore never writes over a vault, and a backup needs --force to.
    let copy = d.join("copy.json");
    pact().env("PACT_PASSPHRASE_FILE", &pass).args(["id", "backup", "--vault"]).arg(&vault).arg("--to").arg(&copy).assert().success();
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
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
    pact()
        .env("PACT_PASSPHRASE_FILE", &pass)
        .args(["id", "create", "--name", "x", "--vault"])
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("readable by others"));
    assert!(!vault.exists());
}

#[test]
fn the_appendix_b_proof_passes_natively() {
    let spec = repo_root().join("pact-protocol/SPEC.md");
    if !spec.exists() {
        eprintln!("skipping: {} is not here", spec.display());
        return;
    }
    pact().args(["vectors", "check", "--spec"]).arg(&spec).assert().success().stdout(all_passed());
    let file = repo_root().join("pact-protocol/vectors/pact-2.0-vectors.json");
    pact().args(["vectors", "check", "--file"]).arg(&file).assert().success().stdout(predicate::str::contains("checks passed"));
}

#[test]
fn the_generator_writes_a_vector_file_the_checker_proves() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("vectors.json");
    pact().args(["vectors", "gen", "--out"]).arg(&out).assert().success();
    let v: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["certificates"].as_object().unwrap().len(), 7);
    assert_eq!(v["envelopes"].as_array().unwrap().len(), 3);
    pact().args(["vectors", "check", "--file"]).arg(&out).assert().success().stdout(all_passed());
    // The Ed25519 certificates are the committed vectors byte for byte.
    let committed = repo_root().join("pact-protocol/vectors/pact-2.0-vectors.json");
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
    let committed = repo_root().join("pact-protocol/vectors/pact-2.0-vectors.json");
    if !committed.exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let c: serde_json::Value = serde_json::from_slice(&fs::read(&committed).unwrap()).unwrap();
    let leaf = from_hex(c["certificates"]["leaf_a"]["der_hex"].as_str().unwrap()).unwrap();
    let leaf_path = dir.path().join("leaf_a.der");
    fs::write(&leaf_path, &leaf).unwrap();
    pact()
        .args(["cert", "show"])
        .arg(&leaf_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("kind        leaf").and(predicate::str::contains("profile     exact")));
    let card = pact_identity::card::encode("Alina Rao", &leaf, Some("required"), &["X-PACT-FUTURE:1".to_string()]).expect("a card");
    let card_path = dir.path().join("alina.vcf");
    fs::write(&card_path, card).unwrap();
    pact().args(["card", "show", "--now", "2026-09-13T12:00:00Z"]).arg(&card_path).assert().success().stdout(
        predicate::str::contains("endpoint    https://agent.alina.example/mcp")
            .and(predicate::str::contains("ignored     X-PACT-FUTURE"))
            .and(predicate::str::contains("name        Alina Rao")),
    );
    pact()
        .args(["card", "check", "--now", "2028-01-01T00:00:00Z"])
        .arg(&card_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("(leaf expired)"));
    let bad = dir.path().join("bad.vcf");
    fs::write(&bad, "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-PACT-VERSION:1\r\nEND:VCARD\r\n").unwrap();
    pact().args(["card", "check"]).arg(&bad).assert().code(1).stdout(predicate::str::contains("refused"));
}

/// The one thing a fake cannot prove: that a real card answers these APDUs the way the standard
/// says. Needs hardware, so it asks for it by name rather than failing on a machine without one.
///
/// To set a card up (Yubico's tool, not this project's):
///   ykman piv keys generate --algorithm ECCP256 9c /tmp/pub.pem
///   ykman piv certificates generate --subject 'CN=PACT root' 9c /tmp/pub.pem
/// then, with the PIN in a 0600 file:
///   PACT_PIV_LIVE=1 PACT_PIN_FILE=/tmp/pin PACT_PASSPHRASE_FILE=/tmp/pass cargo test -p pact -- --ignored live_card
#[test]
#[ignore = "needs a smartcard: PACT_PIV_LIVE=1"]
fn live_card_signs_a_root_and_a_leaf() {
    if std::env::var("PACT_PIV_LIVE").is_err() {
        eprintln!("skipped: set PACT_PIV_LIVE=1 with a PIV card in a reader");
        return;
    }
    let dir = tempfile::tempdir().expect("a directory");
    let vault = dir.path().join("card.pact-vault.json");
    let out = Command::cargo_bin("pact")
        .expect("the binary")
        .args(["id", "create", "--name", "Live Card", "--vault", vault.to_str().unwrap(), "--piv", "9c"])
        .output()
        .expect("it ran");
    assert!(out.status.success(), "create on the card: {}", String::from_utf8_lossy(&out.stderr));
    let fingerprint = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(fingerprint.starts_with("sha256:"), "the root's fingerprint: {fingerprint}");

    let key = dir.path().join("host.key");
    let csr = dir.path().join("req.pem");
    Command::cargo_bin("pact").unwrap().args(["key", "new", "--alg", "ed25519", "--out", key.to_str().unwrap()]).assert().success();
    Command::cargo_bin("pact")
        .unwrap()
        .args(["csr", "new", "--key", key.to_str().unwrap(), "--endpoint", "https://live.example/mcp", "--out", csr.to_str().unwrap()])
        .assert()
        .success();
    let chain = dir.path().join("chain.pem");
    Command::cargo_bin("pact")
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
    Command::cargo_bin("pact")
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
