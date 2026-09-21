//! Files, PEM, passphrases, private writes and the clock: the terminal's side of the wallet's rules.
use base64::Engine;
use pact_identity::time::{format_rfc3339, parse_rfc3339};
use pact_identity::util::from_b64u;
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// One failure: a line for the person, and the process exits 1.
#[derive(Debug)]
pub struct Fail(pub String);

impl<T: std::fmt::Display> From<T> for Fail {
    fn from(e: T) -> Fail {
        Fail(e.to_string())
    }
}

pub type Res<T> = Result<T, Fail>;

pub fn fail<T>(msg: impl Into<String>) -> Res<T> {
    Err(Fail(msg.into()))
}

/// The core through its one boundary; an answer carrying `error` becomes a failure here.
///
/// For the two vault calls, what crosses here is the passphrase and every root key the vault holds
/// — as the arguments, as their serialised text, and (for `vault_open`) as the answer's text. The
/// core zeroizes its own copies; these three were this side's, and were dropped as they stood.
pub fn core(name: &str, mut args: Value) -> Res<Value> {
    let text = Zeroizing::new(args.to_string());
    wipe(&mut args);
    let answer = Zeroizing::new(pact_identity::call(name, &text));
    let out: Value = serde_json::from_str(&answer).map_err(|e| Fail(format!("{name}: {e}")))?;
    if let Some(code) = out.get("error").and_then(|e| e.as_str()) {
        return fail(format!("{}: {}", code, out.get("why").and_then(|w| w.as_str()).unwrap_or("")));
    }
    Ok(out)
}

/// Overwrites every string in a JSON value before it is freed. Dropping a `Value` frees its buffers
/// as they are; a passphrase or a PKCS #8 inside one stays readable in the heap until reused.
pub fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

pub fn read_input(path: &str) -> Res<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        return Ok(buf);
    }
    fs::read(path).map_err(|e| Fail(format!("{path}: {e}")))
}

/// A certificate, request, key or public key as the bytes inside it: DER as given, or the first
/// PEM block's body when the file starts with `-----BEGIN`.
pub fn read_der(path: &str) -> Res<Vec<u8>> {
    let raw = read_input(path)?;
    if raw.starts_with(b"-----BEGIN") {
        let blocks = pem_blocks(&raw)?;
        return blocks.into_iter().next().map(|(_, b)| b).ok_or_else(|| Fail(format!("{path}: no PEM block")));
    }
    Ok(raw)
}

/// Every PEM block in a file, as (label, bytes), in order.
pub fn pem_blocks(raw: &[u8]) -> Res<Vec<(String, Vec<u8>)>> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(l) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            label = Some(l.to_string());
            body.clear();
        } else if line.starts_with("-----END ") {
            let l = label.take().ok_or_else(|| Fail("PEM: END before BEGIN".into()))?;
            out.push((l, from_b64u(&body).map_err(|e| Fail(format!("PEM body: {}", e.why)))?));
        } else if label.is_some() {
            body.push_str(line);
        }
    }
    Ok(out)
}

pub fn pem(label: &str, der: &[u8]) -> String {
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// A name nothing else has: the temporary file a private write goes through. It has to be unique
/// rather than derived from the target, because the mode a file is created with is the only mode
/// this write controls — opening a name that already exists would inherit whatever permissions that
/// file has, and a stale `.tmp` from a killed run, or one a neighbour left, is where the vault's
/// bytes would then land.
fn unique_tmp(path: &Path) -> PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let mut name = path.file_name().map(|f| f.to_os_string()).unwrap_or_default();
    name.push(format!(".{}.{n}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Writes a file only its owner can read, atomically where a file already exists.
pub fn write_private(path: &Path, bytes: &[u8]) -> Res<()> {
    let tmp = unique_tmp(path);
    fill_new(&tmp, bytes).map_err(|e| Fail(format!("{}: {e}", tmp.display())))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return fail(format!("{}: {e}", path.display()));
    }
    sync_parent(path)
}

/// Writes a file only its owner can read, and only where there is no file: the caller has decided
/// that writing over this name would destroy something (a root key, a leaf key) and the decision
/// has to hold at the moment of the write, not at the moment of the check before it.
///
/// Only a name that was already taken is reported as taken. A write that failed for any other
/// reason says what that reason was and leaves nothing at the path — the alternative is a truncated
/// key file that the next run refuses to replace, telling the person it is protecting a key that
/// is not there.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Res<()> {
    fill_new(path, bytes).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => Fail(format!("{}: exists; nothing is written over it", path.display())),
        _ => Fail(format!("{}: {e}", path.display())),
    })?;
    sync_parent(path)
}

/// Makes a file's NAME durable. `sync_all` on the file makes its bytes durable and says nothing
/// about the directory entry that leads to them, so a new vault could be reported as written and be
/// absent after a power loss — and `id create` tells the person that what it just wrote cannot be
/// recovered. ext4 in its default mode usually saves the entry anyway; APFS, XFS and btrfs promise
/// nothing.
///
/// A failure is reported and the file is LEFT: it may be the only copy of a root key.
pub fn sync_parent(path: &Path) -> Res<()> {
    #[cfg(unix)]
    {
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| {
            Fail(format!(
                "{}: written, but its directory {} could not be synced ({e}); copy the file somewhere safe now",
                path.display(),
                dir.display()
            ))
        })?;
    }
    Ok(())
}

/// Creates a file and fills it, owner-only, and only where there is no file. `create_new` rather
/// than `create` is what makes 0600 the file's real mode — an open that found an existing name
/// would inherit that file's permissions instead — and it will not follow a symlink someone put in
/// the way. Anything that goes wrong after the file exists takes the file with it.
fn fill_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// A path a command will write when it is done, checked before it does the thing it cannot undo.
/// The directory has to exist now and the name must not already be one; `-` and stdout are not
/// paths and have nothing to check.
pub fn check_writable(path: Option<&str>) -> Res<()> {
    let Some(p) = path.filter(|p| *p != "-") else { return Ok(()) };
    let target = Path::new(p);
    if target.is_dir() {
        return fail(format!("{p} is a directory"));
    }
    match target.parent().filter(|d| !d.as_os_str().is_empty()) {
        Some(d) if !d.is_dir() => fail(format!("{p}: there is no directory {}", d.display())),
        _ => Ok(()),
    }
}

pub fn write_output(path: Option<&str>, text: &str) -> Res<()> {
    match path {
        Some(p) => fs::write(p, text).map_err(|e| Fail(format!("{p}: {e}"))),
        None => {
            io::stdout().write_all(text.as_bytes())?;
            Ok(())
        }
    }
}

/// The passphrase, from the terminal — never from an argument. `PACT_PASSPHRASE_FILE` serves
/// scripts, read once, and refused when anyone but its owner can read it.
pub fn passphrase(confirm: bool) -> Res<Zeroizing<String>> {
    if let Ok(path) = std::env::var("PACT_PASSPHRASE_FILE") {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).map_err(|e| Fail(format!("{path}: {e}")))?.permissions().mode();
            if mode & 0o077 != 0 {
                return fail(format!("{path}: readable by others (mode {:o}); make it 0600", mode & 0o777));
            }
        }
        let text = Zeroizing::new(fs::read_to_string(&path).map_err(|e| Fail(format!("{path}: {e}")))?);
        let p = Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
        if p.is_empty() {
            return fail(format!("{path}: empty"));
        }
        return Ok(p);
    }
    let first = Zeroizing::new(rpassword::prompt_password("Passphrase: ").map_err(|e| Fail(format!("passphrase: {e}")))?);
    if first.is_empty() {
        return fail("an empty passphrase protects nothing");
    }
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password("Passphrase again: ").map_err(|e| Fail(format!("passphrase: {e}")))?);
        if *again != *first {
            return fail("the passphrases differ");
        }
    }
    Ok(first)
}

/// A yes/no question on stderr, answered on stdin; `yes` skips it.
pub fn confirm(question: &str, yes: bool) -> Res<bool> {
    if yes {
        return Ok(true);
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

pub fn now_or(arg: Option<&str>) -> Res<i64> {
    match arg {
        Some(s) => parse_rfc3339(s).map_err(|e| Fail(format!("--now: {}", e.why))),
        None => Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)),
    }
}

pub fn instant(t: i64) -> String {
    format_rfc3339(t)
}

/// `1y`, `90d`, `6w`, or a bare number of days.
pub fn parse_valid(s: &str) -> Res<i64> {
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&s[..i], &s[i..]),
        None => (s, "d"),
    };
    let n: i64 = num.parse().map_err(|_| Fail(format!("--valid: {s} is not a duration")))?;
    let days = match unit {
        "d" | "" => n,
        "w" => n * 7,
        "y" => n * 365,
        other => return fail(format!("--valid: unknown unit {other} (use d, w or y)")),
    };
    if !(1..=398).contains(&days) {
        return fail("--valid: a leaf lives between one and 398 days");
    }
    Ok(days)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pact-io-{name}-{}-{}", std::process::id(), unique_tmp(Path::new("x")).display()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    // Dropping a serde_json::Value frees its strings as they stand. `wipe` is what the two vault
    // calls and the Vault's own Drop rely on to overwrite them first.
    #[test]
    fn wipe_overwrites_every_string_wherever_it_sits() {
        let mut v = serde_json::json!({
            "passphrase": "correct horse",
            "plaintext": { "roots": [{ "pkcs8": "MC4CAQ", "name": "Alina" }], "n": 3, "ok": true, "none": null },
        });
        wipe(&mut v);
        let mut left = Vec::new();
        fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
            match v {
                Value::String(s) => out.push(s),
                Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
                Value::Object(o) => o.values().for_each(|x| strings(x, out)),
                _ => {}
            }
        }
        strings(&v, &mut left);
        assert_eq!(left.len(), 3, "the three strings are still members");
        assert!(left.iter().all(|s| s.is_empty()), "{left:?}");
        assert_eq!((v["plaintext"]["n"].as_i64(), v["plaintext"]["ok"].as_bool()), (Some(3), Some(true)));
    }

    // What can be shown of a directory sync without pulling the plug: that it really opens the
    // directory the file is in (a parent that is not there is an error, not a shrug), and that
    // both write paths reach it — a file written under a directory that has since gone reports it.
    #[test]
    fn the_directory_is_really_synced_and_a_failure_is_said() {
        let d = scratch("sync");
        let f = d.join("vault.json");
        write_new_private(&f, b"{}").unwrap();
        sync_parent(&f).unwrap();
        write_private(&f, b"{\"a\":1}").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"{\"a\":1}");

        #[cfg(unix)]
        {
            let gone = d.join("no-such-dir").join("vault.json");
            let why = sync_parent(&gone).expect_err("a parent that is not there cannot be synced").0;
            assert!(why.contains("could not be synced"), "{why}");
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pem_round_trips_and_der_passes_through() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let text = pem("CERTIFICATE", &der);
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let blocks = pem_blocks(text.as_bytes()).unwrap();
        assert_eq!(blocks, vec![("CERTIFICATE".to_string(), der.clone())]);
        let two = format!("{}{}", pem("A", &der), pem("B", &[1, 2, 3]));
        assert_eq!(pem_blocks(two.as_bytes()).unwrap().len(), 2);
    }

    #[test]
    fn valid_parses_days_weeks_years_and_caps() {
        assert_eq!(parse_valid("1y").unwrap(), 365);
        assert_eq!(parse_valid("90d").unwrap(), 90);
        assert_eq!(parse_valid("2w").unwrap(), 14);
        assert_eq!(parse_valid("30").unwrap(), 30);
        assert!(parse_valid("2y").is_err());
        assert!(parse_valid("0d").is_err());
        assert!(parse_valid("1x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_writes_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pact-io-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("v.json");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        // A world-readable file left where the temporary one used to be named is not written into,
        // and is not left behind either: the name a private write uses is one nothing else has.
        let stale = dir.join("v.json.tmp");
        fs::write(&stale, b"planted").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o666)).unwrap();
        write_private(&p, b"three").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"three");
        assert_eq!(fs::read(&stale).unwrap(), b"planted", "the planted file is untouched");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp") && n != "v.json.tmp")
            .collect();
        assert!(left.is_empty(), "no temporary files left behind: {left:?}");

        // And the exclusive write refuses a name that is taken rather than destroying it.
        let key = dir.join("host.key");
        write_new_private(&key, b"a key").unwrap();
        let e = write_new_private(&key, b"another key").unwrap_err();
        assert!(e.0.contains("exists; nothing is written over it"), "{}", e.0);
        // A failure that is not "the name is taken" is not reported as one, and leaves no file.
        let missing = dir.join("nowhere/x.key");
        let e = write_new_private(&missing, b"a key").unwrap_err();
        assert!(!e.0.contains("exists"), "a directory that is not there is not a file that is: {}", e.0);
        assert!(!missing.exists());
        assert_eq!(fs::read(&key).unwrap(), b"a key");
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);

        // A directory that is not there is said before anything is done, not after.
        assert!(check_writable(Some(dir.join("nope/x.pem").to_str().unwrap())).is_err());
        assert!(check_writable(Some(dir.to_str().unwrap())).is_err(), "a directory is not an output file");
        assert!(check_writable(Some("plain.pem")).is_ok(), "a bare name has no directory to check");
        assert!(check_writable(Some("-")).is_ok());
        assert!(check_writable(None).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }
}
