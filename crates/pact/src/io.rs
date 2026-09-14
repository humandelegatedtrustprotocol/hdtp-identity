//! Files, PEM, passphrases, private writes and the clock: the terminal's side of the wallet's rules.
use base64::Engine;
use pact_identity::time::{format_rfc3339, parse_rfc3339};
use pact_identity::util::from_b64u;
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

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
pub fn core(name: &str, args: Value) -> Res<Value> {
    let out: Value = serde_json::from_str(&pact_identity::call(name, &args.to_string())).map_err(|e| Fail(format!("{name}: {e}")))?;
    if let Some(code) = out.get("error").and_then(|e| e.as_str()) {
        return fail(format!("{}: {}", code, out.get("why").and_then(|w| w.as_str()).unwrap_or("")));
    }
    Ok(out)
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

/// Writes a file only its owner can read, atomically where a file already exists.
pub fn write_private(path: &Path, bytes: &[u8]) -> Res<()> {
    let tmp: PathBuf = path.with_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(e) => format!("{e}.tmp"),
        None => "tmp".to_string(),
    });
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| Fail(format!("{}: {e}", tmp.display())))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).map_err(|e| Fail(format!("{}: {e}", path.display())))?;
    Ok(())
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
pub fn passphrase(confirm: bool) -> Res<String> {
    if let Ok(path) = std::env::var("PACT_PASSPHRASE_FILE") {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).map_err(|e| Fail(format!("{path}: {e}")))?.permissions().mode();
            if mode & 0o077 != 0 {
                return fail(format!("{path}: readable by others (mode {:o}); make it 0600", mode & 0o777));
            }
        }
        let text = fs::read_to_string(&path).map_err(|e| Fail(format!("{path}: {e}")))?;
        let p = text.trim_end_matches(['\n', '\r']).to_string();
        if p.is_empty() {
            return fail(format!("{path}: empty"));
        }
        return Ok(p);
    }
    let first = rpassword::prompt_password("Passphrase: ").map_err(|e| Fail(format!("passphrase: {e}")))?;
    if first.is_empty() {
        return fail("an empty passphrase protects nothing");
    }
    if confirm {
        let again = rpassword::prompt_password("Passphrase again: ").map_err(|e| Fail(format!("passphrase: {e}")))?;
        if again != first {
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
        fs::remove_dir_all(&dir).unwrap();
    }
}
