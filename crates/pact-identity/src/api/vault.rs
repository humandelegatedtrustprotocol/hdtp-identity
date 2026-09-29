//! The vault section of contract/contract.json (§6 the vault): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::vault;

pub(super) fn vault_seal(a: &Value) -> Result<Value> {
    Ok({
        // In the order the contract's note fixes: the passphrase (absent: `passphrase is required`;
        // empty: `empty passphrase`), the plaintext and its generation, and only then the KDF — read
        // before, a v 1 plaintext under a KDF out of range was named for the KDF here and for its
        // generation in the other port. An empty passphrase was judged after an absent plaintext
        // here and before it in the Go port (T21).
        let passphrase = s(a, "passphrase")?;
        if passphrase.is_empty() {
            return err("bad_request", "empty passphrase");
        }
        // Sealing an absent plaintext sealed the JSON literal `null` and handed back a
        // well-formed vault with nothing in it — a file a person would keep, and restore from.
        let Some(plaintext) = a.get("plaintext").filter(|v| !v.is_null()) else {
            return err("bad_request", "plaintext is required");
        };
        vault::check_sealable(passphrase, plaintext)?;
        // ONE parser, shared with `vault_open`, so the bounds cannot diverge between sealing and
        // opening and `name` is checked on both.
        let kdf = match a.get("kdf") {
            None | Some(Value::Null) => None,
            Some(_) => Some(vault::kdf_from_args(a.get("kdf"))?),
        };
        json!({ "vault": vault::seal(passphrase, plaintext, kdf, opt_bytes(a, "salt")?, opt_bytes(a, "nonce")?)? })
    })
}

pub(super) fn vault_open(a: &Value) -> Result<Value> {
    Ok({
        let Some(doc) = a.get("vault").filter(|v| !v.is_null()) else {
            return err("bad_request", "vault is required");
        };
        json!({ "plaintext": vault::open(s(a, "passphrase")?, doc)? })
    })
}

pub(super) fn wallet_issue(a: &Value) -> Result<Value> {
    vault::wallet_issue(
        a.get("vault_plaintext").unwrap_or(&Value::Null),
        a.get("record_plaintext").unwrap_or(&Value::Null),
        s(a, "root_fingerprint")?,
        &bytes(a, "csr")?,
        instant(a, "now")?,
        valid_days(a)?,
        boolean(a, "move")?,
    )
}
