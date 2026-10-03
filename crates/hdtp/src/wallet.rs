//! The wallet half: a root in a vault, leaves issued from it under SPEC §9's rules, the ledger, the
//! contact book. The rules live in the core's `wallet_issue`; this module adds the terminal's
//! discipline — the passphrase from a prompt, the vault owner-only, nothing a root key ever printed.
//!
//! An identity is two files under one passphrase (SPEC §9). The **vault** is the root and nothing
//! else — `<name>.hdtp-vault.json`, written when the identity is made and again only when a card
//! takes its root (`card-attach`), the copy a person keeps. The **record** beside it —
//! `<name>.hdtp-record.json` — is the ledger and the contact book, and is what every signing
//! writes. A vault carried to a new machine without its record has no ledger there, so the first
//! leaf it issues is a replacement of whatever was live, said so before it is signed; there is
//! nothing to convert.
//!
//! Both files are found, read and written at the vault's REAL location: through a link to the
//! vault, the record is the one beside the file it leads to. Messages name the paths as typed.
//!
//! `files` holds the two files and how they are opened, checked and written; `card` a root held
//! on a PIV card; `id` the identity commands; `contacts` the contact book.
mod card;
mod contacts;
mod exportzip;
mod files;
mod id;

pub use card::{card_attach, card_status, id_create_piv};
pub use contacts::{contacts_export, contacts_import};
pub use id::{id_backup, id_create, id_issue, id_ledger, id_restore, id_show, IssueArgs};

/// Where a vault's record lives: the same name with `hdtp-record` for `hdtp-vault`, and
/// `.hdtp-record.json` appended to a name that says neither. `alina.hdtp-vault.json` keeps its
/// record at `alina.hdtp-record.json`; `v.json` at `v.hdtp-record.json`.
pub fn record_path(vault: &str) -> String {
    let stem = vault.strip_suffix(".json").unwrap_or(vault);
    let stem = stem.strip_suffix(".hdtp-vault").unwrap_or(stem);
    format!("{stem}.hdtp-record.json")
}
