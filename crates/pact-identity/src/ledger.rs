//! The wallet's ledger rules (SPEC §9; CONTRACT §6.1): what signing a leaf for an endpoint would mean,
//! read off the ledger of leaves the wallet has issued. ONE implementation of them: `wallet_issue`
//! applies them to a software root, the `pact` CLI's card path to a card-held root, and a wallet
//! page or a host renders the move notice (design §3) from the same facts.
//!
//! Every entry is read, every root's, before any rule reads one: an entry that does not read is
//! refused, never skipped — skipped, it could be the live leaf, and one live leaf per identity would
//! fail open. So a `not_before` that does not parse never reaches the rules below, which skip it only
//! because they are written over entries already read.
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{err, Result};
use crate::x509;
use serde_json::{json, Map, Value};

const ENTRY_REQUIRED: &[&str] = &["root", "endpoint", "not_before", "not_after", "issued_at"];
const ENTRY_MEMBERS: &[&str] = &["root", "endpoint", "not_before", "not_after", "issued_at", "origin"];
const ENTRY_INSTANTS: &[&str] = &["not_before", "not_after", "issued_at"];

/// The refusal of `ledger_check` and `wallet_issue` when a leaf is live at another endpoint and the
/// caller did not say this is a move. The same words wherever the rule is applied.
pub fn second_home(live_endpoint: &str) -> String {
    format!("a leaf is live for {live_endpoint}: a second endpoint is a move, not a second home")
}

/// The first member, in sorted order, that `allowed` does not name: sorted, so that two ports that
/// iterate a map differently name the same one.
pub(crate) fn stranger(doc: &Map<String, Value>, allowed: &[&str]) -> Option<String> {
    let mut extra: Vec<&String> = doc.keys().filter(|k| !allowed.contains(&k.as_str())).collect();
    extra.sort();
    extra.first().map(|k| k.to_string())
}

/// `sha256:` and 43 base64url characters: a root fingerprint as SPEC §2 writes one.
pub fn is_fingerprint(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| h.len() == 43 && h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
}

/// Every entry of a ledger read as CONTRACT §6's `LedgerEntry`: a list, each entry an object with
/// the required members as strings, the root a fingerprint, the endpoint not empty, the instants parsing, `origin` a string if present, and nothing
/// else. The first that does not read is named by its index and member.
pub fn read(ledger: &Value) -> Result<()> {
    let Some(entries) = ledger.as_array() else { return err("bad_request", "the record's ledger is a list") };
    for (i, e) in entries.iter().enumerate() {
        let Some(o) = e.as_object() else { return err("bad_request", format!("the record's ledger entry {i} does not read")) };
        let unread = |m: &str| err("bad_request", format!("the record's ledger entry {i} does not read: {m}"));
        for m in ENTRY_REQUIRED {
            let Some(text) = o.get(*m).and_then(|v| v.as_str()) else { return unread(m) };
            // The root is a fingerprint and the endpoint is not empty (contract: LedgerEntry), so no
            // entry can name nobody and still be read.
            let wrong = match *m {
                "root" => !is_fingerprint(text),
                "endpoint" => text.is_empty(),
                _ => ENTRY_INSTANTS.contains(m) && parse_rfc3339(text).is_err(),
            };
            if wrong {
                return unread(m);
            }
        }
        if o.get("origin").is_some_and(|v| !v.is_string()) {
            return unread("origin");
        }
        if let Some(k) = stranger(o, ENTRY_MEMBERS) {
            return unread(&k);
        }
    }
    Ok(())
}

/// What the move notice says (design §3), as facts; the page, the CLI and a host render the words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The live leaf is at this endpoint, or none is live and this endpoint has been issued to.
    Renew,
    /// A leaf is live at another endpoint, and this one has never been issued to.
    Move,
    /// No leaf is live, and this endpoint has never been issued to.
    NewHost,
    /// A leaf is live at another endpoint, and this one has been issued to before: the contacts
    /// would move back.
    MoveBack,
    /// The signer cannot see the ledger (no record): nothing above can be said.
    NoLedger,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Renew => "renew",
            Kind::Move => "move",
            Kind::NewHost => "new_host",
            Kind::MoveBack => "move_back",
            Kind::NoLedger => "no_ledger",
        }
    }
}

/// The ledger's answer about one request.
#[derive(Clone, Debug)]
pub struct Facts {
    /// SPEC §9's one live leaf per identity: set when a leaf is live elsewhere and `moving` is false.
    pub refusal: Option<String>,
    /// No entry of this root names the endpoint's host. True with no ledger: every host is new to a
    /// signer that cannot see one.
    pub new_host: bool,
    /// An entry of this root names exactly this endpoint. False with no ledger.
    pub known_endpoint: bool,
    /// The latest `notBefore` this root has been issued, which the next one must follow.
    pub previous_not_before: Option<i64>,
    /// The live leaf: the NEWEST entry of this root by `notBefore` (§14.3: a later notBefore
    /// supersedes every earlier leaf), if it has not expired. An older unexpired entry is history.
    pub live: Option<(String, i64)>,
    pub kind: Kind,
}

fn instant(l: &Value, m: &str) -> Option<i64> {
    l.get(m).and_then(|t| t.as_str()).and_then(|t| parse_rfc3339(t).ok())
}

/// This root's newest entry by `not_before`, as its index in the ledger and that `not_before`: the
/// first of equals, in ledger order, in both ports (§14.3: a later notBefore supersedes every earlier
/// leaf). Over entries `read` has read.
fn newest(entries: &[Value], root: &str) -> Option<(usize, i64)> {
    let mut best: Option<(usize, i64)> = None;
    for (i, l) in entries.iter().enumerate() {
        if l.get("root").and_then(|r| r.as_str()) != Some(root) {
            continue;
        }
        if let Some(t) = instant(l, "not_before") {
            if best.is_none_or(|(_, n)| t > n) {
                best = Some((i, t));
            }
        }
    }
    best
}

/// An entry's `not_after`, when it is after `now`: whether the newest entry is live.
fn live_of(l: &Value, now: i64) -> Option<i64> {
    instant(l, "not_after").filter(|na| *na > now)
}

/// The live leaf of `root`, as the index of its entry in the ledger: the entry `check` reports as
/// `live` — the root's newest by `not_before`, the first of equals, if it has not expired. An older
/// entry still in its validity is history, not live. The `pact` CLI marks this entry as current, so
/// its listing and the rules name the same one (X8: it marked the newest UNEXPIRED entry, and the
/// last of equals). A ledger that does not read is refused, as `check` refuses it.
pub fn live_entry(ledger: &Value, root: &str, now: i64) -> Result<Option<usize>> {
    read(ledger)?;
    let entries = ledger.as_array().map(Vec::as_slice).unwrap_or_default();
    Ok(newest(entries, root).filter(|(i, _)| live_of(&entries[*i], now).is_some()).map(|(i, _)| i))
}

/// The rules, over a ledger (`None` when the signer has none to read). `endpoint` is the request's,
/// in the normal form of §14.1.
pub fn check(ledger: Option<&Value>, root: &str, endpoint: &str, now: i64, moving: bool) -> Result<Facts> {
    if !x509::is_normal_https(endpoint) {
        return err("bad_request", "endpoint is not an https URL in normal form");
    }
    let Some(ledger) = ledger else {
        return Ok(Facts {
            refusal: None,
            new_host: true,
            known_endpoint: false,
            previous_not_before: None,
            live: None,
            kind: Kind::NoLedger,
        });
    };
    read(ledger)?;
    let entries = ledger.as_array().map(Vec::as_slice).unwrap_or_default();
    let endpoint_of = |l: &Value| l.get("endpoint").and_then(|e| e.as_str()).unwrap_or("").to_string();
    let mine: Vec<&Value> = entries.iter().filter(|l| l.get("root").and_then(|r| r.as_str()) == Some(root)).collect();
    let host = x509::host_of(endpoint);
    let new_host = !mine.iter().any(|l| x509::host_of(&endpoint_of(l)) == host);
    let known_endpoint = mine.iter().any(|l| endpoint_of(l) == endpoint);
    let newest = newest(entries, root);
    let previous_not_before = newest.map(|(_, t)| t);
    let live = newest.and_then(|(i, _)| live_of(&entries[i], now).map(|na| (endpoint_of(&entries[i]), na)));
    let elsewhere = live.as_ref().filter(|(e, _)| e != endpoint);
    let kind = match (elsewhere, known_endpoint) {
        (Some(_), true) => Kind::MoveBack,
        (Some(_), false) => Kind::Move,
        (None, true) => Kind::Renew,
        (None, false) => Kind::NewHost,
    };
    let refusal = elsewhere.filter(|_| !moving).map(|(e, _)| second_home(e));
    Ok(Facts { refusal, new_host, known_endpoint, previous_not_before, live, kind })
}

impl Facts {
    /// The answer of CONTRACT §6.1's `ledger_check`.
    pub fn to_value(&self) -> Value {
        let mut notice = Map::new();
        notice.insert("kind".into(), json!(self.kind.name()));
        if matches!(self.kind, Kind::Move | Kind::MoveBack) {
            if let Some((e, na)) = &self.live {
                notice.insert("from".into(), json!(e));
                notice.insert("until".into(), json!(format_rfc3339(*na)));
            }
        }
        json!({
            "refusal": self.refusal,
            "new_host": self.new_host,
            "known_endpoint": self.known_endpoint,
            "previous_not_before": self.previous_not_before.map(format_rfc3339),
            "live": self.live.as_ref().map(|(e, na)| json!({ "endpoint": e, "not_after": format_rfc3339(*na) })),
            "notice": Value::Object(notice),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const A: &str = "https://agent.alina.example/mcp";
    const B: &str = "https://alina.host.example/alina/mcp";
    const NOW: i64 = 1_789_214_400; // 2026-09-12T12:00:00Z

    fn entry(root: &str, endpoint: &str, nb: i64, na: i64) -> Value {
        json!({ "root": root, "endpoint": endpoint, "not_before": format_rfc3339(nb), "not_after": format_rfc3339(na), "issued_at": format_rfc3339(nb) })
    }

    #[test]
    fn ledger_check_names_each_kind_and_refuses_only_a_second_home() {
        let day = 86_400;
        let at_a = json!([entry(ROOT, A, NOW - 10 * day, NOW + 300 * day)]);
        // A renewal where the live leaf is.
        let f = check(Some(&at_a), ROOT, A, NOW, false).unwrap();
        assert_eq!((f.kind.clone(), f.refusal.clone(), f.known_endpoint, f.new_host), (Kind::Renew, None, true, false));
        assert_eq!(f.previous_not_before, Some(NOW - 10 * day));
        // A move to an endpoint never issued to: refused without the flag, the same facts with it.
        let f = check(Some(&at_a), ROOT, B, NOW, false).unwrap();
        assert_eq!(f.kind, Kind::Move);
        assert_eq!(f.refusal.as_deref(), Some(second_home(A).as_str()));
        assert!(f.new_host);
        let f = check(Some(&at_a), ROOT, B, NOW, true).unwrap();
        assert_eq!((f.kind.clone(), f.refusal.clone()), (Kind::Move, None));
        assert_eq!(f.to_value()["notice"], json!({ "kind": "move", "from": A, "until": format_rfc3339(NOW + 300 * day) }));
        // Back to where it was: the newest is at B, and A has been issued to.
        let moved = json!([entry(ROOT, A, NOW - 10 * day, NOW + 300 * day), entry(ROOT, B, NOW - day, NOW + 200 * day)]);
        let f = check(Some(&moved), ROOT, A, NOW, false).unwrap();
        assert_eq!(f.kind, Kind::MoveBack);
        assert_eq!(f.refusal.as_deref(), Some(second_home(B).as_str()));
        assert_eq!(f.live, Some((B.to_string(), NOW + 200 * day)));
        assert_eq!(check(Some(&moved), ROOT, A, NOW, true).unwrap().refusal, None);
        // Nothing live: an empty ledger is a new host; an expired leaf's endpoint is a renewal.
        assert_eq!(check(Some(&json!([])), ROOT, A, NOW, false).unwrap().kind, Kind::NewHost);
        let expired = json!([entry(ROOT, A, NOW - 400 * day, NOW - day)]);
        let f = check(Some(&expired), ROOT, B, NOW, false).unwrap();
        assert_eq!((f.kind.clone(), f.refusal.clone(), f.live.clone()), (Kind::NewHost, None, None));
        assert_eq!(check(Some(&expired), ROOT, A, NOW, false).unwrap().kind, Kind::Renew);
        // Another root's live leaf is not this root's.
        let theirs = json!([entry(OTHER, B, NOW - day, NOW + 300 * day)]);
        let f = check(Some(&theirs), ROOT, A, NOW, false).unwrap();
        assert_eq!((f.kind.clone(), f.refusal.clone(), f.new_host, f.previous_not_before), (Kind::NewHost, None, true, None));
        // No ledger: nothing can be said, and every host is new.
        let f = check(None, ROOT, A, NOW, false).unwrap();
        assert_eq!((f.kind.clone(), f.new_host, f.known_endpoint), (Kind::NoLedger, true, false));
    }

    /// The live leaf is the newest by notBefore, IF unexpired — never the newest of the unexpired.
    /// An older leaf still in its validity is superseded (§14.3) by the newer one that expired.
    #[test]
    fn ledger_check_takes_the_newest_leaf_and_not_the_newest_unexpired_one() {
        let day = 86_400;
        let ledger = json!([entry(ROOT, A, NOW - 100 * day, NOW + 200 * day), entry(ROOT, B, NOW - 50 * day, NOW - day)]);
        let f = check(Some(&ledger), ROOT, B, NOW, false).unwrap();
        assert_eq!((f.live.clone(), f.refusal.clone(), f.kind.clone()), (None, None, Kind::Renew));
        assert_eq!(f.previous_not_before, Some(NOW - 50 * day));
    }

    /// An entry that does not read is refused, never skipped — a `not_before` that does not parse
    /// included, whichever root it names.
    #[test]
    fn the_live_entry_is_the_newest_the_first_of_equals_and_none_when_the_newest_has_expired() {
        let day = 86_400;
        // Two entries share the newest notBefore: the first of them, in ledger order, is live.
        let tie = json!([
            entry(ROOT, A, NOW - 10 * day, NOW + 300 * day),
            entry(ROOT, B, NOW - day, NOW + 90 * day),
            entry(ROOT, A, NOW - day, NOW + 90 * day)
        ]);
        assert_eq!(live_entry(&tie, ROOT, NOW), Ok(Some(1)));
        // The newest has expired and an older one has not: nothing is live, and the older one is history.
        let expired = json!([entry(ROOT, A, NOW - 10 * day, NOW + 300 * day), entry(ROOT, B, NOW - 2 * day, NOW - day)]);
        assert_eq!(live_entry(&expired, ROOT, NOW), Ok(None));
        // Another root's entries are not this root's, and `check` reports the same entry as live.
        let mixed = json!([entry(OTHER, B, NOW - day, NOW + 90 * day), entry(ROOT, A, NOW - 10 * day, NOW + 300 * day)]);
        assert_eq!(live_entry(&mixed, ROOT, NOW), Ok(Some(1)));
        for (ledger, want) in
            [(&tie, Some((B.to_string(), NOW + 90 * day))), (&expired, None), (&mixed, Some((A.to_string(), NOW + 300 * day)))]
        {
            assert_eq!(check(Some(ledger), ROOT, A, NOW, true).unwrap().live, want);
        }
        assert!(live_entry(&json!([{ "root": ROOT }]), ROOT, NOW).is_err(), "a ledger that does not read");
    }

    #[test]
    fn ledger_check_refuses_an_entry_that_does_not_read() {
        let day = 86_400;
        let mut bad = entry(OTHER, B, NOW - day, NOW + 300 * day);
        bad["not_before"] = json!("soon");
        let ledger = json!([entry(ROOT, A, NOW - day, NOW + 300 * day), bad]);
        assert_eq!(check(Some(&ledger), ROOT, A, NOW, false).unwrap_err().why, "the record's ledger entry 1 does not read: not_before");
        assert_eq!(check(Some(&json!({})), ROOT, A, NOW, false).unwrap_err().why, "the record's ledger is a list");
        // A root that is no fingerprint, and an empty endpoint, name nobody: refused, not read.
        for (m, v) in [("root", ""), ("root", "alina"), ("endpoint", "")] {
            let mut e = entry(OTHER, B, NOW - day, NOW + 300 * day);
            e[m] = json!(v);
            let why = check(Some(&json!([e])), ROOT, A, NOW, false).unwrap_err().why;
            assert_eq!(why, format!("the record's ledger entry 0 does not read: {m}"), "{m} = {v:?}");
        }
        assert_eq!(
            check(Some(&json!([])), ROOT, "http://agent.alina.example/mcp", NOW, false).unwrap_err().why,
            "endpoint is not an https URL in normal form"
        );
    }
}
