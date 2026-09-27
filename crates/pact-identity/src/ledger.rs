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

/// Every entry of a ledger read as CONTRACT §6's `LedgerEntry`: a list, each entry an object with
/// the required members as strings, the instants parsing, `origin` a string if present, and nothing
/// else. The first that does not read is named by its index and member.
pub fn read(ledger: &Value) -> Result<()> {
    let Some(entries) = ledger.as_array() else { return err("bad_request", "the record's ledger is a list") };
    for (i, e) in entries.iter().enumerate() {
        let Some(o) = e.as_object() else { return err("bad_request", format!("the record's ledger entry {i} does not read")) };
        let unread = |m: &str| err("bad_request", format!("the record's ledger entry {i} does not read: {m}"));
        for m in ENTRY_REQUIRED {
            let Some(text) = o.get(*m).and_then(|v| v.as_str()) else { return unread(m) };
            if ENTRY_INSTANTS.contains(m) && parse_rfc3339(text).is_err() {
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
    let at = |l: &Value, m: &str| l.get(m).and_then(|t| t.as_str()).and_then(|t| parse_rfc3339(t).ok());
    let endpoint_of = |l: &Value| l.get("endpoint").and_then(|e| e.as_str()).unwrap_or("").to_string();
    let mine: Vec<&Value> =
        ledger.as_array().map(|a| a.iter().filter(|l| l.get("root").and_then(|r| r.as_str()) == Some(root)).collect()).unwrap_or_default();
    let host = x509::host_of(endpoint);
    let new_host = !mine.iter().any(|l| x509::host_of(&endpoint_of(l)) == host);
    let known_endpoint = mine.iter().any(|l| endpoint_of(l) == endpoint);
    // The first of the newest wins a tie, in ledger order, in both ports.
    let mut newest: Option<(i64, &Value)> = None;
    for l in &mine {
        if let Some(t) = at(l, "not_before") {
            if newest.is_none_or(|(n, _)| t > n) {
                newest = Some((t, l));
            }
        }
    }
    let previous_not_before = newest.map(|(t, _)| t);
    let live = newest.and_then(|(_, l)| at(l, "not_after").filter(|na| *na > now).map(|na| (endpoint_of(l), na)));
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
    fn ledger_check_refuses_an_entry_that_does_not_read() {
        let day = 86_400;
        let mut bad = entry(OTHER, B, NOW - day, NOW + 300 * day);
        bad["not_before"] = json!("soon");
        let ledger = json!([entry(ROOT, A, NOW - day, NOW + 300 * day), bad]);
        assert_eq!(check(Some(&ledger), ROOT, A, NOW, false).unwrap_err().why, "the record's ledger entry 1 does not read: not_before");
        assert_eq!(check(Some(&json!({})), ROOT, A, NOW, false).unwrap_err().why, "the record's ledger is a list");
        assert_eq!(
            check(Some(&json!([])), ROOT, "http://agent.alina.example/mcp", NOW, false).unwrap_err().why,
            "endpoint is not an https URL in normal form"
        );
    }
}
