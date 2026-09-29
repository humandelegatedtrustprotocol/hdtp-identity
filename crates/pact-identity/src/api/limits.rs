//! The limits section of contract/contract.json (§6.3 the call budgets): a body for each function it
//! declares, which `api.rs`'s `dispatch` names. The rules and the decision are the `pact-limits`
//! crate's; this file only reads JSON into them and writes the answer back.
use super::*;
use pact_limits::{decide, Charge, Decision, Level, MemoryStore, Rules, StateStore, RULE_MEMBERS};

/// The largest integer every host reads exactly (2^53 - 1): times, counts and contact caps above it
/// are refused rather than rounded.
const MAX_EXACT: i64 = 9_007_199_254_740_991;

/// The first member of `o`, in sorted order, that `allowed` does not name.
fn stranger<'a>(o: &'a Map<String, Value>, allowed: &[&str]) -> Option<&'a str> {
    let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
    keys.sort_unstable();
    keys.into_iter().find(|k| !allowed.contains(k))
}

/// An integer member from 0 to 2^53 - 1, written without a fraction or an exponent.
fn whole(v: Option<&Value>) -> Option<i64> {
    v.and_then(Value::as_i64).filter(|n| (0..=MAX_EXACT).contains(n))
}

/// A rules document read and held to `Rules::check`, or the first reason it cannot be enforced.
fn read_rules(doc: &Value) -> std::result::Result<Rules, String> {
    let Some(o) = doc.as_object() else { return Err("the limits rules are an object".into()) };
    if let Some(k) = stranger(o, &RULE_MEMBERS) {
        return Err(format!("the limits rules hold {}, and nothing else: {k}", RULE_MEMBERS.join(", ")));
    }
    for m in RULE_MEMBERS {
        if !o.get(m).is_some_and(Value::is_number) {
            return Err(format!("{m} is a number"));
        }
    }
    let rules = Rules::from_members(|m| o[m].as_f64().unwrap_or(f64::NAN));
    rules.check()?;
    Ok(rules)
}

pub(super) fn limits_rules_check(a: &Value) -> Result<Value> {
    let Some(doc) = a.get("rules").filter(|v| !v.is_null()) else { return err("bad_request", "rules is required") };
    Ok(match read_rules(doc) {
        Ok(_) => json!({ "ok": true }),
        Err(why) => json!({ "ok": false, "why": why }),
    })
}

const KINDS: &str = "contact_in, guest_in, guest_total, contact_out, stranger_out, integration, pending_in";

fn read_charge(v: Option<&Value>) -> Result<Charge> {
    let Some(o) = v.and_then(Value::as_object) else { return err("bad_request", "charge is required") };
    let Some(kind) = o.get("kind").and_then(Value::as_str) else { return err("bad_request", "charge.kind is required") };
    let members: &[&str] = match kind {
        "contact_in" | "contact_out" => &["kind", "root", "contact_cap"],
        "guest_in" => &["kind", "root", "source", "addressed"],
        "guest_total" | "stranger_out" => &["kind"],
        "integration" => &["kind", "integration", "contact"],
        "pending_in" => &["kind", "held"],
        _ => return err("bad_request", format!("charge.kind is one of {KINDS}")),
    };
    if let Some(k) = stranger(o, members) {
        return err("bad_request", format!("a {kind} charge holds {}, and nothing else: {k}", members.join(", ")));
    }
    let text = |m: &str| match o.get(m).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => err("bad_request", format!("charge.{m} is required")),
    };
    let count =
        |m: &str| whole(o.get(m)).map(|n| n as f64).ok_or_else(|| Error::new("bad_request", format!("charge.{m} is a whole number")));
    Ok(match kind {
        "contact_in" => Charge::ContactIn { root: text("root")?, contact_cap: count("contact_cap")? },
        "contact_out" => Charge::ContactOut { root: text("root")?, contact_cap: count("contact_cap")? },
        "guest_in" => {
            let root = match o.get("root") {
                None | Some(Value::Null) => None,
                Some(Value::String(r)) => Some(r.clone()),
                Some(_) => return err("bad_request", "charge.root is a string or null"),
            };
            let Some(source) = o.get("source").and_then(Value::as_str) else { return err("bad_request", "charge.source is required") };
            let Some(addressed) = o.get("addressed").and_then(Value::as_bool) else {
                return err("bad_request", "charge.addressed is required");
            };
            Charge::GuestIn { root, source: source.to_string(), addressed }
        }
        "guest_total" => Charge::GuestTotal,
        "stranger_out" => Charge::StrangerOut,
        "integration" => Charge::Integration { integration: text("integration")?, contact: text("contact")? },
        _ => Charge::PendingIn { held: count("held")? },
    })
}

/// The rows the caller holds, in sorted order so that the first one that does not read is the same
/// in every port.
fn read_state(v: Option<&Value>) -> Result<MemoryStore> {
    let mut store = MemoryStore::default();
    let o = match v {
        None | Some(Value::Null) => return Ok(store),
        Some(Value::Object(o)) => o,
        Some(_) => return err("bad_request", "state is an object of rows by bucket"),
    };
    let mut keys: Vec<&String> = o.keys().collect();
    keys.sort_unstable();
    for key in keys {
        let bad = |m: &str| Error::new("bad_request", format!("the state's row {key} does not read: {m}"));
        let row = o[key].as_object().ok_or_else(|| bad("a row is an object"))?;
        if let Some(k) = stranger(row, &["tokens", "updated_at"]) {
            return Err(bad(k));
        }
        let tokens = row.get("tokens").and_then(Value::as_f64).filter(|t| t.is_finite()).ok_or_else(|| bad("tokens"))?;
        let updated_at = whole(row.get("updated_at")).ok_or_else(|| bad("updated_at"))?;
        store.put(key, Level { tokens, updated_at });
    }
    Ok(store)
}

pub(super) fn limits_decide(a: &Value) -> Result<Value> {
    // In the order the function needs them (CONTRACT §0): the rules, what is charged, when, the rows.
    let Some(doc) = a.get("rules").filter(|v| !v.is_null()) else { return err("bad_request", "rules is required") };
    let rules = read_rules(doc).map_err(|why| Error::new("bad_request", format!("the limits rules cannot be enforced: {why}")))?;
    let charge = read_charge(a.get("charge"))?;
    if a.get("now").is_none_or(Value::is_null) {
        return err("bad_request", "now is required");
    }
    let now = whole(a.get("now")).ok_or_else(|| Error::new("bad_request", "now is a time in milliseconds"))?;
    let mut store = read_state(a.get("state"))?;
    let decision = decide(&rules, &charge, now, &mut store);
    // The rows the decision wrote, in charge order: every bucket of an allowed call, none of a refusal.
    let writes: Vec<Value> = match decision {
        Decision::Allow => charge
            .buckets(&rules)
            .into_iter()
            .filter_map(|b| store.get(&b.key).map(|l| json!({ "bucket": b.key, "tokens": l.tokens, "updated_at": l.updated_at })))
            .collect(),
        Decision::Refuse { .. } => Vec::new(),
    };
    Ok(match decision {
        Decision::Allow => json!({ "allowed": true, "retry_after": 0, "refused_by": null, "writes": writes }),
        Decision::Refuse { retry_after, which } => {
            json!({ "allowed": false, "retry_after": retry_after, "refused_by": which, "writes": writes })
        }
    })
}
