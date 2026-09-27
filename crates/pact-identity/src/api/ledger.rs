//! The ledger section of contract/contract.json (§6.1 the ledger): a body for each function it
//! declares, which `api.rs`'s `dispatch` names.
use super::*;
use crate::ledger;

pub(super) fn ledger_check(a: &Value) -> Result<Value> {
    // In the order the function needs them (CONTRACT §0): whose ledger, where, when, then the ledger.
    let root = id(a, "root")?;
    let endpoint = s(a, "endpoint")?;
    let now = instant(a, "now")?;
    let moving = match a.get("move") {
        None | Some(Value::Null) => false,
        Some(v) => v.as_bool().ok_or_else(|| Error::new("bad_request", "move is required"))?,
    };
    let book = a.get("ledger").filter(|v| !v.is_null());
    Ok(ledger::check(book, root, endpoint, now, moving)?.to_value())
}
