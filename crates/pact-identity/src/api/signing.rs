//! The signing section of contract/contract.json (§3.1 signing requests): a body for each function
//! it declares, which `api.rs`'s `dispatch` names.
use super::*;
use crate::signing;

pub(super) fn signing_request_check(a: &Value) -> Result<Value> {
    // The arguments are errors; the request's own faults are the answer (CONTRACT §3.1).
    let request = match a.get("request") {
        Some(r @ Value::Object(_)) => r,
        _ => return err("bad_request", "request is required"),
    };
    let origin = s(a, "origin")?;
    let now = instant(a, "now")?;
    let roots = opt_chain(a, "root_spkis")?;
    Ok(match signing::check(request, origin, now, &roots) {
        Ok(c) => c.to_value(),
        Err(e) => json!({ "ok": false, "why": e.why }),
    })
}
