//! The cards section of contract/contract.json (§4 cards): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::card;
use crate::refresh;

pub(super) fn card_encode(a: &Value) -> Result<Value> {
    Ok({
        let (name, cert, seal) = (s(a, "fn")?, bytes(a, "cert")?, opt_s(a, "seal")?);
        // A list of strings, or `extra is required`: an item that was not a string — a number, or
        // null — was dropped here and the card written without it, where the Go port refused the call
        // (T21). Read last, in the contract's order; it was read first, which mattered only once it
        // could refuse.
        let extra: Vec<String> = match a.get("extra") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                items.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<_>>().ok_or_else(|| required("extra"))?
            }
            Some(_) => return Err(required("extra")),
        };
        json!({ "vcard": card::encode(name, &cert, seal, &extra)? })
    })
}

pub(super) fn card_decode(a: &Value) -> Result<Value> {
    Ok({
        // The card, then the instant it is judged at: the contract's order, and the Go port's (R25).
        // `now` is what `expired` MEANS. It was optional, and absent it was 1970: every card ever
        // made decoded, and answered `expired: false`.
        let text = s(a, "vcard")?;
        let now = instant(a, "now")?;
        let c = card::decode(text, now)?;
        json!({ "fn": c.fn_, "version": 1, "seal": c.seal, "cert": b64u(&c.cert), "root": c.root, "endpoint": c.endpoint, "expired": c.expired, "ignored": c.ignored, "bytes": text.len(), "leaf": cert_json(&c.leaf) })
    })
}

/// A peer's answer to `get_card`, judged against the host's pin (refresh.rs). Read in the contract's
/// order: the pin, whose members are the host's own and named by their path; the answer, which must be
/// there and is otherwise read as it was sent; and the instant.
pub(super) fn refresh_check(a: &Value) -> Result<Value> {
    let Some(pin) = a.get("pin").filter(|v| !v.is_null()) else { return Err(required("pin")) };
    let Some(pin) = pin.as_object() else { return Err(required("pin")) };
    let member = |k: &str| pin.get(k).and_then(Value::as_str).ok_or_else(|| required(&format!("pin.{k}")));
    let root = member("root")?;
    refresh::pin_root(root)?;
    let endpoint = member("endpoint")?;
    let leaf = match pin.get("leaf") {
        None | Some(Value::Null) => return Err(required("pin.leaf")),
        Some(Value::String(l)) => from_b64u(l)?,
        Some(_) => return err("parse", "not base64url"),
    };
    let Some(answer) = a.get("answer").filter(|v| !v.is_null()) else { return Err(required("answer")) };
    let now = instant(a, "now")?;
    Ok(refresh::check(&refresh::Pin { root, endpoint, leaf: &leaf }, answer, now)?.to_value())
}
