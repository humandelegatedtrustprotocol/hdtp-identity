//! The cards section of contract/contract.json (§4 cards): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::card;

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
        json!({ "fn": c.fn_, "version": 2, "seal": c.seal, "cert": b64u(&c.cert), "root": c.root, "endpoint": c.endpoint, "expired": c.expired, "ignored": c.ignored, "bytes": text.len(), "leaf": cert_json(&c.leaf) })
    })
}
