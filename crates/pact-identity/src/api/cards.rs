//! The cards section of contract/contract.json (§4 cards): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::card;

pub(super) fn card_encode(a: &Value) -> Result<Value> {
    Ok({
        let extra: Vec<String> = a
            .get("extra")
            .and_then(|e| e.as_array())
            .map(|items| items.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        json!({ "vcard": card::encode(s(a, "fn")?, &bytes(a, "cert")?, opt_s(a, "seal"), &extra)? })
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
