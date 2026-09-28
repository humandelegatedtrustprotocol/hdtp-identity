//! The envelopes section of contract/contract.json (§5 envelopes): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::envelope::{self, CallerPin, Form, OpenResultArgs, SealRequest, SealResult, Wire};
use crate::hpke::{self, Suite};

pub(super) fn suite_for(a: &Value) -> Result<Value> {
    Ok(json!({ "suite": envelope::suite_name(&bytes(a, "spki")?)? }))
}

pub(super) fn hpke_seal(a: &Value) -> Result<Value> {
    Ok({
        let suite = Suite::parse(s(a, "suite")?).ok_or_else(|| Error::new("envelope_invalid", "version or suite"))?;
        let (enc, ct) = hpke::seal(
            suite,
            &public(a, "recipient_spki")?,
            s(a, "info")?.as_bytes(),
            &opt_bytes(a, "aad")?.unwrap_or_default(),
            &bytes(a, "plaintext")?,
            seed32(a, "ephemeral_seed")?,
        )?;
        json!({ "enc": b64u(&enc), "ct": b64u(&ct) })
    })
}

pub(super) fn hpke_open(a: &Value) -> Result<Value> {
    Ok({
        let suite = Suite::parse(s(a, "suite")?).ok_or_else(|| Error::new("envelope_invalid", "version or suite"))?;
        let pt = hpke::open(
            suite,
            &private(a, "recipient_pkcs8")?,
            &public(a, "recipient_spki")?,
            s(a, "info")?.as_bytes(),
            &opt_bytes(a, "aad")?.unwrap_or_default(),
            &bytes(a, "enc")?,
            &bytes(a, "ct")?,
        )?;
        json!({ "plaintext": b64u(&pt) })
    })
}

pub(super) fn seal_request(a: &Value) -> Result<Value> {
    Ok({
        let leaf = x509::parse(&bytes(a, "recipient_leaf")?)?;
        let sender = private(a, "sender_pkcs8")?;
        let sender_chain = present_chain(a, "sender_chain")?;
        let wire = envelope::seal_request(SealRequest {
            recipient: &leaf.public_key,
            sender: &sender,
            form: Form::parse(opt_s(a, "form").unwrap_or("chain"))?,
            sender_chain: sender_chain.as_deref(),
            method: opt_s(a, "method").unwrap_or("tools/call").to_string(),
            params: a.get("params").cloned().unwrap_or(json!({})),
            msg_id: id(a, "msg_id")?.to_string(),
            ts: int(a, "ts")?,
            exp: opt_int(a, "exp"),
            cty: opt_s(a, "cty").map(|c| c.to_string()),
            ephemeral_seed: seed32(a, "ephemeral_seed")?,
        })?;
        serde_json::to_value(wire).map_err(|e| Error::new("internal", e.to_string()))?
    })
}

pub(super) fn seal_result(a: &Value) -> Result<Value> {
    Ok({
        let recipient = public(a, "recipient_spki")?;
        let sender = private(a, "sender_pkcs8")?;
        let sender_chain = present_chain(a, "sender_chain")?;
        let wire = envelope::seal_result(SealResult {
            recipient: &recipient,
            sender: &sender,
            form: Form::parse(opt_s(a, "form").unwrap_or("chain"))?,
            sender_chain: sender_chain.as_deref(),
            result: a.get("result").cloned(),
            error: a.get("error").cloned(),
            msg_id: id(a, "msg_id")?.to_string(),
            ts: int(a, "ts")?,
            exp: opt_int(a, "exp"),
            ephemeral_seed: seed32(a, "ephemeral_seed")?,
        })?;
        serde_json::to_value(wire).map_err(|e| Error::new("internal", e.to_string()))?
    })
}

pub(super) fn open_result(a: &Value) -> Result<Value> {
    Ok({
        let wire: Wire = serde_json::from_value(a.get("envelope").cloned().unwrap_or(Value::Null))
            .map_err(|_| Error::new("envelope_invalid", "envelope members"))?;
        let key = private(a, "my_pkcs8")?;
        let me = public(a, "my_spki")?;
        let pins: Vec<CallerPin> = serde_json::from_value(a.get("pins").cloned().unwrap_or(json!([])))
            .map_err(|e| Error::new("bad_request", format!("pins: {e}")))?;
        envelope::open_result(OpenResultArgs {
            envelope: &wire,
            my_key: &key,
            my_public: &me,
            msg_id: s(a, "msg_id")?,
            now: instant(a, "now")?,
            pins: &pins,
            expected_root: opt_s(a, "expected_root"),
            expected_endpoint: opt_s(a, "expected_endpoint"),
        })?
    })
}

pub(super) fn follow_renewed(a: &Value) -> Result<Value> {
    Ok(envelope::follow_renewed(
        a.get("answer").unwrap_or(&Value::Null),
        s(a, "pinned_root")?,
        &bytes(a, "pinned_leaf")?,
        s(a, "dialed")?,
        instant(a, "now")?,
    ))
}

pub(super) fn decide(a: &Value) -> Result<Value> {
    Ok({
        // A missing `node` is not a decision against an empty node, and the member is named the
        // way the caller wrote it rather than the way serde reports a missing field — the Go port
        // cannot reproduce another library's wording, and CONTRACT §0 promises it will not have to.
        for k in ["node", "envelope", "now"] {
            if a.get(k).is_none_or(Value::is_null) {
                return err("bad_request", format!("{k} is required"));
            }
        }
        let input: envelope::DecideInput =
            serde_json::from_value(a.clone()).map_err(|_| Error::new("bad_request", "decide input does not read"))?;
        serde_json::to_value(envelope::decide(&input)?).map_err(|e| Error::new("internal", e.to_string()))?
    })
}
