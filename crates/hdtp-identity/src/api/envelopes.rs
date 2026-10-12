//! The envelopes section of contract/contract.json (§5 envelopes): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::envelope::{self, CallerPin, DecideInput, Form, OpenResultArgs, SealRequest, SealResult, Wire};
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
            form: Form::parse(opt_s(a, "form")?.unwrap_or("chain"))?,
            sender_chain: sender_chain.as_deref(),
            method: opt_s(a, "method")?.unwrap_or("tools/call").to_string(),
            // Absent or null is `{}` (CONTRACT §0: null is absent); present, sealed as the value it reads as
            // (seal_request's in_order), not as the text it was written in.
            params: a.get("params").filter(|v| !v.is_null()).cloned().unwrap_or(json!({})),
            msg_id: id(a, "msg_id")?.to_string(),
            ts: int(a, "ts")?,
            exp: opt_int(a, "exp")?,
            cty: opt_s(a, "cty")?.map(|c| c.to_string()),
            ephemeral_seed: seed32(a, "ephemeral_seed")?,
        })?;
        serde_json::to_value(wire).map_err(|_| Error::new("internal", crate::util::UNSERIALISABLE))?
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
            form: Form::parse(opt_s(a, "form")?.unwrap_or("chain"))?,
            sender_chain: sender_chain.as_deref(),
            // Null is absent (CONTRACT §0): a null result alone is no result, and beside an error it is
            // not a second one. Both ports sealed it as present.
            result: a.get("result").filter(|v| !v.is_null()).cloned(),
            error: a.get("error").filter(|v| !v.is_null()).cloned(),
            msg_id: id(a, "msg_id")?.to_string(),
            ts: int(a, "ts")?,
            exp: opt_int(a, "exp")?,
            ephemeral_seed: seed32(a, "ephemeral_seed")?,
        })?;
        serde_json::to_value(wire).map_err(|_| Error::new("internal", crate::util::UNSERIALISABLE))?
    })
}

pub(super) fn open_result(a: &Value) -> Result<Value> {
    Ok({
        // Absent is the caller's omission (CONTRACT §0, `envelope is required`); present, it is read as
        // `decide` reads one (§13.1), and every refusal of it is `envelope_invalid`.
        let wire = match a.get("envelope").filter(|v| !v.is_null()) {
            None => return err("bad_request", "envelope is required"),
            Some(v) => Wire::read(v)?,
        };
        let key = private(a, "my_pkcs8")?;
        let me = public(a, "my_spki")?;
        // Absent and null are no pins (§0: null is absent); a pin is refused by the member it lacks,
        // in these words and never serde's (F11, R20, R21).
        let pins: Vec<CallerPin> = match a.get("pins").filter(|v| !v.is_null()) {
            None => Vec::new(),
            Some(v) => CallerPin::read_all(v)?,
        };
        envelope::open_result(OpenResultArgs {
            envelope: &wire,
            my_key: &key,
            my_public: &me,
            msg_id: s(a, "msg_id")?,
            now: instant(a, "now")?,
            pins: &pins,
            expected_root: opt_s(a, "expected_root")?,
            expected_endpoint: opt_s(a, "expected_endpoint")?,
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

/// An envelope the reader refuses (§13.1, `envelope_invalid` and only that) is step 1 of §13.3 failing:
/// a decision, as every later step's refusal is, and not an error of the call.
pub(super) fn decide(a: &Value) -> Result<Value> {
    let out = match DecideInput::read(a) {
        Err(e) if e.code == "envelope_invalid" => {
            envelope::DecideOutput { result: json!({ "code": e.code, "why": e.why }), effects: Vec::new() }
        }
        input => envelope::decide(&input?)?,
    };
    serde_json::to_value(out).map_err(|_| Error::new("internal", crate::util::UNSERIALISABLE))
}

/// A chain proven at the TLS layer, decided by the pins (`envelope::decide_chain`). Read as `decide`
/// reads its own: `node`, `chain` and `now` absent or null, in that order; then the node whole, by the
/// one reader; the chain, as every function reads one; `now`.
pub(super) fn decide_chain(a: &Value) -> Result<Value> {
    for k in ["node", "chain", "now"] {
        if a.get(k).is_none_or(Value::is_null) {
            return Err(required(k));
        }
    }
    let node = envelope::NodeState::read(&a["node"])?;
    let chain = chain(a, "chain")?;
    let now = instant(a, "now")?;
    serde_json::to_value(envelope::decide_chain(&node, &chain, now)?).map_err(|_| Error::new("internal", crate::util::UNSERIALISABLE))
}
