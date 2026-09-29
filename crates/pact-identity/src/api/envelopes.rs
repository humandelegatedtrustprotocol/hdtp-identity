//! The envelopes section of contract/contract.json (§5 envelopes): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::envelope::{
    self, CallerPin, DecideInput, Form, FormerEndpoint, HeldKey, NodeState, OpenResultArgs, Pin, SealRequest, SealResult, Tombstone, Wire,
};
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
        // Absent is the caller's omission (CONTRACT §0, `envelope is required`); present, every refusal
        // of the envelope is `envelope_invalid`, and names the member that is not there (T9, F12,
        // S1-1): it answered "envelope members" for all five faults, and the Go port five ways.
        let wire = match a.get("envelope").filter(|v| !v.is_null()) {
            None => return err("bad_request", "envelope is required"),
            Some(v) => wire_of(v).map_err(|e| Error::new("envelope_invalid", e.why))?,
        };
        let key = private(a, "my_pkcs8")?;
        let me = public(a, "my_spki")?;
        // Absent and null are no pins (§0: null is absent); a pin is refused by the member it lacks,
        // in these words and never serde's (F11, R20, R21).
        let pins: Vec<CallerPin> = match a.get("pins").filter(|v| !v.is_null()) {
            None => Vec::new(),
            Some(v) => list_of(v, "pins", |p, path| {
                let p = pin_of(p, path)?;
                Ok(CallerPin { root: p.root, endpoint: p.endpoint, leaf: p.leaf, state: p.state, leaf_fingerprint: p.leaf_fingerprint })
            })?,
        };
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
        // Then each is read whole, and a member it lacks is named by its path (`node.pins[0].leaf`,
        // `envelope.sig`): it was "decide input does not read" for every one of them, and the Go port
        // decided on the zero value instead (T9, F13, R22). The host decoded these; they are its
        // arguments, so a fault in them is `bad_request`, never a decision about the peer.
        let node = node_state(&a["node"])?;
        let envelope = wire_of(&a["envelope"])?;
        let now = s(a, "now")?.to_string();
        serde_json::to_value(envelope::decide(&DecideInput { now, envelope, node })?).map_err(|e| Error::new("internal", e.to_string()))?
    })
}

// ── the objects inside a member, read by hand (the Go port reads them the same way, in the same order)

/// `<path> is required`: a member of an object inside the arguments that is absent, null or not the
/// type it is, named as CONTRACT §0 names a member of the arguments.
fn required(path: &str) -> Error {
    Error::new("bad_request", format!("{path} is required"))
}

fn object_of<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    v.as_object().ok_or_else(|| required(path))
}

fn text(o: &Map<String, Value>, k: &str, path: &str) -> Result<String> {
    o.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| required(&format!("{path}.{k}")))
}

fn opt_text(o: &Map<String, Value>, k: &str, path: &str) -> Result<Option<String>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.clone())),
        Some(_) => Err(required(&format!("{path}.{k}"))),
    }
}

fn flag(o: &Map<String, Value>, k: &str, path: &str) -> Result<bool> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(required(&format!("{path}.{k}"))),
    }
}

/// A list: each item read by `each`, named `<path>[<i>]`.
fn list_of<T>(v: &Value, path: &str, each: impl Fn(&Value, &str) -> Result<T>) -> Result<Vec<T>> {
    let items = v.as_array().ok_or_else(|| required(path))?;
    items.iter().enumerate().map(|(i, item)| each(item, &format!("{path}[{i}]"))).collect()
}

/// An optional list member: absent or null is empty.
fn opt_list<T>(o: &Map<String, Value>, k: &str, path: &str, each: impl Fn(&Value, &str) -> Result<T>) -> Result<Vec<T>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(v) => list_of(v, &format!("{path}.{k}"), each),
    }
}

fn texts(o: &Map<String, Value>, k: &str, path: &str) -> Result<Vec<String>> {
    opt_list(o, k, path, |v, p| v.as_str().map(str::to_string).ok_or_else(|| required(p)))
}

/// The four members of an envelope as it arrived, in the order the contract lists them: strings that
/// may be anything, judged later by the function.
fn wire_of(v: &Value) -> Result<Wire> {
    let o = object_of(v, "envelope")?;
    Ok(Wire {
        protected: text(o, "protected", "envelope")?,
        enc: text(o, "enc", "envelope")?,
        ct: text(o, "ct", "envelope")?,
        sig: text(o, "sig", "envelope")?,
    })
}

/// A pin, `open_result`'s or a node's: root, endpoint and leaf; `state` absent is `active`.
fn pin_of(v: &Value, path: &str) -> Result<Pin> {
    let o = object_of(v, path)?;
    Ok(Pin {
        root: text(o, "root", path)?,
        endpoint: text(o, "endpoint", path)?,
        leaf: text(o, "leaf", path)?,
        state: opt_text(o, "state", path)?.unwrap_or_else(|| "active".into()),
        leaf_fingerprint: opt_text(o, "leaf_fingerprint", path)?,
    })
}

/// The node state, member by member in the contract's order (`NodeState`). `accept_new_hosts` absent
/// is `auto` (SPEC §5.3, the contract's description), and anything but `auto` or `ask` is refused:
/// the Go port read an absent one as its zero value and held a moved contact the core followed (T8).
fn node_state(v: &Value) -> Result<NodeState> {
    let path = "node";
    let o = object_of(v, path)?;
    let endpoint = text(o, "endpoint", path)?;
    let accept_new_hosts = match opt_text(o, "accept_new_hosts", path)?.as_deref() {
        None => "auto".to_string(),
        Some(h @ ("auto" | "ask")) => h.to_string(),
        Some(_) => return err("bad_request", "node.accept_new_hosts is auto or ask"),
    };
    Ok(NodeState {
        endpoint,
        accept_new_hosts,
        chain: texts(o, "chain", path)?,
        keys: opt_list(o, "keys", path, |v, p| {
            let k = object_of(v, p)?;
            Ok(HeldKey { kid: text(k, "kid", p)?, leaf: text(k, "leaf", p)?, pkcs8: text(k, "pkcs8", p)?, current: flag(k, "current", p)? })
        })?,
        former: texts(o, "former", path)?,
        sibling_kids: texts(o, "sibling_kids", path)?,
        pins: opt_list(o, "pins", path, pin_of)?,
        tombstones: opt_list(o, "tombstones", path, |v, p| {
            let t = object_of(v, p)?;
            Ok(Tombstone { root: text(t, "root", p)?, leaf: text(t, "leaf", p)?, at: text(t, "at", p)? })
        })?,
        former_endpoints: opt_list(o, "former_endpoints", path, |v, p| {
            let f = object_of(v, p)?;
            Ok(FormerEndpoint { root: text(f, "root", p)?, endpoint: text(f, "endpoint", p)?, at: text(f, "at", p)? })
        })?,
        seen: texts(o, "seen", path)?,
    })
}
