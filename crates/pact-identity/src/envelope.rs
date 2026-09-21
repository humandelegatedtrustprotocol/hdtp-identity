//! Sealed envelopes (§13): sealing in both forms, the caller's side of a result, `certificate_renewed`
//! on the caller's side, and `decide` — the receiving side of §13.3, §6.1, §5.3 and §14.4 as one pure
//! function over state the host supplies. `envelope.mjs receive()` is its specification, line for line.
use crate::canonical::canonical;
use crate::card;
use crate::hpke::{self, suite_for, Suite};
use crate::keys::{PrivateKey, PublicKey};
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{b64u, err, from_b64u, wire_b64u, Error, Result};
use crate::x509::{self, compare_leaves, parse, validate_chain, ChainResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

pub const HEADER_MEMBERS: &str = "cty,exp,kid,msg_id,suite,ts,v";
pub const SKEW_S: i64 = 300;
/// §13.1: `exp − ts` is at most 30 days, so no receiver is asked to remember a msg_id for ever.
pub const MAX_LIFETIME_S: i64 = 30 * 86_400;

/// The skew window and the lifetime cap, in arithmetic that cannot overflow.
///
/// `(now - ts).abs()` on a `ts` of `i64::MIN + now` overflows to `i64::MIN`, and `i64::MIN.abs()` is
/// `i64::MIN` again in a release build (a debug build panics instead, which is why `cargo test` was
/// green over it). `i64::MIN <= 300` is true, so the skew window passed, and `exp - ts` wrapped the
/// same way past the thirty-day cap: two normative MUSTs of SPEC 13.3/13.1 bypassed by one header
/// member, from a stranger, in the pinned wasm core.
///
/// Widened to `i128`, where no pair of `i64`s can overflow a difference — not bounded to a band of
/// plausible years, which is what the first fix did (2026-09-20) and which was itself a defect: an
/// `exp` beyond the band answered "outside the time window" where the Go port, computing in
/// `float64`, answers "exp too far from ts". The comment on that fix said the refusals were unchanged,
/// and they were not. Exact arithmetic has no constant to choose and agrees with the other two ports
/// on every input the header's integer check admits.
enum Timing {
    Ok,
    OutsideWindow,
    TooLong,
}

fn timing(now: i64, ts: i64, exp: i64) -> Timing {
    let (now, ts, exp) = (now as i128, ts as i128, exp as i128);
    if !(now < exp && (now - ts).abs() <= SKEW_S as i128) {
        return Timing::OutsideWindow;
    }
    if exp - ts > MAX_LIFETIME_S as i128 {
        return Timing::TooLong;
    }
    Timing::Ok
}

pub const CLAIM_WINDOW_S: i64 = 30 * 86_400;
pub const TOMBSTONE_S: i64 = 30 * 86_400;
pub const CTY_CALL: &str = "application/pact-call+json";
pub const CTY_RESULT: &str = "application/pact-result+json";
pub const INFO_V2: &[u8] = b"PACT-SEAL-v2";
const GUEST_TOOLS: [&str; 2] = ["redeem_invite", "request_contact"];
const PENDING_TOOLS: [&str; 2] = ["contact_accepted", "contact_rejected"];

/// The four wire members.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wire {
    pub protected: String,
    pub enc: String,
    pub ct: String,
    pub sig: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    Chain,
    Leaf,
}

impl Form {
    pub fn parse(s: &str) -> Result<Form> {
        match s {
            "chain" => Ok(Form::Chain),
            "leaf" => Ok(Form::Leaf),
            _ => err("bad_request", "form is chain or leaf"),
        }
    }
}

fn header(suite: Suite, kid: &str, msg_id: &str, ts: i64, exp: i64, cty: &str) -> Vec<u8> {
    let h = json!({ "v": 2, "suite": suite.id(), "kid": kid, "msg_id": msg_id, "ts": ts, "exp": exp, "cty": cty });
    canonical(&h).into_bytes()
}

fn proof(form: Form, sender: &PrivateKey, sender_chain: Option<&[Vec<u8>]>) -> Result<(&'static str, Value)> {
    match form {
        Form::Chain => {
            let chain = sender_chain.ok_or_else(|| Error::new("bad_request", "the chain form needs sender_chain"))?;
            // §13: the chain form carries the leaf and the root, in that order. Two is the only
            // length that is a chain; one or three was assembled here and refused by the Go port.
            if chain.len() != 2 {
                return err("bad_request", "sender_chain must be the leaf and the root");
            }
            Ok(("chain", Value::Array(chain.iter().map(|c| Value::String(b64u(c))).collect())))
        }
        Form::Leaf => Ok(("leaf", Value::String(sender.public().fingerprint()))),
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_body(
    recipient: &PublicKey,
    sender: &PrivateKey,
    body: &Value,
    msg_id: &str,
    ts: i64,
    exp: i64,
    cty: &str,
    seed: Option<[u8; 32]>,
) -> Result<Wire> {
    let suite = suite_for(recipient);
    let aad = header(suite, &recipient.fingerprint(), msg_id, ts, exp, cty);
    let plaintext = serde_json::to_vec(body).map_err(|e| Error::new("internal", e.to_string()))?;
    let (enc, ct) = hpke::seal(suite, recipient, INFO_V2, &aad, &plaintext, seed)?;
    let mut signed = aad.clone();
    signed.extend_from_slice(&enc);
    signed.extend_from_slice(&ct);
    let sig = sender.sign(&signed);
    Ok(Wire { protected: b64u(&aad), enc: b64u(&enc), ct: b64u(&ct), sig: b64u(&sig) })
}

pub struct SealRequest<'a> {
    pub recipient: &'a PublicKey,
    pub sender: &'a PrivateKey,
    pub form: Form,
    pub sender_chain: Option<&'a [Vec<u8>]>,
    pub method: String,
    pub params: Value,
    pub msg_id: String,
    pub ts: i64,
    pub exp: Option<i64>,
    pub cty: Option<String>,
    pub ephemeral_seed: Option<[u8; 32]>,
}

/// `{method, params, chain | leaf}`, in that member order, sealed to the recipient leaf's key.
pub fn seal_request(r: SealRequest<'_>) -> Result<Wire> {
    let (k, v) = proof(r.form, r.sender, r.sender_chain)?;
    let mut body = Map::new();
    body.insert("method".into(), Value::String(r.method.clone()));
    body.insert("params".into(), r.params.clone());
    body.insert(k.into(), v);
    seal_body(
        r.recipient,
        r.sender,
        &Value::Object(body),
        &r.msg_id,
        r.ts,
        r.exp.unwrap_or(r.ts + 600),
        r.cty.as_deref().unwrap_or(CTY_CALL),
        r.ephemeral_seed,
    )
}

pub struct SealResult<'a> {
    pub recipient: &'a PublicKey,
    pub sender: &'a PrivateKey,
    pub form: Form,
    pub sender_chain: Option<&'a [Vec<u8>]>,
    pub result: Option<Value>,
    pub error: Option<Value>,
    pub msg_id: String,
    pub ts: i64,
    pub exp: Option<i64>,
    pub ephemeral_seed: Option<[u8; 32]>,
}

/// `{result | error, chain | leaf}` sealed back to the caller's key with the request's `msg_id`.
pub fn seal_result(r: SealResult<'_>) -> Result<Wire> {
    let (k, v) = proof(r.form, r.sender, r.sender_chain)?;
    let mut body = Map::new();
    match (&r.result, &r.error) {
        (Some(res), None) => body.insert("result".into(), res.clone()),
        (None, Some(e)) => body.insert("error".into(), e.clone()),
        _ => return err("bad_request", "a result carries exactly one of result and error"),
    };
    body.insert(k.into(), v);
    seal_body(r.recipient, r.sender, &Value::Object(body), &r.msg_id, r.ts, r.exp.unwrap_or(r.ts + 600), CTY_RESULT, r.ephemeral_seed)
}

fn members(v: &Value) -> String {
    match v.as_object() {
        Some(o) => {
            let mut k: Vec<&str> = o.keys().map(|s| s.as_str()).collect();
            k.sort_unstable();
            k.join(",")
        }
        None => String::new(),
    }
}

fn decode_header(protected: &str) -> Result<(Vec<u8>, Map<String, Value>)> {
    let aad = wire_b64u(protected).map_err(|_| Error::new("envelope_invalid", "protected is not JSON"))?;
    let h: Value = serde_json::from_slice(&aad).map_err(|_| Error::new("envelope_invalid", "protected is not JSON"))?;
    match h {
        Value::Object(o) => Ok((aad, o)),
        _ => err("envelope_invalid", "protected is not JSON"),
    }
}

fn header_checks(h: &Map<String, Value>) -> Result<Suite> {
    let mut keys: Vec<&str> = h.keys().map(|s| s.as_str()).collect();
    keys.sort_unstable();
    if keys.join(",") != HEADER_MEMBERS {
        return err("envelope_invalid", "header members");
    }
    // The closed set of names exists so two implementations cannot disagree about what was signed;
    // latitude in the types reopens the same gap, since `"1757000000"` and `1757000000` are different
    // bytes under one signature and compare alike in a language that coerces.
    let ints_ok = ["v", "ts", "exp"].iter().all(|k| h.get(*k).map(|v| v.is_i64()).unwrap_or(false));
    let strings_ok = ["suite", "kid", "msg_id", "cty"].iter().all(|k| h.get(*k).map(Value::is_string).unwrap_or(false));
    if !ints_ok || !strings_ok {
        return err("envelope_invalid", "header member types");
    }
    let suite = h.get("suite").and_then(|s| s.as_str()).and_then(Suite::parse);
    match (h.get("v"), suite) {
        (Some(v), Some(s)) if v.as_i64() == Some(2) => Ok(s),
        _ => err("envelope_invalid", "version or suite"),
    }
}

/// The pin that holds the leaf a small-form envelope names, among those that are not blocked.
///
/// The name arrives from somebody who has proved nothing yet, and finding it used to mean parsing
/// EVERY pinned leaf and hashing its key: N X.509 parses and N SHA-256s per envelope on a node with N
/// contacts, before freshness, before replay — and again for the same envelope sent twice. A host
/// already knows each pin's leaf fingerprint (`decide` hands it back when it pins), so a pin MAY
/// carry it: then the match is a string comparison and only the pin that matched is parsed. The match
/// is still held to its own leaf, because a fingerprint beside a certificate is a claim about it.
/// A pin without the member is read as before, so an older host loses nothing but the saving.
fn pin_holding<'a, P>(
    pins: impl Iterator<Item = &'a P>,
    named: &str,
    parts: impl Fn(&'a P) -> (&'a str, Option<&'a str>),
) -> Result<Option<(&'a P, x509::Cert)>>
where
    P: 'a,
{
    for p in pins {
        let (leaf_b64, claimed) = parts(p);
        if claimed.is_some_and(|c| c != named) {
            continue;
        }
        let leaf = parse(&from_b64u(leaf_b64)?)?;
        let actual = leaf.public_key.fingerprint();
        if claimed.is_some() && actual != named {
            return err("parse", "a pin's leaf_fingerprint is not its leaf's");
        }
        if actual == named {
            return Ok(Some((p, leaf)));
        }
    }
    Ok(None)
}

/// A caller's pin, as `open_result` needs it.
#[derive(Deserialize, Clone, Debug)]
pub struct CallerPin {
    pub root: String,
    pub endpoint: String,
    pub leaf: String,
    #[serde(default = "active")]
    pub state: String,
    /// The fingerprint of `leaf`'s key, when the host keeps it — see `pin_holding`.
    #[serde(default)]
    pub leaf_fingerprint: Option<String>,
}

fn active() -> String {
    "active".into()
}

pub struct OpenResultArgs<'a> {
    pub envelope: &'a Wire,
    pub my_key: &'a PrivateKey,
    pub msg_id: &'a str,
    pub now: i64,
    pub pins: &'a [CallerPin],
    pub expected_root: Option<&'a str>,
    pub expected_endpoint: Option<&'a str>,
}

/// The caller's side of §13.2: open, validate the responder's chain or find the named leaf among
/// the pins, refuse a superseded leaf, verify the signature, correlate.
pub fn open_result(a: OpenResultArgs<'_>) -> Result<Value> {
    let invalid = |why: &str| err::<Value>("envelope_invalid", why);
    let (aad, h) = decode_header(&a.envelope.protected)?;
    let suite = header_checks(&h)?;
    let me = a.my_key.public();
    if h.get("kid").and_then(|k| k.as_str()) != Some(&me.fingerprint()) {
        return invalid("kid is not this key");
    }
    if suite_for(&me) != suite {
        return invalid("suite does not fit the key");
    }
    if h.get("cty").and_then(|c| c.as_str()) != Some(CTY_RESULT) {
        return invalid("not a result");
    }
    if h.get("msg_id").and_then(|m| m.as_str()) != Some(a.msg_id) {
        return invalid("msg_id does not correlate");
    }
    let (ts, exp) = (h.get("ts").and_then(|t| t.as_i64()), h.get("exp").and_then(|t| t.as_i64()));
    match (ts, exp) {
        (Some(ts), Some(exp)) => match timing(a.now, ts, exp) {
            Timing::Ok => {}
            Timing::TooLong => return invalid("exp too far from ts"),
            Timing::OutsideWindow => return invalid("outside the time window"),
        },
        _ => return invalid("outside the time window"),
    }
    let enc = wire_b64u(&a.envelope.enc).map_err(|_| Error::new("envelope_invalid", "does not open"))?;
    let ct = wire_b64u(&a.envelope.ct).map_err(|_| Error::new("envelope_invalid", "does not open"))?;
    if enc.len() != suite.npk() {
        return err("envelope_invalid", "encapsulated key is not the suite's length");
    }
    let sig = wire_b64u(&a.envelope.sig).map_err(|_| Error::new("envelope_invalid", "signature"))?;
    let plaintext = hpke::open(suite, a.my_key, INFO_V2, &aad, &enc, &ct).map_err(|_| Error::new("envelope_invalid", "does not open"))?;
    let body: Value = serde_json::from_slice(&plaintext).map_err(|_| Error::new("envelope_invalid", "does not open"))?;
    let m = members(&body);
    let (payload_key, proof_key) = match m.as_str() {
        "chain,result" => ("result", "chain"),
        "leaf,result" => ("result", "leaf"),
        "chain,error" => ("error", "chain"),
        "error,leaf" => ("error", "leaf"),
        _ => return invalid("plaintext members"),
    };
    let mut signed = aad.clone();
    signed.extend_from_slice(&enc);
    signed.extend_from_slice(&ct);
    let mut out = Map::new();
    out.insert("ok".into(), Value::Bool(true));
    out.insert(payload_key.into(), body[payload_key].clone());
    if proof_key == "chain" {
        let chain = chain_of(&body["chain"])?;
        let v = match validate_chain(&chain, a.now, a.expected_root, a.expected_endpoint) {
            ChainResult::Ok(v) => v,
            ChainResult::Refused { rule, reason } => return invalid(&format!("chain rule {rule}: {reason}")),
        };
        if !v.leaf.public_key.verify(&signed, &sig) {
            return invalid("signature is not the chain's leaf key");
        }
        if let Some(p) = a.pins.iter().find(|p| p.root == v.root_fingerprint) {
            let pinned = from_b64u(&p.leaf)?;
            match compare_leaves(&pinned, &chain[0])? {
                "superseded" => return invalid("superseded leaf"),
                "conflict" => return invalid("a different leaf with the same notBefore"),
                "newer" => {
                    out.insert("leaf_update".into(), Value::String(b64u(&chain[0])));
                }
                _ => {}
            }
        } else {
            out.insert("leaf_update".into(), Value::String(b64u(&chain[0])));
        }
        out.insert("root".into(), Value::String(v.root_fingerprint));
        out.insert("endpoint".into(), Value::String(v.endpoint));
        out.insert("form".into(), Value::String("chain".into()));
    } else {
        let Some(named) = body["leaf"].as_str() else { return invalid("plaintext shape") };
        let found =
            pin_holding(a.pins.iter().filter(|p| p.state != "blocked"), named, |p| (p.leaf.as_str(), p.leaf_fingerprint.as_deref()))?;
        let Some((p, leaf)) = found else { return invalid("unknown leaf") };
        if a.now > leaf.not_after {
            return invalid("held leaf has expired");
        }
        if !leaf.public_key.verify(&signed, &sig) {
            return invalid("signature is not the held leaf's key");
        }
        if let Some(r) = a.expected_root {
            if r != p.root {
                return invalid("root is not the one expected");
            }
        }
        if let Some(e) = a.expected_endpoint {
            if e != p.endpoint {
                return invalid("endpoint differs from the one in question");
            }
        }
        out.insert("root".into(), Value::String(p.root.clone()));
        out.insert("endpoint".into(), Value::String(p.endpoint.clone()));
        out.insert("form".into(), Value::String("leaf".into()));
    }
    Ok(Value::Object(out))
}

fn chain_of(v: &Value) -> Result<Vec<Vec<u8>>> {
    let Some(items) = v.as_array() else { return err("envelope_invalid", "plaintext shape") };
    items.iter().map(|c| c.as_str().ok_or_else(|| Error::new("envelope_invalid", "plaintext shape")).and_then(from_b64u)).collect()
}

/// §14.4 on the caller's side: follow only a chain that validates to the pinned root at the dialed
/// address and is newer than or equal to the pinned leaf.
pub fn follow_renewed(answer: &Value, pinned_root: &str, pinned_leaf: &[u8], dialed: &str, now: i64) -> Value {
    if answer.get("code").and_then(|c| c.as_str()) != Some("certificate_renewed") {
        return json!({ "follow": false, "why": "not certificate_renewed" });
    }
    let chain = match answer.pointer("/data/chain").map(chain_of) {
        Some(Ok(c)) => c,
        _ => return json!({ "follow": false, "why": "no chain" }),
    };
    match validate_chain(&chain, now, Some(pinned_root), Some(dialed)) {
        ChainResult::Refused { rule, reason } => json!({ "follow": false, "why": format!("chain rule {rule}: {reason}") }),
        ChainResult::Ok(_) => match compare_leaves(pinned_leaf, &chain[0]) {
            Ok("superseded") => json!({ "follow": false, "why": "older than the pin" }),
            Ok("conflict") => json!({ "follow": false, "why": "a different leaf with the same notBefore" }),
            Ok(_) => json!({ "follow": true, "leaf": b64u(&chain[0]) }),
            Err(e) => json!({ "follow": false, "why": e.why }),
        },
    }
}

// ── decide ────────────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct HeldKey {
    pub kid: String,
    pub leaf: String,
    pub pkcs8: String,
    #[serde(default)]
    pub current: bool,
}

/// Written by hand so `pkcs8` cannot be printed. `PrivateKey` and `PublicKey` deliberately derive no
/// `Debug`; a derive here undid that, and any `{:?}`, `expect` message or panic payload that touched a
/// `HeldKey` printed a host's LEAF PRIVATE KEY. The rest is public and worth keeping debuggable.
impl std::fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldKey")
            .field("kid", &self.kid)
            .field("leaf", &self.leaf)
            .field("pkcs8", &"<redacted>")
            .field("current", &self.current)
            .finish()
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Pin {
    pub root: String,
    pub endpoint: String,
    pub leaf: String,
    #[serde(default = "active")]
    pub state: String,
    /// The fingerprint of `leaf`'s key, when the host keeps it — see `pin_holding`.
    #[serde(default)]
    pub leaf_fingerprint: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Tombstone {
    pub root: String,
    pub leaf: String,
    pub at: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct FormerEndpoint {
    pub root: String,
    pub endpoint: String,
    pub at: String,
}

fn auto() -> String {
    "auto".into()
}

#[derive(Deserialize, Clone, Debug)]
pub struct NodeState {
    pub endpoint: String,
    #[serde(default = "auto")]
    pub accept_new_hosts: String,
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub keys: Vec<HeldKey>,
    #[serde(default)]
    pub former: Vec<String>,
    #[serde(default)]
    pub sibling_kids: Vec<String>,
    #[serde(default)]
    pub pins: Vec<Pin>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default)]
    pub former_endpoints: Vec<FormerEndpoint>,
    #[serde(default)]
    pub seen: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DecideInput {
    pub now: String,
    pub envelope: Wire,
    pub node: NodeState,
}

#[derive(Serialize, Debug)]
pub struct DecideOutput {
    pub result: Value,
    pub effects: Vec<Value>,
}

fn done(result: Value) -> DecideOutput {
    DecideOutput { result, effects: Vec::new() }
}

fn invalid(why: &str) -> DecideOutput {
    done(json!({ "code": "envelope_invalid", "why": why }))
}

struct Freshness<'a> {
    h: &'a Map<String, Value>,
    now: i64,
    seen: &'a [String],
}

impl Freshness<'_> {
    /// `null` when fresh; otherwise the answer to give.
    fn check(&self) -> Option<DecideOutput> {
        if self.h.get("cty").and_then(|c| c.as_str()) != Some(CTY_CALL) {
            return Some(invalid("not a request"));
        }
        let ts = self.h.get("ts").and_then(|t| t.as_i64());
        let exp = self.h.get("exp").and_then(|t| t.as_i64());
        match (ts, exp) {
            (Some(ts), Some(exp)) => match timing(self.now, ts, exp) {
                Timing::Ok => {}
                Timing::TooLong => return Some(invalid("exp too far from ts")),
                Timing::OutsideWindow => return Some(invalid("outside the time window")),
            },
            _ => return Some(invalid("outside the time window")),
        }
        let msg_id = self.h.get("msg_id").and_then(|m| m.as_str()).unwrap_or("");
        if msg_id.is_empty() {
            return Some(invalid("empty msg_id"));
        }
        if self.seen.iter().any(|s| s == msg_id) {
            return Some(done(json!({ "code": "ok", "replayed": true })));
        }
        None
    }
}

/// The receiving rules over the state the host supplies. Changes nothing; returns the decision and
/// the effects to apply. `why` strings are the seed's, verbatim.
pub fn decide(input: &DecideInput) -> Result<DecideOutput> {
    let now = parse_rfc3339(&input.now)?;
    let node = &input.node;
    let e = &input.envelope;

    let (aad, h) = match decode_header(&e.protected) {
        Ok(x) => x,
        Err(_) => return Ok(invalid("protected is not JSON")),
    };
    let suite = match header_checks(&h) {
        Ok(s) => s,
        Err(err) => return Ok(invalid(&err.why)),
    };
    let kid = h.get("kid").and_then(|k| k.as_str()).unwrap_or("");

    // The key this endpoint holds for the identity served at this path: current, or superseded and not past notAfter.
    let mut held = None;
    for k in &node.keys {
        if k.kid != kid {
            continue;
        }
        let leaf = parse(&from_b64u(&k.leaf)?)?;
        if k.current || now <= leaf.not_after {
            held = Some((k, leaf));
            break;
        }
    }
    let Some((held, held_leaf)) = held else {
        if node.sibling_kids.iter().any(|s| s == kid) {
            return Ok(invalid("key held for another identity"));
        }
        if node.former.iter().any(|f| f == kid) {
            return Ok(done(json!({ "code": "certificate_renewed", "data": { "chain": node.chain } })));
        }
        return Ok(invalid("unknown kid"));
    };
    if suite_for(&held_leaf.public_key) != suite {
        return Ok(invalid("suite does not fit the leaf"));
    }
    let key = PrivateKey::from_pkcs8(&Zeroizing::new(from_b64u(&held.pkcs8)?))?;

    let (Ok(enc), Ok(ct)) = (wire_b64u(&e.enc), wire_b64u(&e.ct)) else { return Ok(invalid("does not open")) };
    // `sig` covers the three members concatenated with nothing between them, so the suite's own `enc`
    // length is what fixes the boundary: without it a byte moved from `enc` into `ct` leaves the
    // signed bytes identical.
    if enc.len() != suite.npk() {
        return Ok(invalid("encapsulated key is not the suite's length"));
    }
    let body: Value = match hpke::open(suite, &key, INFO_V2, &aad, &enc, &ct).ok().and_then(|p| serde_json::from_slice(&p).ok()) {
        Some(b) => b,
        None => return Ok(invalid("does not open")),
    };
    let m = members(&body);
    if m != "chain,method,params" && m != "leaf,method,params" {
        return Ok(invalid("plaintext members"));
    }
    let method = body["method"].as_str().unwrap_or("");
    if method != "tools/call" && method != "tools/list" {
        return Ok(invalid("plaintext shape"));
    }
    let mut signed = aad.clone();
    signed.extend_from_slice(&enc);
    signed.extend_from_slice(&ct);
    let sig = wire_b64u(&e.sig).unwrap_or_default();
    let tool: Option<String> = body["params"].get("name").and_then(|n| n.as_str()).map(|s| s.to_string());
    let tool_ref = tool.as_deref();
    let msg_id = h.get("msg_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let fresh = Freshness { h: &h, now, seen: &node.seen };

    // `leaf` is the leaf the signature verified under — the chain's, or the pinned one the small
    // form named — so a host can pin, seal to and answer the caller without opening it again.
    let ok = |tier: &str,
              root: &str,
              endpoint: &str,
              form: &str,
              leaf_b64: &str,
              extra: Map<String, Value>,
              effects: Vec<Value>|
     -> DecideOutput {
        let mut r = Map::new();
        r.insert("code".into(), json!("ok"));
        r.insert("leaf".into(), json!(leaf_b64));
        r.insert("tier".into(), json!(tier));
        r.insert("root".into(), json!(root));
        r.insert("endpoint".into(), json!(endpoint));
        r.insert("method".into(), json!(method));
        r.insert("tool".into(), tool.clone().map(Value::String).unwrap_or(Value::Null));
        r.insert("params".into(), body["params"].clone());
        r.insert("form".into(), json!(form));
        for (k, v) in extra {
            r.insert(k, v);
        }
        let mut eff = effects;
        eff.push(json!({ "op": "seen", "msg_id": msg_id }));
        DecideOutput { result: Value::Object(r), effects: eff }
    };
    let pending_or = |tier_ok: DecideOutput, state: &str| -> DecideOutput {
        if state == "pending_out" {
            if tool_ref.map(|t| PENDING_TOOLS.contains(&t)).unwrap_or(false) {
                let mut r = tier_ok;
                r.result["tier"] = json!("pending");
                r
            } else {
                done(json!({ "code": "pending_approval" }))
            }
        } else {
            tier_ok
        }
    };

    // The small form: the sender names a leaf this node already holds. Anything that cannot be
    // verified against a held leaf — unknown, blocked, or a bad signature — gets the same answer.
    if m == "leaf,method,params" {
        let Some(named) = body["leaf"].as_str() else { return Ok(invalid("plaintext shape")) };
        let chain_required = done(json!({ "code": "chain_required" }));
        let hit =
            pin_holding(node.pins.iter().filter(|p| p.state != "blocked"), named, |p| (p.leaf.as_str(), p.leaf_fingerprint.as_deref()))?;
        let Some((p, leaf)) = hit else { return Ok(chain_required) };
        if now > leaf.not_after {
            return Ok(chain_required); // expiry darkens the small form as it darkens the chain
        }
        if !leaf.public_key.verify(&signed, &sig) {
            return Ok(chain_required);
        }
        if let Some(early) = fresh.check() {
            return Ok(early);
        }
        let r = ok("contact", &p.root, &p.endpoint, "leaf", &p.leaf, Map::new(), Vec::new());
        return Ok(pending_or(r, &p.state));
    }

    // The full form: a chain is a proof from the root and the one way a held leaf is updated.
    let chain = match chain_of(&body["chain"]) {
        Ok(c) => c,
        Err(_) => return Ok(invalid("plaintext shape")),
    };
    let v = match validate_chain(&chain, now, None, None) {
        ChainResult::Ok(v) => v,
        ChainResult::Refused { rule, reason } => return Ok(invalid(&format!("chain rule {rule}: {reason}"))),
    };
    if !v.leaf.public_key.verify(&signed, &sig) {
        return Ok(invalid("signature is not the chain's leaf key"));
    }
    if let Some(early) = fresh.check() {
        return Ok(early);
    }
    let root = v.root_fingerprint.clone();
    let leaf_b64 = b64u(&chain[0]);
    let endpoint = v.endpoint.clone();

    let as_guest = |why: &str| -> DecideOutput {
        if method != "tools/call" || !tool_ref.map(|t| GUEST_TOOLS.contains(&t)).unwrap_or(false) {
            // Refused as a guest — with the root and the leaf named, so a host holding an older pin of
            // this leaf's key learns the root above it and decides again.
            let mut d = invalid("guest may only redeem or request");
            d.result["root"] = json!(root);
            d.result["leaf"] = json!(b64u(&chain[0]));
            return d;
        }
        let card_text = body["params"].get("arguments").and_then(|a| a.get("card")).and_then(|c| c.as_str()).unwrap_or("");
        let card = match card::decode(card_text, now) {
            Ok(c) => c,
            Err(e) => return invalid(&format!("guest card: {}", e.why)),
        };
        if card.cert != chain[0] {
            return invalid("guest card certificate is not the chain's leaf");
        }
        // §14.5: a guest's endpoint never equals the receiver's own. Otherwise a stranger is pinned
        // to this node's own address and every reply it is sent comes straight back here.
        if endpoint == node.endpoint {
            return invalid("guest endpoint is this node's own address");
        }
        let held = node.pins.iter().find(|p| p.root != root && p.endpoint == endpoint).map(|p| p.root.clone());
        let former = node
            .former_endpoints
            .iter()
            .find(|f| f.endpoint == endpoint && f.root != root && parse_rfc3339(&f.at).map(|at| now - at < CLAIM_WINDOW_S).unwrap_or(false))
            .map(|f| f.root.clone());
        let mut extra = Map::new();
        extra.insert("why".into(), json!(why));
        extra.insert("address_claim".into(), held.or(former).map(Value::String).unwrap_or(Value::Null));
        ok("guest", &root, &endpoint, "chain", &leaf_b64, extra, Vec::new())
    };

    let Some(p) = node.pins.iter().find(|p| p.root == root) else {
        if let Some(t) = node.tombstones.iter().find(|t| t.root == root) {
            let at = parse_rfc3339(&t.at)?;
            if now - at < TOMBSTONE_S && compare_leaves(&from_b64u(&t.leaf)?, &chain[0])? == "newer" {
                let mut extra = Map::new();
                extra.insert("forced".into(), json!("tombstone"));
                extra.insert("decision".into(), json!("ask"));
                let effects = vec![
                    json!({ "op": "pending", "root": root, "endpoint": endpoint, "why": "returned after removal", "leaf": b64u(&chain[0]) }),
                ];
                return Ok(ok("pending_new_address", &root, &endpoint, "chain", &leaf_b64, extra, effects));
            }
        }
        return Ok(as_guest("unknown root"));
    };
    if p.state == "blocked" {
        return Ok(as_guest("blocked"));
    }
    let cmp = compare_leaves(&from_b64u(&p.leaf)?, &chain[0])?;
    if cmp == "superseded" {
        return Ok(as_guest("superseded leaf"));
    }
    if cmp == "conflict" {
        return Ok(invalid("a different leaf with the same notBefore"));
    }

    // §14.3 is absolute: a newer leaf from the root takes priority the instant it is seen, whatever
    // the validity of the older one. At another address it is a new address; under `ask` the owner decides.
    let mut effects = Vec::new();
    if endpoint != p.endpoint {
        if node.accept_new_hosts != "auto" {
            let mut extra = Map::new();
            extra.insert("decision".into(), json!("ask"));
            let effects = vec![json!({ "op": "pending", "root": root, "endpoint": endpoint, "why": "ask", "leaf": b64u(&chain[0]) })];
            return Ok(ok("pending_new_address", &root, &endpoint, "chain", &leaf_b64, extra, effects));
        }
        effects.push(json!({ "op": "former_endpoint", "root": root, "endpoint": p.endpoint, "at": format_rfc3339(now) }));
        effects.push(json!({ "op": "pin_update", "root": root, "endpoint": endpoint, "leaf": b64u(&chain[0]) }));
        effects.push(json!({ "op": "event", "event": "new_address", "root": root, "endpoint": endpoint }));
    } else if cmp == "newer" {
        effects.push(json!({ "op": "pin_update", "root": root, "endpoint": endpoint, "leaf": b64u(&chain[0]) }));
        effects.push(json!({ "op": "event", "event": "renewal", "root": root }));
    }
    let r = ok("contact", &root, &endpoint, "chain", &leaf_b64, Map::new(), effects);
    if p.state == "pending_out" && !tool_ref.map(|t| PENDING_TOOLS.contains(&t)).unwrap_or(false) {
        // The pin moved (a peer may move between my request and their answer) but the call waits.
        return Ok(DecideOutput {
            result: json!({ "code": "pending_approval" }),
            effects: r.effects.into_iter().filter(|e| e["op"] != "seen").collect(),
        });
    }
    Ok(pending_or(r, &p.state))
}

/// The suite a recipient's SubjectPublicKeyInfo takes, by name.
pub fn suite_name(spki: &[u8]) -> Result<&'static str> {
    Ok(suite_for(&PublicKey::from_spki(spki)?).id())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values that wrapped. `ts = i64::MIN + now` made `(now - ts).abs()` equal `i64::MIN`, which
    /// is <= 300; a JSON number cannot carry it exactly, so it is held here and not in js/parity.mjs.
    #[test]
    fn timing_cannot_be_wrapped_and_keeps_both_refusals() {
        let now = 1_758_000_000i64;
        assert!(matches!(timing(now, now, now + 600), Timing::Ok));
        assert!(matches!(timing(now, now - 300, now + 600), Timing::Ok));
        assert!(matches!(timing(now, now - 301, now + 600), Timing::OutsideWindow));
        assert!(matches!(timing(now, now + 301, now + 900), Timing::OutsideWindow));
        assert!(matches!(timing(now, now, now), Timing::OutsideWindow), "now < exp is strict");
        // the wrap: both of these were ACCEPTED by the release build
        assert!(matches!(timing(now, i64::MIN + now, i64::MAX), Timing::OutsideWindow));
        assert!(matches!(timing(now, i64::MIN, i64::MAX), Timing::OutsideWindow));
        // and the refusal a far `exp` gets is the lifetime one, as the other ports say — not the
        // window one, which is what a band of plausible years answered
        assert!(matches!(timing(now, now, 1i64 << 41), Timing::TooLong));
        assert!(matches!(timing(now, now, i64::MAX), Timing::TooLong));
        assert!(matches!(timing(now, now, now + MAX_LIFETIME_S), Timing::Ok));
        assert!(matches!(timing(now, now, now + MAX_LIFETIME_S + 1), Timing::TooLong));
    }
}
