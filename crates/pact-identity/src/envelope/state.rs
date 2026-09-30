//! The state `decide` reads: what the host holds (its keys, its pins, what it has forgotten and
//! where contacts used to live) and what it answers. Plain data; the host supplies it and applies
//! the effects `decide` returns.
use super::{CallerPin, Wire};
use crate::util::{err, Error, Result};
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Clone)]
pub struct HeldKey {
    pub kid: String,
    pub leaf: String,
    pub pkcs8: String,
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

#[derive(Clone, Debug)]
pub struct Pin {
    pub root: String,
    pub endpoint: String,
    pub leaf: String,
    pub state: String,
    /// The fingerprint of `leaf`'s key, when the host keeps it — see `pin_holding`.
    pub leaf_fingerprint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Tombstone {
    pub root: String,
    pub leaf: String,
    pub at: String,
}

#[derive(Clone, Debug)]
pub struct FormerEndpoint {
    pub root: String,
    pub endpoint: String,
    pub at: String,
}

#[derive(Clone, Debug)]
pub struct NodeState {
    pub endpoint: String,
    pub accept_new_hosts: String,
    pub chain: Vec<String>,
    pub keys: Vec<HeldKey>,
    pub former: Vec<String>,
    pub sibling_kids: Vec<String>,
    pub pins: Vec<Pin>,
    pub tombstones: Vec<Tombstone>,
    pub former_endpoints: Vec<FormerEndpoint>,
    pub seen: Vec<String>,
}

#[derive(Clone, Debug)]
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

// ── reading them: by hand, member by member, in the contract's order (the Go port's api_envelopes.go
// reads them the same way, in the same order). This is the one reader: serde read them once, with
// its own words and its own defaults, and the Go port's structs read them as zero values (T9, F11,
// F12, F13, R20, R21, T8).

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
impl Wire {
    /// An envelope as it arrived, from JSON.
    pub fn read(v: &Value) -> Result<Wire> {
        let o = object_of(v, "envelope")?;
        Ok(Wire {
            protected: text(o, "protected", "envelope")?,
            enc: text(o, "enc", "envelope")?,
            ct: text(o, "ct", "envelope")?,
            sig: text(o, "sig", "envelope")?,
        })
    }
}

/// A root the host holds — a pin's, a tombstone's, a former endpoint's — is a fingerprint (the
/// contract's `Fingerprint`): one that is not is the host's damaged state, refused by its path. Read
/// as a string, it was a root nothing matched, and a pin or a former endpoint whose root was `abc`
/// came back as the answer's `address_claim: "abc"`, which the contract types as a fingerprint.
fn root(o: &Map<String, Value>, path: &str) -> Result<String> {
    let root = text(o, "root", path)?;
    host_root(&root, path)?;
    Ok(root)
}

/// One root the host holds, at `path`: a fingerprint, or `bad_request` `<path>.root is not a
/// fingerprint`.
pub(crate) fn host_root(root: &str, path: &str) -> Result<()> {
    if !crate::ledger::is_fingerprint(root) {
        return err("bad_request", format!("{path}.root is not a fingerprint"));
    }
    Ok(())
}

/// A held key's `kid`, where it is read: a fingerprint (`HeldKey`), or `bad_request` `<path>.kid is not
/// a fingerprint`. Read as any string, a key whose kid was `""` was a key no envelope named, held by
/// both ports without a word (the review of 2026-09-30, found by parity's nested "" cases).
pub(crate) fn host_kid(kid: &str, path: &str) -> Result<()> {
    if !crate::ledger::is_fingerprint(kid) {
        return err("bad_request", format!("{path}.kid is not a fingerprint"));
    }
    Ok(())
}

/// A pin's `state`, where it is read: one of the three the contract names (`Pin`), or `bad_request`
/// `<path>.state is active, pending_out or blocked`. Any other was read as `active`, so a blocked
/// contact whose host wrote `Blocked`, `blocked ` or `removed` was a full contact (S2 of the review of
/// 2026-09-30). `""` is the typed callers' `active`, the Go port's zero value; the JSON reader never
/// hands it here, since an absent `state` is `active` there and a present `""` is refused.
pub(crate) fn host_state(state: &str, path: &str) -> Result<()> {
    if !matches!(state, "active" | "pending_out" | "blocked") {
        return err("bad_request", format!("{path}.state is active, pending_out or blocked"));
    }
    Ok(())
}

/// A pin's `leaf_fingerprint`, when it has one: a fingerprint, or `bad_request` `<path>.leaf_fingerprint
/// is not a fingerprint`. `""` was a claim that matched no leaf in this port and no claim at all in the
/// Go port, which reads `""` as absent: one pin, `chain_required` here and `ok` there (S1 of the review
/// of 2026-09-30).
pub(crate) fn host_leaf_fingerprint(fp: Option<&str>, path: &str) -> Result<()> {
    if fp.is_some_and(|f| !crate::ledger::is_fingerprint(f)) {
        return err("bad_request", format!("{path}.leaf_fingerprint is not a fingerprint"));
    }
    Ok(())
}

/// A pin as the host holds it, for a typed caller whose pins never passed the reader: its root, its
/// state (`""` read as `active`, the Go port's zero value) and its leaf fingerprint, in the reader's
/// order.
pub(crate) fn host_pin(root: &str, state: &str, leaf_fingerprint: Option<&str>, path: &str) -> Result<()> {
    host_root(root, path)?;
    if !state.is_empty() {
        host_state(state, path)?;
    }
    host_leaf_fingerprint(leaf_fingerprint, path)
}

/// Every held key's kid (`host_kid`), and every root a node state holds — its pins', its tombstones'
/// and its former endpoints' — in the order the reader reads them, held to `host_root`, with each pin's
/// state and leaf fingerprint beside its root (`host_pin`): what the typed `decide` and `decide_chain` ask first,
/// since a typed caller's `NodeState` never passed through the reader, as the Go port's typed `Decide`
/// and `DecideChain` ask it (its `hostRoots`). Only the reader checked, so a typed caller's pin whose
/// root was `abc` was a root nothing matched (the hunt of 2026-09-30).
pub(crate) fn host_roots(node: &NodeState) -> Result<()> {
    for (i, k) in node.keys.iter().enumerate() {
        host_kid(&k.kid, &format!("node.keys[{i}]"))?;
    }
    for (i, p) in node.pins.iter().enumerate() {
        host_pin(&p.root, &p.state, p.leaf_fingerprint.as_deref(), &format!("node.pins[{i}]"))?;
    }
    for (i, t) in node.tombstones.iter().enumerate() {
        host_root(&t.root, &format!("node.tombstones[{i}]"))?;
    }
    for (i, f) in node.former_endpoints.iter().enumerate() {
        host_root(&f.root, &format!("node.former_endpoints[{i}]"))?;
    }
    Ok(())
}

/// A pin, `open_result`'s or a node's: root, endpoint and leaf; `state` absent is `active`.
fn pin_of(v: &Value, path: &str) -> Result<Pin> {
    let o = object_of(v, path)?;
    let root = root(o, path)?;
    let endpoint = text(o, "endpoint", path)?;
    let leaf = text(o, "leaf", path)?;
    let state = opt_text(o, "state", path)?.unwrap_or_else(|| "active".into());
    host_state(&state, path)?;
    let leaf_fingerprint = opt_text(o, "leaf_fingerprint", path)?;
    host_leaf_fingerprint(leaf_fingerprint.as_deref(), path)?;
    Ok(Pin { root, endpoint, leaf, state, leaf_fingerprint })
}

impl CallerPin {
    /// `open_result`'s `pins`, from JSON: a list, each read as a node's pin is, named `pins[<i>]`.
    pub fn read_all(v: &Value) -> Result<Vec<CallerPin>> {
        list_of(v, "pins", |p, path| {
            let p = pin_of(p, path)?;
            Ok(CallerPin { root: p.root, endpoint: p.endpoint, leaf: p.leaf, state: p.state, leaf_fingerprint: p.leaf_fingerprint })
        })
    }
}

impl DecideInput {
    /// `decide`'s arguments, from JSON, in the order CONTRACT §5.1 reads them: `node`, `envelope` and
    /// `now` absent or null, in that order; then the node whole, then the envelope, then `now`. Every
    /// fault is the host's, `bad_request`, named by its path.
    pub fn read(a: &Value) -> Result<DecideInput> {
        // A missing `node` is not a decision against an empty node, and the member is named the way
        // the caller wrote it rather than the way serde reports a missing field — the Go port cannot
        // reproduce another library's wording, and CONTRACT §0 promises it will not have to.
        for k in ["node", "envelope", "now"] {
            if a.get(k).is_none_or(Value::is_null) {
                return err("bad_request", format!("{k} is required"));
            }
        }
        let node = NodeState::read(&a["node"])?;
        let envelope = Wire::read(&a["envelope"])?;
        let now = a["now"].as_str().ok_or_else(|| required("now"))?.to_string();
        Ok(DecideInput { now, envelope, node })
    }
}

impl NodeState {
    /// The node state, from JSON: the one reader, which `decide` and `decide_chain` both use.
    pub fn read(v: &Value) -> Result<NodeState> {
        node_state(v)
    }
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
            let kid = text(k, "kid", p)?;
            host_kid(&kid, p)?;
            Ok(HeldKey { kid, leaf: text(k, "leaf", p)?, pkcs8: text(k, "pkcs8", p)?, current: flag(k, "current", p)? })
        })?,
        former: texts(o, "former", path)?,
        sibling_kids: texts(o, "sibling_kids", path)?,
        pins: opt_list(o, "pins", path, pin_of)?,
        tombstones: opt_list(o, "tombstones", path, |v, p| {
            let t = object_of(v, p)?;
            Ok(Tombstone { root: root(t, p)?, leaf: text(t, "leaf", p)?, at: text(t, "at", p)? })
        })?,
        former_endpoints: opt_list(o, "former_endpoints", path, |v, p| {
            let f = object_of(v, p)?;
            Ok(FormerEndpoint { root: root(f, p)?, endpoint: text(f, "endpoint", p)?, at: text(f, "at", p)? })
        })?,
        seen: texts(o, "seen", path)?,
    })
}
