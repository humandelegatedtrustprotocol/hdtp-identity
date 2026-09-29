//! `decide`: the receiving side of §13.3, §6.1, §5.3 and §14.4 as one pure function over the state
//! the host supplies (`state.rs`). `envelope.mjs receive()` is its specification, line for line.
use super::state::{DecideInput, DecideOutput, NodeState};
use super::{
    chain_of, decode_header, header_checks, members, pin_holding, timing, Timing, CLAIM_WINDOW_S, CTY_CALL, GUEST_TOOLS, INFO_V2,
    PENDING_TOOLS, TOMBSTONE_S,
};
use crate::card;
use crate::hpke::{self, suite_for};
use crate::keys::PrivateKey;
use crate::time::{format_rfc3339, parse_rfc3339};
use crate::util::{b64u, from_b64u, wire_b64u, Result};
use crate::x509::{compare_leaves, parse, validate_chain, ChainResult};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

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
    let body: Value =
        match hpke::open(suite, &key, &held_leaf.public_key, INFO_V2, &aad, &enc, &ct).ok().and_then(|p| serde_json::from_slice(&p).ok()) {
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
    // What a `pending_out` pin may do: call one of the pending tier's tools (§6.1, §6.2), or list them.
    // A listing names no tool; `tools/list` returns what the caller's tier may use (§6), and a sealed
    // call is dispatched in the tier the proven identity earns (§13.2) — so a pending contact's sealed
    // listing answers at the pending tier. Anything else waits for the approval.
    let tool_ref = tool.as_deref();
    let pending_allows = method == "tools/list" || tool_ref.map(|t| PENDING_TOOLS.contains(&t)).unwrap_or(false);
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
            if pending_allows {
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

    Ok(match pinned(node, now, &root, &endpoint, &chain[0])? {
        Pinned::Refused(why) => invalid(why),
        // The guest binding is the call's: the method and tool, the card, and the receiver's own address
        // (§14.5), judged here for the sealed door, per call.
        Pinned::Guest { why, demote, address_claim } => {
            if method != "tools/call" || !tool_ref.map(|t| GUEST_TOOLS.contains(&t)).unwrap_or(false) {
                // Refused as a guest — with the root and the leaf named, so a host holding an older pin
                // of this leaf's key learns the root above it and decides again.
                let mut d = invalid("guest may only redeem or request");
                d.result["root"] = json!(root);
                d.result["leaf"] = json!(leaf_b64);
                return Ok(d);
            }
            let card_text = body["params"].get("arguments").and_then(|a| a.get("card")).and_then(|c| c.as_str()).unwrap_or("");
            let card = match card::decode(card_text, now) {
                Ok(c) => c,
                Err(e) => return Ok(invalid(&format!("guest card: {}", e.why))),
            };
            if card.cert != chain[0] {
                return Ok(invalid("guest card certificate is not the chain's leaf"));
            }
            // §14.5: a guest's endpoint never equals the receiver's own. Otherwise a stranger is pinned
            // to this node's own address and every reply it is sent comes straight back here.
            if endpoint == node.endpoint {
                return Ok(invalid("guest endpoint is this node's own address"));
            }
            ok("guest", &root, &endpoint, "chain", &leaf_b64, guest_members(why, demote, address_claim), Vec::new())
        }
        Pinned::NewAddress { forced, effects } => {
            ok("pending_new_address", &root, &endpoint, "chain", &leaf_b64, new_address_members(forced), effects)
        }
        Pinned::Contact { pending_out, effects } => {
            let r = ok("contact", &root, &endpoint, "chain", &leaf_b64, Map::new(), effects);
            if pending_out && !pending_allows {
                // The pin moved (a peer may move between my request and their answer) but the call waits.
                return Ok(DecideOutput {
                    result: json!({ "code": "pending_approval" }),
                    effects: r.effects.into_iter().filter(|e| e["op"] != "seen").collect(),
                });
            }
            pending_or(r, if pending_out { "pending_out" } else { "active" })
        }
    })
}

/// `decide_chain`: a chain proven outside an envelope — at the TLS layer, where the handshake is the
/// leaf key's signature — decided by the pins alone, exactly as `decide` decides a chain inside one
/// (`pinned`, below; N1, N2). The chain is validated at `now` with no expectation, as `decide` validates
/// a peer's, and one that fails is `envelope_invalid` `chain rule <n>: <reason>`, `decide`'s words for
/// the same chain. What is the call's and not the chain's — a guest's tools and card, the receiver's own
/// address, what a `pending_out` pin may call — the host applies to each call, as `decide` applies it
/// to the envelope's. No `seen`: there is no envelope.
pub fn decide_chain(node: &NodeState, chain: &[Vec<u8>], now: i64) -> Result<DecideOutput> {
    let v = match validate_chain(chain, now, None, None) {
        ChainResult::Ok(v) => v,
        ChainResult::Refused { rule, reason } => return Ok(invalid(&format!("chain rule {rule}: {reason}"))),
    };
    let (root, endpoint, leaf_b64) = (v.root_fingerprint.clone(), v.endpoint.clone(), b64u(&chain[0]));
    let answer = |tier: &str, extra: Map<String, Value>, effects: Vec<Value>| {
        let mut r = Map::new();
        r.insert("code".into(), json!("ok"));
        r.insert("tier".into(), json!(tier));
        r.insert("root".into(), json!(root));
        r.insert("endpoint".into(), json!(endpoint));
        r.insert("leaf".into(), json!(leaf_b64));
        r.extend(extra);
        DecideOutput { result: Value::Object(r), effects }
    };
    Ok(match pinned(node, now, &root, &endpoint, &chain[0])? {
        Pinned::Refused(why) => invalid(why),
        Pinned::Guest { why, demote, address_claim } => answer("guest", guest_members(why, demote, address_claim), Vec::new()),
        Pinned::NewAddress { forced, effects } => answer("pending_new_address", new_address_members(forced), effects),
        Pinned::Contact { pending_out, effects } => answer(if pending_out { "pending" } else { "contact" }, Map::new(), effects),
    })
}

/// What the pins decide about a chain proven at `now` — validated, and signed for by its leaf's key in
/// an envelope or in a TLS handshake: the chain half of `decide`, which `decide_chain` answers on its
/// own for a host's TLS door. The node's TLS door made this decision itself and parted from the
/// envelope's on a removal tombstone and on a conflicting leaf (N1, N2); both doors now take it from
/// here. Changes nothing: the effects are the pin's moves, and `decide` adds the envelope's `seen`.
enum Pinned {
    /// The pin stands, or renewed, or moved under `auto`: tier `contact`, or `pending` while the pin is
    /// `pending_out`, whose calls wait for the answer save the pending tier's own (`decide` judges the
    /// call; a TLS door judges each call).
    Contact { pending_out: bool, effects: Vec<Value> },
    /// A new address for the owner to decide: under `ask`, or forced to `ask` by a removal tombstone
    /// within its window.
    NewAddress { forced: bool, effects: Vec<Value> },
    /// A guest, with the reason, whether a pin stands behind it, and the root that claims its address.
    Guest { why: &'static str, demote: bool, address_claim: Option<String> },
    /// Refused: a different leaf with the pinned one's notBefore (§14.3).
    Refused(&'static str),
}

fn pinned(node: &NodeState, now: i64, root: &str, endpoint: &str, leaf: &[u8]) -> Result<Pinned> {
    // The root that claims this address, for a guest: a pin at it, or a former endpoint within the
    // claim window (§5.2).
    let claim = || {
        let held = node.pins.iter().find(|p| p.root != root && p.endpoint == endpoint).map(|p| p.root.clone());
        let former = node
            .former_endpoints
            .iter()
            .find(|f| f.endpoint == endpoint && f.root != root && parse_rfc3339(&f.at).map(|at| now - at < CLAIM_WINDOW_S).unwrap_or(false))
            .map(|f| f.root.clone());
        held.or(former)
    };
    let guest = |why, demote| Ok(Pinned::Guest { why, demote, address_claim: claim() });
    let Some(p) = node.pins.iter().find(|p| p.root == root) else {
        // The FIRST tombstone for this root, as the seed keeps one per root.
        if let Some(t) = node.tombstones.iter().find(|t| t.root == root) {
            let at = parse_rfc3339(&t.at)?;
            if now - at < TOMBSTONE_S && compare_leaves(&from_b64u(&t.leaf)?, leaf)? == "newer" {
                let effects = vec![
                    json!({ "op": "pending", "root": root, "endpoint": endpoint, "why": "returned after removal", "leaf": b64u(leaf) }),
                ];
                return Ok(Pinned::NewAddress { forced: true, effects });
            }
        }
        return guest("unknown root", false);
    };
    if p.state == "blocked" {
        return guest("blocked", true);
    }
    let cmp = compare_leaves(&from_b64u(&p.leaf)?, leaf)?;
    if cmp == "superseded" {
        return guest("superseded leaf", true);
    }
    if cmp == "conflict" {
        return Ok(Pinned::Refused("a different leaf with the same notBefore"));
    }
    // §14.3 is absolute: a newer leaf from the root takes priority the instant it is seen, whatever
    // the validity of the older one. At another address it is a new address; under `ask` the owner decides.
    let mut effects = Vec::new();
    if endpoint != p.endpoint {
        if node.accept_new_hosts != "auto" {
            let effects = vec![json!({ "op": "pending", "root": root, "endpoint": endpoint, "why": "ask", "leaf": b64u(leaf) })];
            return Ok(Pinned::NewAddress { forced: false, effects });
        }
        effects.push(json!({ "op": "former_endpoint", "root": root, "endpoint": p.endpoint, "at": format_rfc3339(now) }));
        effects.push(json!({ "op": "pin_update", "root": root, "endpoint": endpoint, "leaf": b64u(leaf) }));
        effects.push(json!({ "op": "event", "event": "new_address", "root": root, "endpoint": endpoint }));
    } else if cmp == "newer" {
        effects.push(json!({ "op": "pin_update", "root": root, "endpoint": endpoint, "leaf": b64u(leaf) }));
        effects.push(json!({ "op": "event", "event": "renewal", "root": root }));
    }
    Ok(Pinned::Contact { pending_out: p.state == "pending_out", effects })
}

/// A guest answer's own members: the reason, `demote` (CW-11) and the address claim.
fn guest_members(why: &str, demote: bool, address_claim: Option<String>) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert("why".into(), json!(why));
    extra.insert("demote".into(), json!(demote));
    extra.insert("address_claim".into(), address_claim.map(Value::String).unwrap_or(Value::Null));
    extra
}

/// A new address's own members: forced by a tombstone, and in every case the owner's to decide.
fn new_address_members(forced: bool) -> Map<String, Value> {
    let mut extra = Map::new();
    if forced {
        extra.insert("forced".into(), json!("tombstone"));
    }
    extra.insert("decision".into(), json!("ask"));
    extra
}
