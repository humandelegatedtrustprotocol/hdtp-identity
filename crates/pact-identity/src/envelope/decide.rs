//! `decide`: the receiving side of §13.3, §6.1, §5.3 and §14.4 as one pure function over the state
//! the host supplies (`state.rs`). `envelope.mjs receive()` is its specification, line for line.
use super::state::{DecideInput, DecideOutput};
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
    if p.state == "pending_out" && !pending_allows {
        // The pin moved (a peer may move between my request and their answer) but the call waits.
        return Ok(DecideOutput {
            result: json!({ "code": "pending_approval" }),
            effects: r.effects.into_iter().filter(|e| e["op"] != "seen").collect(),
        });
    }
    Ok(pending_or(r, &p.state))
}
