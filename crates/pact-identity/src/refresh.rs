//! Refreshing ONE contact's card (SPEC §3, §14.3): what a peer's answer to `get_card` proves about a
//! pinned contact, and what the pin should become. Written once, below both hosts: the node's
//! `verifyRefreshedCard` (internal/node/refresh.go) and the cloud's (gateway/src/identity/refresh.ts)
//! ran the same checks in different orders, refused in different words, and the node verified the card
//! signature with its own non-strict verifier (CW-08, N6).
//!
//! A refresh can move a LEAF and never an ADDRESS or a ROOT: the chain is validated against the pinned
//! root, which nothing can change (§14.3), and against the pinned endpoint, so a chain valid somewhere
//! else is §5.3's business and is refused here. The chain is not optional: §6.1 has `get_card` answer
//! "always the chain", and whoever answers at the pinned endpoint decides what is in the answer, so a
//! path taken when something is missing is a path they choose.
//!
//! The answer is the peer's, read as it was sent: anything wrong with it is a refusal, `Refused(why)`,
//! never a fault of the call. The pin is the host's own state: a pinned leaf that does not read is an
//! error of the call, in its reader's class, as `decide` answers the host's damaged state.
use crate::card;
use crate::util::{b64u, err, from_b64u, Result};
use crate::x509::{compare_leaves, parse, validate_chain, ChainResult};
use serde_json::Value;

/// The half of a pin a refresh is judged against: the root, the endpoint, and the leaf pinned there.
pub struct Pin<'a> {
    pub root: &'a str,
    pub endpoint: &'a str,
    pub leaf: &'a [u8],
}

/// What a refresh proved.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// The card is the contact's, under the pinned root, at the pinned endpoint. `renewed` is the newer
    /// leaf the chain proved and its key, when there is one (§14.3: it takes effect when it is seen);
    /// `root_cert` is the pinned root's certificate, which a pin made over a sealed call never had.
    Ok { fn_: String, renewed: Option<(Vec<u8>, Vec<u8>)>, root_cert: Vec<u8> },
    /// What the answer did not prove, in the words both hosts show a person.
    Refused(String),
}

/// The pin's root is a fingerprint (the contract's `Fingerprint`), or the call is refused: a root the
/// host holds that is not one is the host's fault, and compared with the card's it read as
/// `the card names another root`, a refusal of what the peer answered. The adapter asks this as it
/// reads the pin, before the answer; `check` asks it first, for a typed caller.
pub fn pin_root(root: &str) -> Result<()> {
    if !crate::ledger::is_fingerprint(root) {
        return err("bad_request", "pin.root is not a fingerprint");
    }
    Ok(())
}

/// The pinned leaf reads and is a leaf, or the call is refused: a pinned "leaf" that is a CA
/// certificate (the pinned root's own, say) is the host's damaged pin. It read, so it was compared with
/// the chain's leaf and answered as the peer's fault (`two different leaves claim the same notBefore`,
/// when it was the root the chain carries), as a root that was not a fingerprint was (the hunt of
/// 2026-09-30).
fn pin_leaf(leaf: &[u8]) -> Result<()> {
    if parse(leaf)?.ca {
        return err("bad_request", "pin.leaf is a CA certificate, not a leaf");
    }
    Ok(())
}

fn refused(why: impl Into<String>) -> Result<Verdict> {
    Ok(Verdict::Refused(why.into()))
}

/// The whole trust decision over the peer's answer, `{card, card_sig, chain}` as sent, at `now`. In
/// this order: the signed card is there; the chain is two certificates; its members decode; the card
/// decodes; the card names the pinned root; the chain validates to the pinned root at the pinned
/// endpoint; the leaf is not older than the pinned one, nor a different one of the same date; the
/// card carries the leaf the chain proved; the card's signature decodes and verifies under that leaf.
pub fn check(pin: &Pin<'_>, answer: &Value, now: i64) -> Result<Verdict> {
    // The host's own pin first, whatever the peer sent: a pin that does not read is the host's to
    // hear about, and a refresh that cannot compare against it has nothing to decide.
    pin_root(pin.root)?;
    pin_leaf(pin.leaf)?;
    let text = |k: &str| answer.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let (Some(card_text), Some(card_sig)) = (text("card"), text("card_sig")) else {
        return refused("the answer to get_card carries no signed card");
    };
    let items = answer.get("chain").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let members: Vec<&str> = items.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).collect();
    if items.len() != 2 || members.len() != 2 {
        return refused(format!(
            "the answer carries {} certificate(s); get_card answers with the chain, leaf then root (§6.1)",
            items.len()
        ));
    }
    let Ok(chain) = members.iter().map(|m| from_b64u(m)).collect::<Result<Vec<Vec<u8>>>>() else {
        return refused("a chain member is not base64url");
    };
    let card = match card::decode(card_text, now) {
        Ok(c) => c,
        Err(e) => return refused(format!("the card does not decode: {}", e.why)),
    };
    if card.root != pin.root {
        return refused("the card names another root, not the pinned one");
    }
    let v = match validate_chain(&chain, now, Some(pin.root), Some(pin.endpoint)) {
        ChainResult::Ok(v) => v,
        ChainResult::Refused { rule, reason } => return refused(format!("the chain it answered with fails rule {rule}: {reason}")),
    };
    // Both leaves read (the pinned one above, the presented one in the chain), so this cannot fail.
    let renewed = match compare_leaves(pin.leaf, &chain[0])? {
        "newer" => Some((chain[0].clone(), v.leaf.spki.clone())),
        "superseded" => return refused("the leaf it answered with is superseded by the pinned one (§14.3)"),
        "conflict" => return refused("two different leaves claim the same notBefore (§14.3)"),
        _ => None,
    };
    // Signed by the right key is not enough: the same host key can sign a card that embeds some other
    // certificate, and that card would be stored, shown and exported as this contact's.
    if card.cert != chain[0] {
        return refused("the card's certificate is not the leaf the chain proved");
    }
    let Ok(sig) = from_b64u(card_sig) else { return refused("the card signature is not base64url") };
    if !v.leaf.public_key.verify(card_text.as_bytes(), &sig) {
        return refused("the card signature does not verify under the proven leaf key");
    }
    Ok(Verdict::Ok { fn_: card.fn_, renewed, root_cert: chain[1].clone() })
}

impl Verdict {
    /// The answer of CONTRACT §4's `refresh_check`.
    pub fn to_value(&self) -> Value {
        match self {
            Verdict::Ok { fn_, renewed, root_cert } => serde_json::json!({
                "ok": true,
                "fn": fn_,
                "renewed": renewed.as_ref().map(|(leaf, spki)| serde_json::json!({ "leaf": b64u(leaf), "spki": b64u(spki) })),
                "root_cert": b64u(root_cert),
            }),
            Verdict::Refused(why) => serde_json::json!({ "ok": false, "why": why }),
        }
    }
}
