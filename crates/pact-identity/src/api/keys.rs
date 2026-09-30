//! The keys section of contract/contract.json (§1 keys): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::keys::{self, Alg};

pub(super) fn generate_key(a: &Value) -> Result<Value> {
    Ok(key_json(&PrivateKey::generate(Alg::parse(s(a, "alg")?)?)?))
}

/// `alg` first, as CONTRACT §1 lists it, then the seed read for it: the seed's length was judged
/// before a missing algorithm here, and after it in the Go port (T21, R01).
pub(super) fn key_from_seed(a: &Value) -> Result<Value> {
    let alg = Alg::parse(s(a, "alg")?)?;
    let seed = seed32(a, "seed")?.ok_or_else(|| Error::new("bad_request", "seed is required"))?;
    Ok(key_json(&PrivateKey::from_seed(alg, &seed)?))
}

// §2.1. Two calls rather than one so a wallet never hardcodes the salt: the constant lives
// here, the vectors prove it, and a page that gets it wrong fails loudly instead of quietly
// becoming somebody else.
pub(super) fn prf_salt(_: &Value) -> Result<Value> {
    Ok(json!({ "salt": b64u(&keys::prf_salt()), "infos": keys::DERIVATION_INFOS }))
}

pub(super) fn derive_seed(a: &Value) -> Result<Value> {
    Ok(json!({ "seed": b64u(&keys::derive_seed(&bytes(a, "prf")?, s(a, "info")?)?) }))
}

pub(super) fn public_key(a: &Value) -> Result<Value> {
    Ok({
        let k = private(a, "pkcs8")?;
        let p = k.public();
        json!({ "alg": k.alg().name(), "spki": b64u(p.spki()), "fingerprint": p.fingerprint() })
    })
}

pub(super) fn key_info(a: &Value) -> Result<Value> {
    Ok({
        let p = public(a, "spki")?;
        json!({ "alg": p.alg().name(), "fingerprint": p.fingerprint(), "key_id": b64u(&p.key_id()) })
    })
}

pub(super) fn sign(a: &Value) -> Result<Value> {
    Ok(json!({ "sig": b64u(&private(a, "pkcs8")?.sign(&bytes(a, "data")?)) }))
}

pub(super) fn verify(a: &Value) -> Result<Value> {
    Ok(json!({ "valid": public(a, "spki")?.verify(&bytes(a, "data")?, &bytes(a, "sig")?) }))
}
