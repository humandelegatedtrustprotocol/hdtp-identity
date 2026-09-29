//! The certificates section of contract/contract.json (§2 certificates): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::{address, x509};

pub(super) fn build_root(a: &Value) -> Result<Value> {
    Ok({
        let k = private(a, "pkcs8")?;
        let der = x509::build_root(s(a, "cn")?, &k, instant(a, "not_before")?, &serial(a)?)?;
        json!({ "der": b64u(&der), "fingerprint": k.public().fingerprint() })
    })
}

pub(super) fn root_tbs(a: &Value) -> Result<Value> {
    Ok({
        let u = x509::root_tbs(s(a, "cn")?, &public(a, "spki")?, instant(a, "not_before")?, &serial(a)?)?;
        json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)) })
    })
}

pub(super) fn assemble(a: &Value) -> Result<Value> {
    Ok({
        let tbs = bytes(a, "tbs")?;
        // The algorithm outside is the TBS's own third field; a `sig_alg` handed back (base64url
        // DER of the AlgorithmIdentifier) must equal it, so the two can never differ.
        let declared = x509::declared_alg(&tbs)?;
        if let Some(given) = opt_bytes(a, "sig_alg")? {
            if given != declared {
                return err("bad_request", "sig_alg is not the algorithm the tbs declares");
            }
        }
        json!({ "der": b64u(&x509::assemble_raw(&tbs, &declared, &bytes(a, "sig")?)) })
    })
}

pub(super) fn build_leaf(a: &Value) -> Result<Value> {
    Ok({
        let root = private(a, "root_pkcs8")?;
        let issuer = root.public();
        let host = public(a, "host_spki")?;
        let spec = leaf_spec(a, &issuer, &host, serial(a)?)?;
        json!({ "der": b64u(&x509::build_leaf(&spec, &root)?) })
    })
}

pub(super) fn leaf_tbs(a: &Value) -> Result<Value> {
    Ok({
        let issuer = public(a, "root_spki")?;
        let host = public(a, "host_spki")?;
        let spec = leaf_spec(a, &issuer, &host, serial(a)?)?;
        let u = x509::leaf_tbs(&spec)?;
        json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)) })
    })
}

pub(super) fn parse_certificate(a: &Value) -> Result<Value> {
    Ok(cert_json(&x509::parse(&bytes(a, "der")?)?))
}

pub(super) fn profile_error(a: &Value) -> Result<Value> {
    Ok(json!({ "error": x509::profile_error(&x509::parse(&bytes(a, "der")?)?, s(a, "kind")?) }))
}

pub(super) fn validate_chain(a: &Value) -> Result<Value> {
    Ok(chain_result(x509::validate_chain(
        &chain(a, "chain")?,
        instant(a, "now")?,
        opt_s(a, "expected_root")?,
        opt_s(a, "expected_endpoint")?,
    )))
}

pub(super) fn compare_leaves(a: &Value) -> Result<Value> {
    Ok(json!({ "order": x509::compare_leaves(&bytes(a, "pinned")?, &bytes(a, "presented")?)? }))
}

pub(super) fn is_normal_https(a: &Value) -> Result<Value> {
    Ok(json!({ "normal": x509::is_normal_https(s(a, "url")?) }))
}

pub(super) fn address_guard(a: &Value) -> Result<Value> {
    Ok(match address::address_guard(s(a, "endpoint")?, opt_s(a, "self_endpoint")?, boolean(a, "guest")?) {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "why": e.why }),
    })
}

pub(super) fn ip_is_private(a: &Value) -> Result<Value> {
    Ok(json!({ "private": address::ip_is_private(s(a, "ip")?) }))
}
