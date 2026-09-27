//! The csr section of contract/contract.json (§3 certificate signing requests): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::{csr, x509};

pub(super) fn csr_new(a: &Value) -> Result<Value> {
    Ok(json!({ "der": b64u(&csr::csr_new(s(a, "cn")?, &private(a, "host_pkcs8")?, s(a, "endpoint")?, opt_s(a, "dns_name"))?) }))
}

pub(super) fn csr_check(a: &Value) -> Result<Value> {
    Ok(match csr::check(&bytes(a, "der")?, &opt_chain(a, "root_spkis")?) {
        Ok(c) => {
            json!({ "ok": true, "cn": c.cn, "spki": b64u(c.key.spki()), "fingerprint": c.key.fingerprint(), "alg": c.key.alg().name(), "endpoint": c.endpoint, "dns_name": c.dns_name })
        }
        Err(e) => json!({ "ok": false, "why": e.why }),
    })
}

pub(super) fn issue_from_csr(a: &Value) -> Result<Value> {
    Ok({
        let root = private(a, "root_pkcs8")?;
        let mut roots = opt_chain(a, "root_spkis")?;
        roots.push(root.public().spki().to_vec());
        let req = csr::check(&bytes(a, "csr")?, &roots)?;
        let i = csr::issue(&req, s(a, "root_cn")?, &root, instant(a, "now")?, opt_instant(a, "previous_not_before")?, valid_days(a)?)?;
        json!({ "der": b64u(&i.der), "endpoint": req.endpoint, "not_before": format_rfc3339(i.not_before), "not_after": format_rfc3339(i.not_after) })
    })
}

pub(super) fn issue_tbs_from_csr(a: &Value) -> Result<Value> {
    Ok({
        let root = public(a, "root_spki")?;
        let mut roots = opt_chain(a, "root_spkis")?;
        roots.push(root.spki().to_vec());
        let req = csr::check(&bytes(a, "csr")?, &roots)?;
        let (u, nb, na) =
            csr::issue_tbs(&req, s(a, "root_cn")?, &root, instant(a, "now")?, opt_instant(a, "previous_not_before")?, valid_days(a)?)?;
        json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)), "endpoint": req.endpoint, "not_before": format_rfc3339(nb), "not_after": format_rfc3339(na) })
    })
}
