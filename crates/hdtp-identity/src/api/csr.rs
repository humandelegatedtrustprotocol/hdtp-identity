//! The csr section of contract/contract.json (§3 certificate signing requests): a body for each function it declares, which
//! `api.rs`'s `dispatch` names.
use super::*;
use crate::{csr, x509};

pub(super) fn csr_new(a: &Value) -> Result<Value> {
    let (cn, host, endpoint) = (s(a, "cn")?, private(a, "host_pkcs8")?, s(a, "endpoint")?);
    Ok(json!({ "der": b64u(&csr::csr_new(cn, &host, endpoint, dns_name(a)?.as_deref())?) }))
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
        // The root, as its certificate, judged before anything else is read for signing: an expired
        // root is refused before its key is even parsed (§2.2).
        let now = instant(a, "now")?;
        let root = csr::issuing_root(&bytes(a, "root_cert")?, now)?;
        let key = private(a, "root_pkcs8")?;
        let mut roots = opt_chain(a, "root_spkis")?;
        roots.push(root.spki.clone());
        let req = csr::check(&bytes(a, "csr")?, &roots)?;
        let i = csr::issue(&req, &root, &key, now, opt_instant(a, "previous_not_before")?, valid_days(a)?)?;
        json!({ "der": b64u(&i.der), "endpoint": req.endpoint, "not_before": format_rfc3339(i.not_before), "not_after": format_rfc3339(i.not_after), "warnings": warnings(i.ends_with_root, i.not_after) })
    })
}

pub(super) fn issue_tbs_from_csr(a: &Value) -> Result<Value> {
    Ok({
        let now = instant(a, "now")?;
        let root = csr::issuing_root(&bytes(a, "root_cert")?, now)?;
        let mut roots = opt_chain(a, "root_spkis")?;
        roots.push(root.spki.clone());
        let req = csr::check(&bytes(a, "csr")?, &roots)?;
        let (u, nb, na, ends) = csr::issue_tbs(&req, &root, now, opt_instant(a, "previous_not_before")?, valid_days(a)?)?;
        json!({ "tbs": b64u(&u.tbs), "sig_alg": b64u(&x509::sig_alg(&u.sig_alg)), "endpoint": req.endpoint, "not_before": format_rfc3339(nb), "not_after": format_rfc3339(na), "warnings": warnings(ends, na) })
    })
}

fn warnings(ends_with_root: bool, not_after: i64) -> Vec<String> {
    if ends_with_root {
        vec![csr::ends_with_root_warning(not_after)]
    } else {
        vec![]
    }
}
