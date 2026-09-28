//! PKCS #10 (RFC 2986) with an exact profile of its own: the host's key, one endpoint, proof of
//! possession by the host's signature; the wallet's checks and the issuance (SPEC §9).
use crate::address::address_guard;
use crate::der::{self, children, read, read_oid_strict};
use crate::keys::{PrivateKey, PublicKey};
use crate::time::{DAY, HOUR};
use crate::util::{err, Error, Result};
use crate::x509::{self, is_normal_https, name, LeafSpec, MAX_LEAF_DAYS, OID_SAN};

pub const OID_EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";

fn cri(cn: &str, key: &PublicKey, endpoint: &str, dns_name: Option<&str>) -> Vec<u8> {
    let mut names = vec![der::implicit(6, endpoint.as_bytes())];
    if let Some(d) = dns_name {
        names.push(der::implicit(2, d.as_bytes()));
    }
    let san = der::seq(&[der::oid(OID_SAN), der::octet(&der::seq(&names))]);
    let attribute = der::seq(&[der::oid(OID_EXTENSION_REQUEST), der::set(&[der::seq(&[san])])]);
    der::seq(&[der::int(0), name(cn), key.spki().to_vec(), der::explicit(0, &attribute)])
}

pub fn csr_new(cn: &str, host_key: &PrivateKey, endpoint: &str, dns_name: Option<&str>) -> Result<Vec<u8>> {
    let signer = host_key.signer();
    let info = cri(cn, &signer.public(), endpoint, dns_name);
    let alg = host_key.alg().sig_oid()?;
    Ok(der::seq(&[info.clone(), der::seq(&[der::oid(alg)]), der::bitstr(&signer.sign(&info), 0)]))
}

pub struct Csr {
    pub der: Vec<u8>,
    pub cri: Vec<u8>,
    pub cn: String,
    pub key: PublicKey,
    pub endpoint: String,
    pub dns_name: Option<String>,
    pub sig_alg: String,
    pub sig: Vec<u8>,
}

fn shape<T>() -> Result<T> {
    err("bad_request", "request is not in the profile")
}

/// Strictly: nothing but the profile parses.
pub fn parse(bytes: &[u8]) -> Result<Csr> {
    let node = read(bytes, 0)?;
    if node.tag != 0x30 || node.end != bytes.len() {
        return shape();
    }
    let top = children(&node)?;
    if top.len() != 3 || top[0].tag != 0x30 || top[1].tag != 0x30 || top[2].tag != 0x03 || top[2].content.first() != Some(&0) {
        return shape();
    }
    let f = children(&top[0])?;
    if f.len() != 4 || f[0].tag != 0x02 || f[0].content != [0] || f[1].tag != 0x30 || f[2].tag != 0x30 || f[3].tag != 0xa0 {
        return shape();
    }
    let cn = x509_name(&f[1])?;
    let key = PublicKey::from_spki(f[2].raw)?;
    let attrs = children(&f[3])?;
    if attrs.len() != 1 || attrs[0].tag != 0x30 {
        return shape();
    }
    let attr = children(&attrs[0])?;
    if attr.len() != 2 || read_oid_strict(&attr[0])? != OID_EXTENSION_REQUEST || attr[1].tag != 0x31 {
        return shape();
    }
    let values = children(&attr[1])?;
    if values.len() != 1 || values[0].tag != 0x30 {
        return shape();
    }
    let exts = children(&values[0])?;
    if exts.len() != 1 || exts[0].tag != 0x30 {
        return shape();
    }
    let e = children(&exts[0])?;
    if e.len() != 2 || read_oid_strict(&e[0])? != OID_SAN || e[1].tag != 0x04 {
        return shape();
    }
    let san = read(e[1].content, 0)?;
    if san.tag != 0x30 || san.end != e[1].content.len() {
        return shape();
    }
    let names = children(&san)?;
    let mut endpoint = None;
    let mut dns_name = None;
    for n in names {
        match n.tag {
            0x86 if endpoint.is_none() => endpoint = Some(String::from_utf8_lossy(n.content).into_owned()),
            0x82 if dns_name.is_none() => dns_name = Some(String::from_utf8_lossy(n.content).into_owned()),
            _ => return shape(),
        }
    }
    let Some(endpoint) = endpoint else { return shape() };
    let alg = children(&top[1])?;
    if alg.len() != 1 {
        return shape();
    }
    Ok(Csr {
        der: bytes.to_vec(),
        cri: top[0].raw.to_vec(),
        cn,
        key,
        endpoint,
        dns_name,
        sig_alg: read_oid_strict(&alg[0])?,
        sig: top[2].content[1..].to_vec(),
    })
}

fn x509_name(node: &der::Node<'_>) -> Result<String> {
    let rdns = children(node)?;
    if rdns.len() != 1 {
        return shape();
    }
    let atvs = children(&rdns[0])?;
    if atvs.len() != 1 {
        return shape();
    }
    let parts = children(&atvs[0])?;
    if parts.len() != 2 || read_oid_strict(&parts[0])? != x509::OID_CN || parts[1].tag != 0x0c {
        return shape();
    }
    Ok(String::from_utf8_lossy(parts[1].content).into_owned())
}

/// The wallet's checks: proof of possession, the root-key refusal, a normal endpoint, the address guard.
pub fn check(bytes: &[u8], root_spkis: &[Vec<u8>]) -> Result<Csr> {
    let csr = parse(bytes)?;
    let own = csr.key.alg().sig_oid().map_err(|_| Error::new("bad_request", "request key algorithm not in the profile"))?;
    if csr.sig_alg != own || !csr.key.verify(&csr.cri, &csr.sig) {
        return err("bad_request", "the request's signature does not verify: no proof of possession");
    }
    let id = csr.key.key_id();
    if root_spkis.iter().any(|r| r == csr.key.spki() || crate::util::sha256(r) == id) {
        return err("bad_request", "the request's key is a root");
    }
    if !is_normal_https(&csr.endpoint) {
        return err("bad_request", "endpoint is not an https URL in normal form");
    }
    if let Some(d) = &csr.dns_name {
        if d != x509::host_of(&csr.endpoint) {
            return err("bad_request", "dNSName differs from the URI host");
        }
    }
    address_guard(&csr.endpoint, None, false)?;
    Ok(csr)
}

pub struct Issued {
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

/// The monotonic rule of §14.1: notBefore is the later of one hour ago and one second after the
/// previous leaf's; the validity is at most 398 days.
pub fn validity(now: i64, previous_not_before: Option<i64>, valid_days: i64) -> Result<(i64, i64)> {
    if !(1..=MAX_LEAF_DAYS).contains(&valid_days) {
        return err("bad_request", "validity must be between one and 398 days");
    }
    let mut not_before = now - HOUR;
    if let Some(p) = previous_not_before {
        if p + 1 > not_before {
            not_before = p + 1;
        }
    }
    Ok((not_before, not_before + valid_days * DAY))
}

pub fn issue_tbs(
    csr: &Csr,
    root_cn: &str,
    root: &PublicKey,
    now: i64,
    previous_not_before: Option<i64>,
    valid_days: i64,
) -> Result<(x509::Unsigned, i64, i64)> {
    let (not_before, not_after) = validity(now, previous_not_before, valid_days)?;
    let spec = LeafSpec {
        cn: &csr.cn,
        root_cn,
        issuer: root,
        host_key: &csr.key,
        uris: vec![csr.endpoint.clone()],
        dns_name: csr.dns_name.clone(),
        not_before,
        not_after,
        serial: x509::random_serial()?,
        ca: false,
        usage: None,
        aki: None,
        extra: Vec::new(),
        alg_oid: None,
    };
    Ok((x509::leaf_tbs(&spec)?, not_before, not_after))
}

pub fn issue(csr: &Csr, root_cn: &str, root: &PrivateKey, now: i64, previous_not_before: Option<i64>, valid_days: i64) -> Result<Issued> {
    let signer = root.signer();
    let (u, not_before, not_after) = issue_tbs(csr, root_cn, &signer.public(), now, previous_not_before, valid_days)?;
    Ok(Issued { der: x509::assemble(&u.tbs, &u.sig_alg, &signer.sign(&u.tbs)), not_before, not_after })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Alg;
    use crate::util::seed;
    use crate::x509::{validate_chain, ChainResult};

    #[test]
    fn round_trip_and_refusals() {
        let root = PrivateKey::from_seed(Alg::Ed25519, &seed("csr/root")).unwrap();
        let root_der = x509::build_root("Alina Rao", &root, 1_700_000_000, &x509::serial_of("csr/root")).unwrap();
        let host = PrivateKey::from_seed(Alg::P256, &seed("csr/host")).unwrap();
        let csr = csr_new("Alina Rao", &host, "https://agent.alina.example/mcp", Some("agent.alina.example")).unwrap();
        let parsed = check(&csr, &[root.public().spki().to_vec()]).unwrap();
        assert_eq!(parsed.endpoint, "https://agent.alina.example/mcp");
        let now = 1_789_214_400;
        let issued = issue(&parsed, "Alina Rao", &root, now, None, 365).unwrap();
        assert_eq!(issued.not_before, now - HOUR);
        match validate_chain(&[issued.der.clone(), root_der], now, None, Some("https://agent.alina.example/mcp")) {
            ChainResult::Ok(ok) => assert_eq!(ok.leaf.dns, vec!["agent.alina.example"]),
            ChainResult::Refused { rule, reason } => panic!("rule {rule}: {reason}"),
        }
        // The root's own key in a request is refused.
        let bad = csr_new("Alina Rao", &root, "https://agent.alina.example/mcp", None).unwrap();
        assert_eq!(check(&bad, &[root.public().spki().to_vec()]).err().map(|e| e.why), Some("the request's key is a root".to_string()));
        // A tampered request has no proof of possession.
        let mut t = csr.clone();
        let i = t.windows(9).position(|w| w == b"Alina Rao").unwrap();
        t[i + 1] ^= 1;
        assert!(check(&t, &[]).err().map(|e| e.why.contains("proof of possession")).unwrap_or(false));
        // Monotonic notBefore.
        let (nb, _) = validity(now, Some(now + 10), 30).unwrap();
        assert_eq!(nb, now + 11);
        assert!(validity(now, None, 399).is_err());
        assert!(check(&csr_new("x", &host, "https://127.0.0.1/mcp", None).unwrap(), &[]).is_err());
    }
}
