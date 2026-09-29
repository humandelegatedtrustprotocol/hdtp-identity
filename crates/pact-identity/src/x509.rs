//! The §14.1 profile as bytes, the exact-profile check, §14.2 chain validation and the §14.3 comparison.
use crate::der::{self, children, read, read_oid_strict, Node};
use crate::keys::{fingerprint_of_id, Alg, PrivateKey, PublicKey, OID_ECDSA_SHA256, OID_ED25519};
use crate::time::{self, DAY, FOREVER};
use crate::util::{err, Result};

pub const OID_CN: &str = "2.5.4.3";
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const OID_KEY_USAGE: &str = "2.5.29.15";
pub const OID_EKU: &str = "2.5.29.37";
pub const OID_SAN: &str = "2.5.29.17";
pub const OID_SKI: &str = "2.5.29.14";
pub const OID_AKI: &str = "2.5.29.35";
pub const OID_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const MAX_LEAF_DAYS: i64 = 398;
pub const MAX_CERT_BYTES: usize = 4096;

pub fn name(cn: &str) -> Vec<u8> {
    der::seq(&[der::set(&[der::seq(&[der::oid(OID_CN), der::utf8(cn)])])])
}
pub fn sig_alg(oid: &str) -> Vec<u8> {
    der::seq(&[der::oid(oid)])
}
/// The AlgorithmIdentifier a TBS declares as its third field, raw — what the seam hands out and
/// what `assemble_raw` puts outside, so the two can never differ.
pub fn declared_alg(tbs: &[u8]) -> Result<Vec<u8>> {
    let node = read(tbs, 0)?;
    let f = children(&node)?;
    if f.len() < 3 {
        return err("parse", "tbs shape");
    }
    Ok(f[2].raw.to_vec())
}
fn ext(o: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![der::oid(o)];
    if critical {
        parts.push(der::boolean(true));
    }
    parts.push(der::octet(value));
    der::seq(&parts)
}
fn key_usage(bits: &[u8]) -> Vec<u8> {
    let mut byte = 0u8;
    for &b in bits {
        if b < 8 {
            byte |= 0x80 >> b;
        }
    }
    let mut unused = 0u8;
    let mut v = byte;
    while v != 0 && v & 1 == 0 {
        unused += 1;
        v >>= 1;
    }
    der::bitstr(&[byte], unused)
}

/// The vectors' serials: eight bytes of a labelled hash.
pub fn serial_of(label: &str) -> Vec<u8> {
    crate::util::sha256(format!("serial/{label}").as_bytes())[..8].to_vec()
}

/// Eight random bytes, the first of them never zero.
///
/// The profile wants a positive serial of 64–160 bits, and `int_bytes` is now canonical — so a
/// value beginning 0x00 would encode to seven significant bytes and be refused by the profile
/// check below for being under 64 bits. Drawing again is the unbiased way to keep all eight
/// significant, and it costs one extra draw once in every 256 certificates.
pub fn random_serial() -> Result<Vec<u8>> {
    loop {
        let b = crate::util::random(8)?;
        if b[0] != 0 {
            return Ok(b);
        }
    }
}

/// One certificate's TBS and the algorithm it declares, ready to be signed by the issuer — inside
/// the core, or outside it by a root a passkey or security key holds.
pub struct Unsigned {
    pub tbs: Vec<u8>,
    pub sig_alg: String,
}

pub fn assemble(tbs: &[u8], sig_alg_oid: &str, sig: &[u8]) -> Vec<u8> {
    der::seq(&[tbs.to_vec(), sig_alg(sig_alg_oid), der::bitstr(sig, 0)])
}
/// Assemble with the AlgorithmIdentifier as DER bytes — the TBS's own third field.
pub fn assemble_raw(tbs: &[u8], alg_der: &[u8], sig: &[u8]) -> Vec<u8> {
    // The seam NORMALISES an ECDSA signature (SPEC 14.1). What arrives here was made outside this
    // library — a PIV token, a KMS — and none of them returns the low-S twin on purpose, so half the
    // certificates assembled from a card were outside the profile the moment it gained the rule.
    // Swapping a signature for its twin needs no key, which is the whole problem, and here it is the
    // fix. Anything that is not an ECDSA value passes through untouched: an Ed25519 signature, or
    // bytes a later check refuses for what they are.
    let sig = match crate::keys::ecdsa_is_low_s(sig) {
        Some(false) => crate::keys::ecdsa_low_s(sig).unwrap_or_else(|_| sig.to_vec()),
        _ => sig.to_vec(),
    };
    der::seq(&[tbs.to_vec(), alg_der.to_vec(), der::bitstr(&sig, 0)])
}

pub fn root_tbs(cn: &str, key: &PublicKey, not_before: i64, serial: &[u8]) -> Result<Unsigned> {
    let alg_oid = key.alg().sig_oid()?;
    let id = key.key_id();
    let tbs = der::seq(&[
        der::explicit(0, &der::int(2)),
        der::int_bytes(serial),
        sig_alg(alg_oid),
        name(cn),
        der::seq(&[time::der_time(not_before), time::der_time(FOREVER)]),
        name(cn),
        key.spki().to_vec(),
        der::explicit(
            3,
            &der::seq(&[
                ext(OID_BASIC_CONSTRAINTS, true, &der::seq(&[der::boolean(true), der::int(0)])),
                ext(OID_KEY_USAGE, true, &key_usage(&[5])),
                ext(OID_SKI, false, &der::octet(&id)),
            ]),
        ),
    ]);
    Ok(Unsigned { tbs, sig_alg: alg_oid.to_string() })
}

pub fn build_root(cn: &str, key: &PrivateKey, not_before: i64, serial: &[u8]) -> Result<Vec<u8>> {
    let signer = key.signer();
    let u = root_tbs(cn, &signer.public(), not_before, serial)?;
    Ok(assemble(&u.tbs, &u.sig_alg, &signer.sign(&u.tbs)))
}

/// Everything a leaf carries. `ca` and `usage` exist so the CLI's intrusion builder
/// (crates/pact/src/vectors/intrude.rs) can make a CA leaf a wallet never would, and `aki` so a test
/// can name another issuer (tests/findings.rs); a wallet leaves them at their defaults. `extra` and
/// `alg_oid` went with the JSON boundary's reading of them (T16): nothing else ever set them.
pub struct LeafSpec<'a> {
    pub cn: &'a str,
    pub root_cn: &'a str,
    pub issuer: &'a PublicKey,
    pub host_key: &'a PublicKey,
    pub uris: Vec<String>,
    pub dns_name: Option<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub serial: Vec<u8>,
    pub ca: bool,
    pub usage: Option<Vec<u8>>,
    pub aki: Option<Vec<u8>>,
}

pub fn leaf_tbs(s: &LeafSpec<'_>) -> Result<Unsigned> {
    let id = s.host_key.key_id();
    let issuer_id = s.aki.clone().unwrap_or_else(|| s.issuer.key_id().to_vec());
    let bits: Vec<u8> = s.usage.clone().unwrap_or_else(|| if s.host_key.alg() == Alg::P256 { vec![0, 4] } else { vec![0] });
    let mut san: Vec<Vec<u8>> = s.uris.iter().map(|u| der::implicit(6, u.as_bytes())).collect();
    if let Some(d) = &s.dns_name {
        san.push(der::implicit(2, d.as_bytes()));
    }
    let alg_oid = s.issuer.alg().sig_oid()?.to_string();
    let exts = [
        ext(OID_BASIC_CONSTRAINTS, true, &if s.ca { der::seq(&[der::boolean(true)]) } else { der::seq(&[]) }),
        ext(OID_KEY_USAGE, true, &key_usage(&bits)),
        ext(OID_EKU, false, &der::seq(&[der::oid(OID_SERVER_AUTH), der::oid(OID_CLIENT_AUTH)])),
        ext(OID_SAN, false, &der::seq(&san)),
        ext(OID_SKI, false, &der::octet(&id)),
        ext(OID_AKI, false, &der::seq(&[der::implicit(0, &issuer_id)])),
    ];
    let tbs = der::seq(&[
        der::explicit(0, &der::int(2)),
        der::int_bytes(&s.serial),
        sig_alg(&alg_oid),
        name(s.root_cn),
        der::seq(&[time::der_time(s.not_before), time::der_time(s.not_after)]),
        name(s.cn),
        s.host_key.spki().to_vec(),
        der::explicit(3, &der::seq(&exts)),
    ]);
    Ok(Unsigned { tbs, sig_alg: alg_oid })
}

pub fn build_leaf(s: &LeafSpec<'_>, root: &PrivateKey) -> Result<Vec<u8>> {
    let u = leaf_tbs(s)?;
    Ok(assemble(&u.tbs, &u.sig_alg, &root.sign(&u.tbs)))
}

#[derive(Clone, Debug)]
pub struct Extension {
    pub id: String,
    pub critical: bool,
}

/// A certificate read back into the fields the rules need.
#[derive(Clone)]
pub struct Cert {
    pub der: Vec<u8>,
    pub tbs: Vec<u8>,
    pub sig_alg: String,
    pub sig: Vec<u8>,
    pub serial: Vec<u8>,
    pub issuer: String,
    pub subject: String,
    pub not_before: i64,
    pub not_after: i64,
    pub time_tags: [u8; 2],
    pub spki: Vec<u8>,
    pub public_key: PublicKey,
    pub key_id: [u8; 32],
    pub extensions: Vec<Extension>,
    pub ca: bool,
    pub path_len: Option<i64>,
    pub key_usage: Vec<u8>,
    pub eku: Vec<String>,
    pub uris: Vec<String>,
    pub dns: Vec<String>,
    pub other_names: usize,
    pub ski: Option<Vec<u8>>,
    pub aki: Option<Vec<u8>>,
    pub aki_extra: bool,
}

fn name_of(node: &Node<'_>) -> Result<String> {
    let rdns = children(node)?;
    if rdns.len() != 1 {
        return err("parse", "name is not one RDN");
    }
    let atvs = children(&rdns[0])?;
    if atvs.len() != 1 {
        return err("parse", "RDN is not one attribute");
    }
    let parts = children(&atvs[0])?;
    if parts.len() < 2 || read_oid_strict(&parts[0])? != OID_CN || parts[1].tag != 0x0c {
        return err("parse", "name is not a UTF-8 commonName");
    }
    Ok(String::from_utf8_lossy(parts[1].content).into_owned())
}

/// Throws on anything malformed, with the seed's messages.
pub fn parse(der_bytes: &[u8]) -> Result<Cert> {
    let cert = read(der_bytes, 0)?;
    if cert.tag != 0x30 || cert.end != der_bytes.len() {
        return err("parse", "not one SEQUENCE");
    }
    let top = children(&cert)?;
    if top.len() != 3 || top[2].tag != 0x03 || top[2].content.is_empty() || top[2].content[0] != 0 {
        return err("parse", "certificate shape");
    }
    let (tbs, alg, sig) = (&top[0], &top[1], &top[2]);
    let f = children(tbs)?;
    // version [0] EXPLICIT INTEGER 2, exactly: one minimal INTEGER whose value is 2.
    let version_ok = f.len() == 8
        && f[0].tag == 0xa0
        && children(&f[0]).map(|v| v.len() == 1 && v[0].tag == 0x02 && v[0].content == [2u8]).unwrap_or(false)
        && f[7].tag == 0xa3;
    if !version_ok {
        return err("parse", "not a v3 certificate with extensions");
    }
    if !der::int_minimal(f[1].content) {
        return err("parse", "INTEGER not minimal");
    }
    let validity = children(&f[4])?;
    if validity.len() != 2 {
        return err("parse", "time not in the DER form");
    }
    let alg_parts = children(alg)?;
    if alg_parts.len() != 1 || alg_parts[0].tag != 0x06 {
        return err("parse", "certificate shape");
    }
    // RFC 5280 §4.1.1.2: the algorithm inside the TBS and the one outside are the same field twice.
    if f[2].raw != alg.raw {
        return err("parse", "signature algorithm inside and outside differ");
    }
    let public_key = PublicKey::from_spki(f[6].raw)?;
    let mut out = Cert {
        der: der_bytes.to_vec(),
        tbs: tbs.raw.to_vec(),
        sig_alg: read_oid_strict(&alg_parts[0])?,
        sig: sig.content[1..].to_vec(),
        serial: f[1].content.to_vec(),
        issuer: name_of(&f[3])?,
        subject: name_of(&f[5])?,
        not_before: time::read_der_time(validity[0].tag, validity[0].content)?,
        not_after: time::read_der_time(validity[1].tag, validity[1].content)?,
        time_tags: [validity[0].tag, validity[1].tag],
        spki: f[6].raw.to_vec(),
        key_id: crate::util::sha256(f[6].raw),
        public_key,
        extensions: Vec::new(),
        ca: false,
        path_len: None,
        key_usage: Vec::new(),
        eku: Vec::new(),
        uris: Vec::new(),
        dns: Vec::new(),
        other_names: 0,
        ski: None,
        aki: None,
        aki_extra: false,
    };
    let ext_wrapper = children(&f[7])?;
    if ext_wrapper.is_empty() {
        return err("parse", "not a v3 certificate with extensions");
    }
    for e in children(&ext_wrapper[0])? {
        let parts = children(&e)?;
        // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }:
        // two or three parts; a critical BOOLEAN present is TRUE and encoded as 0xFF (DER never
        // encodes the default); the OCTET STRING holds exactly one TLV.
        if parts.len() < 2 || parts.len() > 3 || parts[0].tag != 0x06 || parts[parts.len() - 1].tag != 0x04 {
            return err("parse", "certificate shape");
        }
        let critical = if parts.len() == 3 {
            if !der::bool_true(&parts[1]) {
                return err("parse", "BOOLEAN not in the DER form");
            }
            true
        } else {
            false
        };
        let id = read_oid_strict(&parts[0])?;
        let octets = parts[parts.len() - 1].content;
        let value = read(octets, 0)?;
        if value.end != octets.len() {
            return err("parse", "extension value has trailing bytes");
        }
        // The value is the TYPE its extension names (RFC 5280 4.2.1). Nothing looked at this tag, so
        // a `keyUsage` that is an OCTET STRING whose body happens to look like a BIT STRING's was read
        // as one, a `subjectKeyIdentifier` took its 32 bytes from anything, and a `subjectAltName`
        // could be a SET — each a certificate that validated here (measured 2026-09-20: accepted as a
        // chain) and that SPEC 14.1's exact profile says is not a PACT certificate.
        let want_tag = match id.as_str() {
            OID_BASIC_CONSTRAINTS | OID_EKU | OID_SAN | OID_AKI => Some(0x30),
            OID_KEY_USAGE => Some(0x03),
            OID_SKI => Some(0x04),
            _ => None,
        };
        if want_tag.is_some_and(|t| t != value.tag) {
            return err("parse", "extension value of another type");
        }
        out.extensions.push(Extension { id: id.clone(), critical });
        match id.as_str() {
            OID_BASIC_CONSTRAINTS => {
                // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER
                // OPTIONAL }, which in DER is exactly one of: nothing, [TRUE], [TRUE, n]. This read the
                // FIRST and the LAST element, so `SEQUENCE { NULL }` was a valid leaf and
                // `SEQUENCE { TRUE, 5, 0 }` was a root whose pathLen is 0 here and 5 to every other X.509
                // reader — one certificate, two readings, which is what 14.1 exists to exclude.
                let c = children(&value)?;
                let shape: Vec<u8> = c.iter().map(|x| x.tag).collect();
                if !matches!(shape.as_slice(), [] | [0x01] | [0x01, 0x02]) {
                    return err("parse", "basicConstraints not in the DER form");
                }
                if let Some(first) = c.first() {
                    // cA BOOLEAN DEFAULT FALSE: present means TRUE, and TRUE is 0xFF.
                    if !der::bool_true(first) {
                        return err("parse", "BOOLEAN not in the DER form");
                    }
                    out.ca = true;
                }
                if let Some(n) = c.get(1) {
                    if !der::int_minimal(n.content) || n.content.len() > 8 {
                        return err("parse", "INTEGER not minimal");
                    }
                    // An empty INTEGER reads as `undefined` in the seed: present, and equal to nothing.
                    out.path_len =
                        Some(if n.content.is_empty() { -1 } else { n.content.iter().fold(0i64, |acc, b| (acc << 8) | *b as i64) });
                }
            }
            OID_KEY_USAGE => {
                // BIT STRING: the first byte says how many trailing bits of the last byte are unused;
                // every named bit of every byte counts, so a second byte (decipherOnly) is seen.
                if !der::named_bits_ok(value.content) {
                    return err("parse", "BIT STRING not in the DER form");
                }
                let unused = value.content.first().copied().unwrap_or(0) as usize;
                let bits = &value.content[1.min(value.content.len())..];
                let total = bits.len() * 8 - unused;
                for i in 0..total {
                    if bits[i / 8] & (0x80 >> (i % 8)) != 0 {
                        out.key_usage.push(i as u8);
                    }
                }
            }
            OID_EKU => out.eku = children(&value)?.iter().map(read_oid_strict).collect::<Result<Vec<_>>>()?,
            OID_SAN => {
                for n in children(&value)? {
                    match n.tag {
                        0x86 => out.uris.push(String::from_utf8_lossy(n.content).into_owned()),
                        0x82 => out.dns.push(String::from_utf8_lossy(n.content).into_owned()),
                        _ => out.other_names += 1,
                    }
                }
            }
            OID_SKI => out.ski = Some(value.content.to_vec()),
            OID_AKI => {
                let c = children(&value)?;
                out.aki = c.iter().find(|x| x.tag == 0x80).map(|x| x.content.to_vec());
                out.aki_extra = c.len() != 1;
            }
            _ => {}
        }
    }
    Ok(out)
}

fn same<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a == b
}

/// §14.1 exactly: every field, every extension and its criticality, nothing else.
pub fn profile_error(c: &Cert, kind: &str) -> Option<String> {
    if c.der.len() > MAX_CERT_BYTES {
        return Some("over 4 KiB".into());
    }
    if c.serial.len() < 8 || c.serial.len() > 20 || c.serial[0] & 0x80 != 0 {
        return Some("serial not 64–160 bits positive".into());
    }
    if c.sig_alg != OID_ED25519 && c.sig_alg != OID_ECDSA_SHA256 {
        return Some("signature algorithm not in the profile".into());
    }
    // SPEC 14.1: of an ECDSA signature's two twins, only the low-S one is a PACT certificate. Judged
    // only where the bits ARE an ECDSA value (see `keys::ecdsa_is_low_s`).
    if c.sig_alg == OID_ECDSA_SHA256 && crate::keys::ecdsa_is_low_s(&c.sig) == Some(false) {
        return Some("ECDSA signature not in the low-S form".into());
    }
    if c.public_key.alg() == Alg::X25519 {
        return Some("key algorithm not in the profile".into());
    }
    if c.time_tags[0] != time::tag_for(c.not_before) || c.time_tags[1] != time::tag_for(c.not_after) {
        return Some("time encoding not per RFC 5280".into());
    }
    if c.ski.as_deref() != Some(&c.key_id[..]) {
        return Some("subject key identifier is not the key".into());
    }
    let mut ids: Vec<&str> = c.extensions.iter().map(|e| e.id.as_str()).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    if ids.len() != n {
        return Some("duplicate extension".into());
    }
    let crit = |id: &str| c.extensions.iter().find(|e| e.id == id).map(|e| e.critical);
    if kind == "root" {
        let mut want = vec![OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_SKI];
        want.sort();
        if !same(&ids, &want) {
            return Some("root extensions are not exactly the profile".into());
        }
        if crit(OID_BASIC_CONSTRAINTS) != Some(true) || !c.ca || c.path_len != Some(0) {
            return Some("root basicConstraints".into());
        }
        if crit(OID_KEY_USAGE) != Some(true) || !same(&c.key_usage, &[5]) {
            return Some("root keyUsage is not keyCertSign alone".into());
        }
        if crit(OID_SKI) != Some(false) || c.issuer != c.subject {
            return Some("root identity".into());
        }
        if c.not_after != FOREVER {
            return Some("root notAfter is not 9999-12-31".into());
        }
        return None;
    }
    let mut want = vec![OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_EKU, OID_SAN, OID_SKI, OID_AKI];
    want.sort();
    if !same(&ids, &want) {
        return Some("leaf extensions are not exactly the profile".into());
    }
    if crit(OID_BASIC_CONSTRAINTS) != Some(true) || c.ca || c.path_len.is_some() {
        return Some("leaf basicConstraints".into());
    }
    let expected_usage: &[u8] = if c.public_key.alg() == Alg::P256 { &[0, 4] } else { &[0] };
    if crit(OID_KEY_USAGE) != Some(true) || !same(&c.key_usage, expected_usage) {
        return Some("leaf keyUsage".into());
    }
    let mut eku = c.eku.clone();
    eku.sort();
    let mut want_eku = vec![OID_SERVER_AUTH.to_string(), OID_CLIENT_AUTH.to_string()];
    want_eku.sort();
    if crit(OID_EKU) != Some(false) || eku != want_eku {
        return Some("leaf extendedKeyUsage".into());
    }
    if crit(OID_SAN) != Some(false) || c.other_names > 0 || c.dns.len() > 1 {
        return Some("leaf subjectAltName carries a name type the profile does not".into());
    }
    // …and a key identifier is the 32-byte SHA-256 of a SubjectPublicKeyInfo (§14.1). The subject one
    // was held to that above; this one was only asked to be THERE, so a leaf could name an issuer in
    // three bytes — and a card would show those three bytes to a person as the identity to pin.
    if crit(OID_AKI) != Some(false) || c.aki.as_deref().map(<[u8]>::len) != Some(32) || c.aki_extra {
        return Some("leaf authorityKeyIdentifier is not a key identifier alone".into());
    }
    None
}

/// The declared algorithm must be the issuer key's own; a verifier never picks it from the certificate.
pub fn verify_cert(cert: &Cert, issuer: &PublicKey) -> bool {
    match issuer.alg().sig_oid() {
        Ok(oid) => cert.sig_alg == oid && issuer.verify(&cert.tbs, &cert.sig),
        Err(_) => false,
    }
}

pub fn fingerprint_of(cert: &Cert) -> String {
    fingerprint_of_id(&cert.key_id)
}

pub struct ChainOk {
    pub leaf: Cert,
    pub root: Cert,
    pub root_fingerprint: String,
    pub endpoint: String,
}

pub enum ChainResult {
    Ok(Box<ChainOk>),
    Refused { rule: u8, reason: String },
}

fn refuse(rule: u8, reason: impl Into<String>) -> ChainResult {
    ChainResult::Refused { rule, reason: reason.into() }
}

/// The host of a normal-form https URL: the authority without its port. (The normal form carries
/// no userinfo, and MAY carry a port other than 443 — `is_normal_https` allows it on purpose.)
///
/// This returned the whole authority, under a comment saying a normal form has no port. A dNSName
/// cannot carry one, so on any address but :443 the wallet refused a request that asked for the
/// dNSName §14.1 permits, and rule 5 would have refused the leaf: the feature did not exist there.
/// An IPv6 literal keeps its brackets; it is never a dNSName, and what matters is that one spelling
/// is compared with itself.
pub fn host_of(endpoint: &str) -> &str {
    let rest = endpoint.strip_prefix("https://").unwrap_or(endpoint);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    match authority.strip_prefix('[').and_then(|inner| inner.find(']')) {
        Some(close) => &authority[..close + 2],
        None => authority.split(':').next().unwrap_or(""),
    }
}

/// §14.2, refusing at the first failure and naming the rule.
pub fn validate_chain(chain: &[Vec<u8>], now: i64, expected_root: Option<&str>, expected_endpoint: Option<&str>) -> ChainResult {
    if chain.len() != 2 {
        return refuse(1, format!("chain of {}", chain.len()));
    }
    let leaf = match parse(&chain[0]) {
        Ok(c) => c,
        Err(e) => return refuse(1, e.why),
    };
    let root = match parse(&chain[1]) {
        Ok(c) => c,
        Err(e) => return refuse(1, e.why),
    };
    if let Some(bad) = profile_error(&leaf, "leaf").or_else(|| profile_error(&root, "root")) {
        return refuse(1, bad);
    }
    if !verify_cert(&root, &root.public_key) {
        return refuse(2, "root is not self-signed");
    }
    let root_fingerprint = fingerprint_of(&root);
    if let Some(expected) = expected_root {
        if expected != root_fingerprint {
            return refuse(2, "root is not the one expected");
        }
    }
    if !verify_cert(&leaf, &root.public_key) {
        return refuse(3, "leaf is not signed by the root");
    }
    if leaf.aki.as_deref() != Some(&root.key_id[..]) {
        return refuse(3, "authority key identifier is not the root");
    }
    if now < leaf.not_before || now > leaf.not_after {
        return refuse(4, "leaf outside its validity");
    }
    if leaf.not_after - leaf.not_before > MAX_LEAF_DAYS * DAY {
        return refuse(4, "leaf longer than 398 days");
    }
    if leaf.uris.len() != 1 {
        return refuse(5, format!("{} URIs", leaf.uris.len()));
    }
    let endpoint = leaf.uris[0].clone();
    if !is_normal_https(&endpoint) {
        return refuse(5, "endpoint is not an https URL in normal form");
    }
    if let Some(expected) = expected_endpoint {
        if expected != endpoint {
            return refuse(5, "endpoint differs from the one in question");
        }
    }
    let host = host_of(&endpoint);
    if leaf.dns.iter().any(|d| d != host) {
        return refuse(5, "dNSName differs from the URI host");
    }
    ChainResult::Ok(Box::new(ChainOk { leaf, root, root_fingerprint, endpoint }))
}

fn canonical_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u32>().map(|v| v <= 255).unwrap_or(false)
        })
}

fn ends_in_a_number(host: &str) -> bool {
    let mut labels: Vec<&str> = host.split('.').collect();
    if labels.last() == Some(&"") {
        labels.pop();
    }
    match labels.last() {
        Some(last) if !last.is_empty() => {
            last.bytes().all(|b| b.is_ascii_digit())
                || ((last.starts_with("0x") || last.starts_with("0X")) && last[2..].bytes().all(|b| b.is_ascii_hexdigit()))
        }
        _ => false,
    }
}

fn dot_segment(seg: &str) -> bool {
    let s = seg.to_ascii_lowercase();
    matches!(s.as_str(), "." | ".." | "%2e" | ".%2e" | "%2e." | "%2e%2e")
}

/// The normal form of §14.1, as the WHATWG parser the seed relies on judges it: what the string
/// must already be, so nothing is normalised at comparison time.
pub fn is_normal_https(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else { return false };
    if s.contains('#') || s.contains('?') || s.contains('\\') {
        return false;
    }
    let Some(slash) = rest.find('/') else { return false };
    let (host, path) = (&rest[..slash], &rest[slash..]);
    if host.is_empty() || host.contains('@') {
        return false;
    }
    // A port stays as written when it is not the default: digits, no leading zero, in range, never 443.
    let normal_port = |p: &str| {
        p.len() <= 5
            && !p.is_empty()
            && !p.starts_with('0')
            && p != "443"
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().map(|n| (1..=65535).contains(&n)).unwrap_or(false)
    };
    if let Some(inner) = host.strip_prefix('[') {
        let Some(end) = inner.find(']') else { return false };
        let (inner, rest) = (&inner[..end], &inner[end + 1..]);
        if !rest.is_empty() && !rest.strip_prefix(':').map(normal_port).unwrap_or(false) {
            return false;
        }
        match inner.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => {
                if ip.to_string() != inner || inner.contains('.') {
                    return false;
                }
            }
            Err(_) => return false,
        }
    } else {
        let host = match host.split_once(':') {
            Some((h, p)) => {
                if !normal_port(p) {
                    return false;
                }
                h
            }
            None => host,
        };
        if !host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.') {
            return false;
        }
        // A label that is empty is not a label: a leading dot, a doubled dot, and the trailing dot of
        // the fully-qualified spelling are all other ways to write the same host, and the normal form
        // exists so that one address has one spelling. `https://localhost./mcp` reached the address
        // guard here and was refused as a normal-form failure by the Go port — two ports disagreeing
        // about what a name is.
        if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
            return false;
        }
        if ends_in_a_number(host) && !canonical_ipv4(host) {
            return false;
        }
    }
    if path == "/" || path.ends_with('/') {
        return false;
    }
    if path[1..].split('/').any(dot_segment) {
        return false;
    }
    // RFC 3986 normal form for the path: pchar only, percent-encoding uppercase and never for an
    // unreserved character — so two strings for one address cannot both be "normal".
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            if i + 2 >= b.len() {
                return false;
            }
            let (h, l) = (b[i + 1], b[i + 2]);
            let hex = |d: u8| matches!(d, b'0'..=b'9' | b'A'..=b'F');
            if !hex(h) || !hex(l) {
                return false;
            }
            let v = (h as char).to_digit(16).unwrap() * 16 + (l as char).to_digit(16).unwrap();
            let unreserved = (v as u8).is_ascii_alphanumeric() || matches!(v as u8, b'-' | b'.' | b'_' | b'~');
            if unreserved {
                return false;
            }
            i += 3;
            continue;
        }
        let pchar = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
            );
        if !pchar {
            return false;
        }
        i += 1;
    }
    true
}

/// §14.3: which of two leaves under one root is current. A later notBefore wins the instant it is
/// seen, whatever the validity of the older leaf.
pub fn compare_leaves(pinned: &[u8], presented: &[u8]) -> Result<&'static str> {
    let a = parse(pinned)?;
    let b = parse(presented)?;
    Ok(if b.not_before < a.not_before {
        "superseded"
    } else if b.not_before > a.not_before {
        "newer"
    } else if a.der == b.der {
        "same"
    } else {
        "conflict"
    })
}

impl Cert {
    pub fn kind(&self) -> &'static str {
        if profile_error(self, "leaf").is_none() {
            "leaf"
        } else if profile_error(self, "root").is_none() {
            "root"
        } else {
            "other"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normal_form() {
        assert!(is_normal_https("https://agent.alina.example/mcp"));
        assert!(is_normal_https("https://alina.host.example/alina/mcp"));
        assert!(is_normal_https("https://203.0.113.9/mcp"));
        for good in [
            "https://a.example/x/y-z_~",
            "https://a.example/p%20q",
            "https://a.example/a:b@c",
            "https://agent.alina.example:8443/mcp",
            "https://[2001:db8::1]:8443/mcp",
            "https://203.0.113.9:8080/mcp",
        ] {
            assert!(is_normal_https(good), "{good}");
        }
        for bad in [
            "https://a.example/p%2fq",
            "https://a.example/p%41",
            "https://a.example/p%7e",
            "https://a.example/x|y",
            "https://a.example/p%2",
            "https://a.example/p%",
            "https://a.example:443/mcp",
            "https://a.example:0/mcp",
            "https://a.example:08443/mcp",
            "https://a.example:65536/mcp",
            "https://a.example:/mcp",
            "https://[2001:db8::1]8443/mcp",
            // No zone id in an IPv6 literal, in any spelling: `std` cannot parse one, and that is the rule.
            "https://[2001:db8::1%eth0]/mcp",
            "https://[2001:db8::1%25eth0]/mcp",
            "https://[fe80::1%eth0]/mcp",
        ] {
            assert!(!is_normal_https(bad), "{bad}");
        }
        for bad in [
            "https://agent.alina.example/mcp/",
            "https://agent.alina.example/",
            "https://agent.alina.example",
            "http://agent.alina.example/mcp",
            "https://Agent.Alina.example/mcp",
            "https://agent.alina.example:443/mcp",
            "https://agent.alina.example@mallory.example/mcp",
            "https://agent.alina.example/mcp?x=1",
            "https://agent.alina.example/mcp#f",
            "https://agent.alina.example/mcp/../admin",
            "https://agent.alina.example/a b",
            "https://127.1/mcp",
            "https://agent.alina.example/mcp\\x",
            "HTTPS://agent.alina.example/mcp",
        ] {
            assert!(!is_normal_https(bad), "{bad}");
        }
    }
    #[test]
    fn key_usage_bits() {
        assert_eq!(key_usage(&[5]), vec![0x03, 0x02, 0x02, 0x04]);
        assert_eq!(key_usage(&[0]), vec![0x03, 0x02, 0x07, 0x80]);
        assert_eq!(key_usage(&[0, 4]), vec![0x03, 0x02, 0x03, 0x88]);
    }
}
