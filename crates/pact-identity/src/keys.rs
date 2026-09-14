//! Keys: Ed25519 and P-256 in PKCS #8 and SubjectPublicKeyInfo, fingerprints, and the conversions
//! §13.1 names (RFC 7748 §4.1 and RFC 8032 §5.1.5 to X25519).
use crate::der::{self, children, read, read_oid};
use crate::util::{b64u, err, sha256, Error, Result};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const OID_ED25519: &str = "1.3.101.112";
pub const OID_X25519: &str = "1.3.101.110";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Ed25519,
    P256,
    /// A bare X25519 key: never a certificate key, only an HPKE recipient (the seed accepts one too).
    X25519,
}

impl Alg {
    pub fn name(self) -> &'static str {
        match self {
            Alg::Ed25519 => "ed25519",
            Alg::P256 => "p256",
            Alg::X25519 => "x25519",
        }
    }
    pub fn parse(s: &str) -> Result<Alg> {
        match s {
            "ed25519" => Ok(Alg::Ed25519),
            "p256" => Ok(Alg::P256),
            _ => err("unsupported", format!("unsupported key type {s}")),
        }
    }
    /// The signature algorithm OID a key of this algorithm signs with (§14.1: the issuer key's own).
    pub fn sig_oid(self) -> Result<&'static str> {
        match self {
            Alg::Ed25519 => Ok(OID_ED25519),
            Alg::P256 => Ok(OID_ECDSA_SHA256),
            Alg::X25519 => err("unsupported", "an X25519 key does not sign"),
        }
    }
}

#[derive(Clone)]
enum Public {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::PublicKey),
    X25519([u8; 32]),
}

/// A public key with the exact SubjectPublicKeyInfo bytes it was read from (the fingerprint hashes those).
#[derive(Clone)]
pub struct PublicKey {
    spki: Vec<u8>,
    inner: Public,
}

fn spki_of(alg_id: Vec<u8>, key: &[u8]) -> Vec<u8> {
    der::seq(&[alg_id, der::bitstr(key, 0)])
}

impl PublicKey {
    pub fn from_spki(bytes: &[u8]) -> Result<PublicKey> {
        let node = read(bytes, 0)?;
        if node.tag != 0x30 || node.end != bytes.len() {
            return err("parse", "SubjectPublicKeyInfo is not one SEQUENCE");
        }
        let f = children(&node)?;
        if f.len() != 2 || f[0].tag != 0x30 || f[1].tag != 0x03 || f[1].content.is_empty() || f[1].content[0] != 0 {
            return err("parse", "SubjectPublicKeyInfo shape");
        }
        let alg = children(&f[0])?;
        if alg.is_empty() || alg[0].tag != 0x06 {
            return err("parse", "SubjectPublicKeyInfo algorithm");
        }
        let key = &f[1].content[1..];
        let inner = match read_oid(&alg[0]).as_str() {
            OID_ED25519 if alg.len() == 1 => {
                let k: [u8; 32] = key.try_into().map_err(|_| Error::new("parse", "Ed25519 key is not 32 bytes"))?;
                Public::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&k).map_err(|_| Error::new("parse", "Ed25519 key is not a point"))?)
            }
            OID_X25519 if alg.len() == 1 => {
                let k: [u8; 32] = key.try_into().map_err(|_| Error::new("parse", "X25519 key is not 32 bytes"))?;
                Public::X25519(k)
            }
            OID_EC_PUBLIC_KEY if alg.len() == 2 && alg[1].tag == 0x06 && read_oid(&alg[1]) == OID_PRIME256V1 => {
                Public::P256(p256::PublicKey::from_sec1_bytes(key).map_err(|_| Error::new("parse", "P-256 key is not a point"))?)
            }
            other => return err("unsupported", format!("unsupported key type {other}")),
        };
        Ok(PublicKey { spki: bytes.to_vec(), inner })
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki
    }
    pub fn alg(&self) -> Alg {
        match self.inner {
            Public::Ed25519(_) => Alg::Ed25519,
            Public::P256(_) => Alg::P256,
            Public::X25519(_) => Alg::X25519,
        }
    }
    pub fn key_id(&self) -> [u8; 32] {
        sha256(&self.spki)
    }
    pub fn fingerprint(&self) -> String {
        fingerprint_of_id(&self.key_id())
    }

    /// §13.1: Ed25519 pure, or ECDSA P-256/SHA-256 in DER, by the key's own algorithm.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        match &self.inner {
            Public::Ed25519(k) => match ed25519_dalek::Signature::from_slice(sig) {
                Ok(s) => k.verify_strict(data, &s).is_ok(),
                Err(_) => false,
            },
            Public::P256(k) => match p256::ecdsa::Signature::from_der(sig) {
                Ok(s) => p256::ecdsa::VerifyingKey::from(k).verify(data, &s).is_ok(),
                Err(_) => false,
            },
            Public::X25519(_) => false,
        }
    }

    /// The X25519 public key an HPKE sender seals to: RFC 7748 §4.1 for an Ed25519 key.
    pub fn x25519(&self) -> Result<[u8; 32]> {
        match &self.inner {
            Public::Ed25519(k) => Ok(k.to_montgomery().to_bytes()),
            Public::X25519(k) => Ok(*k),
            Public::P256(_) => err("unsupported", "a P-256 key has no X25519 form"),
        }
    }
    pub fn p256(&self) -> Result<&p256::PublicKey> {
        match &self.inner {
            Public::P256(k) => Ok(k),
            _ => err("unsupported", "not a P-256 key"),
        }
    }
    pub fn p256_uncompressed(&self) -> Result<Vec<u8>> {
        Ok(self.p256()?.to_encoded_point(false).as_bytes().to_vec())
    }
}

pub fn fingerprint_of_id(id: &[u8]) -> String {
    format!("sha256:{}", b64u(id))
}

pub enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::SecretKey),
}

impl PrivateKey {
    pub fn alg(&self) -> Alg {
        match self {
            PrivateKey::Ed25519(_) => Alg::Ed25519,
            PrivateKey::P256(_) => Alg::P256,
        }
    }

    pub fn generate(alg: Alg) -> Result<PrivateKey> {
        let seed: [u8; 32] = crate::util::random(32)?.try_into().unwrap_or([0; 32]);
        let seed = Zeroizing::new(seed);
        PrivateKey::from_seed(alg, &seed)
    }

    /// The vectors' derivation: Ed25519 uses the seed as its secret; P-256 takes the seed mod n, zero becoming one.
    pub fn from_seed(alg: Alg, seed: &[u8; 32]) -> Result<PrivateKey> {
        match alg {
            Alg::Ed25519 => Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed))),
            Alg::P256 => {
                use p256::elliptic_curve::ops::Reduce;
                use p256::elliptic_curve::Field;
                let s = p256::Scalar::reduce(p256::U256::from_be_slice(seed));
                let s = if bool::from(s.is_zero()) { p256::Scalar::ONE } else { s };
                let nz = p256::NonZeroScalar::new(s).into_option().ok_or_else(|| Error::new("key", "zero scalar"))?;
                Ok(PrivateKey::P256(p256::SecretKey::from(nz)))
            }
            Alg::X25519 => err("unsupported", "unsupported key type x25519"),
        }
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<PrivateKey> {
        let node = read(bytes, 0)?;
        if node.tag != 0x30 || node.end != bytes.len() {
            return err("parse", "PKCS #8 is not one SEQUENCE");
        }
        let f = children(&node)?;
        if f.len() < 3 || f[0].tag != 0x02 || f[1].tag != 0x30 || f[2].tag != 0x04 {
            return err("parse", "PKCS #8 shape");
        }
        let alg = children(&f[1])?;
        if alg.is_empty() || alg[0].tag != 0x06 {
            return err("parse", "PKCS #8 algorithm");
        }
        match read_oid(&alg[0]).as_str() {
            OID_ED25519 => {
                let inner = read(f[2].content, 0)?;
                if inner.tag != 0x04 || inner.end != f[2].content.len() {
                    return err("parse", "Ed25519 private key shape");
                }
                let seed: [u8; 32] = inner.content.try_into().map_err(|_| Error::new("parse", "Ed25519 seed is not 32 bytes"))?;
                Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)))
            }
            OID_EC_PUBLIC_KEY if alg.len() == 2 && alg[1].tag == 0x06 && read_oid(&alg[1]) == OID_PRIME256V1 => {
                let ec = read(f[2].content, 0)?;
                if ec.tag != 0x30 || ec.end != f[2].content.len() {
                    return err("parse", "ECPrivateKey shape");
                }
                let g = children(&ec)?;
                if g.len() < 2 || g[0].tag != 0x02 || g[1].tag != 0x04 || g[1].content.len() > 32 || g[1].content.is_empty() {
                    return err("parse", "ECPrivateKey shape");
                }
                let mut d = Zeroizing::new([0u8; 32]);
                d[32 - g[1].content.len()..].copy_from_slice(g[1].content);
                let k = p256::SecretKey::from_slice(&d[..]).map_err(|_| Error::new("parse", "P-256 scalar out of range"))?;
                Ok(PrivateKey::P256(k))
            }
            other => err("unsupported", format!("unsupported key type {other}")),
        }
    }

    pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        match self {
            PrivateKey::Ed25519(k) => Zeroizing::new(der::seq(&[
                der::int(0),
                der::seq(&[der::oid(OID_ED25519)]),
                der::octet(&der::octet(k.as_bytes())),
            ])),
            PrivateKey::P256(k) => {
                let d = Zeroizing::new(k.to_bytes());
                let pubkey = k.public_key().to_encoded_point(false);
                let ec = Zeroizing::new(der::seq(&[der::int(1), der::octet(&d[..]), der::explicit(1, &der::bitstr(pubkey.as_bytes(), 0))]));
                Zeroizing::new(der::seq(&[
                    der::int(0),
                    der::seq(&[der::oid(OID_EC_PUBLIC_KEY), der::oid(OID_PRIME256V1)]),
                    der::octet(&ec),
                ]))
            }
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(k) => {
                let vk = k.verifying_key();
                PublicKey { spki: spki_of(der::seq(&[der::oid(OID_ED25519)]), vk.as_bytes()), inner: Public::Ed25519(vk) }
            }
            PrivateKey::P256(k) => {
                let pk = k.public_key();
                let point = pk.to_encoded_point(false);
                PublicKey { spki: spki_of(der::seq(&[der::oid(OID_EC_PUBLIC_KEY), der::oid(OID_PRIME256V1)]), point.as_bytes()), inner: Public::P256(pk) }
            }
        }
    }

    /// §13.1: Ed25519 pure, or ECDSA P-256/SHA-256 in DER (RFC 6979 deterministic), by the signer's own algorithm.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(k) => k.sign(data).to_bytes().to_vec(),
            PrivateKey::P256(k) => {
                let sk = p256::ecdsa::SigningKey::from(k);
                let sig: p256::ecdsa::Signature = sk.sign(data);
                sig.to_der().as_bytes().to_vec()
            }
        }
    }

    /// RFC 8032 §5.1.5: the clamped low half of SHA-512(seed) is the X25519 scalar.
    pub fn x25519(&self) -> Result<x25519_dalek::StaticSecret> {
        match self {
            PrivateKey::Ed25519(k) => {
                let h = Zeroizing::new(Sha512::digest(k.as_bytes()));
                let mut a = Zeroizing::new([0u8; 32]);
                a.copy_from_slice(&h[..32]);
                a[0] &= 248;
                a[31] &= 127;
                a[31] |= 64;
                Ok(x25519_dalek::StaticSecret::from(*a))
            }
            PrivateKey::P256(_) => err("unsupported", "a P-256 key has no X25519 form"),
        }
    }
    pub fn p256(&self) -> Result<&p256::SecretKey> {
        match self {
            PrivateKey::P256(k) => Ok(k),
            _ => err("unsupported", "not a P-256 key"),
        }
    }
}

/// An X25519 SubjectPublicKeyInfo, for a raw recipient key (the seed builds these for its low-order test).
pub fn x25519_spki(raw: &[u8; 32]) -> Vec<u8> {
    spki_of(der::seq(&[der::oid(OID_X25519)]), raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{from_hex, hex, seed};

    #[test]
    fn ed25519_pkcs8_matches_the_vectors() {
        let k = PrivateKey::from_seed(Alg::Ed25519, &seed("host/alina/2026")).unwrap();
        assert_eq!(hex(&k.to_pkcs8()), "302e020100300506032b6570042204204896ed640768ccb301df47585afe0488dd5095d2c325c68c3b08d66c085b4272");
        let back = PrivateKey::from_pkcs8(&k.to_pkcs8()).unwrap();
        assert_eq!(back.public().spki(), k.public().spki());
        let sig = k.sign(b"x");
        assert!(k.public().verify(b"x", &sig));
        assert!(!k.public().verify(b"y", &sig));
    }

    #[test]
    fn p256_pkcs8_both_forms() {
        let compact = from_hex("3041020100301306072a8648ce3d020106082a8648ce3d0301070427302502010104206a261bbb098c126fe60dcc26a72045d97db5079d52cd59826220705150ad60d7").unwrap();
        let k = PrivateKey::from_pkcs8(&compact).unwrap();
        let derived = PrivateKey::from_seed(Alg::P256, &seed("host/bharat/2026")).unwrap();
        assert_eq!(k.public().spki(), derived.public().spki());
        let full = k.to_pkcs8();
        assert_eq!(full.len(), 138);
        assert_eq!(PrivateKey::from_pkcs8(&full).unwrap().public().spki(), k.public().spki());
        let sig = k.sign(b"x");
        assert!(k.public().verify(b"x", &sig));
        let spki = PublicKey::from_spki(k.public().spki()).unwrap();
        assert_eq!(spki.alg(), Alg::P256);
        assert_eq!(spki.fingerprint(), k.public().fingerprint());
    }

    #[test]
    fn x25519_maps_agree() {
        let k = PrivateKey::from_seed(Alg::Ed25519, &seed("root/alina")).unwrap();
        let pk = x25519_dalek::PublicKey::from(&k.x25519().unwrap());
        assert_eq!(pk.to_bytes(), k.public().x25519().unwrap());
    }
}
