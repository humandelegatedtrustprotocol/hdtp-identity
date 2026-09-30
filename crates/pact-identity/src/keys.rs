//! Keys: Ed25519 and P-256 in PKCS #8 and SubjectPublicKeyInfo, fingerprints, and the conversions
//! §13.1 names (RFC 7748 §4.1 and RFC 8032 §5.1.5 to X25519).
use crate::der::{self, children, read, read_oid, read_oid_strict};
use crate::util::{b64u, err, sha256, Error, Result};
use p256::ecdsa::signature::{Signer as _, Verifier};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

pub const OID_ED25519: &str = "1.3.101.112";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// The two key algorithms of the profile (§14.1). Every other one is refused where a key is read —
/// `unsupported`, `unsupported key type <OID>` — X25519 included: a bare X25519 key was read as a
/// third algorithm here, and so `key_info` named an algorithm the contract does not have, a leaf was
/// built around one, and a seal went to one (T4), where CONTRACT §5 and the SPEC's suite table say
/// the X25519 suite is for an Ed25519 recipient, converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Ed25519,
    P256,
}

impl Alg {
    pub fn name(self) -> &'static str {
        match self {
            Alg::Ed25519 => "ed25519",
            Alg::P256 => "p256",
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
    pub fn sig_oid(self) -> &'static str {
        match self {
            Alg::Ed25519 => OID_ED25519,
            Alg::P256 => OID_ECDSA_SHA256,
        }
    }
}

#[derive(Clone)]
enum Public {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::PublicKey),
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
        let inner = match read_oid_strict(&alg[0])?.as_str() {
            OID_ED25519 if alg.len() == 1 => {
                let k: [u8; 32] = key.try_into().map_err(|_| Error::new("parse", "Ed25519 key is not 32 bytes"))?;
                Public::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&k).map_err(|_| Error::new("parse", "Ed25519 key is not a point"))?)
            }
            OID_EC_PUBLIC_KEY
                if alg.len() == 2 && alg[1].tag == 0x06 && der::oid_minimal(&alg[1]) && read_oid(&alg[1]) == OID_PRIME256V1 =>
            {
                // RFC 5480 §2.2 allows a compressed point; the profile takes the uncompressed form only,
                // so one key has one SubjectPublicKeyInfo and one fingerprint.
                if key.len() != 65 || key[0] != 0x04 {
                    return err("parse", "P-256 key is not the uncompressed point");
                }
                Public::P256(p256::PublicKey::from_sec1_bytes(key).map_err(|_| Error::new("parse", "P-256 key is not a point"))?)
            }
            // Every other key is outside the profile and refused here, where it is read: RSA, X25519,
            // P-384 (named by its ecPublicKey OID), and an Ed25519 key whose AlgorithmIdentifier
            // carries parameters (RFC 8410 has none). The Go port and the seed read these as keys
            // and refused them later, or not at all (R12, T2).
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
        }
    }

    /// The X25519 public key an HPKE sender seals to: RFC 7748 §4.1 for an Ed25519 key.
    pub fn x25519(&self) -> Result<[u8; 32]> {
        match &self.inner {
            Public::Ed25519(k) => Ok(k.to_montgomery().to_bytes()),
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

/// A private key as it was read. An Ed25519 key is its 32-byte seed and nothing derived from it:
/// `from_pkcs8` used to build an `ed25519_dalek::SigningKey`, which derives the verifying key at
/// once (11 us a parse, measured 2026-09-28), and the open path, which needs only the X25519
/// scalar, never used it. Signing and `public()` derive what they need when they are asked.
pub enum PrivateKey {
    Ed25519(Zeroizing<[u8; 32]>),
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
        // Propagated, not defaulted. `random(32)` returns exactly 32 bytes or an error, so the old
        // `unwrap_or([0; 32])` was unreachable — but what it encoded was "if the randomness came back
        // the wrong length, generate the same key for everybody", and every caller would have accepted
        // it. One character, and it cannot rot into a real defect.
        let seed: [u8; 32] =
            crate::util::random(32)?.try_into().map_err(|_| Error::new("internal", "randomness came back the wrong length"))?;
        let seed = Zeroizing::new(seed);
        PrivateKey::from_seed(alg, &seed)
    }

    /// The vectors' derivation: Ed25519 uses the seed as its secret; P-256 takes the seed mod n, zero becoming one.
    pub fn from_seed(alg: Alg, seed: &[u8; 32]) -> Result<PrivateKey> {
        match alg {
            Alg::Ed25519 => Ok(PrivateKey::Ed25519(Zeroizing::new(*seed))),
            Alg::P256 => {
                use p256::elliptic_curve::ops::Reduce;
                use p256::elliptic_curve::Field;
                let s = p256::Scalar::reduce(p256::U256::from_be_slice(seed));
                let s = if bool::from(s.is_zero()) { p256::Scalar::ONE } else { s };
                let nz = p256::NonZeroScalar::new(s).into_option().ok_or_else(|| Error::new("key", "zero scalar"))?;
                Ok(PrivateKey::P256(p256::SecretKey::from(nz)))
            }
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
        match read_oid_strict(&alg[0])?.as_str() {
            // RFC 8410: an Ed25519 AlgorithmIdentifier has NO parameters. `from_spki` has always held
            // a public key to that; a private key with a NULL after the OID was read anyway.
            OID_ED25519 if alg.len() == 1 => {
                let inner = read(f[2].content, 0)?;
                if inner.tag != 0x04 || inner.end != f[2].content.len() {
                    return err("parse", "Ed25519 private key shape");
                }
                let seed: [u8; 32] = inner.content.try_into().map_err(|_| Error::new("parse", "Ed25519 seed is not 32 bytes"))?;
                Ok(PrivateKey::Ed25519(Zeroizing::new(seed)))
            }
            OID_EC_PUBLIC_KEY
                if alg.len() == 2 && alg[1].tag == 0x06 && der::oid_minimal(&alg[1]) && read_oid(&alg[1]) == OID_PRIME256V1 =>
            {
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
            PrivateKey::Ed25519(k) => {
                Zeroizing::new(der::seq(&[der::int(0), der::seq(&[der::oid(OID_ED25519)]), der::octet(&der::octet(&k[..]))]))
            }
            PrivateKey::P256(k) => {
                let d = Zeroizing::new(k.to_bytes());
                // RFC 5915's optional publicKey is left out, because the seed library's
                // `export({format:'der',type:'pkcs8'})` leaves it out and the seed is the authority
                // on bytes (CONTRACT §0). Including it made this core's P-256 private keys a
                // different 138-byte string for the same key the Go port and the vectors write in 67
                // — two spellings of one key, which is the thing the profile exists to prevent. The
                // reader still accepts either form, so keys written before this still open.
                let ec = Zeroizing::new(der::seq(&[der::int(1), der::octet(&d[..])]));
                Zeroizing::new(der::seq(&[
                    der::int(0),
                    der::seq(&[der::oid(OID_EC_PUBLIC_KEY), der::oid(OID_PRIME256V1)]),
                    der::octet(&ec),
                ]))
            }
        }
    }

    /// The key expanded for signing: an Ed25519 seed becomes its `SigningKey` here, once. A caller that
    /// needs the public key AND a signature takes a `Signer` and asks it for both; `public()` and
    /// `sign()` on the key each expand it again. 0.4.0 made the key its seed and left four callers
    /// (the leaf-form seal, a CSR, a root certificate, an issued leaf) expanding it twice: the leaf-form
    /// `seal_result` went from 85.4 to 96.0 us (measured 2026-09-29).
    pub fn signer(&self) -> Signer<'_> {
        match self {
            PrivateKey::Ed25519(seed) => Signer::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed))),
            PrivateKey::P256(k) => Signer::P256(k),
        }
    }

    pub fn public(&self) -> PublicKey {
        self.signer().public()
    }

    /// §13.1: Ed25519 pure, or ECDSA P-256/SHA-256 in DER (RFC 6979 deterministic), by the signer's own algorithm.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signer().sign(data)
    }

    /// RFC 8032 §5.1.5: the clamped low half of SHA-512(seed) is the X25519 scalar.
    pub fn x25519(&self) -> Result<x25519_dalek::StaticSecret> {
        match self {
            PrivateKey::Ed25519(seed) => {
                let h = Zeroizing::new(Sha512::digest(&seed[..]));
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

/// A private key expanded for signing (`PrivateKey::signer`): its public key and its signatures from
/// one expansion.
pub enum Signer<'a> {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    P256(&'a p256::SecretKey),
}

impl Signer<'_> {
    pub fn public(&self) -> PublicKey {
        match self {
            Signer::Ed25519(k) => {
                let vk = k.verifying_key();
                PublicKey { spki: spki_of(der::seq(&[der::oid(OID_ED25519)]), vk.as_bytes()), inner: Public::Ed25519(vk) }
            }
            Signer::P256(k) => {
                let pk = k.public_key();
                let point = pk.to_encoded_point(false);
                PublicKey {
                    spki: spki_of(der::seq(&[der::oid(OID_EC_PUBLIC_KEY), der::oid(OID_PRIME256V1)]), point.as_bytes()),
                    inner: Public::P256(pk),
                }
            }
        }
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Signer::Ed25519(k) => k.sign(data).to_bytes().to_vec(),
            Signer::P256(k) => {
                let sk = p256::ecdsa::SigningKey::from(*k);
                let sig: p256::ecdsa::Signature = sk.sign(data);
                // The low-S twin, always (SPEC 14.1). `p256` does not normalise on its own — only
                // `k256` does, for Bitcoin's sake — so half of what this returned was the high twin,
                // and a certificate carrying that one is outside the profile.
                sig.normalize_s().unwrap_or(sig).to_der().as_bytes().to_vec()
            }
        }
    }
}

/// Whether a DER ECDSA-Sig-Value over P-256 is the low-S twin; `None` when the bytes are not an ECDSA
/// value at all.
///
/// An ECDSA signature `(r, s)` has a twin `(r, n - s)` that verifies under the same key over the same
/// bytes, and anybody can compute it. On a CERTIFICATE that is a second byte string for one leaf —
/// same key, fingerprint, endpoint and notBefore — which `compare_leaves` reads as a conflict, so a
/// card altered in transit pins a leaf the real host can never match. SPEC 14.1 admits one twin.
///
/// `None` is not a refusal: a certificate that declares ECDSA over bytes that are not an ECDSA value
/// cannot verify under any key, and rule 3 refuses it as "a certificate the key did not sign".
pub fn ecdsa_is_low_s(sig_der: &[u8]) -> Option<bool> {
    let sig = p256::ecdsa::Signature::from_der(sig_der).ok()?;
    Some(sig.normalize_s().is_none())
}

/// The same signature as its low-S twin: unchanged if it already is one. For the external-signing
/// seam, where the signature came from a hardware token that has never heard of this rule.
pub fn ecdsa_low_s(sig_der: &[u8]) -> Result<Vec<u8>> {
    let sig = p256::ecdsa::Signature::from_der(sig_der).map_err(|_| Error::new("bad_request", "sig is not a DER ECDSA signature"))?;
    Ok(sig.normalize_s().unwrap_or(sig).to_der().as_bytes().to_vec())
}

// ── §2.1: a root derived from a passkey ──────────────────────────────────────────────────

/// The fixed input handed to the authenticator's `prf` extension: `SHA-256("pact/vault/1")`.
///
/// Fixed, not per-credential, because a wallet arriving cold on a new device has to derive before
/// it can fetch anything — a per-credential salt would have to be fetched first, and there is
/// nothing to fetch it with. The secret is still per-credential, because the PRF is keyed by the
/// credential. The name is inherited and no longer describes anything; these are normative bytes.
pub fn prf_salt() -> [u8; 32] {
    Sha256::digest(b"pact/vault/1").into()
}

/// The three `info` strings §2.1 defines, and the only ones this will derive for.
///
/// Refusing an unknown `info` is the point rather than a restriction. The failure this whole
/// design has to engineer against is *silently deriving a different identity*, and a mistyped
/// domain separator is the cheapest way to do that — it would succeed, return 32 perfectly good
/// bytes, and produce a key belonging to nobody. There is no fourth use, so there is no cost.
pub const DERIVATION_INFOS: [&str; 3] = ["pact/root/1", "pact/store-key/1", "pact/store-id/1"];

/// §2.1: `HKDF-SHA256(ikm = prf, salt = "", info, L = 32)`.
pub fn derive_seed(prf: &[u8], info: &str) -> Result<[u8; 32]> {
    if prf.len() != 32 {
        return err("bad_request", format!("a prf output is 32 bytes, not {}", prf.len()));
    }
    if !DERIVATION_INFOS.contains(&info) {
        return err("bad_request", format!("{info} is not one of the derivation info strings of SPEC \u{a7}2.1"));
    }
    // Zeroized on the way out. These 32 bytes are the seed a wallet turns into the person's ROOT
    // (SPEC 2.1), and CONTRACT section 6's list of what this library scrubs reads as covering them; it
    // did not, because `hkdf_sha256` returned a plain `Vec` that dropped uncleared. The caller still
    // base64s the value into an answer string, which section 6 hands to the host to clear — so this is
    // defence in depth, and it makes the section true.
    let okm = Zeroizing::new(crate::hpke::hkdf_sha256(prf, &[], info.as_bytes(), 32));
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
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
        // Written in the seed library's form: RFC 5915's optional publicKey left out, so one key is
        // one byte string wherever it is written (CONTRACT §0).
        assert_eq!(&k.to_pkcs8()[..], &compact[..]);
        // Read in either form, because keys written before that was true are still keys.
        let full = from_hex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104206a261bbb098c126fe60dcc26a72045d97db5079d52cd59826220705150ad60d7a14403420004d6e652937ca86505559bc84e4936573de2d110833c4718cef004a203c054a92dcdfb5e5765ebc267dc3d241783447ba3b58cec954ea8ca5f24fdb8963dca1897").unwrap();
        assert_eq!(full.len(), 138);
        assert_eq!(PrivateKey::from_pkcs8(&full).unwrap().public().spki(), k.public().spki());
        assert_eq!(&PrivateKey::from_pkcs8(&full).unwrap().to_pkcs8()[..], &compact[..]);
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

    /// `p256` returns either twin; this library returns the low-S one, every time. Half of these
    /// were high before the rule, so forty signatures all low is not luck (2^-40).
    #[test]
    fn every_p256_signature_is_the_low_s_twin() {
        let k = PrivateKey::from_seed(Alg::P256, &seed("low-s/key")).unwrap();
        for i in 0u32..40 {
            let sig = k.sign(&i.to_be_bytes());
            assert_eq!(ecdsa_is_low_s(&sig), Some(true), "signature {i} is the high twin");
            assert!(k.public().verify(&i.to_be_bytes(), &sig));
        }
        assert_eq!(ecdsa_is_low_s(&[1, 2, 3]), None, "bytes that are not an ECDSA value are not judged");
        let ed = PrivateKey::from_seed(Alg::Ed25519, &seed("low-s/ed")).unwrap();
        assert_eq!(ecdsa_is_low_s(&ed.sign(b"x")), None);
    }
}
