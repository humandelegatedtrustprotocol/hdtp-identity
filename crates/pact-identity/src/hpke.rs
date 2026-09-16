//! HPKE Base mode (RFC 9180) for the two PACT suites, exactly as `hpke.mjs` composes it.
use crate::keys::{Alg, PrivateKey, PublicKey};
use crate::util::{err, Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    P256,
    X25519,
}

impl Suite {
    pub const fn id(self) -> &'static str {
        match self {
            Suite::P256 => "PACT-SEAL-P256",
            Suite::X25519 => "PACT-SEAL-X25519",
        }
    }
    pub fn parse(s: &str) -> Option<Suite> {
        match s {
            "PACT-SEAL-P256" => Some(Suite::P256),
            "PACT-SEAL-X25519" => Some(Suite::X25519),
            _ => None,
        }
    }
    /// The encapsulated key's length (RFC 9180 §7.1's `Npk`): an uncompressed P-256 point, or an
    /// X25519 key. §13.1 pins it so `enc` has one length per suite and the signature over
    /// `protected ‖ enc ‖ ct` cannot be read with the boundary in a second place.
    pub const fn npk(self) -> usize {
        match self {
            Suite::P256 => 65,
            Suite::X25519 => 32,
        }
    }
    fn kem(self) -> u16 {
        match self {
            Suite::P256 => 0x0010,
            Suite::X25519 => 0x0020,
        }
    }
    fn aead(self) -> u16 {
        match self {
            Suite::P256 => 0x0001,
            Suite::X25519 => 0x0003,
        }
    }
    fn nk(self) -> usize {
        match self {
            Suite::P256 => 16,
            Suite::X25519 => 32,
        }
    }
    const KDF: u16 = 0x0001;
    const NN: usize = 12;
    const NSECRET: usize = 32;
}

/// Which suite a recipient key needs (§13.1): its curve's.
pub fn suite_for(key: &PublicKey) -> Suite {
    if key.alg() == Alg::P256 { Suite::P256 } else { Suite::X25519 }
}

fn i2osp2(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    Zeroizing::new(m.finalize().into_bytes().to_vec())
}

// The chaining buffers carry key material; they are zeroized on drop.
fn expand(prk: &[u8], info: &[u8], l: usize) -> Vec<u8> {
    let mut t: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut okm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut i = 1u8;
    while okm.len() < l {
        let mut data = Zeroizing::new(t.to_vec());
        data.extend_from_slice(info);
        data.push(i);
        t = hmac(prk, &data);
        okm.extend_from_slice(&t);
        i = i.wrapping_add(1);
    }
    okm.truncate(l);
    okm.to_vec()
}

/// RFC 5869 HKDF-SHA256, plain — not the labelled form the rest of this module composes. §2.1
/// derives a wallet's keys with it, over an EMPTY salt: `HMAC` pads any key shorter than the block
/// to zeros, so an empty salt and RFC 5869's "a string of HashLen zeros" are the same extract, and
/// Node's `hkdfSync` with a zero-length salt agrees byte for byte. The vectors prove it.
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], l: usize) -> Vec<u8> {
    expand(&hmac(salt, ikm), info, l)
}

const V: &[u8] = b"HPKE-v1";

fn labeled_extract(id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut data = Zeroizing::new(V.to_vec());
    data.extend_from_slice(id);
    data.extend_from_slice(label.as_bytes());
    data.extend_from_slice(ikm);
    hmac(salt, &data)
}

fn labeled_expand(id: &[u8], prk: &[u8], label: &str, info: &[u8], l: usize) -> Vec<u8> {
    let mut data = i2osp2(l as u16).to_vec();
    data.extend_from_slice(V);
    data.extend_from_slice(id);
    data.extend_from_slice(label.as_bytes());
    data.extend_from_slice(info);
    expand(prk, &data, l)
}

fn key_schedule(s: Suite, shared_secret: &[u8], info: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let mut id = b"HPKE".to_vec();
    id.extend_from_slice(&i2osp2(s.kem()));
    id.extend_from_slice(&i2osp2(Suite::KDF));
    id.extend_from_slice(&i2osp2(s.aead()));
    let mut ksc = vec![0u8];
    ksc.extend_from_slice(&labeled_extract(&id, &[], "psk_id_hash", &[]));
    ksc.extend_from_slice(&labeled_extract(&id, &[], "info_hash", info));
    let secret = labeled_extract(&id, shared_secret, "secret", &[]);
    (Zeroizing::new(labeled_expand(&id, &secret, "key", &ksc, s.nk())), Zeroizing::new(labeled_expand(&id, &secret, "base_nonce", &ksc, Suite::NN)))
}

fn shared_secret(s: Suite, dh: &[u8], kem_context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if dh.iter().all(|&b| b == 0) {
        return err("internal", "all-zero DH output: low-order point");
    }
    let mut id = b"KEM".to_vec();
    id.extend_from_slice(&i2osp2(s.kem()));
    let eae_prk = labeled_extract(&id, &[], "eae_prk", dh);
    Ok(Zeroizing::new(labeled_expand(&id, &eae_prk, "shared_secret", kem_context, Suite::NSECRET)))
}

fn recipient_public(suite: Suite, key: &PublicKey) -> Result<Vec<u8>> {
    match suite {
        Suite::P256 => key.p256_uncompressed(),
        Suite::X25519 => Ok(key.x25519()?.to_vec()),
    }
}

fn encap(suite: Suite, key: &PublicKey, seed: &[u8; 32]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let pk_r = recipient_public(suite, key)?;
    match suite {
        Suite::P256 => {
            let e = PrivateKey::from_seed(Alg::P256, seed)?;
            let sk = e.p256()?;
            let enc = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
            let dh = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), key.p256()?.as_affine());
            let mut ctx = enc.clone();
            ctx.extend_from_slice(&pk_r);
            Ok((enc, shared_secret(suite, dh.raw_secret_bytes(), &ctx)?))
        }
        Suite::X25519 => {
            let e = x25519_dalek::StaticSecret::from(*seed);
            let enc = x25519_dalek::PublicKey::from(&e).to_bytes().to_vec();
            let pk: [u8; 32] = pk_r.as_slice().try_into().map_err(|_| Error::new("key", "X25519 key is not 32 bytes"))?;
            let dh = e.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
            let mut ctx = enc.clone();
            ctx.extend_from_slice(&pk_r);
            Ok((enc, shared_secret(suite, dh.as_bytes(), &ctx)?))
        }
    }
}

fn decap(suite: Suite, key: &PrivateKey, enc: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let pk_r = recipient_public(suite, &key.public())?;
    let mut ctx = enc.to_vec();
    ctx.extend_from_slice(&pk_r);
    match suite {
        Suite::P256 => {
            let sk = key.p256()?;
            if enc.len() != 65 || enc[0] != 0x04 {
                return err("internal", "encapsulated key is not the uncompressed P-256 point");
            }
            let point = p256::PublicKey::from_sec1_bytes(enc).map_err(|_| Error::new("internal", "encapsulated key is not a P-256 point"))?;
            let dh = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), point.as_affine());
            shared_secret(suite, dh.raw_secret_bytes(), &ctx)
        }
        Suite::X25519 => {
            let sk = key.x25519()?;
            let e: [u8; 32] = enc.try_into().map_err(|_| Error::new("internal", "encapsulated key is not 32 bytes"))?;
            let dh = sk.diffie_hellman(&x25519_dalek::PublicKey::from(e));
            shared_secret(suite, dh.as_bytes(), &ctx)
        }
    }
}

fn aead_seal(s: Suite, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let payload = Payload { msg: plaintext, aad };
    let out = match s {
        Suite::P256 => aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| Error::new("internal", "key length"))?.encrypt(nonce.into(), payload),
        Suite::X25519 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::new("internal", "key length"))?.encrypt(nonce.into(), payload),
    };
    out.map_err(|_| Error::new("internal", "AEAD failure"))
}

fn aead_open(s: Suite, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let payload = Payload { msg: ct, aad };
    let out = match s {
        Suite::P256 => aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| Error::new("internal", "key length"))?.decrypt(nonce.into(), payload),
        Suite::X25519 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::new("internal", "key length"))?.decrypt(nonce.into(), payload),
    };
    out.map_err(|_| Error::new("envelope_invalid", "does not open"))
}

/// Seals to `recipient`. Production draws a fresh ephemeral every time: a reused ephemeral repeats
/// the key and the nonce, and two ciphertexts under them leak the XOR of their plaintexts. A seed
/// exists only for vectors and for demonstrating that leak.
pub fn seal(suite: Suite, recipient: &PublicKey, info: &[u8], aad: &[u8], plaintext: &[u8], seed: Option<[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let seed = match seed {
        Some(s) => Zeroizing::new(s),
        None => Zeroizing::new(crate::util::random(32)?.try_into().map_err(|_| Error::new("internal", "randomness"))?),
    };
    let (enc, ss) = encap(suite, recipient, &seed)?;
    let (key, nonce) = key_schedule(suite, &ss, info);
    let ct = aead_seal(suite, &key, &nonce, aad, plaintext)?;
    Ok((enc, ct))
}

pub fn open(suite: Suite, recipient: &PrivateKey, info: &[u8], aad: &[u8], enc: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if ct.len() < 16 {
        return err("envelope_invalid", "does not open");
    }
    let ss = decap(suite, recipient, enc).map_err(|_| Error::new("envelope_invalid", "does not open"))?;
    let (key, nonce) = key_schedule(suite, &ss, info);
    aead_open(suite, &key, &nonce, aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::seed as label_seed;

    #[test]
    fn round_trips_both_suites() {
        for (alg, suite) in [(Alg::Ed25519, Suite::X25519), (Alg::P256, Suite::P256)] {
            let r = PrivateKey::from_seed(alg, &label_seed("t/r")).unwrap();
            assert_eq!(suite_for(&r.public()), suite);
            let (enc, ct) = seal(suite, &r.public(), b"PACT-SEAL-v2", b"aad", b"hello", None).unwrap();
            assert_eq!(open(suite, &r, b"PACT-SEAL-v2", b"aad", &enc, &ct).unwrap(), b"hello");
            assert!(open(suite, &r, b"PACT-SEAL-v1", b"aad", &enc, &ct).is_err());
            let (enc2, _) = seal(suite, &r.public(), b"PACT-SEAL-v2", b"aad", b"hello", None).unwrap();
            assert_ne!(enc, enc2);
        }
    }

    #[test]
    fn refuses_a_low_order_point() {
        let zero = PublicKey::from_spki(&crate::keys::x25519_spki(&[0u8; 32])).unwrap();
        assert!(seal(Suite::X25519, &zero, b"i", b"", b"x", None).is_err());
    }
}
