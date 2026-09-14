package pactidentity

// HPKE Base mode (RFC 9180) for the two PACT suites, and the detached signature of §13.1.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SuiteP256   = "PACT-SEAL-P256"
	SuiteX25519 = "PACT-SEAL-X25519"
	InfoV2      = "PACT-SEAL-v2"
	InfoV1      = "PACT-SEAL-v1"
)

type suite struct {
	kem, kdf, aead  uint16
	nk, nn, nsecret int
	chacha          bool
}

var suites = map[string]suite{
	SuiteP256:   {kem: 0x0010, kdf: 0x0001, aead: 0x0001, nk: 16, nn: 12, nsecret: 32},
	SuiteX25519: {kem: 0x0020, kdf: 0x0001, aead: 0x0003, nk: 32, nn: 12, nsecret: 32, chacha: true},
}

// SuiteKnown reports whether a suite id is one of the two.
func SuiteKnown(id string) bool { _, ok := suites[id]; return ok }

var hpkeVersion = []byte("HPKE-v1")

func i2osp2(n int) []byte { return []byte{byte(n >> 8), byte(n & 0xff)} }

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, l int) []byte {
	var t, okm []byte
	for i := 1; len(okm) < l; i++ {
		t = hmacSHA256(prk, concat(t, info, []byte{byte(i)}))
		okm = append(okm, t...)
	}
	return okm[:l]
}

func labeledExtract(id, salt []byte, label string, ikm []byte) []byte {
	return hmacSHA256(salt, concat(hpkeVersion, id, []byte(label), ikm))
}

func labeledExpand(id, prk []byte, label string, info []byte, l int) []byte {
	return hkdfExpand(prk, concat(i2osp2(l), hpkeVersion, id, []byte(label), info), l)
}

func keySchedule(s suite, sharedSecret, info []byte) (key, nonce []byte) {
	id := concat([]byte("HPKE"), i2osp2(int(s.kem)), i2osp2(int(s.kdf)), i2osp2(int(s.aead)))
	ksc := concat([]byte{0}, labeledExtract(id, nil, "psk_id_hash", nil), labeledExtract(id, nil, "info_hash", info))
	secret := labeledExtract(id, sharedSecret, "secret", nil)
	return labeledExpand(id, secret, "key", ksc, s.nk), labeledExpand(id, secret, "base_nonce", ksc, s.nn)
}

func sharedSecret(s suite, dh, kemContext []byte) ([]byte, error) {
	zero := true
	for _, b := range dh {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, errors.New("all-zero DH output: low-order point")
	}
	id := concat([]byte("KEM"), i2osp2(int(s.kem)))
	return labeledExpand(id, labeledExtract(id, nil, "eae_prk", dh), "shared_secret", kemContext, s.nsecret), nil
}

// SuiteForKey is §13.1: the suite a recipient key takes is its curve's.
func SuiteForKey(pub *PublicKey) (string, error) {
	alg, err := AlgorithmOf(pub)
	if err != nil {
		return "", err
	}
	if alg == AlgP256 {
		return SuiteP256, nil
	}
	return SuiteX25519, nil
}

// recipientPublic is the KEM public key bytes for a leaf key: the uncompressed P-256 point, or the
// Ed25519 key mapped to X25519.
func recipientPublic(id string, pub *PublicKey) ([]byte, error) {
	if id == SuiteP256 {
		if pub.EC == nil {
			return nil, errors.New("suite does not fit the key")
		}
		return p256Uncompressed(pub.EC), nil
	}
	if pub.Ed == nil {
		return nil, errors.New("suite does not fit the key")
	}
	return ed25519PublicToX25519(pub.Ed), nil
}

func encap(id string, pub *PublicKey, seed []byte) (enc, ss []byte, err error) {
	s := suites[id]
	pkR, err := recipientPublic(id, pub)
	if err != nil {
		return nil, nil, err
	}
	if id == SuiteP256 {
		ek, err := KeyFromSeed(AlgP256, seed)
		if err != nil {
			return nil, nil, err
		}
		e, err := ek.EC.ECDH()
		if err != nil {
			return nil, nil, err
		}
		r, err := ecdh.P256().NewPublicKey(pkR)
		if err != nil {
			return nil, nil, err
		}
		dh, err := e.ECDH(r)
		if err != nil {
			return nil, nil, err
		}
		enc = e.PublicKey().Bytes()
		ss, err = sharedSecret(s, dh, concat(enc, pkR))
		return enc, ss, err
	}
	e, err := x25519FromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	r, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	dh, err := e.ECDH(r)
	if err != nil {
		return nil, nil, errors.New("all-zero DH output: low-order point")
	}
	enc = e.PublicKey().Bytes()
	ss, err = sharedSecret(s, dh, concat(enc, pkR))
	return enc, ss, err
}

func decap(id string, priv *PrivateKey, enc []byte) ([]byte, error) {
	s := suites[id]
	pkR, err := recipientPublic(id, priv.Public)
	if err != nil {
		return nil, err
	}
	if id == SuiteP256 {
		sk, err := priv.EC.ECDH()
		if err != nil {
			return nil, err
		}
		e, err := ecdh.P256().NewPublicKey(enc)
		if err != nil {
			return nil, errors.New("enc is not a P-256 point")
		}
		dh, err := sk.ECDH(e)
		if err != nil {
			return nil, err
		}
		return sharedSecret(s, dh, concat(enc, pkR))
	}
	sk, err := ecdh.X25519().NewPrivateKey(ed25519PrivateToX25519(priv.Ed))
	if err != nil {
		return nil, err
	}
	e, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, errors.New("enc is not 32 bytes")
	}
	dh, err := sk.ECDH(e)
	if err != nil {
		return nil, errors.New("all-zero DH output: low-order point")
	}
	return sharedSecret(s, dh, concat(enc, pkR))
}

func aead(s suite, key []byte) (cipher.AEAD, error) {
	if s.chacha {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealWith(id string, pub *PublicKey, info, aad, plaintext, seed []byte) (enc, ct []byte, err error) {
	s, ok := suites[id]
	if !ok {
		return nil, nil, errors.New("unknown suite")
	}
	enc, ss, err := encap(id, pub, seed)
	if err != nil {
		return nil, nil, err
	}
	key, nonce := keySchedule(s, ss, info)
	c, err := aead(s, key)
	if err != nil {
		return nil, nil, err
	}
	return enc, c.Seal(nil, nonce, plaintext, aad), nil
}

// Seal draws a fresh ephemeral every time. A reused ephemeral repeats the key and the nonce, and two
// ciphertexts under them leak the XOR of their plaintexts — so no seed can be passed here.
func Seal(id string, pub *PublicKey, info, aad, plaintext []byte) (enc, ct []byte, err error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return sealWith(id, pub, info, aad, plaintext, seed)
}

// Open is the recipient side.
func Open(id string, priv *PrivateKey, info, aad, enc, ct []byte) ([]byte, error) {
	s, ok := suites[id]
	if !ok {
		return nil, errors.New("unknown suite")
	}
	ss, err := decap(id, priv, enc)
	if err != nil {
		return nil, err
	}
	key, nonce := keySchedule(s, ss, info)
	c, err := aead(s, key)
	if err != nil {
		return nil, err
	}
	pt, err := c.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("does not open")
	}
	return pt, nil
}

// SignDetached is §13.1: Ed25519 pure, or ECDSA P-256/SHA-256 in DER, by the signer's own algorithm.
func SignDetached(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv.Alg == AlgEd25519 {
		return ed25519.Sign(priv.Ed, data), nil
	}
	h := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, priv.EC, h[:])
}

// VerifyDetached checks a detached signature under the key's own algorithm.
func VerifyDetached(pub *PublicKey, data, sig []byte) bool {
	switch pub.Alg {
	case AlgEd25519:
		// crypto/ed25519 accepts a public key or an R of small order; the Rust core's verify_strict
		// refuses them, and so does this port, so a chain reads the same in both.
		if len(sig) != ed25519.SignatureSize || !ed25519PointOK(pub.Ed) || !ed25519PointOK(sig[:32]) {
			return false
		}
		return ed25519.Verify(pub.Ed, data, sig)
	case AlgP256:
		h := sha256.Sum256(data)
		return ecdsa.VerifyASN1(pub.EC, h[:], sig)
	}
	return false
}
