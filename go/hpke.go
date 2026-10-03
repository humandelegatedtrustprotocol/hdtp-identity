package hdtpidentity

// HPKE Base mode (RFC 9180) for the two HDTP suites, and the detached signature of §13.1.

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
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SuiteP256   = "HDTP-SEAL-P256"
	SuiteX25519 = "HDTP-SEAL-X25519"
	Info        = "HDTP-SEAL-v1"
)

type suite struct {
	kem, kdf, aead  uint16
	nk, nn, nsecret int
	// npk is the encapsulated key's length (RFC 9180 §7.1): an uncompressed P-256 point, or an
	// X25519 key. §13.1 pins it so `enc` has one length per suite and the signature over
	// `protected ‖ enc ‖ ct` cannot be read with the boundary in a second place.
	npk    int
	chacha bool
}

var suites = map[string]suite{
	SuiteP256:   {kem: 0x0010, kdf: 0x0001, aead: 0x0001, nk: 16, nn: 12, nsecret: 32, npk: 65},
	SuiteX25519: {kem: 0x0020, kdf: 0x0001, aead: 0x0003, nk: 32, nn: 12, nsecret: 32, npk: 32, chacha: true},
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
// Ed25519 key mapped to X25519. A suite that is not the key's is the envelope's refusal, in the
// envelope layer's words, as the core's `recipient_public` answers it (F6, R14).
func recipientPublic(id string, pub *PublicKey) ([]byte, error) {
	switch {
	case id == SuiteP256 && pub.Alg == AlgP256 && pub.EC != nil:
		return p256Uncompressed(pub.EC), nil
	case id == SuiteX25519 && pub.Alg == AlgEd25519 && len(pub.Ed) == ed25519.PublicKeySize:
		return ed25519PublicToX25519(pub.Ed), nil
	}
	return nil, errors.New("suite does not fit the key")
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
		e, err := ecdh.P256().NewPrivateKey(ek.scalar)
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

// decap takes the recipient's public key as the host holds it in its leaf, as the Rust core does
// (hpke.rs): it goes into the KEM context, and a key that is not the private key's gives another
// context, another AEAD key, and an open that fails.
//
// The private key must be the suite's own algorithm, and is asked before its material is read: a
// P-256 key has no seed, and under HDTP-SEAL-X25519 the empty seed's scalar — SHA-512 of nothing,
// clamped, a public constant — stood in for one. So any P-256 key opened a seal addressed to the
// Ed25519 key whose X25519 form is that constant times the base point: an admit (T5), where the core's
// `key.x25519()` refuses a P-256 key. It panicked in 0.4.0; 0.4.1 removed the panic, not the cause.
func decap(id string, priv *PrivateKey, pub *PublicKey, enc []byte) ([]byte, error) {
	s := suites[id]
	if (id == SuiteP256 && priv.Alg != AlgP256) || (id == SuiteX25519 && priv.Alg != AlgEd25519) {
		return nil, errors.New("the key is not the suite's")
	}
	pkR, err := recipientPublic(id, pub)
	if err != nil {
		return nil, err
	}
	if id == SuiteP256 {
		sk, err := ecdh.P256().NewPrivateKey(priv.scalar)
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
	sk, err := ecdh.X25519().NewPrivateKey(ed25519SeedToX25519(priv.seed))
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
	if err := needPublic(pub, "the recipient's public key"); err != nil {
		return nil, nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return sealWith(id, pub, info, aad, plaintext, seed)
}

// Open is the recipient side: priv is the recipient's key and pub its public key, from its leaf.
func Open(id string, priv *PrivateKey, pub *PublicKey, info, aad, enc, ct []byte) ([]byte, error) {
	// A caller's mistake, named, before anything: a nil key was a panic in 0.4.0 (dereferenced in
	// decap), and a zero-value one still was. The Rust API's types cannot be nil; the JSON boundary of
	// both ports names the member.
	if err := needPrivate(priv, "the recipient's key"); err != nil {
		return nil, err
	}
	if err := needPublic(pub, "the recipient's public key"); err != nil {
		return nil, err
	}
	s, ok := suites[id]
	if !ok {
		return nil, errors.New("unknown suite")
	}
	// Every way an open can fail is one answer. Which step failed — an `enc` of the wrong length, a
	// point off the curve, a low-order point, the tag — is a fact about the recipient's key that an
	// attacker gets to probe for free, and it is what the Rust core refuses to say. This port said
	// all four, differently.
	ss, err := decap(id, priv, pub, enc)
	if err != nil {
		return nil, errors.New("does not open")
	}
	key, nonce := keySchedule(s, ss, info)
	c, err := aead(s, key)
	if err != nil {
		return nil, errors.New("does not open")
	}
	pt, err := c.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("does not open")
	}
	return pt, nil
}

// SignDetached is §13.1: Ed25519 pure, or ECDSA P-256/SHA-256 in DER, by the signer's own algorithm.
func SignDetached(priv *PrivateKey, data []byte) ([]byte, error) {
	if err := needPrivate(priv, "the signer's key"); err != nil {
		return nil, err
	}
	return priv.Signer().Sign(data)
}

// Sign is SignDetached with the key already expanded. A Signer that is none — nil, as Signer answers
// for a key that is not one, or the zero value — refuses.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	if s == nil || (s.ed == nil && s.ec == nil) {
		return nil, errArg("the signer's key is required")
	}
	if s.ed != nil {
		return ed25519.Sign(s.ed, data), nil
	}
	h := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, s.ec, h[:])
	if err != nil {
		return nil, err
	}
	// The low-S twin, always (SPEC 14.1): crypto/ecdsa returns either, and a certificate carrying
	// the high one is outside the profile.
	return EcdsaLowS(sig)
}

// p256HalfN is the floor half of the P-256 group order (p256N, keys.go): the low-S bound.
var p256HalfN = new(big.Int).Rsh(p256N, 1)

// ecdsaSigParts reads a DER ECDSA-Sig-Value strictly: SEQUENCE { INTEGER r, INTEGER s }, both
// minimal, nothing after. ok is false when the bytes are not one.
func ecdsaSigParts(sig []byte) (r, s *big.Int, ok bool) {
	outer, err := derRead(sig, 0)
	if err != nil || outer.tag != 0x30 || outer.end != len(sig) {
		return nil, nil, false
	}
	parts, err := derChildren(outer)
	if err != nil || len(parts) != 2 {
		return nil, nil, false
	}
	for _, p := range parts {
		if p.tag != 0x02 || !derIntMinimal(p.content) {
			return nil, nil, false
		}
	}
	return new(big.Int).SetBytes(parts[0].content), new(big.Int).SetBytes(parts[1].content), true
}

// EcdsaIsLowS reports whether a DER ECDSA signature over P-256 is the low-S twin. isSig is false
// when the bytes are not an ECDSA value at all — which is not a refusal: a certificate declaring
// ECDSA over such bytes cannot verify under any key, and rule 3 refuses it for that.
//
// An ECDSA signature (r, s) has a twin (r, n - s) that verifies under the same key over the same
// bytes, and anybody can compute it. On a CERTIFICATE that is a second byte string for one leaf,
// which CompareLeaves reads as a conflict — so a card altered in transit pins a leaf the real host
// can never match. SPEC 14.1 admits one twin.
func EcdsaIsLowS(sig []byte) (low, isSig bool) {
	_, s, ok := ecdsaSigParts(sig)
	if !ok {
		return false, false
	}
	return s.Cmp(p256HalfN) <= 0, true
}

// EcdsaLowS is the same signature as its low-S twin: unchanged if it already is one.
func EcdsaLowS(sig []byte) ([]byte, error) {
	r, s, ok := ecdsaSigParts(sig)
	if !ok {
		return nil, errors.New("sig is not a DER ECDSA signature")
	}
	if s.Cmp(p256HalfN) <= 0 {
		return sig, nil
	}
	return seq(derInt(r.Bytes()), derInt(new(big.Int).Sub(p256N, s).Bytes())), nil
}

// VerifyDetached checks a detached signature under the key's own algorithm.
func VerifyDetached(pub *PublicKey, data, sig []byte) bool {
	// A key that is not one verifies nothing; it panicked here (T18).
	if !pub.usable() {
		return false
	}
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

// SuiteNpk is the encapsulated key's one length for a suite, or 0 when the suite is unknown.
func SuiteNpk(suite string) int { return suites[suite].npk }
