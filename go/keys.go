package pactidentity

// Keys: Ed25519 and P-256, their SPKI and PKCS #8 forms, fingerprints, deterministic derivation for
// the vectors, and the conversions to X25519 that §13.1 names.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

const (
	AlgEd25519 = "ed25519"
	AlgP256    = "p256"
)

var (
	p256N, _       = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	p25519         = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	oidEd25519     = "1.3.101.112"
	oidEcPublicKey = "1.2.840.10045.2.1"
	oidPrime256v1  = "1.2.840.10045.3.1.7"
)

// PublicKey is one of the two key algorithms the profile admits, with its SPKI bytes kept as parsed.
type PublicKey struct {
	Alg  string
	Ed   ed25519.PublicKey
	EC   *ecdsa.PublicKey
	SPKI []byte
}

// unsupportedError is an algorithm the profile does not admit, answered as `unsupported` at the
// boundary, where the Rust core answers the same.
type unsupportedError struct{ why string }

func (e unsupportedError) Error() string { return e.why }

// PrivateKey is a private key as it was read: an Ed25519 seed or a P-256 scalar, and nothing derived
// from it. Reading one used to derive the public key (ed25519.NewKeyFromSeed, ecdsa.ParseRawPrivateKey:
// a scalar multiplication each, 16.1 and 14.4 us a parse, measured 2026-09-28), and the open, which
// the Go decide does after reading the held key on every call, never used it. Public() and Signer()
// derive what they are asked for; the X25519 scalar and the P-256 ECDH key come from the seed and the
// scalar directly.
type PrivateKey struct {
	Alg    string
	seed   []byte // Ed25519: the 32-byte seed
	scalar []byte // P-256: the 32-byte scalar, in [1, n-1]
}

// usable says whether a private key is one this package made: an algorithm of the profile and the
// material that algorithm has. nil, the zero value, and a key given an Alg by hand hold nothing to sign
// or open with — and each one panicked where its material was first read (T18).
func (k *PrivateKey) usable() bool {
	return k != nil && ((k.Alg == AlgEd25519 && len(k.seed) == ed25519.SeedSize) || (k.Alg == AlgP256 && len(k.scalar) == 32))
}

// usable says whether a public key is one ParseSPKI or Public made: an algorithm of the profile, its
// point and its SPKI bytes. The zero value, and one assembled by hand without them, is no key.
func (p *PublicKey) usable() bool {
	if p == nil || len(p.SPKI) == 0 {
		return false
	}
	switch p.Alg {
	case AlgEd25519:
		return len(p.Ed) == ed25519.PublicKeySize
	case AlgP256:
		return p.EC != nil && p.EC.Curve == elliptic.P256() && p.EC.X != nil && p.EC.Y != nil
	}
	return false
}

// needPrivate and needPublic are the typed API's check of a key argument, made before any field of it
// is read: `<who> is required`, as the JSON boundary names a member left out (CONTRACT §0). The core's
// typed API takes references, which cannot be nil; this port's took pointers, and a nil or zero-value
// key was a panic in every function below that reads one (T18).
func needPrivate(k *PrivateKey, who string) error {
	if !k.usable() {
		return errArg(who + " is required")
	}
	return nil
}

func needPublic(p *PublicKey, who string) error {
	if !p.usable() {
		return errArg(who + " is required")
	}
	return nil
}

// Public derives the public key, or nil for a key that is not one (see usable): it has no error to
// answer with, and a caller that can be handed such a key asks PKCS8 or SignDetached, which do. A
// caller that also signs takes a Signer and asks it for both.
func (k *PrivateKey) Public() *PublicKey {
	if !k.usable() {
		return nil
	}
	return k.Signer().Public
}

// Signer is a private key expanded for signing: its public key and its signatures from one expansion.
type Signer struct {
	Public *PublicKey
	ed     ed25519.PrivateKey
	ec     *ecdsa.PrivateKey
}

// Signer expands the key once. The key's parts were checked when it was made, so this cannot fail; a
// key that is not one (see usable) gets nil, whose Sign refuses.
func (k *PrivateKey) Signer() *Signer {
	if !k.usable() {
		return nil
	}
	if k.Alg == AlgEd25519 {
		ed := ed25519.NewKeyFromSeed(k.seed)
		pub := ed.Public().(ed25519.PublicKey)
		spki, _ := x509.MarshalPKIXPublicKey(pub)
		return &Signer{ed: ed, Public: &PublicKey{Alg: AlgEd25519, Ed: pub, SPKI: spki}}
	}
	ec, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), k.scalar)
	spki, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	return &Signer{ec: ec, Public: &PublicKey{Alg: AlgP256, EC: &ec.PublicKey, SPKI: spki}}
}

func newEd25519(seed []byte) *PrivateKey {
	return &PrivateKey{Alg: AlgEd25519, seed: append([]byte(nil), seed...)}
}

// newP256 takes a 32-byte scalar, refused outside [1, n-1] as ecdsa.ParseRawPrivateKey refused it,
// without the multiplication that call makes.
func newP256(scalar []byte) (*PrivateKey, error) {
	d := new(big.Int).SetBytes(scalar)
	if len(scalar) != 32 || d.Sign() == 0 || d.Cmp(p256N) >= 0 {
		return nil, errors.New("P-256 scalar out of range")
	}
	return &PrivateKey{Alg: AlgP256, scalar: append([]byte(nil), scalar...)}, nil
}

// B64url encodes without padding, the JSON form of every byte string in the contract.
func B64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64Index maps a byte to its six bits, or -1. Built once: `FromB64url` rebuilt it on every call.
var b64Index = func() (idx [256]int8) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		idx[alphabet[i]] = int8(i)
	}
	idx['+'], idx['/'] = 62, 63
	return idx
}()

// FromB64url decodes leniently, as Node's Buffer.from(s, 'base64url') does: characters outside the
// alphabet are skipped, padding is ignored, and a trailing partial group is dropped.
func FromB64url(s string) []byte {
	idx := &b64Index
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		v := idx[s[i]]
		if v < 0 {
			continue
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
			acc &= (1 << uint(bits)) - 1
		}
	}
	return out
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// Fingerprint is "sha256:" + base64url(SHA-256(SPKI)), applied to any key.
func Fingerprint(spki []byte) string { return "sha256:" + B64url(sha256Sum(spki)) }

// KeyID is the 32 raw bytes of the fingerprint's hash: subjectKeyIdentifier and authorityKeyIdentifier.
func KeyID(spki []byte) []byte { return sha256Sum(spki) }

// ParseSPKI reads a SubjectPublicKeyInfo of the profile: Ed25519 (RFC 8410, no parameters) or P-256,
// uncompressed. Every other algorithm is refused here, where it is read, as the Rust core refuses it:
// `unsupported key type <OID>`.
//
// It parsed with an empty Alg — and X25519 as a third algorithm — so that `profile_error` could name
// the key, as the seed's createPublicKey accepts any key OpenSSL knows. So a certificate carrying an
// RSA, P-384, X25519 or parameterised Ed25519 key was a certificate here: parse_certificate answered
// an `alg` the contract does not have, card_decode took the card, compare_leaves compared it, a
// request carrying one was refused for another reason, and a seal went to a bare X25519 key — each
// where the core refused the key (R12, T2, T3, T4). The seed refuses them where it reads them too.
func ParseSPKI(spki []byte) (*PublicKey, error) {
	n, err := derRead(spki, 0)
	if err != nil {
		return nil, err
	}
	if n.tag != 0x30 || n.end != len(spki) {
		return nil, errors.New("SubjectPublicKeyInfo is not one SEQUENCE")
	}
	parts, err := derChildren(n)
	if err != nil {
		return nil, err
	}
	if len(parts) != 2 || parts[0].tag != 0x30 || parts[1].tag != 0x03 || len(parts[1].content) < 1 || parts[1].content[0] != 0 {
		return nil, errors.New("SubjectPublicKeyInfo shape")
	}
	alg, err := derChildren(parts[0])
	if err != nil || len(alg) < 1 || alg[0].tag != 0x06 {
		return nil, errors.New("SubjectPublicKeyInfo algorithm")
	}
	key := parts[1].content[1:]
	oid, err := readOidStrict(alg[0])
	if err != nil {
		return nil, err
	}
	out := &PublicKey{SPKI: append([]byte(nil), spki...)}
	switch {
	case oid == oidEd25519 && len(alg) == 1:
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("Ed25519 key is not 32 bytes")
		}
		out.Alg = AlgEd25519
		out.Ed = ed25519.PublicKey(append([]byte(nil), key...))
	case oid == oidEcPublicKey && len(alg) == 2 && alg[1].tag == 0x06 && derOidMinimal(alg[1]) && readOid(alg[1]) == oidPrime256v1:
		// RFC 5480 §2.2 allows a compressed point; the profile takes the uncompressed form only,
		// so one key has one SubjectPublicKeyInfo and one fingerprint.
		if len(key) != 65 || key[0] != 0x04 {
			return nil, errors.New("P-256 key is not the uncompressed point")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), key)
		if err != nil {
			return nil, errors.New("P-256 key is not a point")
		}
		out.Alg = AlgP256
		out.EC = pub
	default:
		return nil, unsupportedError{"unsupported key type " + oid}
	}
	return out, nil
}

// ParsePKCS8 reads a PKCS #8 private key of either algorithm.
// The structure is read here rather than handed to encoding/x509 so that a key which will not parse
// is refused in the same words as the Rust core's reader: "PKCS #8 shape" is a different fact from
// "Ed25519 seed is not 32 bytes", and a caller debugging a key deserves to be told which — in one
// vocabulary, whichever port answers (CONTRACT §0).
func ParsePKCS8(der []byte) (*PrivateKey, error) {
	node, err := derRead(der, 0)
	if err != nil {
		return nil, err
	}
	if node.tag != 0x30 || node.end != len(der) {
		return nil, errors.New("PKCS #8 is not one SEQUENCE")
	}
	f, err := derChildren(node)
	if err != nil {
		return nil, err
	}
	if len(f) < 3 || f[0].tag != 0x02 || f[1].tag != 0x30 || f[2].tag != 0x04 {
		return nil, errors.New("PKCS #8 shape")
	}
	alg, err := derChildren(f[1])
	if err != nil {
		return nil, err
	}
	if len(alg) == 0 || alg[0].tag != 0x06 {
		return nil, errors.New("PKCS #8 algorithm")
	}
	oid, err := readOidStrict(alg[0])
	if err != nil {
		return nil, err
	}
	switch {
	// RFC 8410: an Ed25519 AlgorithmIdentifier has NO parameters. ParseSPKI has always held a public
	// key to that; a private key with a NULL after the OID was read anyway.
	case oid == oidEd25519 && len(alg) == 1:
		inner, err := derRead(f[2].content, 0)
		if err != nil {
			return nil, err
		}
		if inner.tag != 0x04 || inner.end != len(f[2].content) {
			return nil, errors.New("Ed25519 private key shape")
		}
		if len(inner.content) != 32 {
			return nil, errors.New("Ed25519 seed is not 32 bytes")
		}
		return newEd25519(inner.content), nil
	case oid == oidEcPublicKey && len(alg) == 2 && alg[1].tag == 0x06 && derOidMinimal(alg[1]) && readOid(alg[1]) == oidPrime256v1:
		ec, err := derRead(f[2].content, 0)
		if err != nil {
			return nil, err
		}
		if ec.tag != 0x30 || ec.end != len(f[2].content) {
			return nil, errors.New("ECPrivateKey shape")
		}
		g, err := derChildren(ec)
		if err != nil {
			return nil, err
		}
		if len(g) < 2 || g[0].tag != 0x02 || g[1].tag != 0x04 || len(g[1].content) > 32 || len(g[1].content) == 0 {
			return nil, errors.New("ECPrivateKey shape")
		}
		d := make([]byte, 32)
		copy(d[32-len(g[1].content):], g[1].content)
		return newP256(d)
	}
	return nil, unsupportedError{"unsupported key type " + oid}
}

// PKCS8 exports the private key in PKCS #8 DER, in the minimal form the vectors carry: Ed25519 per
// RFC 8410; P-256 as an ECPrivateKey of version 1 and the scalar alone, the curve named once in the
// algorithm identifier and the public key derived, never stored.
func (k *PrivateKey) PKCS8() ([]byte, error) {
	// The zero value wrote a 35-byte P-256 key with an empty scalar, and no error (T18).
	if err := needPrivate(k, "the key"); err != nil {
		return nil, err
	}
	if k.Alg == AlgEd25519 {
		// RFC 8410's form, the one x509.MarshalPKCS8PrivateKey writes: the seed in an OCTET STRING
		// inside the privateKey OCTET STRING.
		return seq(derIntN(0), seq(oidBytes(oidEd25519)), octet(octet(k.seed))), nil
	}
	ecKey := seq(derIntN(1), octet(k.scalar))
	return seq(derIntN(0), seq(oidBytes(oidEcPublicKey), oidBytes(oidPrime256v1)), octet(ecKey)), nil
}

// GenerateKey draws a fresh key of the algorithm.
func GenerateKey(alg string) (*PrivateKey, error) {
	switch alg {
	case AlgEd25519:
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		return newEd25519(seed), nil
	case AlgP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return newP256(priv.D.FillBytes(make([]byte, 32)))
	}
	return nil, unsupportedError{"unsupported key type " + alg}
}

// KeyFromSeed is the vectors' derivation: an Ed25519 seed used directly; a P-256 scalar of seed mod n,
// zero becoming one.
//
// The algorithm is judged before the seed, as the core's typed `from_seed` takes an `Alg` already
// parsed and the JSON boundary reads `alg` first.
func KeyFromSeed(alg string, seed []byte) (*PrivateKey, error) {
	if err := algKnown(alg); err != nil {
		return nil, err
	}
	if len(seed) != 32 {
		return nil, errArg("seed is 32 bytes")
	}
	switch alg {
	case AlgEd25519:
		return newEd25519(seed), nil
	case AlgP256:
		k := new(big.Int).SetBytes(seed)
		k.Mod(k, p256N)
		if k.Sign() == 0 {
			k.SetInt64(1)
		}
		return newP256(k.FillBytes(make([]byte, 32)))
	}
	return nil, unsupportedError{"unsupported key type " + alg}
}

// algKnown is the core's `Alg::parse`: an algorithm this profile has, or `unsupported`.
func algKnown(alg string) error {
	if alg != AlgEd25519 && alg != AlgP256 {
		return unsupportedError{"unsupported key type " + alg}
	}
	return nil
}

// AlgorithmOf names the key's algorithm: one of the profile's two, which every key ParseSPKI returns
// has. A key that is not one — nil, the zero value, one assembled by hand — is refused.
func AlgorithmOf(pub *PublicKey) (string, error) {
	if err := needPublic(pub, "the key"); err != nil {
		return "", err
	}
	return pub.Alg, nil
}

func leBytesToInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func intToLE(v *big.Int, n int) []byte {
	be := v.FillBytes(make([]byte, n))
	out := make([]byte, n)
	for i := range be {
		out[n-1-i] = be[i]
	}
	return out
}

// ed25519PublicToX25519 is RFC 7748 §4.1: u = (1 + y) / (1 - y) on the Ed25519 public key's y coordinate.
func ed25519PublicToX25519(pub ed25519.PublicKey) []byte {
	y := leBytesToInt(pub)
	y.And(y, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)))
	num := new(big.Int).Add(big.NewInt(1), y)
	den := new(big.Int).Sub(big.NewInt(1), y)
	den.Add(den, p25519)
	den.Mod(den, p25519)
	den.ModInverse(den, p25519)
	u := new(big.Int).Mul(num, den)
	u.Mod(u, p25519)
	return intToLE(u, 32)
}

// ed25519SeedToX25519 is RFC 8032 §5.1.5: the clamped low half of SHA-512(seed) is the scalar.
func ed25519SeedToX25519(seed []byte) []byte {
	h := sha512.Sum512(seed)
	a := append([]byte(nil), h[:32]...)
	return clamp(a)
}

func clamp(a []byte) []byte {
	a[0] &= 248
	a[31] &= 127
	a[31] |= 64
	return a
}

// x25519FromSeed clamps a 32-byte seed into an X25519 private key, as the vectors' ephemerals are made.
func x25519FromSeed(seed []byte) (*ecdh.PrivateKey, error) {
	a := clamp(append([]byte(nil), seed...))
	return ecdh.X25519().NewPrivateKey(a)
}

func p256Uncompressed(pub *ecdsa.PublicKey) []byte {
	b, _ := pub.Bytes()
	return b
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[2*i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				v = v<<4 | (c - 'A' + 10)
			}
		}
		out[i] = v
	}
	return out
}

// ── §2.1: a root derived from a passkey ──────────────────────────────────────────────────

// PrfSalt is the fixed input handed to the authenticator's prf extension: SHA-256("pact/vault/1").
//
// Fixed, not per-credential, because a wallet arriving cold on a new device has to derive before it
// can fetch anything — a per-credential salt would have to be fetched first, and there is nothing to
// fetch it with. The secret is still per-credential, because the PRF is keyed by the credential. The
// name is inherited and no longer describes anything; these are normative bytes.
func PrfSalt() []byte {
	h := sha256.Sum256([]byte("pact/vault/1"))
	return h[:]
}

// DerivationInfos are the three info strings of SPEC §2.1, and the only ones DeriveSeed will derive
// for. Refusing an unknown one is the point rather than a restriction: the failure this design has
// to engineer against is silently deriving a DIFFERENT identity, and a mistyped domain separator is
// the cheapest way to do it — it would succeed, return 32 perfectly good bytes, and produce a key
// belonging to nobody. There is no fourth use, so there is no cost.
var DerivationInfos = []string{"pact/root/1", "pact/store-key/1", "pact/store-id/1"}

// DeriveSeed is SPEC §2.1: HKDF-SHA256(ikm = prf, salt = "", info, L = 32). HMAC pads any key
// shorter than its block to zeros, so an empty salt and RFC 5869's "a string of HashLen zeros" are
// the same extract.
func DeriveSeed(prf []byte, info string) ([]byte, error) {
	if len(prf) != 32 {
		return nil, errArg(fmt.Sprintf("a prf output is 32 bytes, not %d", len(prf)))
	}
	if !slices.Contains(DerivationInfos, info) {
		return nil, errArg(info + " is not one of the derivation info strings of SPEC §2.1")
	}
	return hkdfExpand(hmacSHA256(nil, prf), []byte(info), 32), nil
}
