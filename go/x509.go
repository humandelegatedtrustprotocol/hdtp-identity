package pactidentity

// The §14.1 profile as bytes, the exact-profile check and §14.2 chain validation, and the §14.3 comparison.

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OID constants of the profile.
const (
	OIDCommonName       = "2.5.4.3"
	OIDEd25519          = "1.3.101.112"
	OIDEcdsaSHA256      = "1.2.840.10045.4.3.2"
	OIDBasicConstraints = "2.5.29.19"
	OIDKeyUsage         = "2.5.29.15"
	OIDExtKeyUsage      = "2.5.29.37"
	OIDSubjectAltName   = "2.5.29.17"
	OIDSubjectKeyID     = "2.5.29.14"
	OIDAuthorityKeyID   = "2.5.29.35"
	OIDServerAuth       = "1.3.6.1.5.5.7.3.1"
	OIDClientAuth       = "1.3.6.1.5.5.7.3.2"
	MaxLeafDays         = 398
	MaxCertBytes        = 4096
)

var forever = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

func nameCN(cn string) []byte { return seq(set(seq(oidBytes(OIDCommonName), utf8s(cn)))) }

func sigAlgFor(alg string) []byte {
	if alg == AlgEd25519 {
		return seq(oidBytes(OIDEd25519))
	}
	return seq(oidBytes(OIDEcdsaSHA256))
}

func extension(oid string, critical bool, value []byte) []byte {
	if critical {
		return seq(oidBytes(oid), derBool(true), octet(value))
	}
	return seq(oidBytes(oid), octet(value))
}

func keyUsageBits(bits []int) []byte {
	var b byte
	for _, bit := range bits {
		b |= 0x80 >> uint(bit)
	}
	unused := 0
	for v := b; v != 0 && v&1 == 0; v >>= 1 {
		unused++
	}
	return bitstr([]byte{b}, unused)
}

// SerialOf is the vectors' serial: SHA-256("serial/" + label), first 8 bytes.
func SerialOf(label string) []byte { return sha256Sum([]byte("serial/" + label))[:8] }

// randomSerial draws eight random bytes with a non-zero first byte.
//
// The profile wants a positive serial of 64–160 bits, and derInt is now canonical — so a value
// beginning 0x00 would encode to seven significant bytes and be refused for being under 64 bits.
// Drawing again is the unbiased way to keep all eight significant; it costs one extra draw once in
// every 256 certificates.
func randomSerial() []byte {
	for {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		if b[0] != 0 {
			return b
		}
	}
}

// RootOpts builds a root certificate to the profile.
type RootOpts struct {
	CN        string
	Key       *PrivateKey
	NotBefore time.Time
	Serial    []byte
}

func rootTBS(cn string, pub *PublicKey, notBefore time.Time, serial []byte) (tbs, alg []byte) {
	if serial == nil {
		serial = randomSerial()
	}
	alg = sigAlgFor(pub.Alg)
	tbs = seq(
		explicit(0, derIntN(2)), derInt(serial), alg, nameCN(cn), seq(derTime(notBefore), derTime(forever)), nameCN(cn), pub.SPKI,
		explicit(3, seq(
			extension(OIDBasicConstraints, true, seq(derBool(true), derIntN(0))),
			extension(OIDKeyUsage, true, keyUsageBits([]int{5})),
			extension(OIDSubjectKeyID, false, octet(KeyID(pub.SPKI))),
		)),
	)
	return tbs, alg
}

// RootTBS is the external-signing seam: the bytes a root key must sign, and the algorithm identifier.
func RootTBS(cn string, pub *PublicKey, notBefore time.Time, serial []byte) (tbs []byte, alg []byte) {
	return rootTBS(cn, pub, notBefore, serial)
}

// Assemble puts a signed TBS together with its algorithm and signature into a certificate.
//
// The seam NORMALISES an ECDSA signature (SPEC 14.1): what arrives here was made outside this
// library — a PIV token, a KMS — and none of them returns the low-S twin on purpose. Swapping a
// signature for its twin needs no key, which is the whole problem, and here it is the fix. Anything
// that is not an ECDSA value passes through untouched.
func Assemble(tbs, alg, sig []byte) []byte {
	if low, isSig := EcdsaIsLowS(sig); isSig && !low {
		if twin, err := EcdsaLowS(sig); err == nil {
			sig = twin
		}
	}
	return seq(tbs, alg, bitstr(sig, 0))
}

// BuildRoot signs a root with its own key.
func BuildRoot(o RootOpts) ([]byte, error) {
	tbs, alg := rootTBS(o.CN, o.Key.Public, o.NotBefore, o.Serial)
	sig, err := SignDetached(o.Key, tbs)
	if err != nil {
		return nil, err
	}
	return Assemble(tbs, alg, sig), nil
}

// ExtraExtension is a knob for the intrusion suite: an extension a wallet never writes.
type ExtraExtension struct {
	OID      string
	Critical bool
	Value    []byte
}

// LeafOpts builds a leaf. URIs, CA, Usage, AKI, Extra and AlgOID exist so the intrusion suite can build
// what a wallet never would; a wallet sets Endpoint, DNSName and the dates.
type LeafOpts struct {
	CN, RootCN string
	RootKey    *PrivateKey // for BuildLeaf
	RootPub    *PublicKey  // for LeafTBS (the seam)
	HostPub    *PublicKey
	Endpoint   string
	URIs       []string
	DNSName    string
	NotBefore  time.Time
	NotAfter   time.Time
	Serial     []byte
	CA         bool
	Usage      []int
	AKI        []byte
	Extra      []ExtraExtension
	AlgOID     string
}

func leafTBS(o LeafOpts, rootPub *PublicKey) (tbs, alg []byte) {
	serial := o.Serial
	if serial == nil {
		serial = randomSerial()
	}
	id := KeyID(o.HostPub.SPKI)
	issuerID := o.AKI
	if issuerID == nil {
		issuerID = KeyID(rootPub.SPKI)
	}
	bits := o.Usage
	if bits == nil {
		if o.HostPub.Alg == AlgP256 {
			bits = []int{0, 4}
		} else {
			bits = []int{0}
		}
	}
	uris := o.URIs
	if uris == nil {
		uris = []string{o.Endpoint}
	}
	var san [][]byte
	for _, u := range uris {
		san = append(san, implicit(6, []byte(u)))
	}
	if o.DNSName != "" {
		san = append(san, implicit(2, []byte(o.DNSName)))
	}
	if o.AlgOID != "" {
		alg = seq(oidBytes(o.AlgOID))
	} else {
		alg = sigAlgFor(rootPub.Alg)
	}
	var bc []byte
	if o.CA {
		bc = seq(derBool(true))
	} else {
		bc = seq()
	}
	exts := [][]byte{
		extension(OIDBasicConstraints, true, bc),
		extension(OIDKeyUsage, true, keyUsageBits(bits)),
		extension(OIDExtKeyUsage, false, seq(oidBytes(OIDServerAuth), oidBytes(OIDClientAuth))),
		extension(OIDSubjectAltName, false, seq(san...)),
		extension(OIDSubjectKeyID, false, octet(id)),
		extension(OIDAuthorityKeyID, false, seq(implicit(0, issuerID))),
	}
	for _, e := range o.Extra {
		exts = append(exts, extension(e.OID, e.Critical, e.Value))
	}
	tbs = seq(
		explicit(0, derIntN(2)), derInt(serial), alg, nameCN(o.RootCN), seq(derTime(o.NotBefore), derTime(o.NotAfter)), nameCN(o.CN), o.HostPub.SPKI,
		explicit(3, seq(exts...)),
	)
	return tbs, alg
}

// LeafTBS is the seam for a leaf: what the root must sign, from the root's public key alone.
func LeafTBS(o LeafOpts) (tbs, alg []byte) { return leafTBS(o, o.RootPub) }

// BuildLeaf issues a leaf under the root key.
func BuildLeaf(o LeafOpts) ([]byte, error) {
	tbs, alg := leafTBS(o, o.RootKey.Public)
	sig, err := SignDetached(o.RootKey, tbs)
	if err != nil {
		return nil, err
	}
	return Assemble(tbs, alg, sig), nil
}

// Cert is a certificate read back into the fields the rules need.
type Cert struct {
	DER, TBS, Sig   []byte
	SigAlg          string
	Serial          []byte
	Issuer, Subject string
	NotBefore       time.Time
	NotAfter        time.Time
	TimeTags        [2]byte
	SPKI            []byte
	PublicKey       *PublicKey
	KeyID           []byte
	Extensions      []extInfo
	CA              bool
	PathLen         *int
	KeyUsage        []int
	EKU             []string
	URIs, DNS       []string
	OtherNames      int
	SKI, AKI        []byte
	AKIExtra        bool
}

type extInfo struct {
	ID       string
	Critical bool
}

func nameOf(n derNode) (string, error) {
	rdns, err := derChildren(n)
	if err != nil {
		return "", err
	}
	if len(rdns) != 1 {
		return "", errors.New("name is not one RDN")
	}
	atvs, err := derChildren(rdns[0])
	if err != nil {
		return "", err
	}
	if len(atvs) != 1 {
		return "", errors.New("RDN is not one attribute")
	}
	parts, err := derChildren(atvs[0])
	if err != nil {
		return "", err
	}
	// The length FIRST, because `parts[0]` on an empty slice panics — and an empty ATV SEQUENCE
	// (`30 00`) is six bytes an attacker sends. Rust puts the same test first in a short-circuiting
	// `||` (x509.rs `name_of`), which is why only this port could be reached; `Decide` walks here
	// through `ValidateChain` -> `Parse` before any signature is verified, so it took no credential.
	if len(parts) < 2 {
		return "", errors.New("name is not a UTF-8 commonName")
	}
	cnOid, err := readOidStrict(parts[0])
	if err != nil {
		return "", err
	}
	if cnOid != OIDCommonName || parts[1].tag != 0x0c {
		return "", errors.New("name is not a UTF-8 commonName")
	}
	return string(parts[1].content), nil
}

// Parse reads a certificate. It errors on anything malformed, with the seed's messages.
func Parse(der []byte) (*Cert, error) {
	cert, err := derRead(der, 0)
	if err != nil {
		return nil, err
	}
	if cert.tag != 0x30 || cert.end != len(der) {
		return nil, errors.New("not one SEQUENCE")
	}
	top, err := derChildren(cert)
	if err != nil {
		return nil, err
	}
	if len(top) != 3 || top[2].tag != 0x03 || len(top[2].content) < 1 || top[2].content[0] != 0 {
		return nil, errors.New("certificate shape")
	}
	tbs, alg, sig := top[0], top[1], top[2]
	f, err := derChildren(tbs)
	if err != nil {
		return nil, err
	}
	if len(f) != 8 || f[0].tag != 0xa0 || f[7].tag != 0xa3 {
		return nil, errors.New("not a v3 certificate with extensions")
	}
	// version [0] EXPLICIT INTEGER 2, exactly: one minimal INTEGER whose value is 2.
	ver, err := derChildren(f[0])
	if err != nil || len(ver) != 1 || ver[0].tag != 0x02 || !bytes.Equal(ver[0].content, []byte{2}) {
		return nil, errors.New("not a v3 certificate with extensions")
	}
	if !derIntMinimal(f[1].content) {
		return nil, errors.New("INTEGER not minimal")
	}
	algParts, err := derChildren(alg)
	if err != nil || len(algParts) != 1 || algParts[0].tag != 0x06 {
		return nil, errors.New("certificate shape")
	}
	// RFC 5280 §4.1.1.2: the algorithm inside the TBS and the one outside are the same field twice.
	if !bytes.Equal(f[2].raw, alg.raw) {
		return nil, errors.New("signature algorithm inside and outside differ")
	}
	validity, err := derChildren(f[4])
	if err != nil || len(validity) != 2 {
		return nil, errors.New("time not in the DER form")
	}
	notBefore, err := readTime(validity[0])
	if err != nil {
		return nil, err
	}
	notAfter, err := readTime(validity[1])
	if err != nil {
		return nil, err
	}
	issuer, err := nameOf(f[3])
	if err != nil {
		return nil, err
	}
	subject, err := nameOf(f[5])
	if err != nil {
		return nil, err
	}
	pub, err := ParseSPKI(f[6].raw)
	if err != nil {
		return nil, err
	}
	sigAlgOid, err := readOidStrict(algParts[0])
	if err != nil {
		return nil, err
	}
	out := &Cert{
		DER: der, TBS: tbs.raw, SigAlg: sigAlgOid, Sig: sig.content[1:],
		Serial: f[1].content, Issuer: issuer, Subject: subject,
		NotBefore: notBefore, NotAfter: notAfter, TimeTags: [2]byte{validity[0].tag, validity[1].tag},
		SPKI: f[6].raw, PublicKey: pub, KeyID: sha256Sum(f[6].raw),
	}
	extWrap, err := derChildren(f[7])
	if err != nil || len(extWrap) < 1 {
		return nil, errors.New("certificate shape")
	}
	exts, err := derChildren(extWrap[0])
	if err != nil {
		return nil, err
	}
	for _, e := range exts {
		parts, err := derChildren(e)
		if err != nil {
			return nil, err
		}
		// Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }:
		// two or three parts; a critical BOOLEAN present is TRUE and encoded as 0xFF (DER never
		// encodes the default); the OCTET STRING holds exactly one TLV.
		if len(parts) < 2 || len(parts) > 3 || parts[0].tag != 0x06 || parts[len(parts)-1].tag != 0x04 {
			return nil, errors.New("certificate shape")
		}
		if !derOidMinimal(parts[0]) {
			return nil, errors.New("OID not in the DER form")
		}
		critical := false
		if len(parts) == 3 {
			if !derBoolTrue(parts[1]) {
				return nil, errors.New("BOOLEAN not in the DER form")
			}
			critical = true
		}
		id, err := readOidStrict(parts[0])
		if err != nil {
			return nil, err
		}
		octets := parts[len(parts)-1].content
		value, err := derRead(octets, 0)
		if err != nil {
			return nil, err
		}
		if value.end != len(octets) {
			return nil, errors.New("extension value has trailing bytes")
		}
		out.Extensions = append(out.Extensions, extInfo{ID: id, Critical: critical})
		switch id {
		case OIDBasicConstraints:
			c, err := derChildren(value)
			if err != nil {
				return nil, err
			}
			if len(c) > 0 && c[0].tag == 0x01 {
				// cA BOOLEAN DEFAULT FALSE: present means TRUE, and TRUE is 0xFF.
				if !derBoolTrue(c[0]) {
					return nil, errors.New("BOOLEAN not in the DER form")
				}
				out.CA = true
			}
			if len(c) > 0 && c[len(c)-1].tag == 0x02 {
				pl := c[len(c)-1].content
				if !derIntMinimal(pl) || len(pl) > 8 {
					return nil, errors.New("INTEGER not minimal")
				}
				v := 0
				for _, b := range pl {
					v = v<<8 | int(b)
				}
				out.PathLen = &v
			}
		case OIDKeyUsage:
			// BIT STRING: the first byte says how many trailing bits of the last byte are unused;
			// every named bit of every byte counts, so a second byte (decipherOnly) is seen.
			if len(value.content) < 1 || !derNamedBitsOK(value.content) {
				return nil, errors.New("BIT STRING not in the DER form")
			}
			unused := int(value.content[0])
			bits := value.content[1:]
			total := len(bits)*8 - unused
			for i := 0; i < total; i++ {
				if bits[i/8]&(0x80>>uint(i%8)) != 0 {
					out.KeyUsage = append(out.KeyUsage, i)
				}
			}
		case OIDExtKeyUsage:
			c, err := derChildren(value)
			if err != nil {
				return nil, err
			}
			for _, o := range c {
				eku, err := readOidStrict(o)
				if err != nil {
					return nil, err
				}
				out.EKU = append(out.EKU, eku)
			}
		case OIDSubjectAltName:
			c, err := derChildren(value)
			if err != nil {
				return nil, err
			}
			for _, n := range c {
				switch n.tag {
				case 0x86:
					out.URIs = append(out.URIs, string(n.content))
				case 0x82:
					out.DNS = append(out.DNS, string(n.content))
				default:
					out.OtherNames++
				}
			}
		case OIDSubjectKeyID:
			out.SKI = value.content
		case OIDAuthorityKeyID:
			c, err := derChildren(value)
			if err != nil {
				return nil, err
			}
			for _, x := range c {
				if x.tag == 0x80 && out.AKI == nil {
					out.AKI = x.content
				}
			}
			out.AKIExtra = len(c) != 1
		}
	}
	return out, nil
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortedStrings(a []string) []string {
	out := append([]string(nil), a...)
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func timeTagFor(t time.Time) byte {
	if t.UTC().Year() < 2050 {
		return 0x17
	}
	return 0x18
}

// ProfileError is §14.1 exactly: every field, every extension and its criticality, nothing else.
// It returns "" for a certificate on the profile; the strings are the seed's.
func ProfileError(c *Cert, kind string) string {
	if len(c.DER) > MaxCertBytes {
		return "over 4 KiB"
	}
	if len(c.Serial) < 8 || len(c.Serial) > 20 || c.Serial[0]&0x80 != 0 {
		return "serial not 64–160 bits positive"
	}
	if c.SigAlg != OIDEd25519 && c.SigAlg != OIDEcdsaSHA256 {
		return "signature algorithm not in the profile"
	}
	// SPEC 14.1: of an ECDSA signature's two twins, only the low-S one is a PACT certificate. Judged
	// only where the bits ARE an ECDSA value (see EcdsaIsLowS).
	if c.SigAlg == OIDEcdsaSHA256 {
		if low, isSig := EcdsaIsLowS(c.Sig); isSig && !low {
			return "ECDSA signature not in the low-S form"
		}
	}
	// The ADMITTED set, not the excluded one. This asked `AlgorithmOf`, which errors only on an
	// EMPTY `Alg` — and `ParseSPKI` sets `Alg = AlgX25519` for OID 1.3.101.110, so an X25519-keyed
	// leaf was inside the profile to this port and outside it to Rust (x509.rs: an explicit X25519
	// refusal). The node pins on this verdict, so it would pin a chain the wallet and the cloud
	// both refuse, leaving the peer stuck rather than cleanly rejected.
	if c.PublicKey == nil || (c.PublicKey.Alg != AlgEd25519 && c.PublicKey.Alg != AlgP256) {
		return "key algorithm not in the profile"
	}
	if c.TimeTags[0] != timeTagFor(c.NotBefore) || c.TimeTags[1] != timeTagFor(c.NotAfter) {
		return "time encoding not per RFC 5280"
	}
	if c.SKI == nil || !bytes.Equal(c.SKI, c.KeyID) {
		return "subject key identifier is not the key"
	}
	ids := make([]string, 0, len(c.Extensions))
	seen := map[string]bool{}
	crit := map[string]bool{}
	for _, e := range c.Extensions {
		ids = append(ids, e.ID)
		if seen[e.ID] {
			return "duplicate extension"
		}
		seen[e.ID] = true
		crit[e.ID] = e.Critical
	}
	if kind == "root" {
		if !sameStrings(sortedStrings(ids), sortedStrings([]string{OIDBasicConstraints, OIDKeyUsage, OIDSubjectKeyID})) {
			return "root extensions are not exactly the profile"
		}
		if !crit[OIDBasicConstraints] || !c.CA || c.PathLen == nil || *c.PathLen != 0 {
			return "root basicConstraints"
		}
		if !crit[OIDKeyUsage] || !sameInts(c.KeyUsage, []int{5}) {
			return "root keyUsage is not keyCertSign alone"
		}
		if crit[OIDSubjectKeyID] || c.Issuer != c.Subject {
			return "root identity"
		}
		if !c.NotAfter.Equal(forever) {
			return "root notAfter is not 9999-12-31"
		}
		return ""
	}
	if !sameStrings(sortedStrings(ids), sortedStrings([]string{OIDBasicConstraints, OIDKeyUsage, OIDExtKeyUsage, OIDSubjectAltName, OIDSubjectKeyID, OIDAuthorityKeyID})) {
		return "leaf extensions are not exactly the profile"
	}
	if !crit[OIDBasicConstraints] || c.CA || c.PathLen != nil {
		return "leaf basicConstraints"
	}
	expected := []int{0}
	if c.PublicKey.Alg == AlgP256 {
		expected = []int{0, 4}
	}
	if !crit[OIDKeyUsage] || !sameInts(c.KeyUsage, expected) {
		return "leaf keyUsage"
	}
	if crit[OIDExtKeyUsage] || !sameStrings(sortedStrings(c.EKU), sortedStrings([]string{OIDServerAuth, OIDClientAuth})) {
		return "leaf extendedKeyUsage"
	}
	if crit[OIDSubjectAltName] || c.OtherNames > 0 || len(c.DNS) > 1 {
		return "leaf subjectAltName carries a name type the profile does not"
	}
	if crit[OIDAuthorityKeyID] || c.AKI == nil || c.AKIExtra {
		return "leaf authorityKeyIdentifier is not a key identifier alone"
	}
	return ""
}

// verifyCert: the signature algorithm the certificate declares must be the issuer key's own; a verifier
// never picks the algorithm from the certificate, so a mismatch is simply a certificate the key did not sign.
func verifyCert(c *Cert, issuer *PublicKey) bool {
	expected := OIDEcdsaSHA256
	if issuer.Alg == AlgEd25519 {
		expected = OIDEd25519
	}
	return c.SigAlg == expected && VerifyDetached(issuer, c.TBS, c.Sig)
}

// FingerprintOf is the certificate key's fingerprint.
func FingerprintOf(c *Cert) string { return "sha256:" + B64url(c.KeyID) }

// ChainOpts are what a verifier already knows about the chain in question.
type ChainOpts struct {
	Now              time.Time
	ExpectedRoot     string
	ExpectedEndpoint string
}

// ChainResult is the verdict of ValidateChain: accepted with the proven facts, or refused by a rule.
type ChainResult struct {
	OK              bool
	Rule            int
	Reason          string
	Leaf, Root      *Cert
	LeafKey         *PublicKey
	RootFingerprint string
	Endpoint        string
}

func refuse(rule int, reason string) ChainResult { return ChainResult{Rule: rule, Reason: reason} }

// ValidateChain is §14.2, refusing at the first failure and naming the rule.
func ValidateChain(chain [][]byte, o ChainOpts) ChainResult {
	if len(chain) != 2 {
		return refuse(1, fmt.Sprintf("chain of %d", len(chain)))
	}
	leaf, err := Parse(chain[0])
	if err != nil {
		return refuse(1, err.Error())
	}
	root, err := Parse(chain[1])
	if err != nil {
		return refuse(1, err.Error())
	}
	bad := ProfileError(leaf, "leaf")
	if bad == "" {
		bad = ProfileError(root, "root")
	}
	if bad != "" {
		return refuse(1, bad)
	}
	if !verifyCert(root, root.PublicKey) {
		return refuse(2, "root is not self-signed")
	}
	rootFingerprint := FingerprintOf(root)
	if o.ExpectedRoot != "" && o.ExpectedRoot != rootFingerprint {
		return refuse(2, "root is not the one expected")
	}
	if !verifyCert(leaf, root.PublicKey) {
		return refuse(3, "leaf is not signed by the root")
	}
	if !bytes.Equal(leaf.AKI, root.KeyID) {
		return refuse(3, "authority key identifier is not the root")
	}
	if o.Now.Before(leaf.NotBefore) || o.Now.After(leaf.NotAfter) {
		return refuse(4, "leaf outside its validity")
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > MaxLeafDays*24*time.Hour {
		return refuse(4, "leaf longer than 398 days")
	}
	if len(leaf.URIs) != 1 {
		return refuse(5, fmt.Sprintf("%d URIs", len(leaf.URIs)))
	}
	endpoint := leaf.URIs[0]
	if !IsNormalHTTPS(endpoint) {
		return refuse(5, "endpoint is not an https URL in normal form")
	}
	if o.ExpectedEndpoint != "" && o.ExpectedEndpoint != endpoint {
		return refuse(5, "endpoint differs from the one in question")
	}
	host := hostOf(endpoint)
	for _, d := range leaf.DNS {
		if d != host {
			return refuse(5, "dNSName differs from the URI host")
		}
	}
	return ChainResult{OK: true, Leaf: leaf, Root: root, LeafKey: leaf.PublicKey, RootFingerprint: rootFingerprint, Endpoint: endpoint}
}

// hostOf returns the authority of a URL already in normal form (no userinfo, no port).
func hostOf(endpoint string) string {
	rest := strings.TrimPrefix(endpoint, "https://")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// IsNormalHTTPS is the normal form of §14.1: what the string must already be, so nothing is normalised
// at comparison time — https, lowercase host, no userinfo, port, query or fragment, a non-empty path
// with no trailing slash, no dot segments, and percent-encoding uppercase and minimal.
func IsNormalHTTPS(s string) bool {
	if !strings.HasPrefix(s, "https://") {
		return false
	}
	rest := s[len("https://"):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return false
	}
	host, path := rest[:slash], rest[slash:]
	if !normalHost(host) {
		return false
	}
	if len(path) < 2 || strings.HasSuffix(path, "/") {
		return false
	}
	for _, seg := range strings.Split(path[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0:
		case c == '%':
			if i+2 >= len(path) || !isUpperHex(path[i+1]) || !isUpperHex(path[i+2]) {
				return false
			}
			if isUnreservedEncoded(path[i+1], path[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

func isUpperHex(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') }

func isUnreservedEncoded(h, l byte) bool {
	v := mustHex(string([]byte{h, l}))[0]
	return (v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z') || (v >= '0' && v <= '9') || strings.IndexByte("-._~", v) >= 0
}

// normalPort accepts a port as RFC 3986 normal form writes one: digits with no leading zero, in
// range, and never the scheme's default (443), which the normal form omits.
func normalPort(p string) bool {
	if p == "" || len(p) > 5 || p[0] == '0' || p == "443" {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
	}
	return n >= 1 && n <= 65535
}

func normalHost(h string) bool {
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return false
		}
		if rest := h[end+1:]; rest != "" {
			if rest[0] != ':' || !normalPort(rest[1:]) {
				return false
			}
		}
		ip := parseIP(h[1:end])
		return ip.IsValid() && ip.Is6() && !ip.Is4In6() && ip.String() == h[1:end]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		if !normalPort(h[i+1:]) {
			return false
		}
		h = h[:i]
	}
	if strings.ContainsAny(h, ":@") {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	labels := strings.Split(h, ".")
	last := labels[len(labels)-1]
	// The WHATWG "ends in a number" rule: a last label that is all digits, or 0x followed by hex
	// digits, makes the host an IPv4 address to a URL parser — so only the canonical dotted quad
	// is the normal form, and 127.1, 2130706433, 0x7f000001 and 0177.0.0.1 are refused.
	numeric := last != ""
	if strings.HasPrefix(last, "0x") {
		for i := 2; i < len(last); i++ {
			if !((last[i] >= '0' && last[i] <= '9') || (last[i] >= 'a' && last[i] <= 'f')) {
				numeric = false
			}
		}
	} else {
		for i := 0; i < len(last); i++ {
			if last[i] < '0' || last[i] > '9' {
				numeric = false
			}
		}
	}
	if numeric {
		// A host whose last label is a number is an IPv4 address to a URL parser, and only its
		// canonical dotted-quad form is the normal form.
		ip := parseIP(h)
		return ip.IsValid() && ip.Is4() && ip.String() == h
	}
	return true
}

// CompareLeaves is §14.3: which of two leaves under one root is current. A later notBefore wins the
// instant it is seen, whatever the validity of the older leaf.
func CompareLeaves(pinned, presented []byte) (string, error) {
	a, err := Parse(pinned)
	if err != nil {
		return "", err
	}
	b, err := Parse(presented)
	if err != nil {
		return "", err
	}
	switch {
	case b.NotBefore.Before(a.NotBefore):
		return "superseded", nil
	case b.NotBefore.After(a.NotBefore):
		return "newer", nil
	case bytes.Equal(a.DER, b.DER):
		return "same", nil
	}
	return "conflict", nil
}
