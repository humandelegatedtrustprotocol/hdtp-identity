package pactidentity

// PKCS #10 (RFC 2986) with a profile as exact as the certificates': version 0, one commonName, the
// host's key, one extensionRequest carrying one subjectAltName with one URI and at most one dNSName
// equal to its host, signed by the CSR's own key with that key's own algorithm — the proof of possession.

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

const oidExtensionRequest = "1.2.840.113549.1.9.14"

func csrInfo(cn string, pub *PublicKey, endpoint, dnsName string) []byte {
	san := [][]byte{implicit(6, []byte(endpoint))}
	if dnsName != "" {
		san = append(san, implicit(2, []byte(dnsName)))
	}
	extensions := seq(extension(OIDSubjectAltName, false, seq(san...)))
	attr := seq(oidBytes(oidExtensionRequest), set(extensions))
	return seq(derIntN(0), nameCN(cn), pub.SPKI, tlv(0xa0, attr))
}

// CSRNew makes a request for the endpoint, signed by the host key.
func CSRNew(cn string, host *PrivateKey, endpoint, dnsName string) ([]byte, error) {
	info := csrInfo(cn, host.Public, endpoint, dnsName)
	sig, err := SignDetached(host, info)
	if err != nil {
		return nil, err
	}
	return seq(info, sigAlgFor(host.Alg), bitstr(sig, 0)), nil
}

// CSRInfo is what a wallet learns from a request it accepted.
type CSRInfo struct {
	OK          bool
	Why         string
	CN          string
	Key         *PublicKey
	Fingerprint string
	Alg         string
	Endpoint    string
	DNSName     string
}

func csrRefuse(why string) CSRInfo { return CSRInfo{Why: why} }

// CSRCheck reads a request strictly, verifies its proof of possession, refuses a key that is a root's,
// and vets the endpoint.
func CSRCheck(der []byte, rootSPKIs [][]byte) CSRInfo {
	top, err := derRead(der, 0)
	if err != nil {
		return csrRefuse("request does not parse: " + err.Error())
	}
	if top.tag != 0x30 || top.end != len(der) {
		return csrRefuse("request does not parse: not one SEQUENCE")
	}
	parts, err := derChildren(top)
	if err != nil || len(parts) != 3 || parts[2].tag != 0x03 || len(parts[2].content) < 1 || parts[2].content[0] != 0 {
		return csrRefuse("request does not parse: request shape")
	}
	info, alg, sig := parts[0], parts[1], parts[2]
	f, err := derChildren(info)
	if err != nil || len(f) != 4 || f[0].tag != 0x02 || !bytes.Equal(f[0].content, []byte{0}) || f[3].tag != 0xa0 {
		return csrRefuse("request does not parse: request info shape")
	}
	cn, err := nameOf(f[1])
	if err != nil {
		return csrRefuse("request does not parse: " + err.Error())
	}
	pub, err := ParseSPKI(f[2].raw)
	if err != nil {
		return csrRefuse("request does not parse: " + err.Error())
	}
	if _, err := AlgorithmOf(pub); err != nil {
		return csrRefuse("key algorithm not in the profile")
	}
	attrs, err := derChildren(f[3])
	if err != nil || len(attrs) != 1 {
		return csrRefuse("request does not parse: one extensionRequest attribute expected")
	}
	attr, err := derChildren(attrs[0])
	if err != nil || len(attr) != 2 || readOid(attr[0]) != oidExtensionRequest || attr[1].tag != 0x31 {
		return csrRefuse("request does not parse: one extensionRequest attribute expected")
	}
	values, err := derChildren(attr[1])
	if err != nil || len(values) != 1 {
		return csrRefuse("request does not parse: one extensions value expected")
	}
	exts, err := derChildren(values[0])
	if err != nil || len(exts) != 1 {
		return csrRefuse("request does not parse: one subjectAltName extension expected")
	}
	ext, err := derChildren(exts[0])
	if err != nil || len(ext) != 2 || readOid(ext[0]) != OIDSubjectAltName || ext[1].tag != 0x04 {
		return csrRefuse("request does not parse: one subjectAltName extension expected")
	}
	san, err := derRead(ext[1].content, 0)
	if err != nil || san.tag != 0x30 || san.end != len(ext[1].content) {
		return csrRefuse("request does not parse: subjectAltName shape")
	}
	names, err := derChildren(san)
	if err != nil {
		return csrRefuse("request does not parse: subjectAltName shape")
	}
	var uris, dns []string
	for _, n := range names {
		switch n.tag {
		case 0x86:
			uris = append(uris, string(n.content))
		case 0x82:
			dns = append(dns, string(n.content))
		default:
			return csrRefuse("subjectAltName carries a name type the profile does not")
		}
	}
	if len(uris) != 1 || len(dns) > 1 {
		return csrRefuse(fmt.Sprintf("%d endpoints", len(uris)))
	}
	algParts, err := derChildren(alg)
	if err != nil || len(algParts) < 1 {
		return csrRefuse("request does not parse: signature algorithm")
	}
	expected := OIDEcdsaSHA256
	if pub.Alg == AlgEd25519 {
		expected = OIDEd25519
	}
	if readOid(algParts[0]) != expected || !VerifyDetached(pub, info.raw, sig.content[1:]) {
		return csrRefuse("the request's signature does not verify: no proof of possession")
	}
	for _, r := range rootSPKIs {
		if bytes.Equal(r, pub.SPKI) {
			return csrRefuse("the key is a root's: a root never becomes a leaf")
		}
	}
	endpoint := uris[0]
	if !IsNormalHTTPS(endpoint) {
		return csrRefuse("endpoint is not an https URL in normal form")
	}
	if len(dns) == 1 && dns[0] != hostOf(endpoint) {
		return csrRefuse("dNSName differs from the URI host")
	}
	if ok, why := AddressGuard(endpoint, "", false); !ok {
		return csrRefuse(why)
	}
	out := CSRInfo{OK: true, CN: cn, Key: pub, Fingerprint: Fingerprint(pub.SPKI), Alg: pub.Alg, Endpoint: endpoint}
	if len(dns) == 1 {
		out.DNSName = dns[0]
	}
	return out
}

// IssueOpts is what a wallet decides when it signs a request.
type IssueOpts struct {
	RootCN            string
	RootKey           *PrivateKey // for IssueFromCSR
	RootPub           *PublicKey  // for IssueTBSFromCSR (the seam)
	RootSPKIs         [][]byte
	Now               time.Time
	PreviousNotBefore *time.Time
	ValidDays         int
	Serial            []byte
}

// Issued is the leaf a wallet produced and the dates it chose.
type Issued struct {
	DER       []byte
	TBS, Alg  []byte
	Endpoint  string
	NotBefore time.Time
	NotAfter  time.Time
}

func issuePlan(csr []byte, o IssueOpts) (LeafOpts, CSRInfo, error) {
	info := CSRCheck(csr, o.RootSPKIs)
	if !info.OK {
		return LeafOpts{}, info, errors.New(info.Why)
	}
	days := o.ValidDays
	if days == 0 {
		days = 365
	}
	if days < 1 || days > MaxLeafDays {
		return LeafOpts{}, info, errors.New("validity must be between one and 398 days")
	}
	notBefore := o.Now.UTC().Add(-time.Hour).Truncate(time.Second)
	if o.PreviousNotBefore != nil {
		if p := o.PreviousNotBefore.UTC().Add(time.Second); p.After(notBefore) {
			notBefore = p
		}
	}
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	return LeafOpts{
		CN: info.CN, RootCN: o.RootCN, RootKey: o.RootKey, RootPub: o.RootPub, HostPub: info.Key,
		Endpoint: info.Endpoint, DNSName: info.DNSName, NotBefore: notBefore, NotAfter: notAfter, Serial: o.Serial,
	}, info, nil
}

// IssueFromCSR is CSRCheck followed by BuildLeaf under the wallet's monotonic rule.
func IssueFromCSR(csr []byte, o IssueOpts) (Issued, error) {
	lo, _, err := issuePlan(csr, o)
	if err != nil {
		return Issued{}, err
	}
	der, err := BuildLeaf(lo)
	if err != nil {
		return Issued{}, err
	}
	return Issued{DER: der, Endpoint: lo.Endpoint, NotBefore: lo.NotBefore, NotAfter: lo.NotAfter}, nil
}

// IssueTBSFromCSR is the same plan for a root that signs elsewhere.
func IssueTBSFromCSR(csr []byte, o IssueOpts) (Issued, error) {
	lo, _, err := issuePlan(csr, o)
	if err != nil {
		return Issued{}, err
	}
	tbs, alg := LeafTBS(lo)
	return Issued{TBS: tbs, Alg: alg, Endpoint: lo.Endpoint, NotBefore: lo.NotBefore, NotAfter: lo.NotAfter}, nil
}
