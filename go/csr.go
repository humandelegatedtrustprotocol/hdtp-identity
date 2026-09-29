package pactidentity

// PKCS #10 (RFC 2986) with a profile as exact as the certificates': version 0, one commonName, the
// host's key, one extensionRequest carrying one subjectAltName with one URI and at most one dNSName
// equal to its host, signed by the CSR's own key with that key's own algorithm — the proof of possession.

import (
	"bytes"
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
	signer := host.Signer()
	info := csrInfo(cn, signer.Public, endpoint, dnsName)
	sig, err := signer.Sign(info)
	if err != nil {
		return nil, err
	}
	return seq(info, sigAlgFor(host.Alg), bitstr(sig, 0)), nil
}

// csrNameOf is `csr.rs`'s `x509_name`: one RDN, one attribute, EXACTLY two elements — the commonName
// OID and a UTF8String. The certificate reader's `nameOf` takes "at least two", which is its own
// question; a request is held to the builder's shape because a wallet is about to sign it.
func csrNameOf(node derNode) (string, error) {
	const shape = "request is not in the profile"
	rdns, err := derChildren(node)
	if err != nil {
		return "", err
	}
	if len(rdns) != 1 {
		return "", errArg(shape)
	}
	atvs, err := derChildren(rdns[0])
	if err != nil {
		return "", err
	}
	if len(atvs) != 1 {
		return "", errArg(shape)
	}
	parts, err := derChildren(atvs[0])
	if err != nil {
		return "", err
	}
	if len(parts) != 2 {
		return "", errArg(shape)
	}
	cnOid, err := readOidStrict(parts[0])
	if err != nil {
		return "", err
	}
	if cnOid != OIDCommonName || parts[1].tag != 0x0c {
		return "", errArg(shape)
	}
	return string(parts[1].content), nil
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
	// err is the refusal with its class, for the functions that answer it as a failure of the call
	// (issue_from_csr): a request whose bytes do not read is `parse`, as the core's csr::check
	// propagates its DER reader's error; one that reads and is refused is `bad_request`.
	err error
}

func csrRefuse(why string) CSRInfo { return CSRInfo{Why: why, err: errArg(why)} }

// csrFail is a request refused by a reader: its own error, and `parse` where it names no class.
func csrFail(err error) CSRInfo {
	if codeFor(err, "") == "" {
		err = parseError{err.Error()}
	}
	return CSRInfo{Why: err.Error(), err: err}
}

// CSRCheck reads a request strictly, verifies its proof of possession, refuses a key that is a root's,
// and vets the endpoint.
func CSRCheck(der []byte, rootSPKIs [][]byte) CSRInfo {
	top, err := derRead(der, 0)
	if err != nil {
		return csrFail(err)
	}
	if top.tag != 0x30 || top.end != len(der) {
		return csrRefuse("request is not in the profile")
	}
	// From here to the algorithm, this is `csr.rs`'s `parse` line for line: where it propagates the
	// DER reader's error this does, and where it answers "not in the profile" this does. It was
	// looser in three places a request could reach — the two parts of the CertificationRequest were
	// never required to be SEQUENCEs, a commonName attribute could carry a third element, and the
	// signatureAlgorithm could carry parameters — and a request is what a HOST hands a WALLET to
	// sign, so laxer than the other port is the wrong direction for the port that issues.
	const shape = "request is not in the profile"
	parts, err := derChildren(top)
	if err != nil {
		return csrFail(err)
	}
	if len(parts) != 3 || parts[0].tag != 0x30 || parts[1].tag != 0x30 || parts[2].tag != 0x03 || len(parts[2].content) < 1 || parts[2].content[0] != 0 {
		return csrRefuse(shape)
	}
	info, alg, sig := parts[0], parts[1], parts[2]
	f, err := derChildren(info)
	if err != nil {
		return csrFail(err)
	}
	if len(f) != 4 || f[0].tag != 0x02 || !bytes.Equal(f[0].content, []byte{0}) || f[1].tag != 0x30 || f[2].tag != 0x30 || f[3].tag != 0xa0 {
		return csrRefuse(shape)
	}
	cn, err := csrNameOf(f[1])
	if err != nil {
		return csrFail(err)
	}
	pub, err := ParseSPKI(f[2].raw)
	if err != nil {
		return csrFail(err)
	}
	attrs, err := derChildren(f[3])
	if err != nil {
		return csrFail(err)
	}
	if len(attrs) != 1 || attrs[0].tag != 0x30 {
		return csrRefuse(shape)
	}
	attr, err := derChildren(attrs[0])
	if err != nil {
		return csrFail(err)
	}
	if len(attr) != 2 {
		return csrRefuse(shape)
	}
	attrOid, err := readOidStrict(attr[0])
	if err != nil {
		return csrFail(err)
	}
	if attrOid != oidExtensionRequest || attr[1].tag != 0x31 {
		return csrRefuse(shape)
	}
	values, err := derChildren(attr[1])
	if err != nil {
		return csrFail(err)
	}
	if len(values) != 1 || values[0].tag != 0x30 {
		return csrRefuse(shape)
	}
	exts, err := derChildren(values[0])
	if err != nil {
		return csrFail(err)
	}
	if len(exts) != 1 || exts[0].tag != 0x30 {
		return csrRefuse(shape)
	}
	ext, err := derChildren(exts[0])
	if err != nil {
		return csrFail(err)
	}
	if len(ext) != 2 {
		return csrRefuse(shape)
	}
	extOid, err := readOidStrict(ext[0])
	if err != nil {
		return csrFail(err)
	}
	if extOid != OIDSubjectAltName || ext[1].tag != 0x04 {
		return csrRefuse(shape)
	}
	san, err := derRead(ext[1].content, 0)
	if err != nil {
		return csrFail(err)
	}
	if san.tag != 0x30 || san.end != len(ext[1].content) {
		return csrRefuse(shape)
	}
	names, err := derChildren(san)
	if err != nil {
		return csrFail(err)
	}
	var uris, dns []string
	for _, n := range names {
		switch {
		case n.tag == 0x86 && len(uris) == 0:
			uris = append(uris, string(n.content))
		case n.tag == 0x82 && len(dns) == 0:
			dns = append(dns, string(n.content))
		default:
			return csrRefuse(shape)
		}
	}
	if len(uris) != 1 {
		return csrRefuse(shape)
	}
	algParts, err := derChildren(alg)
	if err != nil {
		return csrFail(err)
	}
	if len(algParts) != 1 {
		return csrRefuse(shape)
	}
	csrAlgOid, err := readOidStrict(algParts[0])
	if err != nil {
		return csrFail(err)
	}
	// …and only now, with the whole request read, the questions `csr.rs`'s `check` asks, in its order.
	// A key outside the profile was refused where it was read (ParseSPKI), as the core refuses it.
	expected := OIDEcdsaSHA256
	if pub.Alg == AlgEd25519 {
		expected = OIDEd25519
	}
	if csrAlgOid != expected || !VerifyDetached(pub, info.raw, sig.content[1:]) {
		return csrRefuse("the request's signature does not verify: no proof of possession")
	}
	id := KeyID(pub.SPKI)
	for _, r := range rootSPKIs {
		if bytes.Equal(r, pub.SPKI) || bytes.Equal(sha256Sum(r), id) {
			return csrRefuse("the request's key is a root")
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

func issuePlan(csr []byte, o IssueOpts) (LeafOpts, error) {
	info := CSRCheck(csr, o.RootSPKIs)
	if !info.OK {
		return LeafOpts{}, info.err
	}
	return planOf(info, o)
}

// planOf is the leaf a checked request is issued as, under the wallet's monotonic rule.
func planOf(info CSRInfo, o IssueOpts) (LeafOpts, error) {
	days := o.ValidDays
	if days == 0 {
		days = 365 // a Go caller that omits the field takes the default; the JSON boundary refuses an explicit 0
	}
	if days < 1 || days > MaxLeafDays {
		return LeafOpts{}, errArg("validity must be between one and 398 days")
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
	}, nil
}

// IssueFromCSR is CSRCheck followed by BuildLeaf under the wallet's monotonic rule.
func IssueFromCSR(csr []byte, o IssueOpts) (Issued, error) {
	lo, err := issuePlan(csr, o)
	if err != nil {
		return Issued{}, err
	}
	return issuedLeaf(lo)
}

func issuedLeaf(lo LeafOpts) (Issued, error) {
	der, err := BuildLeaf(lo)
	if err != nil {
		return Issued{}, err
	}
	return Issued{DER: der, Endpoint: lo.Endpoint, NotBefore: lo.NotBefore, NotAfter: lo.NotAfter}, nil
}

// IssueTBSFromCSR is the same plan for a root that signs elsewhere.
func IssueTBSFromCSR(csr []byte, o IssueOpts) (Issued, error) {
	lo, err := issuePlan(csr, o)
	if err != nil {
		return Issued{}, err
	}
	return issuedTBS(lo)
}

func issuedTBS(lo LeafOpts) (Issued, error) {
	tbs, alg, err := LeafTBS(lo)
	if err != nil {
		return Issued{}, err
	}
	return Issued{TBS: tbs, Alg: alg, Endpoint: lo.Endpoint, NotBefore: lo.NotBefore, NotAfter: lo.NotAfter}, nil
}
