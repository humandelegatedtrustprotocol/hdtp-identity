package pactidentity

// The Certificates section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name, and the helpers only these use.

import (
	"bytes"
	"encoding/json"
	"time"
)

func callBuildRoot(args json.RawMessage) json.RawMessage {
	var a struct {
		CN        string  `json:"cn"`
		PKCS8     B64     `json:"pkcs8"`
		NotBefore *string `json:"not_before"`
		Serial    B64     `json:"serial"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	priv, err := privIn(a.PKCS8, "pkcs8")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	nb, err := timeIn(a.NotBefore, "not_before")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	serial, err := serialIn(a.Serial)
	if err != nil {
		return failErr(codeArgs, err)
	}
	der, err := BuildRoot(RootOpts{CN: a.CN, Key: priv, NotBefore: nb, Serial: serial})
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(map[string]any{"der": B64url(der), "fingerprint": Fingerprint(priv.Public.SPKI)})
}

func callRootTBS(args json.RawMessage) json.RawMessage {
	var a struct {
		CN        string  `json:"cn"`
		SPKI      B64     `json:"spki"`
		NotBefore *string `json:"not_before"`
		Serial    B64     `json:"serial"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	pub, err := pubIn(a.SPKI, "spki")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	nb, err := timeIn(a.NotBefore, "not_before")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	serial, err := serialIn(a.Serial)
	if err != nil {
		return failErr(codeArgs, err)
	}
	tbs, alg, err := RootTBS(a.CN, pub, nb, serial)
	if err != nil {
		return failErr("internal", err)
	}
	return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
}

func callBuildLeaf(args json.RawMessage) json.RawMessage {
	var a leafArgs
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	root, err := privIn(a.RootPKCS8, "root_pkcs8")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	lo, err := a.opts()
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	lo.RootKey = root
	der, err := BuildLeaf(lo)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(map[string]any{"der": B64url(der)})
}

func callLeafTBS(args json.RawMessage) json.RawMessage {
	var a leafArgs
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	rootPub, err := pubIn(a.RootSPKI, "root_spki")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	lo, err := a.opts()
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	lo.RootPub = rootPub
	tbs, alg, err := LeafTBS(lo)
	if err != nil {
		return failErr("internal", err)
	}
	return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
}

func callParseCertificate(args json.RawMessage) json.RawMessage {
	var a struct {
		DER B64 `json:"der"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.DER, "der"); err != nil {
		return failErr(codeArgs, err)
	}
	c, err := Parse(a.DER)
	if err != nil {
		return failErr("parse", err)
	}
	return ok(certOut(c))
}

func callProfileError(args json.RawMessage) json.RawMessage {
	var a struct {
		DER  B64    `json:"der"`
		Kind string `json:"kind"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.DER, "der"); err != nil {
		return failErr(codeArgs, err)
	}
	c, err := Parse(a.DER)
	if err != nil {
		return failErr("parse", err)
	}
	var e any
	if s := ProfileError(c, a.Kind); s != "" {
		e = s
	}
	return ok(map[string]any{"error": e})
}

func callValidateChain(args json.RawMessage) json.RawMessage {
	var a struct {
		Chain            []B64   `json:"chain"`
		Now              *string `json:"now"`
		ExpectedRoot     string  `json:"expected_root"`
		ExpectedEndpoint string  `json:"expected_endpoint"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if a.Chain == nil {
		return failErr(codeArgs, errArg("chain is required"))
	}
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(chainOut(ValidateChain(chainOf(a.Chain), ChainOpts{Now: now, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})))
}

func callCompareLeaves(args json.RawMessage) json.RawMessage {
	var a struct {
		Pinned    B64 `json:"pinned"`
		Presented B64 `json:"presented"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.Pinned, "pinned"); err != nil {
		return failErr(codeArgs, err)
	}
	if err := need(a.Presented, "presented"); err != nil {
		return failErr(codeArgs, err)
	}
	order, err := CompareLeaves(a.Pinned, a.Presented)
	if err != nil {
		return failErr("parse", err)
	}
	return ok(map[string]any{"order": order})
}

func callIsNormalHTTPS(args json.RawMessage) json.RawMessage {
	var a struct {
		URL *string `json:"url"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	url, err := needStr(a.URL, "url")
	if err != nil {
		return failErr(codeArgs, err)
	}
	return ok(map[string]any{"normal": IsNormalHTTPS(url)})
}

func callAddressGuard(args json.RawMessage) json.RawMessage {
	var a struct {
		Endpoint     *string `json:"endpoint"`
		SelfEndpoint string  `json:"self_endpoint"`
		Guest        bool    `json:"guest"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	endpoint, err := needStr(a.Endpoint, "endpoint")
	if err != nil {
		return failErr(codeArgs, err)
	}
	if good, why := AddressGuard(endpoint, a.SelfEndpoint, a.Guest); !good {
		return ok(map[string]any{"ok": false, "why": why})
	}
	return ok(map[string]any{"ok": true})
}

func callIPIsPrivate(args json.RawMessage) json.RawMessage {
	var a struct {
		IP *string `json:"ip"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	ip, err := needStr(a.IP, "ip")
	if err != nil {
		return failErr(codeArgs, err)
	}
	return ok(map[string]any{"private": IPIsPrivate(ip)})
}

// serialIn is §14.1's serial rule at the boundary: absent means one is made, and a serial that is
// given is 8 to 20 bytes — the width the profile fixes so a serial cannot be a channel or a
// collision. It was checked in the Rust core and not here, so this port signed a certificate with a
// four-byte serial that the other port refused to make.
func serialIn(b B64) ([]byte, error) {
	if b == nil {
		return nil, nil // BuildRoot/BuildLeaf make a random one
	}
	if len(b) < 8 || len(b) > 20 {
		return nil, errArg("serial is 8 to 20 bytes")
	}
	return b, nil
}

func chainOut(r ChainResult) map[string]any {
	if !r.OK {
		return map[string]any{"ok": false, "rule": r.Rule, "reason": r.Reason}
	}
	return map[string]any{
		"ok": true, "leaf_spki": B64url(r.LeafKey.SPKI), "leaf_fingerprint": FingerprintOf(r.Leaf),
		"root_fingerprint": r.RootFingerprint, "endpoint": r.Endpoint,
		"not_before": timeOut(r.Leaf.NotBefore), "not_after": timeOut(r.Leaf.NotAfter), "alg": r.LeafKey.Alg,
	}
}

// assemble finishes a certificate from a TBS an external signer signed: the wallet's seam for a root
// held in a card or an authenticator, where the key is never bytes here. The algorithm outside a
// certificate is the TBS's own third field, so a `sig_alg` handed back must equal it — a mismatch is
// the caller pairing the wrong signature with the wrong body, and is refused rather than assembled.
func assembleFn(args json.RawMessage) json.RawMessage {
	var a struct {
		TBS    B64 `json:"tbs"`
		Sig    B64 `json:"sig"`
		SigAlg B64 `json:"sig_alg"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.TBS, "tbs"); err != nil {
		return failErr(codeArgs, err)
	}
	// A certificate with no signature is not a certificate. This port assembled one when `sig` was
	// absent, which the Rust core refuses — and an unsigned certificate that parses is worse than one
	// that does not, because it travels before anything checks it.
	if err := need(a.Sig, "sig"); err != nil {
		return failErr(codeArgs, err)
	}
	declared, err := declaredAlg(a.TBS)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	if a.SigAlg != nil && !bytes.Equal(a.SigAlg, declared) {
		return fail(codeArgs, "sig_alg is not the algorithm the tbs declares")
	}
	return ok(map[string]any{"der": B64url(Assemble(a.TBS, declared, a.Sig))})
}

// declaredAlg is the AlgorithmIdentifier a TBSCertificate names as its own (§14.1: the algorithm
// inside and outside a certificate are the same bytes).
func declaredAlg(tbs []byte) ([]byte, error) {
	n, err := derRead(tbs, 0)
	if err != nil {
		return nil, err
	}
	f, err := derChildren(n)
	if err != nil {
		return nil, err
	}
	if len(f) < 3 {
		return nil, parseError{"tbs shape"}
	}
	return f[2].raw, nil
}

type leafArgs struct {
	CN        string  `json:"cn"`
	RootCN    string  `json:"root_cn"`
	RootPKCS8 B64     `json:"root_pkcs8"`
	RootSPKI  B64     `json:"root_spki"`
	HostSPKI  B64     `json:"host_spki"`
	Endpoint  string  `json:"endpoint"`
	DNSName   string  `json:"dns_name"`
	NotBefore *string `json:"not_before"`
	NotAfter  *string `json:"not_after"`
	Serial    B64     `json:"serial"`
}

func (a leafArgs) opts() (LeafOpts, error) {
	host, err := pubIn(a.HostSPKI, "host_spki")
	if err != nil {
		return LeafOpts{}, err
	}
	nb, err := timeIn(a.NotBefore, "not_before")
	if err != nil {
		return LeafOpts{}, err
	}
	na, err := timeIn(a.NotAfter, "not_after")
	if err != nil {
		return LeafOpts{}, err
	}
	if na.Sub(nb) > MaxLeafDays*24*time.Hour {
		return LeafOpts{}, errArg("validity over 398 days")
	}
	if !IsNormalHTTPS(a.Endpoint) {
		return LeafOpts{}, errArg("endpoint is not an https URL in normal form")
	}
	serial, err := serialIn(a.Serial)
	if err != nil {
		return LeafOpts{}, err
	}
	return LeafOpts{CN: a.CN, RootCN: a.RootCN, HostPub: host, Endpoint: a.Endpoint, DNSName: a.DNSName, NotBefore: nb, NotAfter: na, Serial: serial}, nil
}
