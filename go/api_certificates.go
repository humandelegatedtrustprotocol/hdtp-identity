package hdtpidentity

// The Certificates section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name, and the helpers only these use. Each reads its members
// as api/certificates.rs does, in its order.

import (
	"bytes"
	"encoding/json"
	"time"
)

func callBuildRoot(a args) json.RawMessage {
	priv, err := a.priv("pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	cn, err := a.str("cn")
	if err != nil {
		return failAs(codeArgs, err)
	}
	nb, err := a.instant("not_before")
	if err != nil {
		return failAs("parse", err)
	}
	serial, err := a.serial()
	if err != nil {
		return failAs(codeArgs, err)
	}
	der, err := BuildRoot(RootOpts{CN: cn, Key: priv, NotBefore: nb, Serial: serial})
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"der": B64url(der), "fingerprint": Fingerprint(priv.Public().SPKI)})
}

func callRootTBS(a args) json.RawMessage {
	cn, err := a.str("cn")
	if err != nil {
		return failAs(codeArgs, err)
	}
	pub, err := a.pub("spki")
	if err != nil {
		return failAs("parse", err)
	}
	nb, err := a.instant("not_before")
	if err != nil {
		return failAs("parse", err)
	}
	serial, err := a.serial()
	if err != nil {
		return failAs(codeArgs, err)
	}
	tbs, alg, err := RootTBS(cn, pub, nb, serial)
	if err != nil {
		return failErr("internal", err)
	}
	return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
}

func callBuildLeaf(a args) json.RawMessage {
	root, err := a.priv("root_pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	lo, err := leafSpec(a)
	if err != nil {
		return failAs("parse", err)
	}
	lo.RootKey = root
	der, err := BuildLeaf(lo)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"der": B64url(der)})
}

func callLeafTBS(a args) json.RawMessage {
	rootPub, err := a.pub("root_spki")
	if err != nil {
		return failAs("parse", err)
	}
	lo, err := leafSpec(a)
	if err != nil {
		return failAs("parse", err)
	}
	lo.RootPub = rootPub
	tbs, alg, err := LeafTBS(lo)
	if err != nil {
		return failErr("internal", err)
	}
	return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
}

func callParseCertificate(a args) json.RawMessage {
	der, err := a.bytes("der")
	if err != nil {
		return failAs(codeArgs, err)
	}
	c, err := Parse(der)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(certOut(c))
}

func callProfileError(a args) json.RawMessage {
	der, err := a.bytes("der")
	if err != nil {
		return failAs(codeArgs, err)
	}
	c, err := Parse(der)
	if err != nil {
		return failAs("parse", err)
	}
	kind, err := a.str("kind")
	if err != nil {
		return failAs(codeArgs, err)
	}
	var e any
	if s := ProfileError(c, kind); s != "" {
		e = s
	}
	return ok(map[string]any{"error": e})
}

func callValidateChain(a args) json.RawMessage {
	chain, err := a.chain("chain")
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	root, err := a.optStr("expected_root")
	if err != nil {
		return failAs(codeArgs, err)
	}
	endpoint, err := a.optStr("expected_endpoint")
	if err != nil {
		return failAs(codeArgs, err)
	}
	o := ChainOpts{Now: now}
	if root != nil {
		o.ExpectedRoot, o.rootGiven = *root, true
	}
	if endpoint != nil {
		o.ExpectedEndpoint, o.endpointGiven = *endpoint, true
	}
	return ok(chainOut(ValidateChain(chain, o)))
}

func callCompareLeaves(a args) json.RawMessage {
	pinned, err := a.bytes("pinned")
	if err != nil {
		return failAs(codeArgs, err)
	}
	presented, err := a.bytes("presented")
	if err != nil {
		return failAs(codeArgs, err)
	}
	order, err := CompareLeaves(pinned, presented)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"order": order})
}

func callIsNormalHTTPS(a args) json.RawMessage {
	url, err := a.str("url")
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"normal": IsNormalHTTPS(url)})
}

func callAddressGuard(a args) json.RawMessage {
	endpoint, err := a.str("endpoint")
	if err != nil {
		return failAs(codeArgs, err)
	}
	self, err := a.optStr("self_endpoint")
	if err != nil {
		return failAs(codeArgs, err)
	}
	guest, err := a.boolean("guest")
	if err != nil {
		return failAs(codeArgs, err)
	}
	selfEndpoint := ""
	if self != nil {
		selfEndpoint = *self
	}
	if good, why := AddressGuard(endpoint, selfEndpoint, guest); !good {
		return ok(map[string]any{"ok": false, "why": why})
	}
	return ok(map[string]any{"ok": true})
}

func callIPIsPrivate(a args) json.RawMessage {
	ip, err := a.str("ip")
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"private": IPIsPrivate(ip)})
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
// Read as the core reads it: the TBS and its algorithm, the `sig_alg` handed back, then `sig`.
func assembleFn(a args) json.RawMessage {
	tbs, err := a.bytes("tbs")
	if err != nil {
		return failAs(codeArgs, err)
	}
	declared, err := declaredAlg(tbs)
	if err != nil {
		return failAs("parse", err)
	}
	given, err := a.optBytes("sig_alg")
	if err != nil {
		return failAs("parse", err)
	}
	if given != nil && !bytes.Equal(given, declared) {
		return fail(codeArgs, "sig_alg is not the algorithm the tbs declares")
	}
	// A certificate with no signature is not a certificate. This port assembled one when `sig` was
	// absent, which the Rust core refuses — and an unsigned certificate that parses is worse than one
	// that does not, because it travels before anything checks it.
	sig, err := a.bytes("sig")
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"der": B64url(Assemble(tbs, declared, sig))})
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

// leafSpec is the core's `leaf_spec`, after the issuer's key: the host's key, the serial, the
// endpoint, the dates and their §14.1 bounds, then the names — the contract's members and no others.
func leafSpec(a args) (LeafOpts, error) {
	host, err := a.pub("host_spki")
	if err != nil {
		return LeafOpts{}, err
	}
	serial, err := a.serial()
	if err != nil {
		return LeafOpts{}, err
	}
	endpoint, err := a.str("endpoint")
	if err != nil {
		return LeafOpts{}, err
	}
	nb, err := a.instant("not_before")
	if err != nil {
		return LeafOpts{}, err
	}
	na, err := a.instant("not_after")
	if err != nil {
		return LeafOpts{}, err
	}
	if na.Sub(nb) > MaxLeafDays*24*time.Hour {
		return LeafOpts{}, errArg("validity over 398 days")
	}
	if !IsNormalHTTPS(endpoint) {
		return LeafOpts{}, errArg("endpoint is not an https URL in normal form")
	}
	cn, err := a.str("cn")
	if err != nil {
		return LeafOpts{}, err
	}
	rootCN, err := a.str("root_cn")
	if err != nil {
		return LeafOpts{}, err
	}
	dns, err := a.dnsName()
	if err != nil {
		return LeafOpts{}, err
	}
	return LeafOpts{CN: cn, RootCN: rootCN, HostPub: host, Endpoint: endpoint, DNSName: dns, NotBefore: nb, NotAfter: na, Serial: serial}, nil
}
