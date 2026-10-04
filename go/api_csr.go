package hdtpidentity

// The Certificate signing requests section of contract/contract.json: a body for each function it
// declares, which api.go's `functions` map dispatches by name, and the helpers only these use. Each
// reads its members as api/csr.rs does, in its order.

import "encoding/json"

func callCSRNew(a args) json.RawMessage {
	cn, err := a.str("cn")
	if err != nil {
		return failAs(codeArgs, err)
	}
	host, err := a.priv("host_pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	endpoint, err := a.str("endpoint")
	if err != nil {
		return failAs(codeArgs, err)
	}
	dnsName, err := a.dnsName()
	if err != nil {
		return failAs(codeArgs, err)
	}
	der, err := CSRNew(cn, host, endpoint, dnsName)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"der": B64url(der)})
}

func callCSRCheck(a args) json.RawMessage {
	der, err := a.bytes("der")
	if err != nil {
		return failAs(codeArgs, err)
	}
	roots, err := a.optChain("root_spkis")
	if err != nil {
		return failAs(codeArgs, err)
	}
	info := CSRCheck(der, roots)
	if !info.OK {
		return ok(map[string]any{"ok": false, "why": info.Why})
	}
	// An absent dNSName is null. It was "" here and null in the Rust core, so the same request
	// read two ways depending on which port answered it.
	var dns any
	if info.DNSName != "" {
		dns = info.DNSName
	}
	return ok(map[string]any{"ok": true, "cn": info.CN, "spki": B64url(info.Key.SPKI), "fingerprint": info.Fingerprint, "alg": info.Alg, "endpoint": info.Endpoint, "dns_name": dns})
}

// issueArgs is what both issue functions read after the root: the request, checked before anything
// else of it is read (csr::check, whose refusal keeps its class: bytes that do not read are `parse`),
// then `root_cn`, `now`, `previous_not_before` and `valid_days`, in the core's order (R27, T15, F3).
// issueArgs reads what both issuers share, in the core's order: `now`; `root_cert`, judged by
// IssuingRoot before anything is signed; then (for issue_from_csr) the caller reads `root_pkcs8`
// through key; then `root_spkis`, the request (checked with the issuing root added), `previous_not_before`
// and `valid_days`.
func issueArgs(a args, key func(*Cert) (*PrivateKey, json.RawMessage)) (CSRInfo, IssueOpts, json.RawMessage) {
	var o IssueOpts
	now, err := a.instant("now")
	if err != nil {
		return CSRInfo{}, o, failAs("parse", err)
	}
	o.Now = now
	der, err := a.bytes("root_cert")
	if err != nil {
		return CSRInfo{}, o, failAs(codeArgs, err)
	}
	if o.Root, err = IssuingRoot(der, now); err != nil {
		return CSRInfo{}, o, failAs("parse", err)
	}
	if key != nil {
		var bad json.RawMessage
		if o.RootKey, bad = key(o.Root); bad != nil {
			return CSRInfo{}, o, bad
		}
	}
	// §9's refusal covers the root that is signing, whether or not the caller listed it: a wallet
	// that omits `root_spkis` still cannot be talked into issuing a leaf for its own root key.
	roots, err := a.optChain("root_spkis")
	if err != nil {
		return CSRInfo{}, o, failAs(codeArgs, err)
	}
	o.RootSPKIs = append(roots, o.Root.SPKI)
	csr, err := a.bytes("csr")
	if err != nil {
		return CSRInfo{}, o, failAs(codeArgs, err)
	}
	info := CSRCheck(csr, o.RootSPKIs)
	if !info.OK {
		return info, o, failAs(codeArgs, info.err)
	}
	if o.PreviousNotBefore, err = a.optInstant("previous_not_before"); err != nil {
		return info, o, failAs("parse", err)
	}
	if o.ValidDays, err = a.validDays(); err != nil {
		return info, o, failAs(codeArgs, err)
	}
	return info, o, nil
}

// warningsOf is the `warnings` an issuer answers: the line saying a leaf ends with its root, or none.
func warningsOf(issued Issued) []string {
	if issued.EndsWithRoot {
		return []string{EndsWithRootWarning(issued.NotAfter)}
	}
	return []string{}
}

func callIssueFromCSR(a args) json.RawMessage {
	info, o, bad := issueArgs(a, func(*Cert) (*PrivateKey, json.RawMessage) {
		k, err := a.priv("root_pkcs8")
		if err != nil {
			return nil, failAs("parse", err)
		}
		return k, nil
	})
	if bad != nil {
		return bad
	}
	if err := keyOfRoot(o); err != nil {
		return failAs(codeArgs, err)
	}
	lo, ends, err := planOf(info, o)
	if err != nil {
		return failAs(codeArgs, err)
	}
	issued, err := issuedLeaf(lo, ends)
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"der": B64url(issued.DER), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter), "warnings": warningsOf(issued)})
}

func callIssueTBSFromCSR(a args) json.RawMessage {
	info, o, bad := issueArgs(a, nil)
	if bad != nil {
		return bad
	}
	lo, ends, err := planOf(info, o)
	if err != nil {
		return failAs(codeArgs, err)
	}
	issued, err := issuedTBS(lo, ends)
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"tbs": B64url(issued.TBS), "sig_alg": B64url(issued.Alg), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter), "warnings": warningsOf(issued)})
}
