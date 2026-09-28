package pactidentity

// The Certificate signing requests section of contract/contract.json: a body for each function it
// declares, which api.go's `functions` map dispatches by name, and the helpers only these use.

import "encoding/json"

func callCSRNew(args json.RawMessage) json.RawMessage {
	var a struct {
		CN        *string `json:"cn"`
		HostPKCS8 B64     `json:"host_pkcs8"`
		Endpoint  *string `json:"endpoint"`
		DNSName   string  `json:"dns_name"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	cn, err := needStr(a.CN, "cn")
	if err != nil {
		return failErr(codeArgs, err)
	}
	host, err := privIn(a.HostPKCS8, "host_pkcs8")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	endpoint, err := needStr(a.Endpoint, "endpoint")
	if err != nil {
		return failErr(codeArgs, err)
	}
	der, err := CSRNew(cn, host, endpoint, a.DNSName)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(map[string]any{"der": B64url(der)})
}

func callCSRCheck(args json.RawMessage) json.RawMessage {
	var a struct {
		DER       B64   `json:"der"`
		RootSPKIs []B64 `json:"root_spkis"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.DER, "der"); err != nil {
		return failErr(codeArgs, err)
	}
	info := CSRCheck(a.DER, chainOf(a.RootSPKIs))
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

func callIssueFromCSR(args json.RawMessage) json.RawMessage {
	var a issueArgs
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	root, err := privIn(a.RootPKCS8, "root_pkcs8")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	o, err := a.opts()
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	// §9's refusal covers the root that is signing, whether or not the caller listed it: a wallet
	// that omits `root_spkis` still cannot be talked into issuing a leaf for its own root key.
	o.RootKey = root
	o.RootSPKIs = append(o.RootSPKIs, root.Public().SPKI)
	issued, err := IssueFromCSR(a.CSR, o)
	if err != nil {
		return failErr("bad_request", err)
	}
	return ok(map[string]any{"der": B64url(issued.DER), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter)})
}

func callIssueTBSFromCSR(args json.RawMessage) json.RawMessage {
	var a issueArgs
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	rootPub, err := pubIn(a.RootSPKI, "root_spki")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	o, err := a.opts()
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	o.RootPub = rootPub
	o.RootSPKIs = append(o.RootSPKIs, rootPub.SPKI)
	issued, err := IssueTBSFromCSR(a.CSR, o)
	if err != nil {
		return failErr("bad_request", err)
	}
	return ok(map[string]any{"tbs": B64url(issued.TBS), "sig_alg": B64url(issued.Alg), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter)})
}

type issueArgs struct {
	CSR               B64     `json:"csr"`
	RootCN            string  `json:"root_cn"`
	RootPKCS8         B64     `json:"root_pkcs8"`
	RootSPKI          B64     `json:"root_spki"`
	RootSPKIs         []B64   `json:"root_spkis"`
	Now               *string `json:"now"`
	PreviousNotBefore *string `json:"previous_not_before"`
	// A pointer so an absent member takes the default and an explicit 0 is refused, as in Rust.
	ValidDays *int `json:"valid_days"`
}

func (a issueArgs) opts() (IssueOpts, error) {
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return IssueOpts{}, err
	}
	days, err := daysOr(a.ValidDays)
	if err != nil {
		return IssueOpts{}, err
	}
	o := IssueOpts{RootCN: a.RootCN, RootSPKIs: chainOf(a.RootSPKIs), Now: now, ValidDays: days}
	if a.PreviousNotBefore != nil {
		p, err := timeIn(a.PreviousNotBefore, "previous_not_before")
		if err != nil {
			return IssueOpts{}, err
		}
		o.PreviousNotBefore = &p
	}
	return o, nil
}
