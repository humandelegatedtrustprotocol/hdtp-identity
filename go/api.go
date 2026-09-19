package pactidentity

// Call is the one boundary every home of the library presents: a function name and a JSON object in,
// one JSON object out, never a panic. The names and shapes are CONTRACT.md's.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The port's own identity, answered by `version`. The spec version is the one thing here that must
// track the Rust core; the module version is this port's.
const (
	ModuleVersion = "0.1.0"
	SpecVersion   = "2.1.0"
)

type apiError struct {
	Error string `json:"error"`
	Why   string `json:"why"`
}

func fail(code, why string) json.RawMessage {
	b, _ := json.Marshal(apiError{Error: code, Why: why})
	return b
}

func failErr(code string, err error) json.RawMessage { return fail(code, err.Error()) }

func ok(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return fail("internal", err.Error())
	}
	return b
}

func timeOut(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The default validity belongs to the boundary: an absent member means a year, and an explicit zero
// is refused, as the Rust core refuses it. (A Go caller of the library passes a real number or
// omits the field, which its struct cannot tell from zero — hence the pointer here.)
func daysOr(v *int) (int, error) {
	if v == nil {
		return 365, nil
	}
	if *v < 1 || *v > MaxLeafDays {
		return 0, errArg("validity must be between one and 398 days")
	}
	return *v, nil
}

func timeIn(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("an instant is required")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, errors.New("not an RFC 3339 instant: " + s)
	}
	return t, nil
}

// A caller's arguments that will not read are a caller mistake, so they answer `bad_request` here
// and in the Rust core alike (CONTRACT §0: the same names, the same shapes, the same codes).
const codeArgs = "bad_request"

// An argument that is missing or of the wrong shape is a caller mistake; bytes that will not decode
// are a parse failure. Both ports answer the same way, so a caller reads one contract (CONTRACT §0).
type argError struct{ why string }

func (e argError) Error() string { return e.why }

func errArg(why string) error { return argError{why} }

// codeFor names an error as CONTRACT §0 names it, wherever it was raised.
func codeFor(err error, fallback string) string {
	var a argError
	if errors.As(err, &a) {
		return codeArgs
	}
	var p parseError
	if errors.As(err, &p) {
		return "parse"
	}
	var u unsupportedError
	if errors.As(err, &u) {
		return "unsupported"
	}
	var v vaultError
	if errors.As(err, &v) {
		return "vault"
	}
	return fallback
}

func decodeArgs(args json.RawMessage, into any) error {
	if len(args) == 0 {
		args = []byte("{}")
	}
	return json.Unmarshal(args, into)
}

// privIn and pubIn take the member's own name so an absent key is reported the way the caller wrote
// it — `host_pkcs8 is required`, not `pkcs8 is required`, when that is the member that is missing.
// Absent is `== nil` (see b64.go): a member present as "" is not missing, it is bytes that will not
// parse, and the parser says so, as the Rust core does.
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

func privIn(der B64, name string) (*PrivateKey, error) {
	if der == nil {
		return nil, errArg(name + " is required")
	}
	return ParsePKCS8(der)
}

func pubIn(spki B64, name string) (*PublicKey, error) {
	if spki == nil {
		return nil, errArg(name + " is required")
	}
	pub, err := ParseSPKI(spki)
	if err != nil {
		return nil, err
	}
	if _, err := AlgorithmOf(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// need is the same rule for a member the function reads directly rather than through a key parser.
func need(b B64, name string) error {
	if b == nil {
		return errArg(name + " is required")
	}
	return nil
}

// needStr is the same rule for a string member: absent (nil) is a caller's mistake that names it.
func needStr(s *string, name string) (string, error) {
	if s == nil {
		return "", errArg(name + " is required")
	}
	return *s, nil
}

// chainIn decodes a list of base64url members the way the wire does, for a test or a caller holding
// strings rather than the boundary's B64. The boundary itself decodes strictly (b64.go).
func chainIn(chain []string) [][]byte {
	out := make([][]byte, 0, len(chain))
	for _, c := range chain {
		out = append(out, FromB64url(c))
	}
	return out
}

func keyOut(priv *PrivateKey) (map[string]any, error) {
	pkcs8, err := priv.PKCS8()
	if err != nil {
		return nil, err
	}
	return map[string]any{"alg": priv.Alg, "pkcs8": B64url(pkcs8), "spki": B64url(priv.Public.SPKI), "fingerprint": Fingerprint(priv.Public.SPKI)}, nil
}

func certOut(c *Cert) map[string]any {
	kind := "other"
	if ProfileError(c, "root") == "" {
		kind = "root"
	} else if ProfileError(c, "leaf") == "" {
		kind = "leaf"
	}
	var profileErr any
	if kind == "other" {
		if c.CA {
			profileErr = ProfileError(c, "root")
		} else {
			profileErr = ProfileError(c, "leaf")
		}
	}
	var pathLen any
	if c.PathLen != nil {
		pathLen = *c.PathLen
	}
	var ski, aki any
	if c.SKI != nil {
		ski = B64url(c.SKI)
	}
	if c.AKI != nil {
		aki = B64url(c.AKI)
	}
	alg := c.PublicKey.Alg
	uris, dns, eku := c.URIs, c.DNS, c.EKU
	if uris == nil {
		uris = []string{}
	}
	if dns == nil {
		dns = []string{}
	}
	if eku == nil {
		eku = []string{}
	}
	ku := c.KeyUsage
	if ku == nil {
		ku = []int{}
	}
	exts := make([]map[string]any, 0, len(c.Extensions))
	for _, e := range c.Extensions {
		exts = append(exts, map[string]any{"id": e.ID, "critical": e.Critical})
	}
	return map[string]any{
		"kind": kind, "subject": c.Subject, "issuer": c.Issuer, "serial": B64url(c.Serial),
		"not_before": timeOut(c.NotBefore), "not_after": timeOut(c.NotAfter), "alg": alg,
		"spki": B64url(c.SPKI), "fingerprint": FingerprintOf(c), "key_id": B64url(c.KeyID),
		"ski": ski, "aki": aki, "ca": c.CA, "path_len": pathLen, "key_usage": ku, "eku": eku,
		"uris": uris, "dns": dns, "sig_alg": c.SigAlg, "profile_error": profileErr, "bytes": len(c.DER),
		"extensions": exts,
	}
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

// Call dispatches one contract function.
func Call(name string, args json.RawMessage) (out json.RawMessage) {
	defer func() {
		if r := recover(); r != nil {
			out = fail("internal", fmt.Sprint(r))
		}
	}()
	fn, found := functions[name]
	if !found {
		return fail("unsupported", "no function named "+name)
	}
	// Arguments are an object, or the member is not there at all. A list, a bare scalar or the literal
	// `null` is a caller's mistake named here, once, rather than as whatever encoding/json says about
	// the struct it failed to fill — which leaks a Go type into an answer the Rust core gives in four
	// words. `null` belongs with the rest: the Rust core's `call` matches an object or refuses, and an
	// absent `args` is a zero-length message, still distinguishable, so nothing else moves.
	//
	// This one cannot be reached through `js/parity.mjs`: its port shim does `JSON.stringify(args ?? {})`,
	// so a null never survives the trip. A case the harness cannot express lives in each port's own
	// suite instead — here and in the Rust core's `api::tests`.
	if t := bytes.TrimSpace(args); len(t) > 0 && t[0] != '{' {
		return fail(codeArgs, "args is a JSON object")
	}
	return fn(args)
}

// Functions lists the contract's names, for a caller that wants to check coverage.
func Functions() []string {
	out := make([]string, 0, len(functions))
	for k := range functions {
		out = append(out, k)
	}
	return out
}

var functions = map[string]func(json.RawMessage) json.RawMessage{
	// The build, not a rule: the one function whose answer is allowed to differ between the ports,
	// because it describes the port. Every other name here must answer as the Rust core answers.
	"version": func(json.RawMessage) json.RawMessage {
		return ok(map[string]any{"module": ModuleVersion, "spec": SpecVersion})
	},

	// §1 keys
	"generate_key": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Alg *string `json:"alg"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		alg, err := needStr(a.Alg, "alg")
		if err != nil {
			return failErr(codeArgs, err)
		}
		priv, err := GenerateKey(alg)
		if err != nil {
			return failErr("unsupported", err)
		}
		o, err := keyOut(priv)
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		return ok(o)
	},
	// §2.1. Two calls rather than one so a wallet never hardcodes the salt: the constant lives here,
	// the vectors prove it, and a caller that gets it wrong fails loudly instead of quietly becoming
	// somebody else.
	"prf_salt": func(args json.RawMessage) json.RawMessage {
		return ok(map[string]any{"salt": B64(PrfSalt()), "infos": DerivationInfos})
	},
	"derive_seed": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Prf  B64     `json:"prf"`
			Info *string `json:"info"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		if err := need(a.Prf, "prf"); err != nil {
			return failErr(codeArgs, err)
		}
		info, err := needStr(a.Info, "info")
		if err != nil {
			return failErr(codeArgs, err)
		}
		seed, err := DeriveSeed(a.Prf, info)
		if err != nil {
			return failErr(codeArgs, err)
		}
		return ok(map[string]any{"seed": B64(seed)})
	},
	"key_from_seed": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Alg  *string `json:"alg"`
			Seed B64     `json:"seed"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		if err := need(a.Seed, "seed"); err != nil {
			return failErr(codeArgs, err)
		}
		alg, err := needStr(a.Alg, "alg")
		if err != nil {
			return failErr(codeArgs, err)
		}
		priv, err := KeyFromSeed(alg, a.Seed)
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		o, err := keyOut(priv)
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		return ok(o)
	},
	"public_key": func(args json.RawMessage) json.RawMessage {
		var a struct {
			PKCS8 B64 `json:"pkcs8"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		priv, err := privIn(a.PKCS8, "pkcs8")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		return ok(map[string]any{"alg": priv.Alg, "spki": B64url(priv.Public.SPKI), "fingerprint": Fingerprint(priv.Public.SPKI)})
	},
	"key_info": func(args json.RawMessage) json.RawMessage {
		var a struct {
			SPKI B64 `json:"spki"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		pub, err := pubIn(a.SPKI, "spki")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		return ok(map[string]any{"alg": pub.Alg, "fingerprint": Fingerprint(pub.SPKI), "key_id": B64url(KeyID(pub.SPKI))})
	},
	"sign": func(args json.RawMessage) json.RawMessage {
		var a struct {
			PKCS8 B64 `json:"pkcs8"`
			Data  B64 `json:"data"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		priv, err := privIn(a.PKCS8, "pkcs8")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		if err := need(a.Data, "data"); err != nil {
			return failErr(codeArgs, err)
		}
		sig, err := SignDetached(priv, a.Data)
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		return ok(map[string]any{"sig": B64url(sig)})
	},
	"verify": func(args json.RawMessage) json.RawMessage {
		var a struct {
			SPKI B64 `json:"spki"`
			Data B64 `json:"data"`
			Sig  B64 `json:"sig"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		pub, err := pubIn(a.SPKI, "spki")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		if err := need(a.Data, "data"); err != nil {
			return failErr(codeArgs, err)
		}
		if err := need(a.Sig, "sig"); err != nil {
			return failErr(codeArgs, err)
		}
		return ok(map[string]any{"valid": VerifyDetached(pub, a.Data, a.Sig)})
	},

	// §2 certificates
	"build_root": func(args json.RawMessage) json.RawMessage {
		var a struct {
			CN        string `json:"cn"`
			PKCS8     B64    `json:"pkcs8"`
			NotBefore string `json:"not_before"`
			Serial    B64    `json:"serial"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		priv, err := privIn(a.PKCS8, "pkcs8")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		nb, err := timeIn(a.NotBefore)
		if err != nil {
			return failErr("parse", err)
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
	},
	"root_tbs": func(args json.RawMessage) json.RawMessage {
		var a struct {
			CN        string `json:"cn"`
			SPKI      B64    `json:"spki"`
			NotBefore string `json:"not_before"`
			Serial    B64    `json:"serial"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		pub, err := pubIn(a.SPKI, "spki")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		nb, err := timeIn(a.NotBefore)
		if err != nil {
			return failErr("parse", err)
		}
		serial, err := serialIn(a.Serial)
		if err != nil {
			return failErr(codeArgs, err)
		}
		tbs, alg := RootTBS(a.CN, pub, nb, serial)
		return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
	},
	"assemble_root": assembleFn,
	"assemble_leaf": assembleFn,
	"build_leaf": func(args json.RawMessage) json.RawMessage {
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
	},
	"leaf_tbs": func(args json.RawMessage) json.RawMessage {
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
		tbs, alg := LeafTBS(lo)
		return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
	},
	"parse_certificate": func(args json.RawMessage) json.RawMessage {
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
	},
	"profile_error": func(args json.RawMessage) json.RawMessage {
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
	},
	"validate_chain": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Chain            []B64  `json:"chain"`
			Now              string `json:"now"`
			ExpectedRoot     string `json:"expected_root"`
			ExpectedEndpoint string `json:"expected_endpoint"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		if a.Chain == nil {
			return failErr(codeArgs, errArg("chain is required"))
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		return ok(chainOut(ValidateChain(chainOf(a.Chain), ChainOpts{Now: now, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})))
	},
	"compare_leaves": func(args json.RawMessage) json.RawMessage {
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
	},
	"is_normal_https": func(args json.RawMessage) json.RawMessage {
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
	},
	"address_guard": func(args json.RawMessage) json.RawMessage {
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
	},
	"ip_is_private": func(args json.RawMessage) json.RawMessage {
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
	},

	// §3 CSR
	"csr_new": func(args json.RawMessage) json.RawMessage {
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
	},
	"csr_check": func(args json.RawMessage) json.RawMessage {
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
	},
	"issue_from_csr": func(args json.RawMessage) json.RawMessage {
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
		o.RootSPKIs = append(o.RootSPKIs, root.Public.SPKI)
		issued, err := IssueFromCSR(a.CSR, o)
		if err != nil {
			return failErr("bad_request", err)
		}
		return ok(map[string]any{"der": B64url(issued.DER), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter)})
	},
	"issue_tbs_from_csr": func(args json.RawMessage) json.RawMessage {
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
	},

	// §4 cards
	"card_encode": func(args json.RawMessage) json.RawMessage {
		var a struct {
			FN    *string  `json:"fn"`
			Cert  B64      `json:"cert"`
			Seal  string   `json:"seal"`
			Extra []string `json:"extra"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		fn, err := needStr(a.FN, "fn")
		if err != nil {
			return failErr(codeArgs, err)
		}
		if err := need(a.Cert, "cert"); err != nil {
			return failErr(codeArgs, err)
		}
		return ok(map[string]any{"vcard": EncodeCard(fn, a.Cert, a.Seal, a.Extra)})
	},
	"card_decode": func(args json.RawMessage) json.RawMessage {
		var a struct {
			VCard *string `json:"vcard"`
			Now   string  `json:"now"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		vcard, err := needStr(a.VCard, "vcard")
		if err != nil {
			return failErr(codeArgs, err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		c, err := DecodeCard(vcard, now)
		if err != nil {
			return failErr("bad_request", err)
		}
		ignored := c.Ignored
		if ignored == nil {
			ignored = []string{}
		}
		// `leaf` is the certificate read back, not a second call the caller has to make. It was
		// missing here while the Rust core, `pact card show` and the defender all read it: a member
		// no vector looks at, so nothing noticed.
		return ok(map[string]any{"fn": c.FN, "version": 2, "seal": c.Seal, "cert": B64url(c.Cert), "root": c.Root, "endpoint": c.Endpoint, "expired": c.Expired, "ignored": ignored, "bytes": c.Bytes, "leaf": certOut(c.Leaf)})
	},
	// §5 envelopes
	"suite_for": func(args json.RawMessage) json.RawMessage {
		var a struct {
			SPKI B64 `json:"spki"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		pub, err := pubIn(a.SPKI, "spki")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		s, _ := SuiteForKey(pub)
		return ok(map[string]any{"suite": s})
	},
	"hpke_seal": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Suite         *string `json:"suite"`
			RecipientSPKI B64     `json:"recipient_spki"`
			Info          string  `json:"info"`
			AAD           B64     `json:"aad"`
			Plaintext     B64     `json:"plaintext"`
			EphemeralSeed B64     `json:"ephemeral_seed"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		suite, err := needStr(a.Suite, "suite")
		if err != nil {
			return failErr(codeArgs, err)
		}
		if !SuiteKnown(suite) {
			return fail("envelope_invalid", "version or suite")
		}
		pub, err2 := pubIn(a.RecipientSPKI, "recipient_spki")
		if err2 != nil {
			return failErr(codeFor(err2, "parse"), err2)
		}
		var enc, ct []byte
		if len(a.EphemeralSeed) > 0 {
			seed := a.EphemeralSeed
			if len(seed) != 32 {
				return fail("parse", "ephemeral_seed must be 32 bytes")
			}
			enc, ct, err = sealWith(suite, pub, []byte(a.Info), a.AAD, a.Plaintext, seed)
		} else {
			enc, ct, err = Seal(suite, pub, []byte(a.Info), a.AAD, a.Plaintext)
		}
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		return ok(map[string]any{"enc": B64url(enc), "ct": B64url(ct)})
	},
	"hpke_open": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Suite          *string `json:"suite"`
			RecipientPKCS8 B64     `json:"recipient_pkcs8"`
			Info           string  `json:"info"`
			AAD            B64     `json:"aad"`
			Enc            B64     `json:"enc"`
			Ct             B64     `json:"ct"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		suite, err := needStr(a.Suite, "suite")
		if err != nil {
			return failErr(codeArgs, err)
		}
		if !SuiteKnown(suite) {
			return fail("envelope_invalid", "version or suite")
		}
		priv, err2 := privIn(a.RecipientPKCS8, "recipient_pkcs8")
		if err2 != nil {
			return failErr(codeFor(err2, "parse"), err2)
		}
		pt, err := Open(suite, priv, []byte(a.Info), a.AAD, a.Enc, a.Ct)
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		return ok(map[string]any{"plaintext": B64url(pt)})
	},
	"seal_request": func(args json.RawMessage) json.RawMessage {
		var a sealArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		if err := need(a.RecipientLeaf, "recipient_leaf"); err != nil {
			return failErr(codeArgs, err)
		}
		leaf, err := Parse(a.RecipientLeaf)
		if err != nil {
			return failErr("parse", err)
		}
		o, err := a.opts(leaf.PublicKey)
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		o.Method, o.Params, o.Cty = a.Method, a.Params, a.Cty
		env, err := SealRequest(o)
		if err != nil {
			return failErr(codeFor(err, "envelope_invalid"), err)
		}
		return ok(env)
	},
	"seal_result": func(args json.RawMessage) json.RawMessage {
		var a sealArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		pub, err := pubIn(a.RecipientSPKI, "recipient_spki")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		o, err := a.opts(pub)
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		o.Result, o.Error = a.Result, a.Error
		env, err := SealResult(o)
		if err != nil {
			return failErr(codeFor(err, "envelope_invalid"), err)
		}
		return ok(env)
	},
	"open_result": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Envelope         *Envelope `json:"envelope"`
			MyPKCS8          B64       `json:"my_pkcs8"`
			MsgID            string    `json:"msg_id"`
			Now              string    `json:"now"`
			Pins             []Pin     `json:"pins"`
			ExpectedRoot     string    `json:"expected_root"`
			ExpectedEndpoint string    `json:"expected_endpoint"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		if a.Envelope == nil {
			return fail("envelope_invalid", "envelope members")
		}
		priv, err := privIn(a.MyPKCS8, "my_pkcs8")
		if err != nil {
			return failErr(codeFor(err, "parse"), err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		opened, err := OpenResult(*a.Envelope, OpenOpts{Recipient: priv, MsgID: a.MsgID, Now: now, Pins: a.Pins, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		out := map[string]any{"ok": true, "root": opened.Root, "endpoint": opened.Endpoint, "form": opened.Form}
		if opened.Result != nil {
			out["result"] = opened.Result
		}
		if opened.Error != nil {
			out["error"] = opened.Error
		}
		if opened.LeafUpdate != nil {
			out["leaf_update"] = B64url(opened.LeafUpdate)
		}
		return ok(out)
	},
	"follow_renewed": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Answer struct {
				Code string `json:"code"`
				Data struct {
					Chain []B64 `json:"chain"`
				} `json:"data"`
			} `json:"answer"`
			PinnedRoot *string `json:"pinned_root"`
			PinnedLeaf B64     `json:"pinned_leaf"`
			Dialed     *string `json:"dialed"`
			Now        string  `json:"now"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		pinnedRoot, err := needStr(a.PinnedRoot, "pinned_root")
		if err != nil {
			return failErr(codeArgs, err)
		}
		if err := need(a.PinnedLeaf, "pinned_leaf"); err != nil {
			return failErr(codeArgs, err)
		}
		dialed, err := needStr(a.Dialed, "dialed")
		if err != nil {
			return failErr(codeArgs, err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		if a.Answer.Code != "certificate_renewed" {
			return ok(map[string]any{"follow": false, "why": "not a certificate_renewed answer"})
		}
		follow, why, leaf := FollowRenewed(chainOf(a.Answer.Data.Chain), pinnedRoot, a.PinnedLeaf, dialed, now)
		if !follow {
			return ok(map[string]any{"follow": false, "why": why})
		}
		return ok(map[string]any{"follow": true, "leaf": B64url(leaf)})
	},
	"decide": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Now      string     `json:"now"`
			Envelope *Envelope  `json:"envelope"`
			Node     *NodeState `json:"node"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		// Without a node there is nothing to decide against: no keys, no pins, no tombstones. This
		// port answered anyway, refusing the envelope for an "unknown kid" — a decision that reads
		// like a verdict on the envelope and is really a verdict on an argument that was not there.
		if a.Node == nil {
			return failErr(codeArgs, errArg("node is required"))
		}
		if a.Envelope == nil {
			return failErr(codeArgs, errArg("envelope is required"))
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		return ok(Decide(now, *a.Envelope, *a.Node))
	},

	// §6 vault
	"vault_seal": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Passphrase string          `json:"passphrase"`
			Plaintext  json.RawMessage `json:"plaintext"`
			KDF        *KDF            `json:"kdf"`
			Salt       B64             `json:"salt"`
			Nonce      B64             `json:"nonce"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		if a.Passphrase == "" {
			return fail("bad_request", "empty passphrase")
		}
		if len(bytes.TrimSpace(a.Plaintext)) == 0 || string(bytes.TrimSpace(a.Plaintext)) == "null" {
			return fail(codeArgs, "plaintext is required")
		}
		pt, err := compactJSON(a.Plaintext)
		if err != nil {
			return fail("parse", "plaintext is not JSON")
		}
		salt, nonce := []byte(a.Salt), []byte(a.Nonce)
		v, err := VaultSeal(a.Passphrase, pt, a.KDF, salt, nonce)
		if err != nil {
			return failErr("vault", err)
		}
		return ok(map[string]any{"vault": v})
	},
	"vault_open": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Passphrase string          `json:"passphrase"`
			Vault      json.RawMessage `json:"vault"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		// The document as received, every member of it: the AAD is the header as written, so a
		// member added after sealing fails to open here as it does in the Rust core.
		if len(bytes.TrimSpace(a.Vault)) == 0 || string(bytes.TrimSpace(a.Vault)) == "null" {
			return fail(codeArgs, "vault is required")
		}
		dv, err := decodeJSON(a.Vault)
		doc, isDoc := dv.(map[string]any)
		if err != nil || !isDoc {
			return fail("vault", "not a pact-vault/1 document")
		}
		pt, err := VaultOpenDoc(a.Passphrase, doc)
		if err != nil {
			return failErr("vault", err)
		}
		return ok(map[string]any{"plaintext": json.RawMessage(pt)})
	},
	"wallet_issue": func(args json.RawMessage) json.RawMessage {
		var a struct {
			VaultPlaintext  VaultPlaintext `json:"vault_plaintext"`
			RootFingerprint *string        `json:"root_fingerprint"`
			CSR             B64            `json:"csr"`
			Now             string         `json:"now"`
			ValidDays       *int           `json:"valid_days"`
			Move            bool           `json:"move"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr(codeFor(err, codeArgs), err)
		}
		fingerprint, err := needStr(a.RootFingerprint, "root_fingerprint")
		if err != nil {
			return failErr(codeArgs, err)
		}
		if err := need(a.CSR, "csr"); err != nil {
			return failErr(codeArgs, err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		days, err := daysOr(a.ValidDays)
		if err != nil {
			return failErr("bad_request", err)
		}
		issued, err := WalletIssue(a.VaultPlaintext, fingerprint, a.CSR, now, days, a.Move)
		if err != nil {
			return failErr("bad_request", err)
		}
		warnings := issued.Warnings
		if warnings == nil {
			warnings = []string{}
		}
		// The full shape of CONTRACT §6: the certificate, where and when it is good for, the ledger
		// entry to append, whether this host is new, and what a person should be told.
		return ok(map[string]any{
			"der": B64url(issued.DER), "ledger_entry": issued.Entry, "warnings": warnings, "new_host": issued.NewHost,
			"endpoint": issued.Entry.Endpoint, "not_before": issued.Entry.NotBefore, "not_after": issued.Entry.NotAfter,
		})
	},
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
	CN        string `json:"cn"`
	RootCN    string `json:"root_cn"`
	RootPKCS8 B64    `json:"root_pkcs8"`
	RootSPKI  B64    `json:"root_spki"`
	HostSPKI  B64    `json:"host_spki"`
	Endpoint  string `json:"endpoint"`
	DNSName   string `json:"dns_name"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Serial    B64    `json:"serial"`
}

func (a leafArgs) opts() (LeafOpts, error) {
	host, err := pubIn(a.HostSPKI, "host_spki")
	if err != nil {
		return LeafOpts{}, err
	}
	nb, err := timeIn(a.NotBefore)
	if err != nil {
		return LeafOpts{}, err
	}
	na, err := timeIn(a.NotAfter)
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

type issueArgs struct {
	CSR               B64    `json:"csr"`
	RootCN            string `json:"root_cn"`
	RootPKCS8         B64    `json:"root_pkcs8"`
	RootSPKI          B64    `json:"root_spki"`
	RootSPKIs         []B64  `json:"root_spkis"`
	Now               string `json:"now"`
	PreviousNotBefore string `json:"previous_not_before"`
	// A pointer so an absent member takes the default and an explicit 0 is refused, as in Rust.
	ValidDays *int `json:"valid_days"`
}

func (a issueArgs) opts() (IssueOpts, error) {
	now, err := timeIn(a.Now)
	if err != nil {
		return IssueOpts{}, err
	}
	days, err := daysOr(a.ValidDays)
	if err != nil {
		return IssueOpts{}, err
	}
	o := IssueOpts{RootCN: a.RootCN, RootSPKIs: chainOf(a.RootSPKIs), Now: now, ValidDays: days}
	if a.PreviousNotBefore != "" {
		p, err := timeIn(a.PreviousNotBefore)
		if err != nil {
			return IssueOpts{}, err
		}
		o.PreviousNotBefore = &p
	}
	return o, nil
}

type sealArgs struct {
	RecipientLeaf B64             `json:"recipient_leaf"`
	RecipientSPKI B64             `json:"recipient_spki"`
	SenderPKCS8   B64             `json:"sender_pkcs8"`
	Form          string          `json:"form"`
	SenderChain   []B64           `json:"sender_chain"`
	Method        string          `json:"method"`
	Params        json.RawMessage `json:"params"`
	Result        json.RawMessage `json:"result"`
	Error         json.RawMessage `json:"error"`
	MsgID         string          `json:"msg_id"`
	TS            int64           `json:"ts"`
	Exp           int64           `json:"exp"`
	Cty           string          `json:"cty"`
	EphemeralSeed B64             `json:"ephemeral_seed"`
}

func (a sealArgs) opts(recipient *PublicKey) (SealOpts, error) {
	sender, err := privIn(a.SenderPKCS8, "sender_pkcs8")
	if err != nil {
		return SealOpts{}, err
	}
	form := a.Form
	if form == "" {
		form = "chain"
	}
	if form != "chain" && form != "leaf" {
		return SealOpts{}, errArg("form is chain or leaf")
	}
	if form == "chain" && a.SenderChain == nil {
		return SealOpts{}, errArg("the chain form needs sender_chain")
	}
	if a.MsgID == "" {
		return SealOpts{}, errArg("msg_id is required")
	}
	if a.TS == 0 {
		return SealOpts{}, errArg("ts is required")
	}
	if a.EphemeralSeed != nil && len(a.EphemeralSeed) != 32 {
		return SealOpts{}, parseError{"ephemeral_seed must be 32 bytes"}
	}
	return SealOpts{RecipientKey: recipient, Sender: sender, Form: form, SenderChain: chainOf(a.SenderChain), MsgID: a.MsgID, TS: a.TS, Exp: a.Exp, Seed: a.EphemeralSeed}, nil
}
