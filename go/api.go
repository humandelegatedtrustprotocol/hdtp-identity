package pactidentity

// Call is the one boundary every home of the library presents: a function name and a JSON object in,
// one JSON object out, never a panic. The names and shapes are CONTRACT.md's.

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
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

func decodeArgs(args json.RawMessage, into any) error {
	if len(args) == 0 {
		args = []byte("{}")
	}
	return json.Unmarshal(args, into)
}

func privIn(b64 string) (*PrivateKey, error) {
	if b64 == "" {
		return nil, errors.New("a private key is required")
	}
	return ParsePKCS8(FromB64url(b64))
}

func pubIn(b64 string) (*PublicKey, error) {
	if b64 == "" {
		return nil, errors.New("a public key is required")
	}
	pub, err := ParseSPKI(FromB64url(b64))
	if err != nil {
		return nil, err
	}
	if _, err := AlgorithmOf(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

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
	return map[string]any{
		"kind": kind, "subject": c.Subject, "issuer": c.Issuer, "serial": B64url(c.Serial),
		"not_before": timeOut(c.NotBefore), "not_after": timeOut(c.NotAfter), "alg": alg,
		"spki": B64url(c.SPKI), "fingerprint": FingerprintOf(c), "key_id": B64url(c.KeyID),
		"ski": ski, "aki": aki, "ca": c.CA, "path_len": pathLen, "key_usage": ku, "eku": eku,
		"uris": uris, "dns": dns, "sig_alg": c.SigAlg, "profile_error": profileErr, "bytes": len(c.DER),
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
	// §1 keys
	"generate_key": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Alg string `json:"alg"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := GenerateKey(a.Alg)
		if err != nil {
			return failErr("unsupported", err)
		}
		o, err := keyOut(priv)
		if err != nil {
			return failErr("key", err)
		}
		return ok(o)
	},
	"key_from_seed": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Alg  string `json:"alg"`
			Seed string `json:"seed"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := KeyFromSeed(a.Alg, FromB64url(a.Seed))
		if err != nil {
			return failErr("key", err)
		}
		o, err := keyOut(priv)
		if err != nil {
			return failErr("key", err)
		}
		return ok(o)
	},
	"public_key": func(args json.RawMessage) json.RawMessage {
		var a struct {
			PKCS8 string `json:"pkcs8"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := privIn(a.PKCS8)
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"alg": priv.Alg, "spki": B64url(priv.Public.SPKI), "fingerprint": Fingerprint(priv.Public.SPKI)})
	},
	"key_info": func(args json.RawMessage) json.RawMessage {
		var a struct {
			SPKI string `json:"spki"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		pub, err := pubIn(a.SPKI)
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"alg": pub.Alg, "fingerprint": Fingerprint(pub.SPKI), "key_id": B64url(KeyID(pub.SPKI))})
	},
	"sign": func(args json.RawMessage) json.RawMessage {
		var a struct {
			PKCS8 string `json:"pkcs8"`
			Data  string `json:"data"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := privIn(a.PKCS8)
		if err != nil {
			return failErr("key", err)
		}
		sig, err := SignDetached(priv, FromB64url(a.Data))
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"sig": B64url(sig)})
	},
	"verify": func(args json.RawMessage) json.RawMessage {
		var a struct {
			SPKI string `json:"spki"`
			Data string `json:"data"`
			Sig  string `json:"sig"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		pub, err := pubIn(a.SPKI)
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"valid": VerifyDetached(pub, FromB64url(a.Data), FromB64url(a.Sig))})
	},

	// §2 certificates
	"build_root": func(args json.RawMessage) json.RawMessage {
		var a struct {
			CN        string `json:"cn"`
			PKCS8     string `json:"pkcs8"`
			NotBefore string `json:"not_before"`
			Serial    string `json:"serial"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := privIn(a.PKCS8)
		if err != nil {
			return failErr("key", err)
		}
		nb, err := timeIn(a.NotBefore)
		if err != nil {
			return failErr("parse", err)
		}
		var serial []byte
		if a.Serial != "" {
			serial = FromB64url(a.Serial)
		}
		der, err := BuildRoot(RootOpts{CN: a.CN, Key: priv, NotBefore: nb, Serial: serial})
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"der": B64url(der), "fingerprint": Fingerprint(priv.Public.SPKI)})
	},
	"root_tbs": func(args json.RawMessage) json.RawMessage {
		var a struct {
			CN        string `json:"cn"`
			SPKI      string `json:"spki"`
			NotBefore string `json:"not_before"`
			Serial    string `json:"serial"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		pub, err := pubIn(a.SPKI)
		if err != nil {
			return failErr("key", err)
		}
		nb, err := timeIn(a.NotBefore)
		if err != nil {
			return failErr("parse", err)
		}
		var serial []byte
		if a.Serial != "" {
			serial = FromB64url(a.Serial)
		}
		tbs, alg := RootTBS(a.CN, pub, nb, serial)
		return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg), "fingerprint": Fingerprint(pub.SPKI)})
	},
	"assemble_root": assembleFn,
	"assemble_leaf": assembleFn,
	"build_leaf": func(args json.RawMessage) json.RawMessage {
		var a leafArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		root, err := privIn(a.RootPKCS8)
		if err != nil {
			return failErr("key", err)
		}
		lo, err := a.opts()
		if err != nil {
			return failErr("parse", err)
		}
		lo.RootKey = root
		der, err := BuildLeaf(lo)
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"der": B64url(der)})
	},
	"leaf_tbs": func(args json.RawMessage) json.RawMessage {
		var a leafArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		rootPub, err := pubIn(a.RootSPKI)
		if err != nil {
			return failErr("key", err)
		}
		lo, err := a.opts()
		if err != nil {
			return failErr("parse", err)
		}
		lo.RootPub = rootPub
		tbs, alg := LeafTBS(lo)
		return ok(map[string]any{"tbs": B64url(tbs), "sig_alg": B64url(alg)})
	},
	"parse_certificate": func(args json.RawMessage) json.RawMessage {
		var a struct {
			DER string `json:"der"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		c, err := Parse(FromB64url(a.DER))
		if err != nil {
			return failErr("parse", err)
		}
		return ok(certOut(c))
	},
	"profile_error": func(args json.RawMessage) json.RawMessage {
		var a struct {
			DER  string `json:"der"`
			Kind string `json:"kind"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		c, err := Parse(FromB64url(a.DER))
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
			Chain            []string `json:"chain"`
			Now              string   `json:"now"`
			ExpectedRoot     string   `json:"expected_root"`
			ExpectedEndpoint string   `json:"expected_endpoint"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		return ok(chainOut(ValidateChain(chainIn(a.Chain), ChainOpts{Now: now, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})))
	},
	"compare_leaves": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Pinned    string `json:"pinned"`
			Presented string `json:"presented"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		order, err := CompareLeaves(FromB64url(a.Pinned), FromB64url(a.Presented))
		if err != nil {
			return failErr("parse", err)
		}
		return ok(map[string]any{"order": order})
	},
	"is_normal_https": func(args json.RawMessage) json.RawMessage {
		var a struct {
			URL string `json:"url"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		return ok(map[string]any{"normal": IsNormalHTTPS(a.URL)})
	},
	"address_guard": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Endpoint     string `json:"endpoint"`
			SelfEndpoint string `json:"self_endpoint"`
			Guest        bool   `json:"guest"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		if good, why := AddressGuard(a.Endpoint, a.SelfEndpoint, a.Guest); !good {
			return ok(map[string]any{"ok": false, "why": why})
		}
		return ok(map[string]any{"ok": true})
	},
	"ip_is_private": func(args json.RawMessage) json.RawMessage {
		var a struct {
			IP string `json:"ip"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		return ok(map[string]any{"private": IPIsPrivate(a.IP)})
	},

	// §3 CSR
	"csr_new": func(args json.RawMessage) json.RawMessage {
		var a struct {
			CN        string `json:"cn"`
			HostPKCS8 string `json:"host_pkcs8"`
			Endpoint  string `json:"endpoint"`
			DNSName   string `json:"dns_name"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		host, err := privIn(a.HostPKCS8)
		if err != nil {
			return failErr("key", err)
		}
		der, err := CSRNew(a.CN, host, a.Endpoint, a.DNSName)
		if err != nil {
			return failErr("key", err)
		}
		return ok(map[string]any{"der": B64url(der)})
	},
	"csr_check": func(args json.RawMessage) json.RawMessage {
		var a struct {
			DER       string   `json:"der"`
			RootSPKIs []string `json:"root_spkis"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		info := CSRCheck(FromB64url(a.DER), chainIn(a.RootSPKIs))
		if !info.OK {
			return ok(map[string]any{"ok": false, "why": info.Why})
		}
		return ok(map[string]any{"ok": true, "cn": info.CN, "spki": B64url(info.Key.SPKI), "fingerprint": info.Fingerprint, "alg": info.Alg, "endpoint": info.Endpoint, "dns_name": info.DNSName})
	},
	"issue_from_csr": func(args json.RawMessage) json.RawMessage {
		var a issueArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		root, err := privIn(a.RootPKCS8)
		if err != nil {
			return failErr("key", err)
		}
		o, err := a.opts()
		if err != nil {
			return failErr("parse", err)
		}
		o.RootKey = root
		issued, err := IssueFromCSR(FromB64url(a.CSR), o)
		if err != nil {
			return failErr("bad_request", err)
		}
		return ok(map[string]any{"der": B64url(issued.DER), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter)})
	},
	"issue_tbs_from_csr": func(args json.RawMessage) json.RawMessage {
		var a issueArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		rootPub, err := pubIn(a.RootSPKI)
		if err != nil {
			return failErr("key", err)
		}
		o, err := a.opts()
		if err != nil {
			return failErr("parse", err)
		}
		o.RootPub = rootPub
		issued, err := IssueTBSFromCSR(FromB64url(a.CSR), o)
		if err != nil {
			return failErr("bad_request", err)
		}
		return ok(map[string]any{"tbs": B64url(issued.TBS), "sig_alg": B64url(issued.Alg), "endpoint": issued.Endpoint, "not_before": timeOut(issued.NotBefore), "not_after": timeOut(issued.NotAfter)})
	},

	// §4 cards
	"card_encode": func(args json.RawMessage) json.RawMessage {
		var a struct {
			FN    string   `json:"fn"`
			Cert  string   `json:"cert"`
			Seal  string   `json:"seal"`
			Extra []string `json:"extra"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		return ok(map[string]any{"vcard": EncodeCard(a.FN, FromB64url(a.Cert), a.Seal, a.Extra)})
	},
	"card_decode": func(args json.RawMessage) json.RawMessage {
		var a struct {
			VCard string `json:"vcard"`
			Now   string `json:"now"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		c, err := DecodeCard(a.VCard, now)
		if err != nil {
			return failErr("bad_request", err)
		}
		ignored := c.Ignored
		if ignored == nil {
			ignored = []string{}
		}
		return ok(map[string]any{"fn": c.FN, "version": 2, "seal": c.Seal, "cert": B64url(c.Cert), "root": c.Root, "endpoint": c.Endpoint, "expired": c.Expired, "ignored": ignored, "bytes": c.Bytes})
	},
	"card_compat_encode": func(args json.RawMessage) json.RawMessage {
		var a struct {
			FN   string `json:"fn"`
			Cert string `json:"cert"`
			Seal string `json:"seal"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		v, err := EncodeCompatCard(a.FN, FromB64url(a.Cert), a.Seal)
		if err != nil {
			return failErr("parse", err)
		}
		return ok(map[string]any{"vcard": v})
	},

	// §5 envelopes
	"suite_for": func(args json.RawMessage) json.RawMessage {
		var a struct {
			SPKI string `json:"spki"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		pub, err := pubIn(a.SPKI)
		if err != nil {
			return failErr("key", err)
		}
		s, _ := SuiteForKey(pub)
		return ok(map[string]any{"suite": s})
	},
	"hpke_seal": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Suite         string `json:"suite"`
			RecipientSPKI string `json:"recipient_spki"`
			Info          string `json:"info"`
			AAD           string `json:"aad"`
			Plaintext     string `json:"plaintext"`
			EphemeralSeed string `json:"ephemeral_seed"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		pub, err := pubIn(a.RecipientSPKI)
		if err != nil {
			return failErr("key", err)
		}
		var enc, ct []byte
		if a.EphemeralSeed != "" {
			seed := FromB64url(a.EphemeralSeed)
			if len(seed) != 32 {
				return fail("parse", "ephemeral_seed must be 32 bytes")
			}
			enc, ct, err = sealWith(a.Suite, pub, []byte(a.Info), FromB64url(a.AAD), FromB64url(a.Plaintext), seed)
		} else {
			enc, ct, err = Seal(a.Suite, pub, []byte(a.Info), FromB64url(a.AAD), FromB64url(a.Plaintext))
		}
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		return ok(map[string]any{"enc": B64url(enc), "ct": B64url(ct)})
	},
	"hpke_open": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Suite          string `json:"suite"`
			RecipientPKCS8 string `json:"recipient_pkcs8"`
			Info           string `json:"info"`
			AAD            string `json:"aad"`
			Enc            string `json:"enc"`
			Ct             string `json:"ct"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := privIn(a.RecipientPKCS8)
		if err != nil {
			return failErr("key", err)
		}
		pt, err := Open(a.Suite, priv, []byte(a.Info), FromB64url(a.AAD), FromB64url(a.Enc), FromB64url(a.Ct))
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		return ok(map[string]any{"plaintext": B64url(pt)})
	},
	"seal_request": func(args json.RawMessage) json.RawMessage {
		var a sealArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		if a.EphemeralSeed != "" {
			return fail("unsupported", "seal_request draws its own ephemeral; a seed is refused")
		}
		leaf, err := Parse(FromB64url(a.RecipientLeaf))
		if err != nil {
			return failErr("parse", err)
		}
		o, err := a.opts(leaf.PublicKey)
		if err != nil {
			return failErr("key", err)
		}
		o.Method, o.Params, o.Cty = a.Method, a.Params, a.Cty
		env, err := SealRequest(o)
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		return ok(env)
	},
	"seal_result": func(args json.RawMessage) json.RawMessage {
		var a sealArgs
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		if a.EphemeralSeed != "" {
			return fail("unsupported", "seal_result draws its own ephemeral; a seed is refused")
		}
		pub, err := pubIn(a.RecipientSPKI)
		if err != nil {
			return failErr("key", err)
		}
		o, err := a.opts(pub)
		if err != nil {
			return failErr("key", err)
		}
		o.Result, o.Error = a.Result, a.Error
		env, err := SealResult(o)
		if err != nil {
			return failErr("envelope_invalid", err)
		}
		return ok(env)
	},
	"open_result": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Envelope         Envelope `json:"envelope"`
			MyPKCS8          string   `json:"my_pkcs8"`
			MsgID            string   `json:"msg_id"`
			Now              string   `json:"now"`
			Pins             []Pin    `json:"pins"`
			ExpectedRoot     string   `json:"expected_root"`
			ExpectedEndpoint string   `json:"expected_endpoint"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		priv, err := privIn(a.MyPKCS8)
		if err != nil {
			return failErr("key", err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		opened, err := OpenResult(a.Envelope, OpenOpts{Recipient: priv, MsgID: a.MsgID, Now: now, Pins: a.Pins, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})
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
					Chain []string `json:"chain"`
				} `json:"data"`
			} `json:"answer"`
			PinnedRoot string `json:"pinned_root"`
			PinnedLeaf string `json:"pinned_leaf"`
			Dialed     string `json:"dialed"`
			Now        string `json:"now"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		if a.Answer.Code != "certificate_renewed" {
			return ok(map[string]any{"follow": false, "why": "not a certificate_renewed answer"})
		}
		follow, why, leaf := FollowRenewed(chainIn(a.Answer.Data.Chain), a.PinnedRoot, FromB64url(a.PinnedLeaf), a.Dialed, now)
		if !follow {
			return ok(map[string]any{"follow": false, "why": why})
		}
		return ok(map[string]any{"follow": true, "leaf": B64url(leaf)})
	},
	"decide": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Now      string    `json:"now"`
			Envelope Envelope  `json:"envelope"`
			Node     NodeState `json:"node"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		return ok(Decide(now, a.Envelope, a.Node))
	},

	// §6 vault
	"vault_seal": func(args json.RawMessage) json.RawMessage {
		var a struct {
			Passphrase string          `json:"passphrase"`
			Plaintext  json.RawMessage `json:"plaintext"`
			KDF        *KDF            `json:"kdf"`
			Salt       string          `json:"salt"`
			Nonce      string          `json:"nonce"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		if a.Passphrase == "" {
			return fail("bad_request", "empty passphrase")
		}
		pt, err := compactJSON(a.Plaintext)
		if err != nil {
			return fail("parse", "plaintext is not JSON")
		}
		var salt, nonce []byte
		if a.Salt != "" {
			salt = FromB64url(a.Salt)
		}
		if a.Nonce != "" {
			nonce = FromB64url(a.Nonce)
		}
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
			return failErr("parse", err)
		}
		// The document as received, every member of it: the AAD is the header as written, so a
		// member added after sealing fails to open here as it does in the Rust core.
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
			RootFingerprint string         `json:"root_fingerprint"`
			CSR             string         `json:"csr"`
			Now             string         `json:"now"`
			ValidDays       int            `json:"valid_days"`
			Move            bool           `json:"move"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return failErr("parse", err)
		}
		now, err := timeIn(a.Now)
		if err != nil {
			return failErr("parse", err)
		}
		issued, err := WalletIssue(a.VaultPlaintext, a.RootFingerprint, FromB64url(a.CSR), now, a.ValidDays, a.Move)
		if err != nil {
			return failErr("bad_request", err)
		}
		warnings := issued.Warnings
		if warnings == nil {
			warnings = []string{}
		}
		return ok(map[string]any{"der": B64url(issued.DER), "ledger_entry": issued.Entry, "warnings": warnings, "new_host": issued.NewHost})
	},
}

func assembleFn(args json.RawMessage) json.RawMessage {
	var a struct {
		TBS    string `json:"tbs"`
		Sig    string `json:"sig"`
		SigAlg string `json:"sig_alg"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr("parse", err)
	}
	tbs := FromB64url(a.TBS)
	var alg []byte
	if a.SigAlg != "" {
		alg = FromB64url(a.SigAlg)
	} else {
		// The algorithm is the TBS's own third field.
		n, err := derRead(tbs, 0)
		if err != nil {
			return failErr("parse", err)
		}
		f, err := derChildren(n)
		if err != nil || len(f) < 3 {
			return fail("parse", "tbs shape")
		}
		alg = f[2].raw
	}
	der := Assemble(tbs, alg, FromB64url(a.Sig))
	if _, err := Parse(der); err != nil {
		return failErr("parse", err)
	}
	return ok(map[string]any{"der": B64url(der)})
}

type leafArgs struct {
	CN        string `json:"cn"`
	RootCN    string `json:"root_cn"`
	RootPKCS8 string `json:"root_pkcs8"`
	RootSPKI  string `json:"root_spki"`
	HostSPKI  string `json:"host_spki"`
	Endpoint  string `json:"endpoint"`
	DNSName   string `json:"dns_name"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Serial    string `json:"serial"`
}

func (a leafArgs) opts() (LeafOpts, error) {
	host, err := pubIn(a.HostSPKI)
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
		return LeafOpts{}, errors.New("validity over 398 days")
	}
	if !IsNormalHTTPS(a.Endpoint) {
		return LeafOpts{}, errors.New("endpoint is not an https URL in normal form")
	}
	var serial []byte
	if a.Serial != "" {
		serial = FromB64url(a.Serial)
	}
	return LeafOpts{CN: a.CN, RootCN: a.RootCN, HostPub: host, Endpoint: a.Endpoint, DNSName: a.DNSName, NotBefore: nb, NotAfter: na, Serial: serial}, nil
}

type issueArgs struct {
	CSR               string   `json:"csr"`
	RootCN            string   `json:"root_cn"`
	RootPKCS8         string   `json:"root_pkcs8"`
	RootSPKI          string   `json:"root_spki"`
	RootSPKIs         []string `json:"root_spkis"`
	Now               string   `json:"now"`
	PreviousNotBefore string   `json:"previous_not_before"`
	ValidDays         int      `json:"valid_days"`
}

func (a issueArgs) opts() (IssueOpts, error) {
	now, err := timeIn(a.Now)
	if err != nil {
		return IssueOpts{}, err
	}
	o := IssueOpts{RootCN: a.RootCN, RootSPKIs: chainIn(a.RootSPKIs), Now: now, ValidDays: a.ValidDays}
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
	RecipientLeaf string          `json:"recipient_leaf"`
	RecipientSPKI string          `json:"recipient_spki"`
	SenderPKCS8   string          `json:"sender_pkcs8"`
	Form          string          `json:"form"`
	SenderChain   []string        `json:"sender_chain"`
	Method        string          `json:"method"`
	Params        json.RawMessage `json:"params"`
	Result        json.RawMessage `json:"result"`
	Error         json.RawMessage `json:"error"`
	MsgID         string          `json:"msg_id"`
	TS            int64           `json:"ts"`
	Exp           int64           `json:"exp"`
	Cty           string          `json:"cty"`
	EphemeralSeed string          `json:"ephemeral_seed"`
}

func (a sealArgs) opts(recipient *PublicKey) (SealOpts, error) {
	sender, err := privIn(a.SenderPKCS8)
	if err != nil {
		return SealOpts{}, err
	}
	if a.MsgID == "" {
		return SealOpts{}, errors.New("msg_id is required")
	}
	if a.TS == 0 {
		return SealOpts{}, errors.New("ts is required")
	}
	return SealOpts{RecipientKey: recipient, Sender: sender, Form: a.Form, SenderChain: chainIn(a.SenderChain), MsgID: a.MsgID, TS: a.TS, Exp: a.Exp}, nil
}
