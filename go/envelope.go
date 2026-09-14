package pactidentity

// Envelopes: sealing requests and results (§13.1, §13.2), the caller side of a result, following
// certificate_renewed (§14.4), and Decide — the receiving side of §13.3 in order, §6.1 tiers, §5.3 new
// addresses with the removal tombstone, and §14.4 — as one pure function over host-supplied state.
// The seed's envelope.mjs is its specification line for line; every `why` is the seed's, verbatim.

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"
)

const (
	HeaderMembers = "cty,exp,kid,msg_id,suite,ts,v"
	SkewSeconds   = 300
	ClaimWindow   = 30 * 24 * time.Hour
	Tombstone     = 30 * 24 * time.Hour
	CtyCall       = "application/pact-call+json"
	CtyResult     = "application/pact-result+json"
)

var (
	guestTools   = map[string]bool{"redeem_invite": true, "request_contact": true}
	pendingTools = map[string]bool{"contact_accepted": true, "contact_rejected": true}
)

// Envelope is the four-member wire object.
type Envelope struct {
	Protected string `json:"protected"`
	Enc       string `json:"enc"`
	Ct        string `json:"ct"`
	Sig       string `json:"sig"`
}

// SealOpts is what a sender decides. Form is "chain" (the sender's leaf and root inside) or "leaf" (the
// sender's leaf fingerprint). Params, Result and Error are raw JSON, embedded as given.
type SealOpts struct {
	RecipientKey *PublicKey
	Sender       *PrivateKey
	Form         string
	SenderChain  [][]byte
	Method       string
	Params       json.RawMessage
	Result       json.RawMessage
	Error        json.RawMessage
	MsgID        string
	TS           int64
	Exp          int64
	Cty          string
	Seed         []byte // test-only: a deterministic ephemeral for the vectors
}

func headerJSON(suite, kid, msgID string, ts, exp int64, cty string) []byte {
	return Canonical(map[string]any{"v": int64(2), "suite": suite, "kid": kid, "msg_id": msgID, "ts": ts, "exp": exp, "cty": cty})
}

func proofMember(o SealOpts) ([]byte, error) {
	switch o.Form {
	case "chain":
		if len(o.SenderChain) != 2 {
			return nil, errors.New("sender_chain must be the leaf and the root")
		}
		return []byte(`,"chain":[` + jsonString(B64url(o.SenderChain[0])) + `,` + jsonString(B64url(o.SenderChain[1])) + `]`), nil
	case "leaf":
		return []byte(`,"leaf":` + jsonString(Fingerprint(o.Sender.Public.SPKI))), nil
	}
	return nil, errors.New("form must be chain or leaf")
}

func sealBody(o SealOpts, body []byte) (*Envelope, error) {
	suite, err := SuiteForKey(o.RecipientKey)
	if err != nil {
		return nil, err
	}
	exp := o.Exp
	if exp == 0 {
		exp = o.TS + 600
	}
	aad := headerJSON(suite, Fingerprint(o.RecipientKey.SPKI), o.MsgID, o.TS, exp, o.Cty)
	var enc, ct []byte
	if o.Seed != nil {
		enc, ct, err = sealWith(suite, o.RecipientKey, []byte(InfoV2), aad, body, o.Seed)
	} else {
		enc, ct, err = Seal(suite, o.RecipientKey, []byte(InfoV2), aad, body)
	}
	if err != nil {
		return nil, err
	}
	sig, err := SignDetached(o.Sender, concat(aad, enc, ct))
	if err != nil {
		return nil, err
	}
	return &Envelope{Protected: B64url(aad), Enc: B64url(enc), Ct: B64url(ct), Sig: B64url(sig)}, nil
}

// SealRequest seals a call to a recipient leaf key: plaintext {method, params, chain|leaf}.
func SealRequest(o SealOpts) (*Envelope, error) {
	if o.Method == "" {
		o.Method = "tools/call"
	}
	if o.Cty == "" {
		o.Cty = CtyCall
	}
	params, err := compactJSON(o.Params)
	if err != nil {
		return nil, errors.New("params is not JSON")
	}
	proof, err := proofMember(o)
	if err != nil {
		return nil, err
	}
	body := concat([]byte(`{"method":`+jsonString(o.Method)+`,"params":`), params, proof, []byte("}"))
	return sealBody(o, body)
}

// SealResult seals a result back: plaintext {result|error, chain|leaf}, cty application/pact-result+json.
func SealResult(o SealOpts) (*Envelope, error) {
	o.Cty = CtyResult
	var lead []byte
	switch {
	case o.Result != nil && o.Error == nil:
		r, err := compactJSON(o.Result)
		if err != nil {
			return nil, errors.New("result is not JSON")
		}
		lead = concat([]byte(`{"result":`), r)
	case o.Error != nil && o.Result == nil:
		e, err := compactJSON(o.Error)
		if err != nil {
			return nil, errors.New("error is not JSON")
		}
		lead = concat([]byte(`{"error":`), e)
	default:
		return nil, errors.New("exactly one of result and error")
	}
	proof, err := proofMember(o)
	if err != nil {
		return nil, err
	}
	return sealBody(o, concat(lead, proof, []byte("}")))
}

// Pin is what a receiver keeps per pinned root.
type Pin struct {
	Root     string `json:"root"`
	Endpoint string `json:"endpoint"`
	Leaf     string `json:"leaf"`
	State    string `json:"state"`
}

// HeldKey is a leaf this endpoint holds for the identity served at the path.
type HeldKey struct {
	Kid     string `json:"kid"`
	Leaf    string `json:"leaf"`
	PKCS8   string `json:"pkcs8"`
	Current bool   `json:"current"`
}

// TombstoneRec remembers a removed root and the leaf that removed it, for 30 days.
type TombstoneRec struct {
	Root string `json:"root"`
	Leaf string `json:"leaf"`
	At   string `json:"at"`
}

// FormerEndpoint remembers where a pinned root used to be, for the address-claim rule.
type FormerEndpoint struct {
	Root     string `json:"root"`
	Endpoint string `json:"endpoint"`
	At       string `json:"at"`
}

// NodeState is everything Decide reads.
type NodeState struct {
	Endpoint        string           `json:"endpoint"`
	AcceptNewHosts  string           `json:"accept_new_hosts"`
	Chain           []string         `json:"chain"`
	Keys            []HeldKey        `json:"keys"`
	Former          []string         `json:"former"`
	SiblingKids     []string         `json:"sibling_kids"`
	Pins            []Pin            `json:"pins"`
	Tombstones      []TombstoneRec   `json:"tombstones"`
	FormerEndpoints []FormerEndpoint `json:"former_endpoints"`
	Seen            []string         `json:"seen"`
}

// Decision is what Decide returns: the result, and the effects the host applies.
type Decision struct {
	Result  map[string]any   `json:"result"`
	Effects []map[string]any `json:"effects"`
}

func invalid(why string) Decision {
	return Decision{Result: map[string]any{"code": "envelope_invalid", "why": why}, Effects: []map[string]any{}}
}

func parseInstant(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func numberOf(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint8:
		return float64(x), true
	}
	return 0, false
}

// Decide is receive() of the seed, without the mutation.
func Decide(now time.Time, env Envelope, node NodeState) Decision {
	effects := []map[string]any{}
	aad := FromB64url(env.Protected)
	hv, err := decodeJSON(aad)
	if err != nil {
		return invalid("protected is not JSON")
	}
	header, ok := hv.(map[string]any)
	if !ok || sortedKeys(header) != HeaderMembers {
		return invalid("header members")
	}
	v, _ := numberOf(header["v"])
	suite, _ := header["suite"].(string)
	if v != 2 || !SuiteKnown(suite) {
		return invalid("version or suite")
	}
	kid, _ := header["kid"].(string)

	var held *HeldKey
	var heldLeaf *Cert
	for i := range node.Keys {
		k := &node.Keys[i]
		if k.Kid != kid {
			continue
		}
		leaf, err := Parse(FromB64url(k.Leaf))
		if err != nil {
			continue
		}
		if k.Current || !now.After(leaf.NotAfter) {
			held, heldLeaf = k, leaf
			break
		}
	}
	if held == nil {
		for _, s := range node.SiblingKids {
			if s == kid {
				return invalid("key held for another identity")
			}
		}
		for _, f := range node.Former {
			if f == kid {
				chain := make([]any, 0, len(node.Chain))
				for _, c := range node.Chain {
					chain = append(chain, c)
				}
				return Decision{Result: map[string]any{"code": "certificate_renewed", "data": map[string]any{"chain": chain}}, Effects: effects}
			}
		}
		return invalid("unknown kid")
	}
	if s, _ := SuiteForKey(heldLeaf.PublicKey); s != suite {
		return invalid("suite does not fit the leaf")
	}
	priv, err := ParsePKCS8(FromB64url(held.PKCS8))
	if err != nil {
		return invalid("does not open")
	}
	enc, ct := FromB64url(env.Enc), FromB64url(env.Ct)
	plaintext, err := Open(suite, priv, []byte(InfoV2), aad, enc, ct)
	if err != nil {
		return invalid("does not open")
	}
	bv, err := decodeJSON(plaintext)
	if err != nil {
		return invalid("does not open")
	}
	body, _ := bv.(map[string]any)
	members := ""
	if body != nil {
		members = sortedKeys(body)
	}
	if members != "chain,method,params" && members != "leaf,method,params" {
		return invalid("plaintext members")
	}
	method, _ := body["method"].(string)
	if method != "tools/call" && method != "tools/list" {
		return invalid("plaintext shape")
	}
	signed := concat(aad, enc, ct)
	sig := FromB64url(env.Sig)
	params, _ := body["params"].(map[string]any)
	tool, hasTool := "", false
	if params != nil {
		tool, hasTool = params["name"].(string)
	}

	nowS := float64(now.Unix())
	freshness := func() *Decision {
		if cty, _ := header["cty"].(string); cty != CtyCall {
			d := invalid("not a request")
			return &d
		}
		exp, okE := numberOf(header["exp"])
		ts, okT := numberOf(header["ts"])
		if !okE || !okT || !(nowS < exp) || math.Abs(nowS-ts) > SkewSeconds {
			d := invalid("outside the time window")
			return &d
		}
		if exp-ts > MaxLifetimeSeconds {
			d := invalid("exp too far from ts")
			return &d
		}
		msgID, ok := header["msg_id"].(string)
		if !ok || msgID == "" {
			d := invalid("empty msg_id")
			return &d
		}
		for _, s := range node.Seen {
			if s == msgID {
				d := Decision{Result: map[string]any{"code": "ok", "replayed": true}, Effects: effects}
				return &d
			}
		}
		return nil
	}
	msgID, _ := header["msg_id"].(string)
	// leafB64 is the leaf the signature verified under — the chain's, or the
	// pinned one the small form named — so a host can pin, seal to and answer
	// the caller without opening the envelope a second time.
	leafB64 := ""
	result := func(tier, root, endpoint, form string, extra map[string]any) Decision {
		effects = append(effects, map[string]any{"op": "seen", "msg_id": msgID})
		r := map[string]any{"code": "ok", "tier": tier, "root": root, "endpoint": endpoint, "method": method, "form": form, "params": body["params"], "leaf": leafB64}
		if hasTool {
			r["tool"] = tool
		}
		for k, v := range extra {
			r[k] = v
		}
		return Decision{Result: r, Effects: effects}
	}
	pendingApproval := func() Decision {
		return Decision{Result: map[string]any{"code": "pending_approval"}, Effects: effects}
	}

	// The small form: the sender names a leaf this node already holds. Anything that cannot be verified
	// against a held leaf — unknown, blocked, or a bad signature — gets the same answer, so nothing leaks.
	if members == "leaf,method,params" {
		ref, ok := body["leaf"].(string)
		if !ok {
			return invalid("plaintext shape")
		}
		chainRequired := Decision{Result: map[string]any{"code": "chain_required"}, Effects: effects}
		var hit *Pin
		var hitLeaf *Cert
		for i := range node.Pins {
			p := &node.Pins[i]
			if p.State == "blocked" {
				continue
			}
			leaf, err := Parse(FromB64url(p.Leaf))
			if err != nil {
				continue
			}
			if Fingerprint(leaf.SPKI) == ref {
				hit, hitLeaf = p, leaf
				break
			}
		}
		if hit == nil {
			return chainRequired
		}
		if now.After(hitLeaf.NotAfter) {
			return chainRequired // expiry darkens the small form as it darkens the chain
		}
		if !VerifyDetached(hitLeaf.PublicKey, signed, sig) {
			return chainRequired
		}
		if early := freshness(); early != nil {
			return *early
		}
		leafB64 = hit.Leaf
		if hit.State == "pending_out" {
			if pendingTools[tool] {
				return result("pending", hit.Root, hit.Endpoint, "leaf", nil)
			}
			return pendingApproval()
		}
		return result("contact", hit.Root, hit.Endpoint, "leaf", nil)
	}

	// The full form: a chain is a proof from the root and the one way a held leaf is updated.
	chainAny, ok := body["chain"].([]any)
	if !ok {
		return invalid("plaintext shape")
	}
	chain := make([][]byte, 0, len(chainAny))
	for _, c := range chainAny {
		s, ok := c.(string)
		if !ok {
			return invalid("plaintext shape")
		}
		chain = append(chain, FromB64url(s))
	}
	vr := ValidateChain(chain, ChainOpts{Now: now})
	if !vr.OK {
		return invalid("chain rule " + itoa(vr.Rule) + ": " + vr.Reason)
	}
	if !VerifyDetached(vr.LeafKey, signed, sig) {
		return invalid("signature is not the chain's leaf key")
	}
	if early := freshness(); early != nil {
		return *early
	}
	root, endpoint := vr.RootFingerprint, vr.Endpoint
	leafB64 = B64url(chain[0])

	asGuest := func(why string) Decision {
		if method != "tools/call" || !guestTools[tool] {
			// Refused as a guest — with the root and the leaf named, so a host
			// holding a 1.x pin of this leaf's key can upgrade it (Appendix C
			// row 6) and decide again.
			d := invalid("guest may only redeem or request")
			d.Result["root"], d.Result["leaf"] = root, B64url(chain[0])
			return d
		}
		cardText := ""
		if params != nil {
			if args, ok := params["arguments"].(map[string]any); ok {
				cardText, _ = args["card"].(string)
			}
		}
		card, err := DecodeCard(cardText, now)
		if err != nil {
			return invalid("guest card: " + err.Error())
		}
		if !bytes.Equal(card.Cert, chain[0]) {
			return invalid("guest card certificate is not the chain's leaf")
		}
		var claim any
		for _, p := range node.Pins {
			if p.Root != root && p.Endpoint == endpoint {
				claim = p.Root
				break
			}
		}
		if claim == nil {
			for _, f := range node.FormerEndpoints {
				at, ok := parseInstant(f.At)
				if f.Endpoint == endpoint && f.Root != root && ok && now.Sub(at) < ClaimWindow {
					claim = f.Root
					break
				}
			}
		}
		return result("guest", root, endpoint, "chain", map[string]any{"why": why, "address_claim": claim})
	}

	var pin *Pin
	for i := range node.Pins {
		if node.Pins[i].Root == root {
			pin = &node.Pins[i]
			break
		}
	}
	if pin == nil {
		for _, t := range node.Tombstones {
			if t.Root != root {
				continue
			}
			at, ok := parseInstant(t.At)
			if !ok || now.Sub(at) >= Tombstone {
				continue
			}
			if cmp, err := CompareLeaves(FromB64url(t.Leaf), chain[0]); err == nil && cmp == "newer" {
				effects = append(effects, map[string]any{"op": "pending", "root": root, "endpoint": endpoint, "why": "returned after removal", "leaf": B64url(chain[0])})
				return result("pending_new_address", root, endpoint, "chain", map[string]any{"forced": "tombstone", "decision": "ask"})
			}
		}
		return asGuest("unknown root")
	}
	if pin.State == "blocked" {
		return asGuest("blocked")
	}
	cmp, err := CompareLeaves(FromB64url(pin.Leaf), chain[0])
	if err != nil {
		return invalid("chain rule 1: " + err.Error())
	}
	if cmp == "superseded" {
		return asGuest("superseded leaf")
	}
	if cmp == "conflict" {
		return invalid("a different leaf with the same notBefore")
	}

	// §14.3 is absolute: a newer leaf from the root takes priority the instant it is seen, whatever the
	// validity of the older one. At another address it is a new address; under `ask` the owner decides.
	pinnedEndpoint := pin.Endpoint
	if endpoint != pin.Endpoint {
		if node.AcceptNewHosts != "auto" {
			effects = append(effects, map[string]any{"op": "pending", "root": root, "endpoint": endpoint, "why": "ask", "leaf": B64url(chain[0])})
			return result("pending_new_address", root, endpoint, "chain", map[string]any{"decision": "ask"})
		}
		effects = append(effects,
			map[string]any{"op": "former_endpoint", "root": root, "endpoint": pin.Endpoint, "at": now.UTC().Format(time.RFC3339)},
			map[string]any{"op": "pin_update", "root": root, "endpoint": endpoint, "leaf": B64url(chain[0])},
			map[string]any{"op": "event", "event": "new_address", "root": root, "endpoint": endpoint},
		)
		pinnedEndpoint = endpoint
	} else if cmp == "newer" {
		effects = append(effects,
			map[string]any{"op": "pin_update", "root": root, "endpoint": pin.Endpoint, "leaf": B64url(chain[0])},
			map[string]any{"op": "event", "event": "renewal", "root": root},
		)
	}
	if pin.State == "pending_out" {
		if pendingTools[tool] {
			return result("pending", root, pinnedEndpoint, "chain", nil)
		}
		return pendingApproval()
	}
	return result("contact", root, pinnedEndpoint, "chain", nil)
}

func itoa(n int) string { return strconv.Itoa(n) }

// OpenOpts is the caller side of a sealed result.
type OpenOpts struct {
	Recipient        *PrivateKey
	MsgID            string
	Now              time.Time
	Pins             []Pin
	ExpectedRoot     string
	ExpectedEndpoint string
}

// Opened is a verified result: the result or error object, who answered, and a newer leaf if one rode along.
type Opened struct {
	Result     json.RawMessage
	Error      json.RawMessage
	Root       string
	Endpoint   string
	Form       string
	LeafUpdate []byte
}

// OpenResult is §13.2 for the receiving caller: decode, open, validate the chain or find the named leaf
// among its pins, verify the signature and correlate. Every failure is envelope_invalid.
func OpenResult(env Envelope, o OpenOpts) (*Opened, error) {
	aad := FromB64url(env.Protected)
	hv, err := decodeJSON(aad)
	if err != nil {
		return nil, errors.New("protected is not JSON")
	}
	header, ok := hv.(map[string]any)
	if !ok || sortedKeys(header) != HeaderMembers {
		return nil, errors.New("header members")
	}
	v, _ := numberOf(header["v"])
	suite, _ := header["suite"].(string)
	mine, _ := SuiteForKey(o.Recipient.Public)
	if v != 2 || suite != mine {
		return nil, errors.New("version or suite")
	}
	if kid, _ := header["kid"].(string); kid != Fingerprint(o.Recipient.Public.SPKI) {
		return nil, errors.New("not sealed to this key")
	}
	if cty, _ := header["cty"].(string); cty != CtyResult {
		return nil, errors.New("not a result")
	}
	if msgID, _ := header["msg_id"].(string); msgID != o.MsgID {
		return nil, errors.New("msg_id does not correlate")
	}
	exp, okE := numberOf(header["exp"])
	ts, okT := numberOf(header["ts"])
	if !okE || !okT || !(float64(o.Now.Unix()) < exp) || math.Abs(float64(o.Now.Unix())-ts) > SkewSeconds {
		return nil, errors.New("outside the time window")
	}
	if exp-ts > MaxLifetimeSeconds {
		return nil, errors.New("exp too far from ts")
	}
	enc, ct := FromB64url(env.Enc), FromB64url(env.Ct)
	plaintext, err := Open(suite, o.Recipient, []byte(InfoV2), aad, enc, ct)
	if err != nil {
		return nil, errors.New("does not open")
	}
	bv, err := decodeJSON(plaintext)
	if err != nil {
		return nil, errors.New("does not open")
	}
	body, _ := bv.(map[string]any)
	members := ""
	if body != nil {
		members = sortedKeys(body)
	}
	var out Opened
	switch members {
	case "chain,result", "leaf,result":
		out.Result, _ = json.Marshal(body["result"])
	case "chain,error", "error,leaf":
		out.Error, _ = json.Marshal(body["error"])
	default:
		return nil, errors.New("plaintext members")
	}
	signed := concat(aad, enc, ct)
	sig := FromB64url(env.Sig)
	if ref, ok := body["leaf"].(string); ok {
		out.Form = "leaf"
		for _, p := range o.Pins {
			if p.State == "blocked" {
				continue
			}
			leaf, err := Parse(FromB64url(p.Leaf))
			if err != nil || Fingerprint(leaf.SPKI) != ref {
				continue
			}
			if o.Now.After(leaf.NotAfter) {
				return nil, errors.New("the named leaf has expired")
			}
			if !VerifyDetached(leaf.PublicKey, signed, sig) {
				return nil, errors.New("signature is not the named leaf's key")
			}
			if o.ExpectedRoot != "" && p.Root != o.ExpectedRoot {
				return nil, errors.New("root is not the one expected")
			}
			if o.ExpectedEndpoint != "" && p.Endpoint != o.ExpectedEndpoint {
				return nil, errors.New("endpoint differs from the one in question")
			}
			out.Root, out.Endpoint = p.Root, p.Endpoint
			return &out, nil
		}
		return nil, errors.New("leaf not held")
	}
	chainAny, ok := body["chain"].([]any)
	if !ok {
		return nil, errors.New("plaintext shape")
	}
	chain := make([][]byte, 0, len(chainAny))
	for _, c := range chainAny {
		s, ok := c.(string)
		if !ok {
			return nil, errors.New("plaintext shape")
		}
		chain = append(chain, FromB64url(s))
	}
	vr := ValidateChain(chain, ChainOpts{Now: o.Now, ExpectedRoot: o.ExpectedRoot, ExpectedEndpoint: o.ExpectedEndpoint})
	if !vr.OK {
		return nil, errors.New("chain rule " + itoa(vr.Rule) + ": " + vr.Reason)
	}
	if !VerifyDetached(vr.LeafKey, signed, sig) {
		return nil, errors.New("signature is not the chain's leaf key")
	}
	out.Form, out.Root, out.Endpoint = "chain", vr.RootFingerprint, vr.Endpoint
	for _, p := range o.Pins {
		if p.Root != vr.RootFingerprint {
			continue
		}
		cmp, err := CompareLeaves(FromB64url(p.Leaf), chain[0])
		if err != nil || cmp == "superseded" {
			return nil, errors.New("superseded leaf")
		}
		if cmp == "conflict" {
			return nil, errors.New("a different leaf with the same notBefore")
		}
		if cmp == "newer" || p.Endpoint != vr.Endpoint {
			out.LeafUpdate = chain[0]
		}
	}
	return &out, nil
}

// FollowRenewed is §14.4 on the caller's side: follow a certificate_renewed answer only when its chain
// validates to the pinned root at the dialed address and is newer than or equal to the pin.
func FollowRenewed(answerChain [][]byte, pinnedRoot string, pinnedLeaf []byte, dialed string, now time.Time) (bool, string, []byte) {
	vr := ValidateChain(answerChain, ChainOpts{Now: now, ExpectedRoot: pinnedRoot, ExpectedEndpoint: dialed})
	if !vr.OK {
		return false, "chain rule " + itoa(vr.Rule) + ": " + vr.Reason, nil
	}
	cmp, err := CompareLeaves(pinnedLeaf, answerChain[0])
	if err != nil {
		return false, err.Error(), nil
	}
	if cmp == "superseded" {
		return false, "older than the pinned leaf", nil
	}
	if cmp == "conflict" {
		return false, "a different leaf with the same notBefore", nil
	}
	return true, "", answerChain[0]
}
