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

// SkewSeconds, ClaimWindow and Tombstone are contract/contract.json's `Windows`, which
// constants_test.go holds them to (and tests/constants.rs the Rust core's).
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
	// Seed fixes the ephemeral so a vector can be reproduced byte for byte, which is how a port
	// proves its sealing agrees with the seed library's. Production leaves it nil and draws its own.
	Seed []byte
}

func headerJSON(suite, kid, msgID string, ts, exp int64, cty string) []byte {
	return Canonical(map[string]any{"v": int64(2), "suite": suite, "kid": kid, "msg_id": msgID, "ts": ts, "exp": exp, "cty": cty})
}

func proofMember(o SealOpts, signer *Signer) ([]byte, error) {
	switch o.Form {
	case "chain":
		if len(o.SenderChain) != 2 {
			return nil, errArg("sender_chain must be the leaf and the root")
		}
		return []byte(`,"chain":[` + jsonString(B64url(o.SenderChain[0])) + `,` + jsonString(B64url(o.SenderChain[1])) + `]`), nil
	case "leaf":
		return []byte(`,"leaf":` + jsonString(Fingerprint(signer.Public.SPKI))), nil
	}
	return nil, errArg("form is chain or leaf")
}

func sealBody(o SealOpts, signer *Signer, body []byte) (*Envelope, error) {
	suite, err := SuiteForKey(o.RecipientKey)
	if err != nil {
		return nil, err
	}
	aad := headerJSON(suite, Fingerprint(o.RecipientKey.SPKI), o.MsgID, o.TS, o.Exp, o.Cty)
	var enc, ct []byte
	if o.Seed != nil {
		enc, ct, err = sealWith(suite, o.RecipientKey, []byte(InfoV2), aad, body, o.Seed)
	} else {
		enc, ct, err = Seal(suite, o.RecipientKey, []byte(InfoV2), aad, body)
	}
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(concat(aad, enc, ct))
	if err != nil {
		return nil, err
	}
	return &Envelope{Protected: B64url(aad), Enc: B64url(enc), Ct: B64url(ct), Sig: B64url(sig)}, nil
}

// SealRequest seals a call to a recipient leaf key: plaintext {method, params, chain|leaf}.
//
// A field left at its zero value takes the default a Go caller means by leaving it out: Method
// tools/call, Cty application/pact-call+json, Exp TS+600, Params {}. The JSON boundary cannot mean
// that — `exp: 0` and `method: ""` are values there, sealed as given, as the core and the seed seal
// them (CONTRACT §0; C2, T7, R18) — so it resolves its own defaults and calls sealRequest.
func SealRequest(o SealOpts) (*Envelope, error) {
	if o.Method == "" {
		o.Method = "tools/call"
	}
	if o.Cty == "" {
		o.Cty = CtyCall
	}
	if o.Exp == 0 {
		o.Exp = o.TS + 600
	}
	if o.Params == nil {
		o.Params = json.RawMessage(`{}`)
	}
	return sealRequest(o)
}

// sealRequest seals exactly what it is given.
func sealRequest(o SealOpts) (*Envelope, error) {
	params, err := compactJSON(o.Params)
	if err != nil {
		return nil, errors.New("params is not JSON")
	}
	if o.Sender == nil {
		return nil, errArg("the sender's key is required")
	}
	// One expansion of the sender's key for the leaf form's fingerprint and the signature.
	signer := o.Sender.Signer()
	proof, err := proofMember(o, signer)
	if err != nil {
		return nil, err
	}
	body := concat([]byte(`{"method":`+jsonString(o.Method)+`,"params":`), params, proof, []byte("}"))
	return sealBody(o, signer, body)
}

// SealResult seals a result back: plaintext {result|error, chain|leaf}, cty application/pact-result+json.
// An Exp left at zero is TS+600, as SealRequest's is; the JSON boundary calls sealResult with its own.
func SealResult(o SealOpts) (*Envelope, error) {
	if o.Exp == 0 {
		o.Exp = o.TS + 600
	}
	return sealResult(o)
}

// sealResult seals exactly what it is given. The proof member is judged before the result, as the
// core's seal_result judges them: a chain of one beside no result was named for the result here and
// for the chain there (R19).
func sealResult(o SealOpts) (*Envelope, error) {
	o.Cty = CtyResult
	if o.Sender == nil {
		return nil, errArg("the sender's key is required")
	}
	// One expansion of the sender's key for the leaf form's fingerprint and the signature.
	signer := o.Sender.Signer()
	proof, err := proofMember(o, signer)
	if err != nil {
		return nil, err
	}
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
		return nil, errArg("a result carries exactly one of result and error")
	}
	return sealBody(o, signer, concat(lead, proof, []byte("}")))
}

// Pin is what a receiver keeps per pinned root.
type Pin struct {
	Root     string `json:"root"`
	Endpoint string `json:"endpoint"`
	Leaf     string `json:"leaf"`
	State    string `json:"state"`
	// LeafFingerprint is the fingerprint of Leaf's key, when the host keeps it: see pinHolding.
	LeafFingerprint string `json:"leaf_fingerprint,omitempty"`
}

// pinHolding finds the pin that holds the leaf a small-form envelope names, among those not blocked.
//
// The name arrives from somebody who has proved nothing yet, and finding it used to mean parsing
// EVERY pinned leaf and hashing its key — N X.509 parses per envelope on a node with N contacts,
// before freshness and before replay. A pin MAY say which leaf it holds; then the match is a string
// comparison and only the pin that matched is parsed. The match is still held to its own leaf: a
// fingerprint beside a certificate is a claim about it. A pin without the member is read as before.
// As `envelope.rs`'s `pin_holding`, including its words.
func pinHolding(pins []Pin, named string) (*Pin, *Cert, error) {
	for i := range pins {
		p := &pins[i]
		if p.State == "blocked" || (p.LeafFingerprint != "" && p.LeafFingerprint != named) {
			continue
		}
		leafDER, err := decodeB64url(p.Leaf)
		if err != nil {
			return nil, nil, err
		}
		leaf, err := Parse(leafDER)
		if err != nil {
			return nil, nil, parseError{err.Error()}
		}
		actual := Fingerprint(leaf.SPKI)
		if p.LeafFingerprint != "" && actual != named {
			return nil, nil, parseError{"a pin's leaf_fingerprint is not its leaf's"}
		}
		if actual == named {
			return p, leaf, nil
		}
	}
	return nil, nil, nil
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

// parseInstant is parseInstantZ: one grammar for every instant this port reads (SPEC 2.2.2).
func parseInstant(s string) (time.Time, bool) {
	return parseInstantZ(s)
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

// headerTypesOK is §13.1's other half: the closed set of member names exists so two implementations
// cannot disagree about what was signed, and latitude in the types reopens the same gap — `"1757000000"`
// and `1757000000` are different bytes under one signature and compare alike where a language coerces.
func headerTypesOK(h map[string]any) bool {
	for _, k := range []string{"v", "ts", "exp"} {
		// decodeJSON keeps numbers as json.Number, which a JSON string never becomes: a `"1757000000"`
		// arrives as a Go string and is refused here rather than coerced downstream.
		n, ok := h[k].(json.Number)
		if !ok {
			return false
		}
		if _, err := n.Int64(); err != nil {
			return false
		}
	}
	for _, k := range []string{"suite", "kid", "msg_id", "cty"} {
		if _, ok := h[k].(string); !ok {
			return false
		}
	}
	return true
}

// Decide is receive() of the seed, without the mutation.
//
// The error is for the NODE'S OWN state, never for the envelope: a held key's leaf, a pin's leaf or a
// tombstone that will not read. The seed throws on those and the Rust core returns Err. This port
// used to skip the row and decide without it — so one unparseable instant turned a peer returning
// after removal into a plain guest, and one unparseable pin answered `chain_required` to a contact.
// A decision made on state the node could not read is not a decision; the host is told instead.
func Decide(now time.Time, env Envelope, node NodeState) (Decision, error) {
	var unreadable error
	d := decide(now.Truncate(time.Second), env, node, &unreadable)
	if unreadable != nil {
		return Decision{}, unreadable
	}
	return d, nil
}

// unreadableState records the first piece of host state that would not read, in the words the core
// uses for the same bytes (CONTRACT §0: both are `parse`).
func unreadableState(into *error, err error) Decision {
	var p parseError
	if !errors.As(err, &p) {
		err = parseError{err.Error()}
	}
	*into = err
	return Decision{}
}

func decide(now time.Time, env Envelope, node NodeState, unreadable *error) Decision {
	effects := []map[string]any{}
	// Every member is base64url and nothing else. The lenient reader skips what it does not know, so
	// `protected` with a stray character decoded to the same bytes, the signature — which covers the
	// DECODED bytes — still verified, and this port accepted a second spelling of an envelope the core
	// refuses.
	aad, err := wireB64url(env.Protected)
	if err != nil {
		return invalid("protected is not JSON")
	}
	hv, err := decodeJSON(aad)
	if err != nil {
		return invalid("protected is not JSON")
	}
	header, ok := hv.(map[string]any)
	if !ok || sortedKeys(header) != HeaderMembers {
		return invalid("header members")
	}
	if !headerTypesOK(header) {
		return invalid("header member types")
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
		leafDER, err := decodeB64url(k.Leaf)
		if err != nil {
			return unreadableState(unreadable, err)
		}
		leaf, err := Parse(leafDER)
		if err != nil {
			return unreadableState(unreadable, err)
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
	enc, errEnc := wireB64url(env.Enc)
	ct, errCt := wireB64url(env.Ct)
	if errEnc != nil || errCt != nil {
		return invalid("does not open")
	}
	// `sig` covers the three members concatenated with nothing between them, so the suite's own `enc`
	// length is what fixes the boundary: without it a byte moved from `enc` into `ct` leaves the signed
	// bytes identical.
	if len(enc) != SuiteNpk(suite) {
		return invalid("encapsulated key is not the suite's length")
	}
	plaintext, err := Open(suite, priv, heldLeaf.PublicKey, []byte(InfoV2), aad, enc, ct)
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
	// An undecodable signature is no signature: it fails below, in the words of the form it came in.
	sig, _ := wireB64url(env.Sig)
	params, _ := body["params"].(map[string]any)
	tool, hasTool := "", false
	if params != nil {
		tool, hasTool = params["name"].(string)
	}
	// What a `pending_out` pin may do: call one of the pending tier's tools (§6.1, §6.2), or list them.
	// A listing names no tool; `tools/list` returns what the caller's tier may use (§6), and a sealed
	// call is dispatched in the tier the proven identity earns (§13.2) — so a pending contact's sealed
	// listing answers at the pending tier. Anything else waits for the approval.
	pendingAllows := method == "tools/list" || pendingTools[tool]

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
		// ALWAYS present, null when the call names no tool, because that is what the Rust core does
		// (envelope.rs `ok`). Omitting it made a member appear in one port's answer and not the
		// other's — the exact defect js/parity.mjs exists to catch, and it survived because the
		// gate counted `decide`'s refusals as successes, so no populated answer was ever compared.
		r["tool"] = nil
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
		hit, hitLeaf, err := pinHolding(node.Pins, ref)
		if err != nil {
			return unreadableState(unreadable, err)
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
			if pendingAllows {
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
			// holding an older pin of this leaf's key learns the root above it (§14.3
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
		// §14.5: a guest's endpoint never equals the receiver's own. Otherwise a stranger is pinned
		// to this node's own address and every reply it is sent comes straight back here.
		if endpoint == node.Endpoint {
			return invalid("guest endpoint is this node's own address")
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
		// The FIRST tombstone for this root, as the core reads it; the seed keeps one per root, so a
		// second is a host's mistake and not a second chance. This loop used to try every one.
		for _, t := range node.Tombstones {
			if t.Root != root {
				continue
			}
			at, ok := parseInstant(t.At)
			if !ok {
				return unreadableState(unreadable, parseError{"not an RFC 3339 instant: " + t.At})
			}
			if now.Sub(at) < Tombstone {
				was, err := decodeB64url(t.Leaf)
				if err != nil {
					return unreadableState(unreadable, err)
				}
				cmp, err := CompareLeaves(was, chain[0])
				if err != nil {
					return unreadableState(unreadable, err)
				}
				if cmp == "newer" {
					effects = append(effects, map[string]any{"op": "pending", "root": root, "endpoint": endpoint, "why": "returned after removal", "leaf": B64url(chain[0])})
					return result("pending_new_address", root, endpoint, "chain", map[string]any{"forced": "tombstone", "decision": "ask"})
				}
			}
			break
		}
		return asGuest("unknown root")
	}
	if pin.State == "blocked" {
		return asGuest("blocked")
	}
	pinnedDER, err := decodeB64url(pin.Leaf)
	if err != nil {
		return unreadableState(unreadable, err)
	}
	cmp, err := CompareLeaves(pinnedDER, chain[0])
	if err != nil {
		return unreadableState(unreadable, err)
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
		if pendingAllows {
			return result("pending", root, pinnedEndpoint, "chain", nil)
		}
		return pendingApproval()
	}
	return result("contact", root, pinnedEndpoint, "chain", nil)
}

func itoa(n int) string { return strconv.Itoa(n) }

// OpenOpts is the caller side of a sealed result.
type OpenOpts struct {
	Recipient *PrivateKey
	// RecipientPublic is the recipient's own public key, from its leaf: the kid is checked against it
	// and the open puts it in the KEM context. Never derived from Recipient.
	RecipientPublic  *PublicKey
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
	// Named, never a panic: in 0.4.0 a caller that left RecipientPublic out compiled, and the kid
	// check dereferenced nil.
	if o.Recipient == nil {
		return nil, errArg("the recipient's key is required")
	}
	if o.RecipientPublic == nil {
		return nil, errArg("the recipient's public key is required")
	}
	o.Now = o.Now.Truncate(time.Second)
	aad, err := wireB64url(env.Protected)
	if err != nil {
		return nil, errors.New("protected is not JSON")
	}
	hv, err := decodeJSON(aad)
	if err != nil {
		return nil, errors.New("protected is not JSON")
	}
	header, ok := hv.(map[string]any)
	if !ok || sortedKeys(header) != HeaderMembers {
		return nil, errors.New("header members")
	}
	if !headerTypesOK(header) {
		return nil, errors.New("header member types")
	}
	// Three questions in the core's order and the core's words: is this a version and a suite anyone
	// speaks, is it sealed to THIS key, does the suite fit this key. They were two questions here —
	// "version or suite" also meant "a suite that is known and is not mine" — asked before the kid, so
	// an envelope wrong in both ways was refused for a different reason by each port.
	v, _ := numberOf(header["v"])
	suite, _ := header["suite"].(string)
	if v != 2 || !SuiteKnown(suite) {
		return nil, errors.New("version or suite")
	}
	if kid, _ := header["kid"].(string); kid != Fingerprint(o.RecipientPublic.SPKI) {
		return nil, errors.New("kid is not this key")
	}
	if mine, _ := SuiteForKey(o.RecipientPublic); suite != mine {
		return nil, errors.New("suite does not fit the key")
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
	enc, errEnc := wireB64url(env.Enc)
	ct, errCt := wireB64url(env.Ct)
	if errEnc != nil || errCt != nil {
		return nil, errors.New("does not open")
	}
	if len(enc) != SuiteNpk(suite) {
		return nil, errors.New("encapsulated key is not the suite's length")
	}
	sig, err := wireB64url(env.Sig)
	if err != nil {
		return nil, errors.New("signature")
	}
	plaintext, err := Open(suite, o.Recipient, o.RecipientPublic, []byte(InfoV2), aad, enc, ct)
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
	if ref, ok := body["leaf"].(string); ok {
		out.Form = "leaf"
		// A pin that will not read is the caller's own state gone wrong, and is said as such (`parse`),
		// not stepped over on the way to "unknown leaf". pinHolding parses only the pin that matches.
		p, leaf, err := pinHolding(o.Pins, ref)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, errors.New("unknown leaf")
		}
		if o.Now.After(leaf.NotAfter) {
			return nil, errors.New("held leaf has expired")
		}
		if !VerifyDetached(leaf.PublicKey, signed, sig) {
			return nil, errors.New("signature is not the held leaf's key")
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
	pinned := false
	for _, p := range o.Pins {
		if p.Root != vr.RootFingerprint {
			continue
		}
		pinned = true
		cmp, err := CompareLeaves(FromB64url(p.Leaf), chain[0])
		if err != nil || cmp == "superseded" {
			return nil, errors.New("superseded leaf")
		}
		if cmp == "conflict" {
			return nil, errors.New("a different leaf with the same notBefore")
		}
		if cmp == "newer" {
			out.LeafUpdate = chain[0]
		}
	}
	// No pin for this root is first contact, and the leaf that rode along is what a caller pins.
	// Handing it back only from inside the loop meant a caller holding no pins was never told what to
	// pin — it could read a result and still have nothing to recognise the peer by next time.
	if !pinned {
		out.LeafUpdate = chain[0]
	}
	return &out, nil
}

// FollowRenewed is §14.4 on the caller's side: follow a certificate_renewed answer only when its chain
// validates to the pinned root at the dialed address and is newer than or equal to the pin.
func FollowRenewed(answerChain [][]byte, pinnedRoot string, pinnedLeaf []byte, dialed string, now time.Time) (bool, string, []byte) {
	now = now.Truncate(time.Second)
	vr := ValidateChain(answerChain, ChainOpts{Now: now, ExpectedRoot: pinnedRoot, ExpectedEndpoint: dialed})
	if !vr.OK {
		return false, "chain rule " + itoa(vr.Rule) + ": " + vr.Reason, nil
	}
	cmp, err := CompareLeaves(pinnedLeaf, answerChain[0])
	if err != nil {
		return false, err.Error(), nil
	}
	if cmp == "superseded" {
		return false, "older than the pin", nil
	}
	if cmp == "conflict" {
		return false, "a different leaf with the same notBefore", nil
	}
	return true, "", answerChain[0]
}
