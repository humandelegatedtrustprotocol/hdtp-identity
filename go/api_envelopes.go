package pactidentity

// The Envelopes section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name, and the helpers only these use.

import "encoding/json"

func callSuiteFor(a args) json.RawMessage {
	pub, err := a.pub("spki")
	if err != nil {
		return failAs("parse", err)
	}
	s, _ := SuiteForKey(pub)
	return ok(map[string]any{"suite": s})
}

func callHPKESeal(a args) json.RawMessage {
	suite, err := a.str("suite")
	if err != nil {
		return failAs(codeArgs, err)
	}
	if !SuiteKnown(suite) {
		return fail("envelope_invalid", "version or suite")
	}
	pub, err := a.pub("recipient_spki")
	if err != nil {
		return failAs("parse", err)
	}
	// In the core's order after the key: info, aad, plaintext, then the test-only seed. info and
	// plaintext were read as empty when they were absent, and a seed of the wrong length was `parse`
	// here and "" a fresh seal (R15, F7, R16, T13).
	info, err := a.str("info")
	if err != nil {
		return failAs(codeArgs, err)
	}
	aad, err := a.optBytes("aad")
	if err != nil {
		return failAs(codeArgs, err)
	}
	plaintext, err := a.bytes("plaintext")
	if err != nil {
		return failAs(codeArgs, err)
	}
	seed, err := a.seed32("ephemeral_seed")
	if err != nil {
		return failAs(codeArgs, err)
	}
	var enc, ct []byte
	if seed != nil {
		enc, ct, err = sealWith(suite, pub, []byte(info), aad, plaintext, seed)
	} else {
		enc, ct, err = Seal(suite, pub, []byte(info), aad, plaintext)
	}
	if err != nil {
		return failErr("envelope_invalid", err)
	}
	return ok(map[string]any{"enc": B64url(enc), "ct": B64url(ct)})
}

func callHPKEOpen(a args) json.RawMessage {
	suite, err := a.str("suite")
	if err != nil {
		return failAs(codeArgs, err)
	}
	if !SuiteKnown(suite) {
		return fail("envelope_invalid", "version or suite")
	}
	priv, err := a.priv("recipient_pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	pub, err := a.pub("recipient_spki")
	if err != nil {
		return failAs("parse", err)
	}
	// info, enc and ct absent were read as empty and answered "does not open" (R15, F7).
	info, err := a.str("info")
	if err != nil {
		return failAs(codeArgs, err)
	}
	aad, err := a.optBytes("aad")
	if err != nil {
		return failAs(codeArgs, err)
	}
	enc, err := a.bytes("enc")
	if err != nil {
		return failAs(codeArgs, err)
	}
	ct, err := a.bytes("ct")
	if err != nil {
		return failAs(codeArgs, err)
	}
	pt, err := Open(suite, priv, pub, []byte(info), aad, enc, ct)
	if err != nil {
		return failErr("envelope_invalid", err)
	}
	return ok(map[string]any{"plaintext": B64url(pt)})
}

func callSealRequest(a args) json.RawMessage {
	leafDER, err := a.bytes("recipient_leaf")
	if err != nil {
		return failAs(codeArgs, err)
	}
	leaf, err := Parse(leafDER)
	if err != nil {
		return failAs("parse", err)
	}
	o, err := sealArgs(a, leaf.PublicKey, func(o *SealOpts) error {
		method, err := a.optStr("method")
		if err != nil {
			return err
		}
		o.Method = "tools/call"
		if method != nil {
			o.Method = *method
		}
		// `params` absent or null is {} (the contract's note; CONTRACT §0: null is absent); present, it is
		// sealed as given.
		o.Params = a.present("params")
		if o.Params == nil {
			o.Params = json.RawMessage(`{}`)
		}
		return nil
	}, func(o *SealOpts) error {
		cty, err := a.optStr("cty")
		if err != nil {
			return err
		}
		o.Cty = CtyCall
		if cty != nil {
			o.Cty = *cty
		}
		return nil
	})
	if err != nil {
		return failAs("parse", err)
	}
	env, err := sealRequest(o)
	if err != nil {
		return failAs("envelope_invalid", err)
	}
	return ok(env)
}

func callSealResult(a args) json.RawMessage {
	pub, err := a.pub("recipient_spki")
	if err != nil {
		return failAs("parse", err)
	}
	o, err := sealArgs(a, pub, func(o *SealOpts) error {
		// Null is absent (CONTRACT §0): a null result alone is no result, and beside an error it is not a
		// second one. Both ports sealed it as present.
		o.Result, o.Error = a.present("result"), a.present("error")
		return nil
	}, nil)
	if err != nil {
		return failAs("parse", err)
	}
	env, err := sealResult(o)
	if err != nil {
		return failAs("envelope_invalid", err)
	}
	return ok(env)
}

func callOpenResult(a args) json.RawMessage {
	// Absent is the caller's omission (CONTRACT §0, `envelope is required`); present, every refusal
	// of the envelope is `envelope_invalid`, and names the member that is not there (T9, F12, S1-1).
	raw := a.present("envelope")
	if raw == nil {
		return fail(codeArgs, "envelope is required")
	}
	env, err := wireOf(a.value("envelope"))
	if err != nil {
		return failErr("envelope_invalid", err)
	}
	priv, err := a.priv("my_pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	me, err := a.pub("my_spki")
	if err != nil {
		return failAs("parse", err)
	}
	// A pin is read whole and refused by the member it lacks: one lacking its root or endpoint
	// opened here as though it were a pin (F11, R20).
	var pins []Pin
	if v := a.value("pins"); v != nil {
		if pins, err = listOf(v, "pins", pinOf); err != nil {
			return failAs(codeArgs, err)
		}
	}
	msgID, err := a.str("msg_id")
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
	o := OpenOpts{Recipient: priv, RecipientPublic: me, MsgID: msgID, Now: now, Pins: pins}
	if root != nil {
		o.ExpectedRoot, o.rootGiven = *root, true
	}
	if endpoint != nil {
		o.ExpectedEndpoint, o.endpointGiven = *endpoint, true
	}
	opened, err := OpenResult(env, o)
	if err != nil {
		return failAs("envelope_invalid", err)
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
}

// follow_renewed reads the pin it follows from, then the peer's answer as it was sent, whatever its
// shape (the contract's `answer: true`): a code that is not `certificate_renewed` and a `data.chain`
// that is not a list of base64url strings are answers, `{follow: false}`, as the core gives them,
// where this port refused them as arguments that did not read (F14, R22).
func callFollowRenewed(a args) json.RawMessage {
	pinnedRoot, err := a.str("pinned_root")
	if err != nil {
		return failAs(codeArgs, err)
	}
	pinnedLeaf, err := a.bytes("pinned_leaf")
	if err != nil {
		return failAs(codeArgs, err)
	}
	dialed, err := a.str("dialed")
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	answer, _ := a.value("answer").(map[string]any)
	if code, _ := answer["code"].(string); code != "certificate_renewed" {
		return ok(map[string]any{"follow": false, "why": "not certificate_renewed"})
	}
	data, _ := answer["data"].(map[string]any)
	chain, isChain := chainOfAny(data["chain"])
	if !isChain {
		return ok(map[string]any{"follow": false, "why": "no chain"})
	}
	follow, why, leaf := FollowRenewed(chain, pinnedRoot, pinnedLeaf, dialed, now)
	if !follow {
		return ok(map[string]any{"follow": false, "why": why})
	}
	return ok(map[string]any{"follow": true, "leaf": B64url(leaf)})
}

// chainOfAny is the core's `chain_of`: a list of base64url strings, or nothing.
func chainOfAny(v any) ([][]byte, bool) {
	items, isList := v.([]any)
	if !isList {
		return nil, false
	}
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		s, isStr := item.(string)
		if !isStr {
			return nil, false
		}
		b, err := DecodeB64url(s)
		if err != nil {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}

func callDecide(a args) json.RawMessage {
	// Without a node there is nothing to decide against: no keys, no pins, no tombstones. This
	// port answered anyway, refusing the envelope for an "unknown kid" — a decision that reads
	// like a verdict on the envelope and is really a verdict on an argument that was not there.
	for _, k := range []string{"node", "envelope", "now"} {
		if a.present(k) == nil {
			return fail(codeArgs, k+" is required")
		}
	}
	// Then each is read whole, and a member it lacks is named by its path: this port decided on
	// the zero value (a node with no endpoint was `ok`; an envelope with no `sig` a refusal of the
	// signature) where the core refused the call (T9, F13, R22).
	node, err := nodeStateOf(a.value("node"))
	if err != nil {
		return failAs(codeArgs, err)
	}
	env, err := wireOf(a.value("envelope"))
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	d, err := Decide(now, env, node)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(d)
}

// callDecideChain is a chain proven at the TLS layer, decided by the pins (DecideChain). Read as
// callDecide reads its own: `node`, `chain` and `now` absent or null, in that order; then the node
// whole, by the one reader; the chain, as every function reads one; `now`.
func callDecideChain(a args) json.RawMessage {
	for _, k := range []string{"node", "chain", "now"} {
		if a.present(k) == nil {
			return fail(codeArgs, k+" is required")
		}
	}
	node, err := nodeStateOf(a.value("node"))
	if err != nil {
		return failAs(codeArgs, err)
	}
	chain, err := a.chain("chain")
	if err != nil {
		return failAs("parse", err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	d, err := DecideChain(now, chain, node)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(d)
}

// ── the objects inside a member, read by hand (api/envelopes.rs reads them the same way, in the same order)

// required is `<path> is required`: a member of an object inside the arguments that is absent, null
// or not the type it is, named as CONTRACT §0 names a member of the arguments.
func required(path string) error { return errArg(path + " is required") }

type shape struct {
	o    map[string]any
	path string
}

func shapeOf(v any, path string) (shape, error) {
	o, isObj := v.(map[string]any)
	if !isObj {
		return shape{}, required(path)
	}
	return shape{o, path}, nil
}

func (s shape) text(k string) (string, error) {
	v, isStr := s.o[k].(string)
	if !isStr {
		return "", required(s.path + "." + k)
	}
	return v, nil
}

func (s shape) optText(k string) (*string, error) {
	switch v := s.o[k].(type) {
	case nil:
		return nil, nil
	case string:
		return &v, nil
	}
	return nil, required(s.path + "." + k)
}

func (s shape) flag(k string) (bool, error) {
	switch v := s.o[k].(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	}
	return false, required(s.path + "." + k)
}

// listOf reads a list, each item by `each`, named `<path>[<i>]`.
func listOf[T any](v any, path string, each func(any, string) (T, error)) ([]T, error) {
	items, isList := v.([]any)
	if !isList {
		return nil, required(path)
	}
	out := make([]T, 0, len(items))
	for i, item := range items {
		t, err := each(item, path+"["+itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// optList is an optional list member: absent or null is empty.
func optList[T any](s shape, k string, each func(any, string) (T, error)) ([]T, error) {
	if s.o[k] == nil {
		return nil, nil
	}
	return listOf(s.o[k], s.path+"."+k, each)
}

func (s shape) texts(k string) ([]string, error) {
	return optList(s, k, func(v any, path string) (string, error) {
		t, isStr := v.(string)
		if !isStr {
			return "", required(path)
		}
		return t, nil
	})
}

// wireOf is the four members of an envelope as it arrived, in the order the contract lists them:
// strings that may be anything, judged later by the function.
func wireOf(v any) (Envelope, error) {
	s, err := shapeOf(v, "envelope")
	if err != nil {
		return Envelope{}, err
	}
	var e Envelope
	for _, m := range []struct {
		k  string
		to *string
	}{{"protected", &e.Protected}, {"enc", &e.Enc}, {"ct", &e.Ct}, {"sig", &e.Sig}} {
		if *m.to, err = s.text(m.k); err != nil {
			return Envelope{}, err
		}
	}
	return e, nil
}

// pinOf is a pin, open_result's or a node's: root, endpoint and leaf; `state` absent is `active`.
func pinOf(v any, path string) (Pin, error) {
	s, err := shapeOf(v, path)
	if err != nil {
		return Pin{}, err
	}
	var p Pin
	if p.Root, err = s.text("root"); err != nil {
		return Pin{}, err
	}
	if p.Endpoint, err = s.text("endpoint"); err != nil {
		return Pin{}, err
	}
	if p.Leaf, err = s.text("leaf"); err != nil {
		return Pin{}, err
	}
	state, err := s.optText("state")
	if err != nil {
		return Pin{}, err
	}
	p.State = "active"
	if state != nil {
		p.State = *state
	}
	fp, err := s.optText("leaf_fingerprint")
	if err != nil {
		return Pin{}, err
	}
	if fp != nil {
		p.LeafFingerprint = *fp
	}
	return p, nil
}

// nodeStateOf is the node state, member by member in the contract's order (NodeState). An absent
// `accept_new_hosts` is `auto` (SPEC §5.3, the contract's description); this port read it as its
// zero value, and so held a moved contact the core followed (T8). Anything but `auto` or `ask` is
// refused. The typed Decide keeps a Go caller's zero value, which the node fills itself.
func nodeStateOf(v any) (NodeState, error) {
	s, err := shapeOf(v, "node")
	if err != nil {
		return NodeState{}, err
	}
	var n NodeState
	if n.Endpoint, err = s.text("endpoint"); err != nil {
		return NodeState{}, err
	}
	hosts, err := s.optText("accept_new_hosts")
	if err != nil {
		return NodeState{}, err
	}
	switch {
	case hosts == nil:
		n.AcceptNewHosts = "auto"
	case *hosts == "auto" || *hosts == "ask":
		n.AcceptNewHosts = *hosts
	default:
		return NodeState{}, errArg("node.accept_new_hosts is auto or ask")
	}
	if n.Chain, err = s.texts("chain"); err != nil {
		return NodeState{}, err
	}
	if n.Keys, err = optList(s, "keys", func(v any, path string) (HeldKey, error) {
		k, err := shapeOf(v, path)
		if err != nil {
			return HeldKey{}, err
		}
		var h HeldKey
		if h.Kid, err = k.text("kid"); err != nil {
			return HeldKey{}, err
		}
		if h.Leaf, err = k.text("leaf"); err != nil {
			return HeldKey{}, err
		}
		if h.PKCS8, err = k.text("pkcs8"); err != nil {
			return HeldKey{}, err
		}
		h.Current, err = k.flag("current")
		return h, err
	}); err != nil {
		return NodeState{}, err
	}
	if n.Former, err = s.texts("former"); err != nil {
		return NodeState{}, err
	}
	if n.SiblingKids, err = s.texts("sibling_kids"); err != nil {
		return NodeState{}, err
	}
	if n.Pins, err = optList(s, "pins", pinOf); err != nil {
		return NodeState{}, err
	}
	if n.Tombstones, err = optList(s, "tombstones", func(v any, path string) (TombstoneRec, error) {
		t, err := shapeOf(v, path)
		if err != nil {
			return TombstoneRec{}, err
		}
		var r TombstoneRec
		if r.Root, err = t.text("root"); err != nil {
			return TombstoneRec{}, err
		}
		if r.Leaf, err = t.text("leaf"); err != nil {
			return TombstoneRec{}, err
		}
		r.At, err = t.text("at")
		return r, err
	}); err != nil {
		return NodeState{}, err
	}
	if n.FormerEndpoints, err = optList(s, "former_endpoints", func(v any, path string) (FormerEndpoint, error) {
		f, err := shapeOf(v, path)
		if err != nil {
			return FormerEndpoint{}, err
		}
		var r FormerEndpoint
		if r.Root, err = f.text("root"); err != nil {
			return FormerEndpoint{}, err
		}
		if r.Endpoint, err = f.text("endpoint"); err != nil {
			return FormerEndpoint{}, err
		}
		r.At, err = f.text("at")
		return r, err
	}); err != nil {
		return NodeState{}, err
	}
	if n.Seen, err = s.texts("seen"); err != nil {
		return NodeState{}, err
	}
	return n, nil
}

// sealArgs reads what seal_request and seal_result share, in the core's order (api/envelopes.rs):
// the sender's key, the chain (decoded where it is read, required only when the form needs it),
// the form, the body's own members (`body`: method and params, or result and error), msg_id, ts, exp,
// the members after it (`after`: cty), and the test-only seed. Every member is a value as given: ts
// and exp may be 0, method and cty may be "" (C2, T7, R18), and the defaults are an absent member's.
// The chain's presence and length are judged when the proof member is made, after all of them, as
// the core judges them (F10, R19).
func sealArgs(a args, recipient *PublicKey, body, after func(*SealOpts) error) (SealOpts, error) {
	o := SealOpts{RecipientKey: recipient}
	var err error
	if o.Sender, err = a.priv("sender_pkcs8"); err != nil {
		return o, err
	}
	if o.SenderChain, err = a.presentChain("sender_chain"); err != nil {
		return o, err
	}
	form, err := a.optStr("form")
	if err != nil {
		return o, err
	}
	o.Form = "chain"
	if form != nil {
		o.Form = *form
	}
	if o.Form != "chain" && o.Form != "leaf" {
		return o, errArg("form is chain or leaf")
	}
	if err := body(&o); err != nil {
		return o, err
	}
	if o.MsgID, err = a.id("msg_id"); err != nil {
		return o, err
	}
	if o.TS, err = a.int("ts"); err != nil {
		return o, err
	}
	exp, err := a.optInt("exp")
	if err != nil {
		return o, err
	}
	o.Exp = o.TS + 600
	if exp != nil {
		o.Exp = *exp
	}
	if after != nil {
		if err := after(&o); err != nil {
			return o, err
		}
	}
	if o.Seed, err = a.seed32("ephemeral_seed"); err != nil {
		return o, err
	}
	// The chain form's missing chain is the seal's to name (proofMember), after the header's times,
	// as the core's `proof` names it.
	return o, nil
}
