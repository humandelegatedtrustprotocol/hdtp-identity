package pactidentity

// The Envelopes section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name, and the helpers only these use.

import (
	"bytes"
	"encoding/json"
)

func callSuiteFor(args json.RawMessage) json.RawMessage {
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
		return failErr("parse", err)
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
		// `params` absent is {} (the contract's note); present, it is sealed as given.
		o.Params = a["params"]
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
		// Present is present: `null` too is a result, as the core reads it.
		o.Result, o.Error = a["result"], a["error"]
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

func callOpenResult(args json.RawMessage) json.RawMessage {
	var a struct {
		Envelope         *Envelope `json:"envelope"`
		MyPKCS8          B64       `json:"my_pkcs8"`
		MySPKI           B64       `json:"my_spki"`
		MsgID            string    `json:"msg_id"`
		Now              *string   `json:"now"`
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
	me, err := pubIn(a.MySPKI, "my_spki")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	opened, err := OpenResult(*a.Envelope, OpenOpts{Recipient: priv, RecipientPublic: me, MsgID: a.MsgID, Now: now, Pins: a.Pins, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})
	if err != nil {
		return failErr(codeFor(err, "envelope_invalid"), err)
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

func callFollowRenewed(args json.RawMessage) json.RawMessage {
	var a struct {
		Answer struct {
			Code string `json:"code"`
			Data struct {
				// Raw, because ABSENT and EMPTY are different answers (CONTRACT §0): no `chain`
				// member — or one that is not a list of base64url strings — is "no chain", and
				// `[]` is a chain of 0 that rule 1 refuses. Decoded as a slice, both were nil.
				Chain json.RawMessage `json:"chain"`
			} `json:"data"`
		} `json:"answer"`
		PinnedRoot *string `json:"pinned_root"`
		PinnedLeaf B64     `json:"pinned_leaf"`
		Dialed     *string `json:"dialed"`
		Now        *string `json:"now"`
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
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	if a.Answer.Code != "certificate_renewed" {
		return ok(map[string]any{"follow": false, "why": "not certificate_renewed"})
	}
	var answered []B64
	if raw := bytes.TrimSpace(a.Answer.Data.Chain); len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &answered) != nil {
		return ok(map[string]any{"follow": false, "why": "no chain"})
	}
	follow, why, leaf := FollowRenewed(chainOf(answered), pinnedRoot, a.PinnedLeaf, dialed, now)
	if !follow {
		return ok(map[string]any{"follow": false, "why": why})
	}
	return ok(map[string]any{"follow": true, "leaf": B64url(leaf)})
}

func callDecide(args json.RawMessage) json.RawMessage {
	var a struct {
		Now      *string    `json:"now"`
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
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	d, err := Decide(now, *a.Envelope, *a.Node)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(d)
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
	if o.Form == "chain" && o.SenderChain == nil {
		return o, errArg("the chain form needs sender_chain")
	}
	return o, nil
}
