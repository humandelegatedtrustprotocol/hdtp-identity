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

func callHPKESeal(args json.RawMessage) json.RawMessage {
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
}

func callHPKEOpen(args json.RawMessage) json.RawMessage {
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
}

func callSealRequest(args json.RawMessage) json.RawMessage {
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
}

func callSealResult(args json.RawMessage) json.RawMessage {
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
}

func callOpenResult(args json.RawMessage) json.RawMessage {
	var a struct {
		Envelope         *Envelope `json:"envelope"`
		MyPKCS8          B64       `json:"my_pkcs8"`
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
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	opened, err := OpenResult(*a.Envelope, OpenOpts{Recipient: priv, MsgID: a.MsgID, Now: now, Pins: a.Pins, ExpectedRoot: a.ExpectedRoot, ExpectedEndpoint: a.ExpectedEndpoint})
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
