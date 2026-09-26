package pactidentity

// The Cards section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name.

import "encoding/json"

func callCardEncode(args json.RawMessage) json.RawMessage {
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
	vcard, err := EncodeCard(fn, a.Cert, a.Seal, a.Extra)
	if err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	return ok(map[string]any{"vcard": vcard})
}

func callCardDecode(args json.RawMessage) json.RawMessage {
	var a struct {
		VCard *string `json:"vcard"`
		Now   *string `json:"now"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	vcard, err := needStr(a.VCard, "vcard")
	if err != nil {
		return failErr(codeArgs, err)
	}
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
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
}
