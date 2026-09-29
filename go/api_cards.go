package pactidentity

// The Cards section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name. Each reads its members as api/cards.rs does, in its
// order.

import "encoding/json"

func callCardEncode(a args) json.RawMessage {
	fn, err := a.str("fn")
	if err != nil {
		return failAs(codeArgs, err)
	}
	cert, err := a.bytes("cert")
	if err != nil {
		return failAs(codeArgs, err)
	}
	seal, err := a.optStr("seal")
	if err != nil {
		return failAs(codeArgs, err)
	}
	sealPolicy := ""
	if seal != nil {
		sealPolicy = *seal
	}
	// A list of strings, or `extra is required`: an item that is not a string, null included, is
	// refused, as the core refuses it (T21; it dropped the item and wrote the card without it).
	var extra []string
	if raw := a.present("extra"); raw != nil {
		if raw[0] != '[' || json.Unmarshal(raw, &extra) != nil || holdsNull(raw) {
			return fail(codeArgs, "extra is required")
		}
	}
	vcard, err := EncodeCard(fn, cert, sealPolicy, extra)
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"vcard": vcard})
}

// card_decode reads the card, then the instant it is judged at: the contract's order, which the core
// now reads too (R25).
func callCardDecode(a args) json.RawMessage {
	vcard, err := a.str("vcard")
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
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

// callRefreshCheck judges a peer's answer to get_card against the host's pin (RefreshCheck). Read in
// the contract's order, as the core's refresh_check: the pin, whose members are the host's own and
// named by their path; the answer, which must be there and is otherwise read as it was sent; the
// instant.
func callRefreshCheck(a args) json.RawMessage {
	pin, isObj := a.value("pin").(map[string]any)
	if !isObj {
		return fail(codeArgs, "pin is required")
	}
	root, isText := pin["root"].(string)
	if !isText {
		return fail(codeArgs, "pin.root is required")
	}
	endpoint, isText := pin["endpoint"].(string)
	if !isText {
		return fail(codeArgs, "pin.endpoint is required")
	}
	var leaf []byte
	switch l := pin["leaf"].(type) {
	case nil:
		return fail(codeArgs, "pin.leaf is required")
	case string:
		der, err := DecodeB64url(l)
		if err != nil {
			return failAs("parse", err)
		}
		leaf = der
	default:
		return fail("parse", "not base64url")
	}
	answer := a.present("answer")
	if answer == nil {
		return fail(codeArgs, "answer is required")
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	v, err := RefreshCheck(RefreshPin{Root: root, Endpoint: endpoint, Leaf: leaf}, answer, now)
	if err != nil {
		return failAs("parse", err)
	}
	if !v.OK {
		return ok(map[string]any{"ok": false, "why": v.Why})
	}
	var renewed any
	if v.Renewed != nil {
		renewed = map[string]any{"leaf": B64url(v.Renewed.Leaf), "spki": B64url(v.Renewed.SPKI)}
	}
	return ok(map[string]any{"ok": true, "fn": v.FN, "renewed": renewed, "root_cert": B64url(v.RootCert)})
}
