package pactidentity

// Refreshing ONE contact's card (SPEC §3, §14.3): what a peer's answer to `get_card` proves about a
// pinned contact, and what the pin should become. Written once, below both hosts, as the core's
// refresh.rs: the node's verifyRefreshedCard (internal/node/refresh.go) and the cloud's
// (gateway/src/identity/refresh.ts) ran the same checks in different orders, refused in different
// words, and the node verified the card signature with its own non-strict verifier (CW-08, N6).
//
// A refresh can move a LEAF and never an ADDRESS or a ROOT: the chain is validated against the pinned
// root, which nothing can change (§14.3), and against the pinned endpoint, so a chain valid somewhere
// else is §5.3's business and is refused here. The answer is the peer's, read as it was sent: anything
// wrong with it is a refusal (OK false, Why), never an error. The pin is the host's own state: a pinned
// leaf that does not read is the error, in its reader's class.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// RefreshPin is the half of a pin a refresh is judged against: the root, the endpoint, and the leaf
// (DER) pinned there.
type RefreshPin struct {
	Root, Endpoint string
	Leaf           []byte
}

// RefreshVerdict is what a refresh proved. When OK, FN is the card's name, Renewed the newer leaf the
// chain proved (nil when the leaf is the pinned one), and RootCert the pinned root's certificate,
// which a pin made over a sealed call never had. When not, Why says what the answer did not prove.
type RefreshVerdict struct {
	OK       bool
	Why      string
	FN       string
	Renewed  *RenewedLeaf
	RootCert []byte
}

// RenewedLeaf is a newer leaf a refresh proved, and its key's SubjectPublicKeyInfo.
type RenewedLeaf struct {
	Leaf, SPKI []byte
}

// refreshPinRoot is the core's refresh::pin_root: the pin's root is a fingerprint (the contract's
// Fingerprint), or the call is refused. A root the host holds that is not one is the host's fault, and
// compared with the card's it read as "the card names another root", a refusal of what the peer
// answered. The adapter asks this as it reads the pin, before the answer; RefreshCheck asks it first.
func refreshPinRoot(root string) error {
	if !IsFingerprint(root) {
		return errArg("pin.root is not a fingerprint")
	}
	return nil
}

// RefreshCheck judges the peer's answer, {card, card_sig, chain} as it was sent, against the pin at
// now. In this order: the signed card is there; the chain is two certificates; its members decode;
// the card decodes; the card names the pinned root; the chain validates to the pinned root at the
// pinned endpoint; the leaf is not older than the pinned one, nor a different one of the same date;
// the card carries the leaf the chain proved; the card's signature decodes and verifies under it.
func RefreshCheck(pin RefreshPin, answer json.RawMessage, now time.Time) (RefreshVerdict, error) {
	now = now.Truncate(time.Second)
	// The host's own pin first, whatever the peer sent.
	if err := refreshPinRoot(pin.Root); err != nil {
		return RefreshVerdict{}, err
	}
	if _, err := Parse(pin.Leaf); err != nil {
		return RefreshVerdict{}, classed(err)
	}
	refused := func(why string) (RefreshVerdict, error) { return RefreshVerdict{Why: why}, nil }
	var doc map[string]any
	if v, err := decodeJSON(answer); err == nil {
		doc, _ = v.(map[string]any)
	}
	card, _ := doc["card"].(string)
	sig, _ := doc["card_sig"].(string)
	if card == "" || sig == "" {
		return refused("the answer to get_card carries no signed card")
	}
	items, _ := doc["chain"].([]any)
	var members []string
	for _, it := range items {
		if s, isText := it.(string); isText && s != "" {
			members = append(members, s)
		}
	}
	if len(items) != 2 || len(members) != 2 {
		return refused(fmt.Sprintf("the answer carries %d certificate(s); get_card answers with the chain, leaf then root (§6.1)", len(items)))
	}
	chain := make([][]byte, 0, 2)
	for _, m := range members {
		der, err := DecodeB64url(m)
		if err != nil {
			return refused("a chain member is not base64url")
		}
		chain = append(chain, der)
	}
	c, err := DecodeCard(card, now)
	if err != nil {
		return refused("the card does not decode: " + err.Error())
	}
	if c.Root != pin.Root {
		return refused("the card names another root, not the pinned one")
	}
	// The pin's root and endpoint are always given, "" included, as the core's Some(..) compares them.
	vr := ValidateChain(chain, ChainOpts{Now: now, ExpectedRoot: pin.Root, ExpectedEndpoint: pin.Endpoint, rootGiven: true, endpointGiven: true})
	if !vr.OK {
		return refused(fmt.Sprintf("the chain it answered with fails rule %d: %s", vr.Rule, vr.Reason))
	}
	// Both leaves read (the pinned one above, the presented one in the chain), so this cannot fail.
	order, err := CompareLeaves(pin.Leaf, chain[0])
	if err != nil {
		return RefreshVerdict{}, classed(err)
	}
	var renewed *RenewedLeaf
	switch order {
	case "newer":
		renewed = &RenewedLeaf{Leaf: chain[0], SPKI: vr.LeafKey.SPKI}
	case "superseded":
		return refused("the leaf it answered with is superseded by the pinned one (§14.3)")
	case "conflict":
		return refused("two different leaves claim the same notBefore (§14.3)")
	}
	// Signed by the right key is not enough: the same host key can sign a card that embeds some other
	// certificate, and that card would be stored, shown and exported as this contact's.
	if !bytes.Equal(c.Cert, chain[0]) {
		return refused("the card's certificate is not the leaf the chain proved")
	}
	sigBytes, err := DecodeB64url(sig)
	if err != nil {
		return refused("the card signature is not base64url")
	}
	if !VerifyDetached(vr.LeafKey, []byte(card), sigBytes) {
		return refused("the card signature does not verify under the proven leaf key")
	}
	return RefreshVerdict{OK: true, FN: c.FN, Renewed: renewed, RootCert: chain[1]}, nil
}
