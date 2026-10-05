package hdtpidentity

// §3, Reading a card: a card whose folding a paste damaged reads, and a property after the certificate
// is not swallowed into it. Damage that is not whitespace is what it was: a cut certificate is refused
// by the DER parse, and a changed character reads, as a certificate its root did not sign.

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// pastedCard is a card as a chat delivered the owner's on 2026-10-05: every continuation of
// X-HDTP-CERT without its leading space but the third, a blank line after the first and the fourth,
// LF line ends. The seed's vectors/check.mjs damages its card the same way.
func pastedCard(t *testing.T, card string) string {
	t.Helper()
	lines := strings.Split(card, "\r\n")
	first := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "X-HDTP-CERT:") })
	conts := 0
	for _, l := range lines[first+1:] {
		if strings.HasPrefix(l, " ") {
			conts++
		}
	}
	if conts < 4 {
		t.Fatalf("the certificate is folded over %d lines, too few to damage", conts+1)
	}
	for k := 1; k <= conts; k++ {
		l := lines[first+k]
		if k != 3 {
			l = l[1:]
		}
		if k == 1 || k == 4 {
			l += "\n"
		}
		lines[first+k] = l
	}
	return strings.Join(lines, "\n")
}

func TestCardAsAChatDeliversIt(t *testing.T) {
	v := loadVectors(t)
	leaf, root := hexBytes(t, v.Certificates["leaf_a"].DerHex), hexBytes(t, v.Certificates["root_a"].DerHex)
	now := mustTime(t, v.Now)
	card, err := EncodeCard("Alina Rao", leaf, "required", nil)
	if err != nil {
		t.Fatal(err)
	}
	pasted := pastedCard(t, card)
	certValue := regexp.MustCompile(`X-HDTP-CERT:[\s\S]*?\r\nX-HDTP-SEAL`)
	withCert := func(value string) string {
		return certValue.ReplaceAllLiteralString(card, "X-HDTP-CERT:"+value+"\r\nX-HDTP-SEAL")
	}
	b64 := B64url(leaf)
	for _, tc := range []struct{ what, text, seal string }{
		{"as the owner pasted it", pasted, "required"},
		{"folded correctly (the control)", card, "required"},
		{"not folded at all", strings.ReplaceAll(card, "\r\n ", ""), "required"},
		{"with a space and a tab inside", withCert(b64[:9] + " \t" + b64[9:]), "required"},
		{"pasted, then X-HDTP-SEAL:none", strings.Replace(pasted, "X-HDTP-SEAL:required", "X-HDTP-SEAL:none", 1), "none"},
		{"pasted, then a group-prefixed property and the seal", strings.Replace(pasted, "X-HDTP-SEAL:required", "item1.EMAIL;type=INTERNET:a@example.com\nX-HDTP-SEAL:optional", 1), "optional"},
	} {
		c, err := DecodeCard(tc.text, now)
		if err != nil {
			t.Errorf("a card %s: %v", tc.what, err)
			continue
		}
		if !bytes.Equal(c.Cert, leaf) || c.Seal != tc.seal {
			t.Errorf("a card %s: another certificate or seal %q; want the leaf and seal %q", tc.what, c.Seal, tc.seal)
		}
	}
	// A vertical tab and a no-break space are not what a fold or a paste writes: still refused.
	for _, bad := range []string{"\v", " "} {
		if _, err := DecodeCard(withCert(b64[:9]+bad+b64[9:]), now); err == nil || err.Error() != "certificate does not parse: not base64url" {
			t.Errorf("a certificate with %q inside: %v", bad, err)
		}
	}
	// Cut at 120 characters, a multiple of four: the base64url reads, the DER does not.
	if _, err := DecodeCard(withCert(b64[:120]), now); err == nil || !strings.HasPrefix(err.Error(), "certificate does not parse: ") {
		t.Errorf("a cut certificate: %v", err)
	}
	// One character of the signature changed, the value broken over two lines with no fold: the card
	// reads, its certificate is another leaf, and the chain does not validate.
	mid := len(b64) - 30
	swap := "A"
	if b64[mid] == 'A' {
		swap = "B"
	}
	changed := b64[:mid] + swap + b64[mid+1:]
	c, err := DecodeCard(withCert(changed[:60]+"\n"+changed[60:]), now)
	if err != nil || bytes.Equal(c.Cert, leaf) {
		t.Fatalf("a changed character: %v; want another leaf, read", err)
	}
	if r := ValidateChain([][]byte{c.Cert, root}, ChainOpts{Now: now}); r.OK || r.Rule != 3 {
		t.Errorf("a changed character: chain %+v, want refused by rule 3", r)
	}
	if r := ValidateChain([][]byte{leaf, root}, ChainOpts{Now: now}); !r.OK {
		t.Errorf("the unchanged leaf (the control): %+v", r)
	}
}
