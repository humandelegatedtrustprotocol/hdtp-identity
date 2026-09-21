package pactidentity

// The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

// seal is "" for none; extra lines go between the certificate and the seal.
//
// EncodeCard writes a card, and refuses a control character in anything it is handed: a card is
// LINES, and a line break in a name, the seal policy or an extra line writes a property of the
// writer's choosing. The decoder reads the FIRST of a name, so `FN` "x\r\nX-PACT-SEAL:none" made a
// card that requires sealing into one that does not.
func EncodeCard(fn string, cert []byte, seal string, extra []string) (string, error) {
	for _, part := range append([][2]string{{"fn", fn}, {"seal", seal}}, extraParts(extra)...) {
		for _, r := range part[1] {
			if unicode.IsControl(r) {
				return "", argError{part[0] + " carries a control character"}
			}
		}
	}
	lines := []string{"BEGIN:VCARD", "VERSION:4.0", "FN:" + fn, "X-PACT-VERSION:2", "X-PACT-CERT:" + B64url(cert)}
	lines = append(lines, extra...)
	if seal != "" {
		lines = append(lines, "X-PACT-SEAL:"+seal)
	}
	lines = append(lines, "END:VCARD")
	for i, l := range lines {
		lines[i] = fold(l)
	}
	return strings.Join(lines, "\r\n") + "\r\n", nil
}

func extraParts(extra []string) [][2]string {
	out := make([][2]string, 0, len(extra))
	for _, e := range extra {
		out = append(out, [2]string{"extra", e})
	}
	return out
}

func fold(line string) string {
	units := utf16.Encode([]rune(line))
	if len(units) <= 75 {
		return line
	}
	whole := func(i int) int {
		if i > 0 && i < len(units) && units[i-1] >= 0xD800 && units[i-1] < 0xDC00 {
			return i - 1
		}
		return i
	}
	first := whole(75)
	parts := []string{string(utf16.Decode(units[:first]))}
	for i := first; i < len(units); {
		end := whole(min(i+74, len(units)))
		parts = append(parts, " "+string(utf16.Decode(units[i:end])))
		i = end
	}
	return strings.Join(parts, "\r\n")
}

// Card is a decoded 2.0 card.
type Card struct {
	FN       string
	Version  int
	Seal     string
	Cert     []byte
	Leaf     *Cert
	Root     string
	Endpoint string
	Expired  bool
	Ignored  []string
	Bytes    int
}

// CardError is an intake refusal: bad_request with the seed's reason.
type CardError struct{ Why string }

func (e CardError) Error() string { return e.Why }

var unfoldRE = regexp.MustCompile("\r?\n[ \t]")

// DecodeCard is intake per §3: refuses what has no root to pin or no address to reach; an expired leaf
// is not a refusal.
func DecodeCard(text string, now time.Time) (*Card, error) {
	now = now.Truncate(time.Second)
	unfolded := unfoldRE.ReplaceAllString(text, "")
	props := map[string][]string{}
	var order []string
	for _, line := range regexp.MustCompile("\r?\n").Split(unfolded, -1) {
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.ToUpper(strings.SplitN(line[:i], ";", 2)[0])
		if _, ok := props[name]; !ok {
			order = append(order, name)
		}
		props[name] = append(props[name], line[i+1:])
	}
	first := func(name string) (string, bool) {
		v, ok := props[name]
		if !ok || len(v) == 0 {
			return "", false
		}
		return v[0], true
	}
	version, ok := first("X-PACT-VERSION")
	if version != "2" {
		if ok && version != "" {
			return nil, CardError{"version not implemented"}
		}
		return nil, CardError{"no X-PACT-VERSION"}
	}
	certs := props["X-PACT-CERT"]
	if len(certs) != 1 {
		return nil, CardError{fmt.Sprintf("%d certificates", len(certs))}
	}
	leaf, err := Parse(FromB64url(certs[0]))
	if err != nil {
		return nil, CardError{"certificate does not parse: " + err.Error()}
	}
	if leaf.AKI == nil {
		return nil, CardError{"no issuer key identifier"}
	}
	// What is about to be shown to a person as the identity to pin is this value, so it has to BE a
	// key identifier: 32 bytes (§14.1). Three bytes used to come out as `sha256:AQID`.
	if len(leaf.AKI) != 32 {
		return nil, CardError{"issuer key identifier is not 32 bytes"}
	}
	if len(leaf.URIs) != 1 {
		return nil, CardError{fmt.Sprintf("%d endpoints", len(leaf.URIs))}
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > MaxLeafDays*24*time.Hour {
		return nil, CardError{"validity over 398 days"}
	}
	fn, _ := first("FN")
	seal, ok := first("X-PACT-SEAL")
	if !ok {
		seal = "none"
	}
	var ignored []string
	for _, k := range order {
		if strings.HasPrefix(k, "X-PACT-") && k != "X-PACT-VERSION" && k != "X-PACT-CERT" && k != "X-PACT-SEAL" {
			ignored = append(ignored, k)
		}
	}
	return &Card{
		FN: fn, Version: 2, Seal: seal, Cert: leaf.DER, Leaf: leaf, Root: "sha256:" + B64url(leaf.AKI), Endpoint: leaf.URIs[0],
		Expired: leaf.NotAfter.Before(now), Ignored: ignored, Bytes: len(text),
	}, nil
}
