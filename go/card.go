package pactidentity

// The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

// EncodeCard writes a 2.0 card. seal is "" for none; extra lines go between the certificate and the seal.
func EncodeCard(fn string, cert []byte, seal string, extra []string) string {
	lines := []string{"BEGIN:VCARD", "VERSION:4.0", "FN:" + fn, "X-PACT-VERSION:2", "X-PACT-CERT:" + B64url(cert)}
	lines = append(lines, extra...)
	if seal != "" {
		lines = append(lines, "X-PACT-SEAL:"+seal)
	}
	lines = append(lines, "END:VCARD")
	for i, l := range lines {
		lines[i] = fold(l)
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// EncodeCompatCard is Appendix C: a 1.x card toward a peer known to be 1.x, the leaf carried as an extra.
func EncodeCompatCard(fn string, cert []byte, seal string) (string, error) {
	leaf, err := Parse(cert)
	if err != nil {
		return "", err
	}
	if len(leaf.URIs) != 1 {
		return "", fmt.Errorf("%d endpoints", len(leaf.URIs))
	}
	lines := []string{"BEGIN:VCARD", "VERSION:4.0", "FN:" + fn, "X-PACT-VERSION:1", "X-PACT-ENDPOINT:" + leaf.URIs[0], "X-PACT-KEY:" + FingerprintOf(leaf), "X-PACT-CERT:" + B64url(cert)}
	if seal != "" {
		lines = append(lines, "X-PACT-SEAL:"+seal)
	}
	lines = append(lines, "END:VCARD")
	for i, l := range lines {
		lines[i] = fold(l)
	}
	return strings.Join(lines, "\r\n") + "\r\n", nil
}

// fold breaks a line with one-space continuations, counted in UTF-16 code units — what the seed
// library counts, and so the definition every port follows (CONTRACT §0). Counting octets (as this
// once did) or code points makes three implementations that agree only on ASCII. Where a break
// would fall between the halves of a surrogate pair it moves one unit earlier, so the pair stays
// whole; the seed emits a lone surrogate there, which UTF-8 cannot carry.
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
