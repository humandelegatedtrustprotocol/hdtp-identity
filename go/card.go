package hdtpidentity

// The §3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// seal is "" for none; extra lines go between the certificate and the seal.
//
// EncodeCard writes a card, and refuses a control character in anything it is handed: a card is
// LINES, and a line break in a name, the seal policy or an extra line writes a property of the
// writer's choosing. The decoder reads the FIRST of a name, so `FN` "x\r\nX-HDTP-SEAL:none" made a
// card that requires sealing into one that does not.
func EncodeCard(fn string, cert []byte, seal string, extra []string) (string, error) {
	for _, part := range append([][2]string{{"fn", fn}, {"seal", seal}}, extraParts(extra)...) {
		for _, r := range part[1] {
			if unicode.IsControl(r) {
				return "", argError{part[0] + " carries a control character"}
			}
		}
	}
	lines := []string{"BEGIN:VCARD", "VERSION:4.0", "FN:" + fn, "X-HDTP-VERSION:1", "X-HDTP-CERT:" + B64url(cert)}
	lines = append(lines, extra...)
	if seal != "" {
		lines = append(lines, "X-HDTP-SEAL:"+seal)
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

// fold is RFC 6350 §3.2 folding: a line is at most 75 octets, a continuation a space and at most 74
// more, and a break never falls inside a UTF-8 sequence — it moves back to the start of the character.
func fold(line string) string {
	if len(line) <= 75 {
		return line
	}
	var parts []string
	for i, width := 0, 75; i < len(line); width = 74 {
		end := min(i+width, len(line))
		for end < len(line) && !utf8.RuneStart(line[end]) {
			end--
		}
		if i == 0 {
			parts = append(parts, line[:end])
		} else {
			parts = append(parts, " "+line[i:end])
		}
		i = end
	}
	return strings.Join(parts, "\r\n")
}

// Card is a decoded card.
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

var (
	unfoldRE = regexp.MustCompile("\r?\n[ \t]")
	lineRE   = regexp.MustCompile("\r?\n")
	// propertyRE is a line that STARTS A PROPERTY: `[group.]NAME[;params]:`, the group and the name of
	// ASCII letters, digits and `-` — the seed's PROPERTY, and the core's starts_property. A base64url
	// line never matches: it has no `:`.
	propertyRE = regexp.MustCompile(`^(?:[A-Za-z0-9-]+\.)?[A-Za-z0-9-]+(?:;[^:]*)?:`)
	// cardWhitespace is what a base64url value loses: space, tab, CR and LF, and nothing else.
	cardWhitespace = strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")
)

// b64urlProperties are the base64url-valued properties a card carries, read by step 3 of DecodeCard.
var b64urlProperties = []string{"X-HDTP-CERT"}

// DecodeCard is intake per §3: refuses what has no root to pin or no address to reach; an expired leaf
// is not a refusal.
//
// Reading a card (§3, "Reading a card"), in three steps, as the seed's decodeCard and the core read one:
//  1. RFC 6350 §3.2 unfolding: a line break, CRLF or LF, followed by ONE space or tab is removed, and
//     the text is split into lines at CRLF or LF;
//  2. a line starts a property when it begins `[group.]NAME[;params]:` (propertyRE);
//  3. a base64url-valued property (b64urlProperties: X-HDTP-CERT) also takes every following line that
//     starts no property, and its value loses every space, tab, CR and LF.
//
// Step 3 reads a card whose folding was damaged in transit: pasted through a chat, which drops a
// continuation's leading space or adds blank lines. Base64url has none of those four characters, so
// removing them gives back the writer's bytes whenever nothing else was damaged. A character that was
// changed or lost still is, and is caught where it always was: by the DER parse below, or by chain
// validation (§14.2) at the first exchange, since a card carries no root to check its leaf against.
// Any other line that starts no property is ignored.
func DecodeCard(text string, now time.Time) (*Card, error) {
	now = now.Truncate(time.Second)
	unfolded := unfoldRE.ReplaceAllString(text, "")
	props := map[string][]string{}
	var order []string
	joining := "" // the base64url property whose last value later lines join, while they start no property
	for _, line := range lineRE.Split(unfolded, -1) {
		if !propertyRE.MatchString(line) {
			if joining != "" {
				v := props[joining]
				v[len(v)-1] += line
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		name := strings.ToUpper(strings.SplitN(line[:i], ";", 2)[0])
		if _, ok := props[name]; !ok {
			order = append(order, name)
		}
		props[name] = append(props[name], line[i+1:])
		joining = ""
		if slices.Contains(b64urlProperties, name) {
			joining = name
		}
	}
	for _, name := range b64urlProperties {
		for j, v := range props[name] {
			props[name][j] = cardWhitespace.Replace(v)
		}
	}
	first := func(name string) (string, bool) {
		v, ok := props[name]
		if !ok || len(v) == 0 {
			return "", false
		}
		return v[0], true
	}
	version, ok := first("X-HDTP-VERSION")
	if version != "1" {
		if ok && version != "" {
			return nil, CardError{"version not implemented"}
		}
		return nil, CardError{"no X-HDTP-VERSION"}
	}
	certs := props["X-HDTP-CERT"]
	if len(certs) != 1 {
		return nil, CardError{fmt.Sprintf("%d certificates", len(certs))}
	}
	// Read strictly, as the core reads it and the seed's card.mjs now does: this port skipped a stray
	// character, so a card whose certificate carried one was taken here and refused by the core (C7).
	der, err := DecodeB64url(certs[0])
	if err != nil {
		return nil, CardError{"certificate does not parse: " + err.Error()}
	}
	leaf, err := Parse(der)
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
	seal, ok := first("X-HDTP-SEAL")
	if !ok {
		seal = "none"
	}
	var ignored []string
	for _, k := range order {
		if strings.HasPrefix(k, "X-HDTP-") && k != "X-HDTP-VERSION" && k != "X-HDTP-CERT" && k != "X-HDTP-SEAL" {
			ignored = append(ignored, k)
		}
	}
	return &Card{
		FN: fn, Version: 1, Seal: seal, Cert: leaf.DER, Leaf: leaf, Root: "sha256:" + B64url(leaf.AKI), Endpoint: leaf.URIs[0],
		Expired: leaf.NotAfter.Before(now), Ignored: ignored, Bytes: len(text),
	}, nil
}
