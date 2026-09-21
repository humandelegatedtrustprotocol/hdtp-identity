package pactidentity

// A base64url member of a request, decoded strictly.
//
// `FromB64url` is lenient, as the seed library's `Buffer.from(s, 'base64url')` is: it skips every
// character outside the alphabet and cannot fail. That is the right reading for bytes already on the
// wire, where the seed is the authority. It is the wrong reading for an argument a caller hands the
// boundary, and the difference was a hole: `csr_check`'s `root_spkis` decoded "!!!" to no bytes at
// all, so §9's root-key refusal — which matches the request's key against every root it was given —
// had nothing to match and accepted a CSR carrying the root's own key. The Rust core's `from_b64u`
// refuses the same input, so the two ports answered differently on the same call, which CONTRACT §0
// forbids.
//
// Declaring a request field as B64 makes that impossible to reintroduce: a member that is not
// base64url is a caller's mistake reported as `parse`, never an empty byte string.
//
// A B64 also carries whether the member was there at all. An absent member leaves the field nil; a
// member present as `""` decodes to a non-nil empty slice. The Rust core draws exactly that line —
// absent answers "<name> is required", present-but-empty falls through to the parser, which says
// what is wrong with no bytes — so every required-member check below asks `== nil`, never `len()`.
// The literal `null` is the trap in the middle: encoding/json calls UnmarshalJSON for it rather than
// leaving the field alone, so it is caught here and treated as absent, which is what it means.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// parseError names bytes that will not decode, so `codeFor` answers `parse` where the Rust core does.
type parseError struct{ why string }

func (e parseError) Error() string { return e.why }

// B64 is a base64url byte string in a request. Padding and the standard alphabet's `+/` are accepted
// (the Rust core accepts both too); anything else is refused.
type B64 []byte

func (b *B64) UnmarshalJSON(p []byte) error {
	if string(bytes.TrimSpace(p)) == "null" {
		return nil // an explicit null is an absent member, and stays nil
	}
	var s string
	if err := json.Unmarshal(p, &s); err != nil {
		return parseError{"not base64url"}
	}
	out, err := decodeB64url(s)
	if err != nil {
		return err
	}
	*b = out
	return nil
}

// MarshalJSON keeps a B64 field printable in the same form it arrives in, for any struct reused as output.
func (b B64) MarshalJSON() ([]byte, error) { return json.Marshal(B64url(b)) }

func decodeB64url(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		case '+':
			return '-'
		case '/':
			return '_'
		}
		return r
	}, s)
	// Strict: the UNUSED low bits of a last character must be zero, as the core's decoder requires.
	// Without it `…QQ` and `…QR` are one byte string, the signature — which covers the decoded bytes —
	// verifies over both, and this port accepted a second spelling of an envelope the core refuses.
	out, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(cleaned, "="))
	if err != nil {
		return nil, parseError{"not base64url"}
	}
	return out, nil
}

// wireB64url reads a member of an envelope as it travels: unpadded base64url in its ONE canonical
// spelling (§13.1), as the core's `wire_b64u` does. decodeB64url is for what a caller hands the
// boundary and forgives padding, the standard alphabet and whitespace; none of that may be forgiven
// on the wire, because `sig` covers the DECODED bytes and every spelling a reader accepts is another
// envelope that verifies. encoding/base64 silently skips CR and LF even in strict mode, so they are
// refused by hand.
func wireB64url(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, parseError{"not base64url"}
	}
	out, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, parseError{"not base64url"}
	}
	return out, nil
}

// Bytes is the decoded value; a nil B64 is an absent member, which each function judges for itself.
func (b B64) Bytes() []byte { return []byte(b) }

// chainOf turns a list of base64url members into DER, having already decoded them strictly.
func chainOf(list []B64) [][]byte {
	out := make([][]byte, 0, len(list))
	for _, c := range list {
		out = append(out, []byte(c))
	}
	return out
}

var errNotB64 = errors.New("not base64url")
