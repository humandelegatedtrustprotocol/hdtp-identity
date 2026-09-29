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
// So every base64url member a caller hands the boundary is read by decodeB64url (api_args.go's
// `bytes`, `optBytes` and `chain`): a member that is not base64url is a caller's mistake reported as
// `parse`, never an empty byte string. Absent and present-but-empty stay apart there — absent is
// `<name> is required`, `""` is no bytes, which the parser then says is wrong — as the core draws
// the line.

import (
	"encoding/base64"
	"strings"
)

// parseError names bytes that will not decode, so `codeFor` answers `parse` where the Rust core does.
type parseError struct{ why string }

func (e parseError) Error() string { return e.why }

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
