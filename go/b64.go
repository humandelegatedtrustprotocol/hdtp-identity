package hdtpidentity

// Bytes as base64url, read by one of two rules and never by a third.
//
// DecodeB64url is for bytes a caller hands the boundary, and for every string this port reads that
// it did not write itself: a card's certificate, a peer's plaintext chain, a pin, a held key, a
// vault's salt, nonce and ciphertext (CONTRACT §0). It forgives the padding and the standard
// alphabet's `+` and `/`, and refuses everything else as `parse`, `not base64url`: a character
// outside the alphabet, whitespace of any kind included, and a last character with a spare bit set.
// js/b64url-arguments.json is the list of cases it and the Rust core's `from_b64u` are held to. This
// port forgave space, tab, CR and LF and the core every Unicode whitespace character, so a key with a
// vertical tab in it was a key to one and `parse` to the other (C10); the contract forgives padding
// and alphabet, and no whitespace.
//
// wireB64url is for the four members of an envelope that travelled (CONTRACT §5), and forgives
// nothing.
//
// There was a third: `FromB64url`, lenient as Node's `Buffer.from(s, 'base64url')` is, which skipped
// every character outside the alphabet and could not fail. This port read a card's certificate, a
// peer's plaintext chain, a pin's leaf, a held key and a vault's ciphertext with it, so a stray `!`
// in any of them was a card, a chain, a key or a vault this port took and the Rust core refused (X9,
// C7, C8, T10, R23), and `csr_check`'s `root_spkis` once decoded "!!!" to no bytes at all, so §9's
// root-key refusal had nothing to match. It is gone; nothing reads bytes that way now.
//
// Absent and present-but-empty stay apart at the boundary (api_args.go's `bytes`, `optBytes` and
// `chain`): absent is `<name> is required`, `""` is no bytes, which the parser then says is wrong —
// as the core draws the line.

import (
	"encoding/base64"
	"strings"
)

// parseError names bytes that will not decode, so `codeFor` answers `parse` where the Rust core does.
type parseError struct{ why string }

func (e parseError) Error() string { return e.why }

// DecodeB64url reads bytes this port did not write: base64url, forgiving the padding and the standard
// alphabet, and nothing else. What does not read is a parse error, `not base64url`.
func DecodeB64url(s string) ([]byte, error) {
	// encoding/base64 skips CR and LF even in strict mode, so they are refused by hand.
	if strings.ContainsAny(s, "\r\n") {
		return nil, parseError{"not base64url"}
	}
	cleaned := strings.Map(func(r rune) rune {
		switch r {
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
// spelling (§13.1), as the core's `wire_b64u` does. DecodeB64url is for what a caller hands the
// boundary and forgives padding and the standard alphabet; none of that may be forgiven
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
