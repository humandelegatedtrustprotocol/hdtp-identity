package hdtpidentity

// RFC 8785 for the objects HDTP canonicalises: members sorted by UTF-16 code unit, no whitespace,
// numbers in their shortest form, strings escaped as JSON.stringify escapes them.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeJSON reads JSON into the generic shape (map[string]any, []any, json.Number, string, bool, nil),
// keeping numbers as written — and refuses what the core's serde_json refuses and encoding/json
// reads: bytes that are not UTF-8 and a \u escape of half a surrogate pair, both of which
// encoding/json reads as U+FFFD, and what jsonLimit finds. So every text this port reads, an
// envelope's header and body, a manifest, a line of messages.jsonl, is JSON to it exactly when it is
// JSON to the core. A body holding `1e400` was decided `ok` here and refused as `does not open`
// there (R40); so was a header or a body holding "\ud800" or a byte 0xFF, until the review of
// 2026-09-30 (M1).
func decodeJSON(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("not UTF-8")
	}
	if loneSurrogate(b) {
		return nil, errors.New("a string holds half of a UTF-16 surrogate pair")
	}
	if why := jsonLimit(b); why != "" {
		return nil, errors.New(why)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("trailing JSON")
	}
	return v, nil
}

// jsonMaxDepth is how many containers JSON text may nest, one inside another: serde_json refuses the
// 128th, and encoding/json reads ten thousand.
const jsonMaxDepth = 127

// What jsonLimit finds, in the words both ports answer.
const (
	jsonNumberBeyondDouble = "a number is outside the range of a double"
	jsonNestedTooDeep      = "nested more than 127 deep"
)

// jsonLimit is the core's `json_limit` (crates/hdtp-identity/src/util.rs), the same scan: the first
// thing, in text order, that JSON text holds and one port's parser refuses while the other's reads
// it — a number infinite as a double, or containers nested more than jsonMaxDepth deep. Strings are
// skipped, escapes and all. "" when there is none.
func jsonLimit(text []byte) string {
	depth := 0
	for i := 0; i < len(text); {
		switch c := text[i]; {
		case c == '"':
			i++
			for i < len(text) && text[i] != '"' {
				if text[i] == '\\' {
					i++
				}
				i++
			}
			i++
		case c == '[' || c == '{':
			depth++
			if depth > jsonMaxDepth {
				return jsonNestedTooDeep
			}
			i++
		case c == ']' || c == '}':
			if depth > 0 {
				depth--
			}
			i++
		case c == '-' || c >= '0' && c <= '9':
			start := i
			for i < len(text) && strings.IndexByte("0123456789+-.eE", text[i]) >= 0 {
				i++
			}
			// ParseFloat is ±Inf, with ErrRange, for a number past the largest double; a number
			// that underflows is 0 (or a subnormal), not infinite, as it is to serde_json.
			if f, _ := strconv.ParseFloat(string(text[start:i]), 64); math.IsInf(f, 0) {
				return jsonNumberBeyondDouble
			}
		default:
			i++
		}
	}
	return ""
}

// Canonical serialises a generic JSON value per RFC 8785.
func Canonical(v any) []byte {
	var b bytes.Buffer
	writeCanonical(&b, v)
	return b.Bytes()
}

func writeCanonical(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(canonicalNumber(x.String()))
	case float64:
		b.WriteString(es6Number(x))
	case int:
		b.WriteString(canonicalNumber(strconv.Itoa(x)))
	case int64:
		// As the double it is, past 2^53, as every number here: this wrote the int64's digits, so a
		// header's ts of 9007199254740993 was that here and 9007199254740992 in the core and the seed.
		b.WriteString(canonicalNumber(strconv.FormatInt(x, 10)))
	case string:
		writeJSONString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k)
			b.WriteByte(':')
			writeCanonical(b, x[k])
		}
		b.WriteByte('}')
	default:
		raw, _ := json.Marshal(x)
		var generic any
		_ = json.Unmarshal(raw, &generic)
		writeCanonical(b, generic)
	}
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// canonicalNumber prints a JSON number as RFC 8785 does: as ECMAScript's Number would, which means
// as the DOUBLE it is. An integer keeps its digits only while a double holds it exactly (up to 2^53);
// past that the seed — JavaScript — prints the nearest double's shortest form, and so does this.
func canonicalNumber(s string) string {
	const exact = 1 << 53
	if i, err := strconv.ParseInt(s, 10, 64); err == nil && i >= -exact && i <= exact {
		return strconv.FormatInt(i, 10)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	return es6Number(f)
}

// es6Number is Number.prototype.toString for a finite double, as `canonical.rs`'s `number` is: no
// exponent from 1e-6 up to 1e21, and outside that one digit, an optional fraction, `e`, an explicit
// sign and NO leading zero in the exponent. It used to hand everything that was not an integer to
// Go's `%g`, which writes `1e-07` for ECMAScript's `1e-7` and switches to an exponent at 1e-5, where
// ECMAScript still writes `0.00001`; and it printed negative zero as `-0`.
func es6Number(f float64) string {
	if f == 0 {
		return "0"
	}
	if abs := math.Abs(f); abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.TrimLeft(exponent[1:], "0")
	if digits == "" {
		digits = "0"
	}
	return mantissa + "e" + exponent[:1] + digits
}

// writeJSONString escapes as RFC 8785 §3.2.2.2 and JSON.stringify do: quote, backslash, the short
// forms for \b \f \n \r \t, \u00xx for the other controls, everything else raw.
func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				// Written by hand: fmt allocated for each one, which a member of thousands made the
				// reader's cost.
				const hexDigits = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[r>>4])
				b.WriteByte(hexDigits[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// jsonString is JSON.stringify for one string.
func jsonString(s string) string {
	var b bytes.Buffer
	writeJSONString(&b, s)
	return b.String()
}

// inOrder writes a JSON value a caller handed in as it is sealed into a plaintext (params, result,
// error, a vault's document), as the core's canonical::in_order writes it: strings as RFC 8785 writes
// them; an integer the core holds as one (an i64, or a u64 past it: sealedInteger) by its digits, and
// every other number as RFC 8785 writes it; and members in the order they were written, a member
// written twice once, where it first appeared, with the value it was given last — as serde_json's
// preserve_order map and JSON.parse read it. Not sorted: Appendix B's plaintexts write `name` before
// `arguments`. This port
// sealed the caller's text compacted, duplicates, escapes and `1.50` as written, where the core sealed
// the value it had read: two plaintexts for one call.
func inOrder(raw []byte) ([]byte, error) {
	if why := jsonLimit(raw); why != "" {
		return nil, errors.New(why)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readInOrder(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var b bytes.Buffer
	writeInOrder(&b, v)
	return b.Bytes(), nil
}

// inOrderObject is an object as inOrder reads one: its member names in the order they first appeared,
// and each one's last value.
type inOrderObject struct {
	names  []string
	values map[string]any
}

func readInOrder(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := t.(json.Delim)
	if !isDelim {
		return t, nil // json.Number, string, bool or nil
	}
	switch delim {
	case '{':
		o := &inOrderObject{values: map[string]any{}}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, _ := k.(string)
			v, err := readInOrder(d)
			if err != nil {
				return nil, err
			}
			if _, seen := o.values[name]; !seen {
				o.names = append(o.names, name)
			}
			o.values[name] = v
		}
		_, err = d.Token()
		return o, err
	case '[':
		list := []any{}
		for d.More() {
			v, err := readInOrder(d)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		_, err = d.Token()
		return list, err
	}
	return nil, errors.New("not JSON")
}

func writeInOrder(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case *inOrderObject:
		b.WriteByte('{')
		for i, k := range x.names {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k)
			b.WriteByte(':')
			writeInOrder(b, x.values[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeInOrder(b, e)
		}
		b.WriteByte(']')
	case json.Number:
		if sealedInteger(string(x)) {
			b.WriteString(string(x))
		} else {
			writeCanonical(b, x)
		}
	default:
		writeCanonical(b, x)
	}
}

// sealedInteger is a number the core's serde_json holds as an integer, which a sealed value keeps
// by its digits (the owner's choice on M2 of the review of 2026-09-30): digits with an optional
// minus, no fraction and no exponent, within an i64 when negative and a u64 otherwise, and not -0,
// which serde holds as a double. RFC 8785's double is the header's rule (Canonical); this writer
// printed 12345678901234567891 as 12345678901234567000, as the core's did.
func sealedInteger(s string) bool {
	if s == "-0" || strings.ContainsAny(s, ".eE") {
		return false
	}
	if strings.HasPrefix(s, "-") {
		_, err := strconv.ParseInt(s, 10, 64)
		return err == nil
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// sortedKeys joins an object's member names in code-point order with commas — the seed's
// Object.keys(x).sort().join(',') — which is how header and plaintext shapes are checked.
func sortedKeys(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	return strings.Join(keys, ",")
}
