package pactidentity

// RFC 8785 for the objects PACT canonicalises: members sorted by UTF-16 code unit, no whitespace,
// numbers in their shortest form, strings escaped as JSON.stringify escapes them.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// decodeJSON reads JSON into the generic shape (map[string]any, []any, json.Number, string, bool, nil),
// keeping numbers as written.
func decodeJSON(b []byte) (any, error) {
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
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
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
				fmt.Fprintf(b, `\u%04x`, r)
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

// compactJSON removes insignificant whitespace from a JSON document without re-escaping it.
func compactJSON(raw []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
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
