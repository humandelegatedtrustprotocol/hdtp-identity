package pactidentity

// A function's arguments as the caller wrote them: each member's JSON text, by its exact name.
//
// `Call` reads the object once, holds it to the members the function declares (CONTRACT §0: a member
// the function does not declare is refused by name, before any member is read), and hands it to the
// function, which reads each member in the order it needs it. The export section read its arguments
// this way already (api/export.rs's order, its words); every section now does.
//
// A map rather than a struct: encoding/json matches a struct's fields without regard to case, so
// `{"CN": ...}` filled `cn` here and was an undeclared member to the Rust core, and a struct cannot
// tell a member that is absent from one that is its zero value.

import (
	"encoding/json"
	"strconv"
	"time"
)

type args map[string]json.RawMessage

// readArgs is the arguments `Call` was handed, as an object: none at all is `{}`.
func readArgs(raw json.RawMessage) (args, json.RawMessage) {
	a := args{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fail(codeArgs, "args is a JSON object")
		}
	}
	return a, nil
}

func (a args) value(k string) any {
	raw, has := a[k]
	if !has {
		return nil
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return nil
	}
	return v
}

// text is a string member, decoded straight into a string: a 16 MiB CSV member decoded through a
// generic Decoder was buffered twice over before it was a string once.
func (a args) text(k string) (string, bool) {
	raw, has := a[k]
	if !has || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// str is the core's `s`: a string, or `<k> is required`.
func (a args) str(k string) (string, error) {
	s, isText := a.text(k)
	if !isText {
		return "", errArg(k + " is required")
	}
	return s, nil
}

// present is a member's JSON text, or nil when it is absent or null: CONTRACT §0, the JSON literal
// null counts as absent.
func (a args) present(k string) json.RawMessage {
	raw := a[k]
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// id is the core's `id`: a string that is not empty, or `<k> is required`.
func (a args) id(k string) (string, error) {
	s, err := a.str(k)
	if err == nil && s == "" {
		err = errArg(k + " is required")
	}
	return s, err
}

// optStr is the core's `opt_s`, an optional string: absent or null is nil; present and not a string
// is `<k> is required`, CONTRACT §0's answer for a member of the wrong type.
func (a args) optStr(k string) (*string, error) {
	if a.present(k) == nil {
		return nil, nil
	}
	s, err := a.str(k)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// instant is the core's `instant`: a required RFC 3339 instant in the one grammar (parseInstantZ).
// Absent or not a string is `<k> is required`; present and unreadable is `parse`, in the core's words.
func (a args) instant(k string) (time.Time, error) {
	s, err := a.str(k)
	if err != nil {
		return time.Time{}, err
	}
	t, ok := parseInstantZ(s)
	if !ok {
		return time.Time{}, parseError{"not an RFC 3339 instant: " + s}
	}
	return t, nil
}

// optInstant is the core's `opt_instant`: optStr's reading, then the instant's.
func (a args) optInstant(k string) (*time.Time, error) {
	s, err := a.optStr(k)
	if s == nil || err != nil {
		return nil, err
	}
	t, ok := parseInstantZ(*s)
	if !ok {
		return nil, parseError{"not an RFC 3339 instant: " + *s}
	}
	return &t, nil
}

// bytes is the core's `bytes`: absent or null is `<k> is required`; present and not a base64url
// string is `parse`, `not base64url`.
func (a args) bytes(k string) ([]byte, error) {
	if a.present(k) == nil {
		return nil, errArg(k + " is required")
	}
	return a.optBytes(k)
}

// optBytes is the core's `opt_bytes`: absent or null is nil; a member of the wrong type is refused as
// bytes that will not decode; `""` is a non-nil empty slice.
func (a args) optBytes(k string) ([]byte, error) {
	if a.present(k) == nil {
		return nil, nil
	}
	s, isText := a.text(k)
	if !isText {
		return nil, parseError{"not base64url"}
	}
	b, err := decodeB64url(s)
	if b == nil && err == nil {
		b = []byte{}
	}
	return b, err
}

// int is the core's `int`: an integer as integerText reads one; anything else, absent and null
// included, is `<k> is required`.
func (a args) int(k string) (int64, error) {
	n, err := a.optInt(k)
	if err == nil && n == nil {
		err = errArg(k + " is required")
	}
	if err != nil {
		return 0, err
	}
	return *n, nil
}

// optInt is the core's `opt_int`, an optional integer: absent or null is nil; present and not an
// integer is `<k> is required`.
func (a args) optInt(k string) (*int64, error) {
	raw := a.present(k)
	if raw == nil {
		return nil, nil
	}
	n, isInt := integerText(string(raw))
	if !isInt {
		return nil, errArg(k + " is required")
	}
	return &n, nil
}

// integerText is a JSON number as the core reads an integer (serde_json's `as_i64`): digits with an
// optional minus, no fraction, no exponent, within 64 bits — and not `-0`, which serde_json reads as
// the float negative zero. strconv reads `-0` as 0, and so this port sealed an `exp` of -0 as 0 and
// charged a limits `now` of -0 where the core refused both (S3-1).
func integerText(s string) (int64, bool) {
	if s == "-0" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// boolean is the core's `boolean`, an optional boolean: absent or null is false; present and not a
// boolean is `<k> is required`.
func (a args) boolean(k string) (bool, error) {
	switch string(a.present(k)) {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errArg(k + " is required")
}

// chain is the core's `chain`: a list of base64url strings. Not a list — absent and null included —
// is `<k> is required`; an item that is not a base64url string, null included, is `not base64url`.
func (a args) chain(k string) ([][]byte, error) {
	raw := a.present(k)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errArg(k + " is required")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, errArg(k + " is required")
	}
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		var s string
		if len(item) == 0 || item[0] != '"' || json.Unmarshal(item, &s) != nil {
			return nil, parseError{"not base64url"}
		}
		b, err := decodeB64url(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// optChain is the core's `opt_chain`: absent or null is an empty list, anything else is `chain`.
func (a args) optChain(k string) ([][]byte, error) {
	if a.present(k) == nil {
		return [][]byte{}, nil
	}
	return a.chain(k)
}

// presentChain is the core's `present_chain`: absent or null is nil, anything else is `chain` — a
// chain that was sent and does not read is never one that was not sent.
func (a args) presentChain(k string) ([][]byte, error) {
	if a.present(k) == nil {
		return nil, nil
	}
	return a.chain(k)
}

// seed32 is the core's `seed32`: an optional member of exactly 32 bytes (`<k> is 32 bytes`).
func (a args) seed32(k string) ([]byte, error) {
	b, err := a.optBytes(k)
	if err != nil || b == nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errArg(k + " is 32 bytes")
	}
	return b, nil
}

// serial is §14.1's serial rule, the core's `serial`: absent means one is made (nil here; BuildRoot
// and BuildLeaf make it), and a serial that is given is 8 to 20 bytes — the width the profile fixes
// so a serial cannot be a channel or a collision.
func (a args) serial() ([]byte, error) {
	b, err := a.optBytes("serial")
	if err != nil || b == nil {
		return nil, err
	}
	if len(b) < 8 || len(b) > 20 {
		return nil, errArg("serial is 8 to 20 bytes")
	}
	return b, nil
}

// validDays is the core's `valid_days`: absent or null is a year; present and not an integer is
// `valid_days is required`, never a year it was not asked for; outside 1–398 is refused.
func (a args) validDays() (int, error) {
	n, err := a.optInt("valid_days")
	if err != nil {
		return 0, err
	}
	if n == nil {
		return 365, nil
	}
	if *n < 1 || *n > MaxLeafDays {
		return 0, errArg("validity must be between one and 398 days")
	}
	return int(*n), nil
}

// dnsName is an optional `dns_name`: absent or null is none (the typed CSRNew and LeafOpts read ""
// as none, which a Go caller means by it); present and empty is refused, `dns_name is empty`. The
// core wrote an empty dNSName for it, which csr_check and rule 5 then refuse, and this port wrote
// none (R26, F4).
func (a args) dnsName() (string, error) {
	dns, err := a.optStr("dns_name")
	if err != nil || dns == nil {
		return "", err
	}
	if *dns == "" {
		return "", errArg("dns_name is empty")
	}
	return *dns, nil
}

// priv and pub are the core's `private` and `public`: the member's bytes, then the key parser, whose
// refusal names what is wrong with them.
func (a args) priv(k string) (*PrivateKey, error) {
	der, err := a.bytes(k)
	if err != nil {
		return nil, err
	}
	return ParsePKCS8(der)
}

func (a args) pub(k string) (*PublicKey, error) {
	der, err := a.bytes(k)
	if err != nil {
		return nil, err
	}
	return ParseSPKI(der)
}

func (a args) list(k string) ([]any, error) {
	l, isList := a.value(k).([]any)
	if !isList {
		return nil, errArg(k + " is required")
	}
	return l, nil
}

func (a args) optList(k string) ([]any, error) {
	switch v := a.value(k).(type) {
	case nil:
		return []any{}, nil
	case []any:
		return v, nil
	}
	return nil, errArg(k + " is required")
}

// strings is a list of strings, decoded straight into one: a list of an id per message decoded as
// a list of interfaces first held each id twice over. A member that is not a list is `<k> is
// required`; a list holding anything but strings — null included, which a decoder into strings
// would quietly read as "" — is `<k> is a list of strings`.
func (a args) strings(k string) ([]string, error) {
	raw, has := a[k]
	if !has || len(raw) == 0 || raw[0] != '[' {
		return nil, errArg(k + " is required")
	}
	out := []string{}
	if json.Unmarshal(raw, &out) != nil || holdsNull(raw) {
		return nil, errArg(k + " is a list of strings")
	}
	return out, nil
}

// holdsNull is whether JSON text holds a null outside every string in it.
func holdsNull(raw []byte) bool {
	in := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case in && c == '\\':
			i++
		case c == '"':
			in = !in
		case !in && c == 'n':
			return true
		}
	}
	return false
}

func (a args) count(k string) (uint64, error) {
	v := a.value(k)
	if v == nil {
		return 0, nil
	}
	n, ok := asU64(v)
	if !ok {
		return 0, errArg(k + " is a whole number")
	}
	return n, nil
}
