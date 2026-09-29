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

// optStr is the core's `opt_s`: anything but a string is absent.
func (a args) optStr(k string) *string {
	s, isText := a.text(k)
	if !isText {
		return nil
	}
	return &s
}

func (a args) instant(k string) (time.Time, json.RawMessage) {
	s, err := a.str(k)
	if err != nil {
		return time.Time{}, failErr(codeArgs, err)
	}
	t, ok := parseInstantZ(s)
	if !ok {
		return time.Time{}, fail("parse", "not an RFC 3339 instant: "+s)
	}
	return t, nil
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
