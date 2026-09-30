package pactidentity

import (
	"encoding/json"
	"testing"
)

// One grammar for every instant both ports read (SPEC 2.2.2): `YYYY-MM-DDTHH:MM:SS`, an optional
// `.` and digits (dropped), and `Z`. Upper-case T and Z only, no offset, no `,` before a fraction.
// parseInstantZ is the one reader (the boundary's `instant` in api_args.go, parseInstant and the
// export's instants all go through it); the Rust core's instants_have_one_grammar holds parse_rfc3339 to the same list.
func TestInstantsHaveOneGrammar(t *testing.T) {
	for _, good := range []string{"2026-09-13T12:00:00Z", "2026-09-13T12:00:00.5Z", "2026-09-13T12:00:00.123456789Z", "2024-02-29T23:59:59Z"} {
		if _, ok := parseInstantZ(good); !ok {
			t.Errorf("%s: refused", good)
		}
	}
	a, _ := parseInstantZ("2026-09-13T12:00:00.999Z")
	b, _ := parseInstantZ("2026-09-13T12:00:00Z")
	if !a.Equal(b) {
		t.Errorf("a fraction is dropped: %v and %v", a, b)
	}
	for _, bad := range []string{
		"2026-09-13T12:00:00z", "2026-09-13t12:00:00Z", "2026-09-13 12:00:00Z", "2026-09-13T12:00:00,5Z", "2026-09-13T12:00:00.Z",
		"2026-09-13T12:00:00+00:00", "2026-09-13T12:00:00-01:00", "2026-09-13T12:00:00", "2026-09-13T24:00:00Z", "2026-09-13T12:00:60Z",
		"2025-02-29T00:00:00Z", "26-09-13T12:00:00Z",
	} {
		if _, ok := parseInstantZ(bad); ok {
			t.Errorf("%s: read", bad)
		}
		if _, ok := parseInstant(bad); ok {
			t.Errorf("%s: read by parseInstant", bad)
		}
		raw, _ := json.Marshal(bad)
		if _, err := (args{"now": raw}).instant("now"); err == nil {
			t.Errorf("%s: read by the boundary", bad)
		}
	}
}
