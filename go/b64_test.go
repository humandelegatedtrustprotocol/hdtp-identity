package hdtpidentity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Bytes this port did not write, read as js/b64url-arguments.json says: one list, which the Rust
// core's `from_b64u` is held to as well. The core forgave every Unicode whitespace character and this
// port four, so a key with a vertical tab in it was a key there and `parse` here (C10). Neither
// forgives any now.
func TestArgumentsAreReadAsOneListSays(t *testing.T) {
	raw, err := os.ReadFile("../js/b64url-arguments.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name string  `json:"name"`
			In   string  `json:"in"`
			Hex  *string `json:"hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("js/b64url-arguments.json holds %d cases", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		got, err := DecodeB64url(c.In)
		switch {
		case c.Hex != nil && (err != nil || hex.EncodeToString(got) != *c.Hex):
			t.Errorf("%s: %x, %v; want %s", c.Name, got, err, *c.Hex)
		case c.Hex == nil && (err == nil || codeFor(err, "") != "parse" || err.Error() != "not base64url"):
			t.Errorf("%s: %x, %v; want parse, not base64url", c.Name, got, err)
		}
	}
}
