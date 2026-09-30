package pactidentity

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The dispatcher's member lists are contract/contract.json's `params.properties`, function by
// function, in order — as the core's `every_function_declares_the_contracts_members` holds its own —
// and Call refuses a member outside them, by name, before it reads the ones inside them.
func TestEveryFunctionDeclaresTheContractsMembers(t *testing.T) {
	raw, err := os.ReadFile("../contract/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Methods map[string]struct {
			Params struct {
				Properties json.RawMessage `json:"properties"`
			} `json:"params"`
		} `json:"methods"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	for name, m := range contract.Methods {
		// The members in the order the contract writes them: a map would lose it.
		var want []string
		if len(m.Params.Properties) > 0 {
			d := json.NewDecoder(strings.NewReader(string(m.Params.Properties)))
			if _, err := d.Token(); err != nil {
				t.Fatal(err)
			}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, k.(string))
				var skip json.RawMessage
				if err := d.Decode(&skip); err != nil {
					t.Fatal(err)
				}
			}
		}
		fn, found := functions[name]
		if !found {
			t.Errorf("%s: the contract declares it and the dispatcher has no entry", name)
			continue
		}
		if !slices.Equal(fn.members, want) {
			t.Errorf("%s: the dispatcher holds its arguments to %v, and the contract declares %v", name, fn.members, want)
		}
		for _, member := range want {
			if out := string(Call(name, json.RawMessage(`{"`+member+`":null}`))); strings.Contains(out, "takes no member") {
				t.Errorf("%s(%s) answered %s", name, member, out)
			}
		}
		out := string(Call(name, json.RawMessage(`{"zz":2,"not_a_member":1}`)))
		if w := `{"error":"bad_request","why":"` + name + ` takes no member \"not_a_member\""}`; out != w {
			t.Errorf("%s answered %s, want %s", name, out, w)
		}
	}
	if len(functions) != len(contract.Methods) {
		t.Errorf("the dispatcher has %d names and the contract %d", len(functions), len(contract.Methods))
	}
	if out := string(Call("nope", json.RawMessage(`{"not_a_member":1}`))); !strings.Contains(out, "no function named nope") {
		t.Errorf("nope answered %s", out)
	}
}

// An empty expectation is "not given" to a Go caller of the typed API and a value at the JSON
// boundary (CONTRACT §0). The node's first certification passes ExpectedRoot "" and must validate
// (pact-gateway internal/identity/leaf.go, installLeaf's ValidateChain, before the account has a
// root); the same chain with `expected_root: ""` handed to Call is refused, as the core refuses it.
// FollowRenewed's pinned root and dialed address are always held.
func TestAnEmptyExpectationIsNotGivenOnlyToAGoCaller(t *testing.T) {
	p := reviewIdentity(t, "ed25519", reviewEndpoint)
	now := mustTime(t, "2026-09-13T12:00:00Z")
	chain := [][]byte{p.leaf, p.root}
	if vr := ValidateChain(chain, ChainOpts{Now: now}); !vr.OK {
		t.Fatalf("the typed call with no expectation must validate: %+v", vr)
	}
	for _, member := range []string{"expected_root", "expected_endpoint"} {
		raw, _ := json.Marshal(map[string]any{"chain": []string{B64url(p.leaf), B64url(p.root)}, "now": "2026-09-13T12:00:00Z", member: ""})
		var out map[string]any
		if err := json.Unmarshal(Call("validate_chain", raw), &out); err != nil || out["ok"] != false {
			t.Errorf("validate_chain with %s \"\" answered %v", member, out)
		}
	}
	if follow, why, _ := FollowRenewed(chain, "", p.leaf, reviewEndpoint, now); follow || why != "chain rule 2: root is not the one expected" {
		t.Errorf("FollowRenewed from an empty pinned root: %v %q", follow, why)
	}
	if follow, why, _ := FollowRenewed(chain, p.rootFP, p.leaf, "", now); follow || why != "chain rule 5: endpoint differs from the one in question" {
		t.Errorf("FollowRenewed to an empty dialed address: %v %q", follow, why)
	}
}

// An integer is what the core reads as one (serde_json's `as_i64`): js/boundary-text.json's list,
// which the core's the_arguments_text_is_read_as_the_go_port_reads_it reads too — no fraction, no
// exponent, within 64 bits, and not -0, which serde_json reads as a float. strconv reads -0 as 0, so
// this port sealed an `exp` of -0 and decided a limits `now` of -0 where the core refused both (S3-1).
func TestAnIntegerIsWhatTheCoreReadsAsOne(t *testing.T) {
	doc := boundaryText(t)
	for list, want := range map[string]bool{"read": true, "refused": false} {
		for _, text := range doc.Integers[list] {
			if _, isInt := integerText(text); isInt != want {
				t.Errorf("integerText(%s) = %v, want %v", text, isInt, want)
			}
			if _, err := (args{"k": json.RawMessage(text)}).optInt("k"); (err == nil) != want {
				t.Errorf("optInt(%s): %v", text, err)
			}
		}
	}
	if n, err := (args{"k": json.RawMessage("null")}).optInt("k"); n != nil || err != nil {
		t.Errorf("optInt(null) = %v, %v: null is absent", n, err)
	}
	if _, isWhole := limitsWhole(json.Number("-0")); isWhole {
		t.Error("limitsWhole(-0) read a whole number")
	}
}

// boundaryText is js/boundary-text.json: the arguments text both ports read alike, one list for both.
type boundaryTextDoc struct {
	MaxDepth int `json:"max_depth"`
	Nested   struct {
		Within json.RawMessage `json:"within"`
		Beyond json.RawMessage `json:"beyond"`
	} `json:"nested"`
	Calls []struct {
		Args string          `json:"args"`
		Want json.RawMessage `json:"want"`
	} `json:"calls"`
	Integers    map[string][]string `json:"integers"`
	UnknownName struct {
		Fn   string          `json:"fn"`
		Want json.RawMessage `json:"want"`
		Args []string        `json:"args"`
	} `json:"unknown_name"`
}

func boundaryText(t *testing.T) boundaryTextDoc {
	t.Helper()
	raw, err := os.ReadFile("../js/boundary-text.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc boundaryTextDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// sameJSON is whether two JSON texts hold one value.
func sameJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

// A vault document's KDF parameters are whole numbers written as whole numbers, as the core reads
// them: `t` spelled 1.0 gives the canonical header `t` 1 gives, and opened here (C11's verifier, C5).
func TestAVaultsKDFNumbersAreWholeNumbers(t *testing.T) {
	doc := func(member string, n json.Number) map[string]any {
		kdf := map[string]any{"name": "argon2id", "m_kib": json.Number("8192"), "t": json.Number("1"), "p": json.Number("1")}
		kdf[member] = n
		return map[string]any{"format": VaultFormat, "kdf": kdf, "salt": "AAAAAAAAAAAAAAAAAAAAAA", "nonce": "AAAAAAAAAAAAAAAA", "ct": "AAAA"}
	}
	for _, c := range []struct {
		member string
		n      json.Number
	}{{"t", "1.0"}, {"m_kib", "8192.0"}, {"p", "1e0"}, {"m_kib", "8192.5"}, {"p", "257"}, {"t", "-0"}} {
		_, err := VaultOpenDoc("x", doc(c.member, c.n))
		if err == nil || err.Error() != "kdf parameters out of range" {
			t.Errorf("%s %s: %v", c.member, c.n, err)
		}
	}
	// The control: whole numbers read, and the document fails only at the passphrase.
	if _, err := VaultOpenDoc("x", doc("t", "1")); err == nil || err.Error() == "kdf parameters out of range" {
		t.Errorf("whole numbers: %v", err)
	}
	// A Go caller's own decoding kept no spelling: a float64 counts when it is whole, and only then.
	half := doc("t", "1")
	half["kdf"].(map[string]any)["t"] = 1.5
	if _, err := VaultOpenDoc("x", half); err == nil || err.Error() != "kdf parameters out of range" {
		t.Errorf("t 1.5 as a float64: %v", err)
	}
	half["kdf"].(map[string]any)["t"] = 1.0
	if _, err := VaultOpenDoc("x", half); err == nil || err.Error() == "kdf parameters out of range" {
		t.Errorf("t 1 as a float64: %v", err)
	}
}

// What one port's parser refuses and the other's reads is named at Call before any member is read,
// in the core's words (R40, S3-2), and text that does not parse is `args is a JSON object`:
// js/boundary-text.json's calls, which the core's the_arguments_text_is_read_as_the_go_port_reads_it
// answers too (the adapter's request line cannot carry text that does not parse, so parity cannot
// ask). Every text this port reads refuses the same, as serde_json does.
func TestJSONTheCoreDoesNotReadIsNotReadHere(t *testing.T) {
	doc := boundaryText(t)
	if doc.MaxDepth != jsonMaxDepth {
		t.Fatalf("jsonMaxDepth is %d and js/boundary-text.json says %d", jsonMaxDepth, doc.MaxDepth)
	}
	for _, c := range doc.Calls {
		if out := Call("key_info", json.RawMessage(c.Args)); !sameJSON(out, c.Want) {
			t.Errorf("key_info(%.60s) = %s, want %s", c.Args, out, c.Want)
		}
	}
	// A name no function has is judged before the arguments are read, whatever they are (R34).
	u := doc.UnknownName
	if len(u.Args) < 5 {
		t.Fatalf("js/boundary-text.json's unknown_name holds %d texts", len(u.Args))
	}
	for _, text := range u.Args {
		if out := Call(u.Fn, json.RawMessage(text)); !sameJSON(out, u.Want) {
			t.Errorf("%s(%.40s) = %s, want %s", u.Fn, text, out, u.Want)
		}
	}
	nested := func(n int) string { return strings.Repeat("[", n) + "1" + strings.Repeat("]", n) }
	for n, want := range map[int]json.RawMessage{jsonMaxDepth - 1: doc.Nested.Within, jsonMaxDepth: doc.Nested.Beyond} {
		if out := Call("key_info", json.RawMessage(`{"spki":`+nested(n)+`}`)); !sameJSON(out, want) {
			t.Errorf("key_info of an spki %d deep = %s, want %s", n, out, want)
		}
	}
	for _, text := range []string{`{"x":1e400}`, `{"x":` + nested(jsonMaxDepth) + `}`} {
		if _, err := decodeJSON([]byte(text)); err == nil {
			t.Errorf("decodeJSON read %.40s", text)
		}
	}
	if _, err := decodeJSON([]byte(`{"x":` + nested(jsonMaxDepth-1) + `}`)); err != nil {
		t.Errorf("decodeJSON at %d deep: %v", jsonMaxDepth, err)
	}
}

// A vault's plaintext is JSON exactly when the core's parser reads it: one holding a number infinite
// as a double (R40), half a surrogate pair or a byte that is not UTF-8 (the review of 2026-09-30, M1)
// opened here, where the core finds the vault damaged. The controls open.
func TestAVaultPlaintextTheCoreCannotReadIsDamage(t *testing.T) {
	kdf := &KDF{Name: "argon2id", MKiB: 8192, T: 1, P: 1}
	for plaintext, want := range map[string]error{
		`{"v":2,"roots":[],"n":1e400}`:          errVault,
		`{"v":2,"roots":[],"n":"\ud800"}`:       errVault,
		`{"v":2,"roots":[],"\udc00":1}`:         errVault,
		"{\"v\":2,\"roots\":[],\"n\":\"\xff\"}": errVault,
		`{"v":2,"roots":[],"n":1e308}`:          nil,
		`{"v":2,"roots":[],"n":"\ud83d\ude00"}`: nil,
	} {
		sealed, err := vaultSealAny("a passphrase", []byte(plaintext), kdf, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(sealed)
		doc, _ := decodeJSON(raw)
		if _, err := VaultOpenDoc("a passphrase", doc.(map[string]any)); err != want {
			t.Errorf("%s opened as %v, want %v", plaintext, err, want)
		}
	}
}
