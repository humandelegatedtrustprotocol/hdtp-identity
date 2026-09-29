package pactidentity

import (
	"encoding/json"
	"os"
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
// (pact-gateway internal/identity/leaf.go:561); the same chain with `expected_root: ""` handed to Call
// is refused, as the core refuses it. FollowRenewed's pinned root and dialed address are always held.
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

// An integer is what the core reads as one (serde_json's `as_i64`): no fraction, no exponent, within
// 64 bits, and not -0, which serde_json reads as a float. strconv reads -0 as 0, so this port sealed
// an `exp` of -0 and decided a limits `now` of -0 where the core refused both (S3-1).
func TestAnIntegerIsWhatTheCoreReadsAsOne(t *testing.T) {
	for text, want := range map[string]bool{
		"0": true, "7": true, "-7": true, "9223372036854775807": true, "-9223372036854775808": true,
		"-0": false, "7.0": false, "1.5": false, "1e2": false, `"7"`: false, "9223372036854775808": false, "-9223372036854775809": false,
	} {
		if _, isInt := integerText(text); isInt != want {
			t.Errorf("integerText(%s) = %v, want %v", text, isInt, want)
		}
		_, err := args{"k": json.RawMessage(text)}.optInt("k")
		if (err == nil) != want {
			t.Errorf("optInt(%s): %v", text, err)
		}
	}
	if n, err := (args{"k": json.RawMessage("null")}).optInt("k"); n != nil || err != nil {
		t.Errorf("optInt(null) = %v, %v: null is absent", n, err)
	}
	if _, isWhole := limitsWhole(json.Number("-0")); isWhole {
		t.Error("limitsWhole(-0) read a whole number")
	}
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
