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
