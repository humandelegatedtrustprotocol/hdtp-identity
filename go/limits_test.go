package pactidentity

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// The cloud's TypeScript and this port decide alike: every step of js/cases/limits-vectors.json,
// replayed on this port's own state (swept after every step, where the TypeScript swept at most once
// a minute), every row compared bit for bit.
func TestLimitsDecideAsTheTypeScriptDid(t *testing.T) {
	raw, err := os.ReadFile("../js/cases/limits-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Sequences []struct {
			Seed  int                  `json:"seed"`
			Rules map[string]float64   `json:"rules"`
			Steps [][4]json.RawMessage `json:"steps"`
		} `json:"sequences"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	steps, refused := 0, 0
	for _, seq := range file.Sequences {
		rules := LimitsRules(seq.Rules)
		if err := rules.Check(); err != nil {
			t.Fatalf("seed %d: %v", seq.Seed, err)
		}
		store := LimitsMemoryStore{}
		for i, step := range seq.Steps {
			var c struct {
				Kind        string  `json:"kind"`
				Root        *string `json:"root"`
				ContactCap  float64 `json:"contact_cap"`
				Source      string  `json:"source"`
				Addressed   bool    `json:"addressed"`
				Integration string  `json:"integration"`
				Contact     string  `json:"contact"`
			}
			var now int64
			if json.Unmarshal(step[0], &c) != nil || json.Unmarshal(step[1], &now) != nil {
				t.Fatalf("seed %d step %d does not read", seq.Seed, i)
			}
			charge := LimitsCharge{Kind: c.Kind, Root: c.Root, ContactCap: c.ContactCap, Source: c.Source, Addressed: c.Addressed, Integration: c.Integration, Contact: c.Contact}
			got := LimitsDecide(rules, charge, now, store)
			var refusal []json.RawMessage
			if json.Unmarshal(step[2], &refusal) == nil {
				var after uint64
				var which string
				_ = json.Unmarshal(refusal[0], &after)
				_ = json.Unmarshal(refusal[1], &which)
				if got.Allowed || got.RetryAfter == nil || *got.RetryAfter != after || got.Which != which {
					t.Fatalf("seed %d step %d: %+v, the TypeScript refused (%d, %s)", seq.Seed, i, got, after, which)
				}
				refused++
			} else {
				if !got.Allowed {
					t.Fatalf("seed %d step %d: refused by %s, the TypeScript let it through", seq.Seed, i, got.Which)
				}
				var writes [][3]json.RawMessage
				_ = json.Unmarshal(step[3], &writes)
				for j, b := range charge.Buckets(rules) {
					var key string
					var tokens float64
					var at int64
					_ = json.Unmarshal(writes[j][0], &key)
					_ = json.Unmarshal(writes[j][1], &tokens)
					_ = json.Unmarshal(writes[j][2], &at)
					row, _ := store.Get(b.Key)
					if key != b.Key || math.Float64bits(row.Tokens) != math.Float64bits(tokens) || row.UpdatedAt != at {
						t.Fatalf("seed %d step %d: %s holds %v at %d, the TypeScript wrote %s %v at %d", seq.Seed, i, b.Key, row.Tokens, row.UpdatedAt, key, tokens, at)
					}
				}
			}
			store.Sweep(now)
			steps++
		}
	}
	if steps < 1000 || refused < 100 {
		t.Fatalf("the vectors hold %d steps, %d refused", steps, refused)
	}
}

func limitsTestRules() LimitsRules {
	return LimitsRules{
		"contact_calls_per_second": 2, "contact_burst": 5, "identity_capacity_per_second": 7,
		"guest_calls_per_hour": 3, "guest_source_calls_per_hour": 4, "stranger_calls_out_per_hour": 6,
		"integration_calls_per_hour": 8, "guest_total_calls_per_hour": 9, "pending_in_cap": 2,
	}
}

// Every rule refuses once its burst is spent, naming its bucket; a fresh key is the control.
func TestLimitsEveryRuleRefusesAndAFreshKeyGetsThrough(t *testing.T) {
	r := limitsTestRules()
	root, empty := "rA", ""
	cases := []struct {
		c     LimitsCharge
		key   string
		burst int
	}{
		{LimitsCharge{Kind: "contact_in", Root: &root, ContactCap: 100}, "contact:rA", 5},
		{LimitsCharge{Kind: "contact_out", Root: &root, ContactCap: 100}, "out:contact:rA", 5},
		{LimitsCharge{Kind: "contact_in", Root: &root, ContactCap: 1}, "identity", 2},
		{LimitsCharge{Kind: "contact_out", Root: &root, ContactCap: 1}, "out:identity", 2},
		{LimitsCharge{Kind: "guest_in", Root: &root, Source: "s1", Addressed: true}, "guest:rA:s1", 3},
		{LimitsCharge{Kind: "guest_in", Root: &root, Source: "s1"}, "guest:rA", 3},
		{LimitsCharge{Kind: "guest_in", Root: &empty, Source: "s1", Addressed: true}, "source:s1", 4},
		{LimitsCharge{Kind: "guest_in", Source: "s1"}, "source:s1", 4},
		{LimitsCharge{Kind: "guest_total"}, "guest-total", 9},
		{LimitsCharge{Kind: "stranger_out"}, "out:stranger", 6},
		{LimitsCharge{Kind: "integration", Integration: "i1", Contact: "rA"}, "integration:i1:rA", 8},
	}
	for _, tc := range cases {
		store := LimitsMemoryStore{}
		for i := 0; i < tc.burst; i++ {
			if d := LimitsDecide(r, tc.c, 0, store); !d.Allowed {
				t.Fatalf("%s: call %d of its burst refused by %s", tc.key, i, d.Which)
			}
		}
		before := len(store)
		d := LimitsDecide(r, tc.c, 0, store)
		if d.Allowed || d.Which != tc.key || d.RetryAfter == nil || *d.RetryAfter < 1 {
			t.Fatalf("%s: %+v", tc.key, d)
		}
		if len(store) != before {
			t.Fatalf("%s: a refusal wrote a row", tc.key)
		}
	}
	if d := LimitsDecide(r, LimitsCharge{Kind: "pending_in", Held: 1}, 0, LimitsMemoryStore{}); !d.Allowed {
		t.Fatal("one request under the cap was refused")
	}
	if d := LimitsDecide(r, LimitsCharge{Kind: "pending_in", Held: 2}, 0, LimitsMemoryStore{}); d.Allowed || d.Which != "pending_in" || d.RetryAfter != nil {
		t.Fatalf("at the cap: %+v", d)
	}
}

// What the crate's types cannot hold, this port's refuse (T21): a rules map without a member is that
// member's `is a number`, as a document without it is, and not a rule about a 0 nobody wrote; a
// charge of a kind nobody has is refused, where it spent no bucket and was allowed. The control is the
// same rules whole, and a kind that exists.
func TestLimitsRefuseWhatTheCratesTypesCannotHold(t *testing.T) {
	r := limitsTestRules()
	if err := r.Check(); err != nil {
		t.Fatalf("the whole rules: %v", err)
	}
	for _, name := range LimitsRuleMembers {
		without := LimitsRules{}
		for k, v := range r {
			if k != name {
				without[k] = v
			}
		}
		if err := without.Check(); err == nil || err.Error() != name+" is a number" {
			t.Errorf("rules without %s: %v", name, err)
		}
	}
	if d := LimitsDecide(r, LimitsCharge{Kind: "everything"}, 0, LimitsMemoryStore{}); d.Allowed || d.Which != "charge.kind" || d.RetryAfter != nil {
		t.Errorf("a charge of an unknown kind: %+v", d)
	}
	if d := LimitsDecide(r, LimitsCharge{Kind: "stranger_out"}, 0, LimitsMemoryStore{}); !d.Allowed {
		t.Errorf("a charge of a known kind: %+v", d)
	}
}
