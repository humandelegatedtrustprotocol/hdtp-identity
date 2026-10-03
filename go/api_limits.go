package hdtpidentity

// The limits section of contract/contract.json: a body for each function it declares, which api.go's
// `functions` map dispatches by name. Arguments are read as the Rust core reads them (api/limits.rs):
// every number as written (json.Number), a whole number only when written without a fraction or an
// exponent, and every list of members checked in sorted order.

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// limitsMaxExact is 2^53 - 1: times, counts and contact caps above it are refused, not rounded.
const limitsMaxExact = 9_007_199_254_740_991

func limitsWhole(v any) (int64, bool) {
	n, isNum := v.(json.Number)
	if !isNum {
		return 0, false
	}
	i, isInt := integerText(string(n))
	if !isInt || i < 0 || i > limitsMaxExact {
		return 0, false
	}
	return i, true
}

func limitsNumber(v any) (float64, bool) {
	n, isNum := v.(json.Number)
	if !isNum {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return f, err == nil
}

// limitsReadRules reads a rules document and holds it to Check; the error is the first reason.
func limitsReadRules(doc any) (LimitsRules, error) {
	o, isObj := doc.(map[string]any)
	if !isObj {
		return nil, errArg("the limits rules are an object")
	}
	if k := stranger(o, LimitsRuleMembers); k != "" {
		return nil, errArg("the limits rules hold " + strings.Join(LimitsRuleMembers, ", ") + ", and nothing else: " + k)
	}
	rules := LimitsRules{}
	for _, m := range LimitsRuleMembers {
		f, isNum := limitsNumber(o[m])
		if !isNum {
			return nil, errArg(m + " is a number")
		}
		rules[m] = f
	}
	if err := rules.Check(); err != nil {
		return nil, err
	}
	return rules, nil
}

func callLimitsRulesCheck(a args) json.RawMessage {
	doc := a.value("rules")
	if doc == nil {
		return fail(codeArgs, "rules is required")
	}
	if _, err := limitsReadRules(doc); err != nil {
		return ok(map[string]any{"ok": false, "why": err.Error()})
	}
	return ok(map[string]any{"ok": true})
}

var limitsKinds = strings.Join(limitsChargeKinds, ", ")

func limitsReadCharge(v any) (LimitsCharge, error) {
	o, isObj := v.(map[string]any)
	if !isObj {
		return LimitsCharge{}, errArg("charge is required")
	}
	kind, isStr := o["kind"].(string)
	if !isStr {
		return LimitsCharge{}, errArg("charge.kind is required")
	}
	var members []string
	switch kind {
	case "contact_in", "contact_out":
		members = []string{"kind", "root", "contact_cap"}
	case "guest_in":
		members = []string{"kind", "root", "source", "addressed"}
	case "guest_total", "stranger_out":
		members = []string{"kind"}
	case "integration":
		members = []string{"kind", "integration", "contact"}
	case "pending_in":
		members = []string{"kind", "held"}
	default:
		return LimitsCharge{}, errArg("charge.kind is one of " + limitsKinds)
	}
	if k := stranger(o, members); k != "" {
		return LimitsCharge{}, errArg("a " + kind + " charge holds " + strings.Join(members, ", ") + ", and nothing else: " + k)
	}
	text := func(m string) (string, error) {
		s, isStr := o[m].(string)
		if !isStr || s == "" {
			return "", errArg("charge." + m + " is required")
		}
		return s, nil
	}
	count := func(m string) (float64, error) {
		n, isWhole := limitsWhole(o[m])
		if !isWhole {
			return 0, errArg("charge." + m + " is a whole number")
		}
		return float64(n), nil
	}
	c := LimitsCharge{Kind: kind}
	var err error
	switch kind {
	case "contact_in", "contact_out":
		var root string
		if root, err = text("root"); err != nil {
			return c, err
		}
		c.Root = &root
		if c.ContactCap, err = count("contact_cap"); err != nil {
			return c, err
		}
	case "guest_in":
		switch r := o["root"].(type) {
		case nil:
		case string:
			c.Root = &r
		default:
			return c, errArg("charge.root is a string or null")
		}
		source, isStr := o["source"].(string)
		if !isStr {
			return c, errArg("charge.source is required")
		}
		c.Source = source
		addressed, isBool := o["addressed"].(bool)
		if !isBool {
			return c, errArg("charge.addressed is required")
		}
		c.Addressed = addressed
	case "integration":
		if c.Integration, err = text("integration"); err != nil {
			return c, err
		}
		if c.Contact, err = text("contact"); err != nil {
			return c, err
		}
	case "pending_in":
		if c.Held, err = count("held"); err != nil {
			return c, err
		}
	}
	return c, nil
}

func limitsReadState(v any) (LimitsMemoryStore, error) {
	store := LimitsMemoryStore{}
	if v == nil {
		return store, nil
	}
	o, isObj := v.(map[string]any)
	if !isObj {
		return nil, errArg("state is an object of rows by bucket")
	}
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		bad := func(m string) error { return errArg("the state's row " + key + " does not read: " + m) }
		row, isObj := o[key].(map[string]any)
		if !isObj {
			return nil, bad("a row is an object")
		}
		if k := stranger(row, []string{"tokens", "updated_at"}); k != "" {
			return nil, bad(k)
		}
		tokens, isNum := limitsNumber(row["tokens"])
		if !isNum {
			return nil, bad("tokens")
		}
		updated, isWhole := limitsWhole(row["updated_at"])
		if !isWhole {
			return nil, bad("updated_at")
		}
		store.Put(key, LimitsLevel{Tokens: tokens, UpdatedAt: updated})
	}
	return store, nil
}

type limitsWrite struct {
	Bucket    string  `json:"bucket"`
	Tokens    float64 `json:"tokens"`
	UpdatedAt int64   `json:"updated_at"`
}

type limitsAnswer struct {
	Allowed    bool          `json:"allowed"`
	RetryAfter *uint64       `json:"retry_after"`
	RefusedBy  *string       `json:"refused_by"`
	Writes     []limitsWrite `json:"writes"`
}

// limitsRulesAndCharge reads the rules and the charge, in that order and in these words: what
// limits_decide and limits_buckets both read first, by one reader, as the core's rules_and_charge.
func limitsRulesAndCharge(a args) (LimitsRules, LimitsCharge, json.RawMessage) {
	doc := a.value("rules")
	if doc == nil {
		return nil, LimitsCharge{}, fail(codeArgs, "rules is required")
	}
	rules, err := limitsReadRules(doc)
	if err != nil {
		return nil, LimitsCharge{}, fail(codeArgs, "the limits rules cannot be enforced: "+err.Error())
	}
	charge, err := limitsReadCharge(a.value("charge"))
	if err != nil {
		return nil, LimitsCharge{}, failErr(codeArgs, err)
	}
	return rules, charge, nil
}

type limitsBucketOut struct {
	Key       string  `json:"key"`
	PerSecond float64 `json:"per_second"`
	Burst     float64 `json:"burst"`
}

// callLimitsBuckets answers the buckets a charge is charged to, in charge order, each with its key,
// rate and burst: the rows a host holds for limits_decide's `state`, from Buckets, the one place the
// key scheme is written. The Wasm could decide a charge and not say which rows it reads (X2).
func callLimitsBuckets(a args) json.RawMessage {
	rules, charge, bad := limitsRulesAndCharge(a)
	if bad != nil {
		return bad
	}
	out := []limitsBucketOut{}
	for _, b := range charge.Buckets(rules) {
		out = append(out, limitsBucketOut{Key: b.Key, PerSecond: b.PerSecond, Burst: b.Burst})
	}
	return ok(map[string]any{"buckets": out})
}

func callLimitsDecide(a args) json.RawMessage {
	// In the order the function needs them (CONTRACT §0): the rules, what is charged, when, the rows.
	rules, charge, bad := limitsRulesAndCharge(a)
	if bad != nil {
		return bad
	}
	// Absent or null is `now is required`, as CONTRACT §0 has every absent member (S1-2).
	if a.present("now") == nil {
		return fail(codeArgs, "now is required")
	}
	now, isWhole := limitsWhole(a.value("now"))
	if !isWhole {
		return fail(codeArgs, "now is a time in milliseconds")
	}
	store, err := limitsReadState(a.value("state"))
	if err != nil {
		return failErr(codeArgs, err)
	}
	d := LimitsDecide(rules, charge, now, store)
	answer := limitsAnswer{Allowed: d.Allowed, Writes: []limitsWrite{}}
	if d.Allowed {
		zero := uint64(0)
		answer.RetryAfter = &zero
		for _, b := range charge.Buckets(rules) {
			l, _ := store.Get(b.Key)
			answer.Writes = append(answer.Writes, limitsWrite{Bucket: b.Key, Tokens: l.Tokens, UpdatedAt: l.UpdatedAt})
		}
	} else {
		answer.RetryAfter = d.RetryAfter
		answer.RefusedBy = &d.Which
	}
	return ok(answer)
}
