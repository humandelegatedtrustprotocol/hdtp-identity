package pactidentity

// PACT SPEC §12's per-caller call budgets: the Go port of crates/pact-limits, for the node's layer 2
// (pact-gateway docs/release/two-layer-limits-2026-09-28.md). The same token buckets, the same keys,
// the same arithmetic in the same order, held to the Rust crate by parity and to the cloud's
// TypeScript by js/cases/limits-vectors.json (limits_test.go).
//
// One thing Go does that Rust and JavaScript do not: the compiler may fuse x*y + z into one
// fused multiply-add on arm64, which rounds once where the others round twice. Every such sum here
// converts its product explicitly (float64(x*y)), which the language defines as a rounding point.

import (
	"fmt"
	"math"
)

// LimitsBucket is one token bucket: its row, its rate in calls a second, and the most calls it holds.
type LimitsBucket struct {
	Key       string
	PerSecond float64
	Burst     float64
}

func perHourBucket(key string, n float64) LimitsBucket {
	return LimitsBucket{Key: key, PerSecond: n / 3600, Burst: n}
}

// LimitsLevel is a bucket's row: the tokens left when last charged, and when (milliseconds).
type LimitsLevel struct {
	Tokens    float64
	UpdatedAt int64
}

// LimitsStore is where the counters live; a missing row is a full bucket.
type LimitsStore interface {
	Get(key string) (LimitsLevel, bool)
	Put(key string, level LimitsLevel)
}

// LimitsIdleMS is how long a row may sit untouched before it is full whatever it budgets.
const LimitsIdleMS int64 = 3_600_000

// LimitsRuleMembers are the members of a rules document, in the order they are checked.
var LimitsRuleMembers = []string{
	"contact_calls_per_second",
	"contact_burst",
	"identity_capacity_per_second",
	"guest_calls_per_hour",
	"guest_source_calls_per_hour",
	"stranger_calls_out_per_hour",
	"integration_calls_per_hour",
	"guest_total_calls_per_hour",
	"pending_in_cap",
}

// LimitsRules are the numbers of §12's call budgets, by member name.
type LimitsRules map[string]float64

// Check says whether the rules can be enforced as written: crates/pact-limits's Rules::check.
func (r LimitsRules) Check() error {
	for _, name := range LimitsRuleMembers {
		v := r[name]
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return errArg(name + " is a number")
		}
		if name == "contact_calls_per_second" {
			if v <= 0 {
				return errArg(name + " is above 0")
			}
		} else if v < 1 {
			return errArg(name + " is at least 1")
		}
	}
	if c := r["pending_in_cap"]; c != math.Trunc(c) {
		return errArg("pending_in_cap is a whole number")
	}
	if r["contact_burst"]/r["contact_calls_per_second"] > float64(LimitsIdleMS/1000) {
		return errArg("contact_burst / contact_calls_per_second is at most 3600: a contact's bucket refills within the hour an idle row is kept")
	}
	return nil
}

func (r LimitsRules) identityPerSecond(contactCap float64) float64 {
	return math.Max(1, math.Min(contactCap*r["contact_calls_per_second"], r["identity_capacity_per_second"]))
}

// LimitsCharge is what a call is charged to: Kind and the members that kind reads.
type LimitsCharge struct {
	Kind        string
	Root        *string // contact_in, contact_out; guest_in (nil or empty: no proven root)
	ContactCap  float64
	Source      string
	Addressed   bool
	Integration string
	Contact     string
	Held        float64
}

// Buckets are the buckets a charge spends, in order, with the cloud's keys.
func (c LimitsCharge) Buckets(r LimitsRules) []LimitsBucket {
	contact := func(key string) LimitsBucket {
		return LimitsBucket{Key: key, PerSecond: r["contact_calls_per_second"], Burst: r["contact_burst"]}
	}
	identity := func(key string, limit float64) LimitsBucket {
		v := r.identityPerSecond(limit)
		return LimitsBucket{Key: key, PerSecond: v, Burst: v}
	}
	root := ""
	if c.Root != nil {
		root = *c.Root
	}
	switch c.Kind {
	case "contact_in":
		return []LimitsBucket{contact("contact:" + root), identity("identity", c.ContactCap)}
	case "contact_out":
		return []LimitsBucket{contact("out:contact:" + root), identity("out:identity", c.ContactCap)}
	case "guest_in":
		switch {
		case root == "":
			return []LimitsBucket{perHourBucket("source:"+c.Source, r["guest_source_calls_per_hour"])}
		case c.Addressed:
			return []LimitsBucket{perHourBucket("guest:"+root+":"+c.Source, r["guest_calls_per_hour"])}
		default:
			return []LimitsBucket{perHourBucket("guest:"+root, r["guest_calls_per_hour"])}
		}
	case "guest_total":
		return []LimitsBucket{perHourBucket("guest-total", r["guest_total_calls_per_hour"])}
	case "stranger_out":
		return []LimitsBucket{perHourBucket("out:stranger", r["stranger_calls_out_per_hour"])}
	case "integration":
		return []LimitsBucket{perHourBucket(fmt.Sprintf("integration:%s:%s", c.Integration, c.Contact), r["integration_calls_per_hour"])}
	}
	return nil
}

// LimitsDecision is the answer: Allowed, or refused by Which, with RetryAfter seconds (nil for the
// pending cap, which no wait refills).
type LimitsDecision struct {
	Allowed    bool
	RetryAfter *uint64
	Which      string
}

// LimitsDecide charges one call to every bucket of the charge or to none: crates/pact-limits's decide.
func LimitsDecide(r LimitsRules, c LimitsCharge, now int64, store LimitsStore) LimitsDecision {
	if c.Kind == "pending_in" {
		if c.Held >= r["pending_in_cap"] {
			return LimitsDecision{Which: "pending_in"}
		}
		return LimitsDecision{Allowed: true}
	}
	buckets := c.Buckets(r)
	levels := make([]float64, len(buckets))
	for i, b := range buckets {
		row, found := store.Get(b.Key)
		if !found {
			levels[i] = b.Burst
			continue
		}
		elapsed := float64(max(0, now-row.UpdatedAt)) / 1000
		levels[i] = math.Min(b.Burst, row.Tokens+float64(elapsed*b.PerSecond))
	}
	retryAfter, which := 0.0, ""
	for i, b := range buckets {
		if levels[i] >= 1 {
			continue
		}
		wait := math.Max(1, math.Ceil((1-levels[i])/b.PerSecond))
		if wait > retryAfter {
			retryAfter, which = wait, b.Key
		}
	}
	if retryAfter > 0 {
		n := uint64(retryAfter)
		return LimitsDecision{RetryAfter: &n, Which: which}
	}
	for i, b := range buckets {
		store.Put(b.Key, LimitsLevel{Tokens: levels[i] - 1, UpdatedAt: now})
	}
	return LimitsDecision{Allowed: true}
}

// LimitsMemoryStore keeps rows in memory: the contract function's state, and the tests'.
type LimitsMemoryStore map[string]LimitsLevel

func (m LimitsMemoryStore) Get(key string) (LimitsLevel, bool) { l, ok := m[key]; return l, ok }
func (m LimitsMemoryStore) Put(key string, level LimitsLevel)  { m[key] = level }

// Sweep deletes every row idle for longer than LimitsIdleMS, which changes no decision under rules
// that pass Check.
func (m LimitsMemoryStore) Sweep(now int64) {
	for k, l := range m {
		if l.UpdatedAt < now-LimitsIdleMS {
			delete(m, k)
		}
	}
}
