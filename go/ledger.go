package pactidentity

// The wallet's ledger rules (SPEC §9; CONTRACT §6.1): what signing a leaf for an endpoint would mean,
// read off the ledger of leaves the wallet has issued. ONE implementation of them in this port:
// WalletIssue applies them, and a host renders the move notice (design §3) from the same facts.
//
// Every entry is read, every root's, before any rule reads one: an entry that does not read is
// refused, never skipped — skipped, it could be the live leaf, and one live leaf per identity would
// fail open. So a not_before that does not parse never reaches the rules, which skip it only because
// they are written over entries already read.

import (
	"errors"
	"fmt"
	"time"
)

// The kinds of the move notice, as ledger_check names them.
const (
	LedgerRenew    = "renew"
	LedgerMove     = "move"
	LedgerNewHost  = "new_host"
	LedgerMoveBack = "move_back"
	LedgerNoLedger = "no_ledger"
)

// SecondHome is the refusal of ledger_check and WalletIssue when a leaf is live at another endpoint
// and the caller did not say this is a move: the same words wherever the rule is applied.
func SecondHome(liveEndpoint string) string {
	return "a leaf is live for " + liveEndpoint + ": a second endpoint is a move, not a second home"
}

// ReadLedger reads every entry of a decoded ledger as CONTRACT §6's LedgerEntry: a list, each entry
// an object with the required members as strings, the instants parsing, origin a string if present,
// and nothing else. The first that does not read is named by its index and member.
func ReadLedger(ledger any) error {
	entries, isList := ledger.([]any)
	if !isList {
		return errors.New("the record's ledger is a list")
	}
	for i, e := range entries {
		o, isObj := e.(map[string]any)
		if !isObj {
			return fmt.Errorf("the record's ledger entry %d does not read", i)
		}
		unread := func(m string) error { return fmt.Errorf("the record's ledger entry %d does not read: %s", i, m) }
		for _, m := range entryRequired {
			text, isText := o[m].(string)
			if !isText {
				return unread(m)
			}
			if entryInstants[m] {
				if _, ok := parseInstant(text); !ok {
					return unread(m)
				}
			}
		}
		if origin, has := o["origin"]; has {
			if _, isText := origin.(string); !isText {
				return unread("origin")
			}
		}
		if k := stranger(o, entryMembers); k != "" {
			return unread(k)
		}
	}
	return nil
}

// LedgerLive is the live leaf: where it is, and until when.
type LedgerLive struct {
	Endpoint string
	NotAfter time.Time
}

// LedgerFacts is the ledger's answer about one request.
type LedgerFacts struct {
	// Refusal is SPEC §9's one live leaf per identity: set when a leaf is live elsewhere and the
	// caller did not say this is a move.
	Refusal string
	// NewHost: no entry of this root names the endpoint's host. True with no ledger: every host is
	// new to a signer that cannot see one.
	NewHost bool
	// KnownEndpoint: an entry of this root names exactly this endpoint. False with no ledger.
	KnownEndpoint bool
	// PreviousNotBefore is the latest notBefore this root has been issued.
	PreviousNotBefore *time.Time
	// Live is the NEWEST entry of this root by notBefore (§14.3), if it has not expired. An older
	// unexpired entry is history.
	Live *LedgerLive
	Kind string
}

// LedgerCheck applies the rules to a ledger; a nil ledger is none to read (no record), and an empty
// one is a ledger with nothing in it. endpoint is the request's, in the normal form of §14.1.
func LedgerCheck(ledger []LedgerEntry, root, endpoint string, now time.Time, move bool) (*LedgerFacts, error) {
	if !IsNormalHTTPS(endpoint) {
		return nil, errArg("endpoint is not an https URL in normal form")
	}
	if ledger == nil {
		return &LedgerFacts{NewHost: true, Kind: LedgerNoLedger}, nil
	}
	// Every entry read, as ReadLedger reads it, for a Go caller that holds typed entries.
	for i, e := range ledger {
		for _, m := range [][2]string{{"root", e.Root}, {"endpoint", e.Endpoint}, {"not_before", e.NotBefore}, {"not_after", e.NotAfter}, {"issued_at", e.IssuedAt}} {
			if _, ok := parseInstant(m[1]); m[1] == "" || entryInstants[m[0]] && !ok {
				return nil, errArg(fmt.Sprintf("the record's ledger entry %d does not read: %s", i, m[0]))
			}
		}
	}
	host := hostOf(endpoint)
	f := &LedgerFacts{NewHost: true}
	var newest *LedgerEntry
	var newestAt time.Time
	for i := range ledger {
		e := &ledger[i]
		if e.Root != root {
			continue
		}
		if hostOf(e.Endpoint) == host {
			f.NewHost = false
		}
		if e.Endpoint == endpoint {
			f.KnownEndpoint = true
		}
		// The first of the newest wins a tie, in ledger order, in both ports.
		if nb, ok := parseInstant(e.NotBefore); ok && (newest == nil || nb.Truncate(time.Second).After(newestAt)) {
			newest, newestAt = e, nb.Truncate(time.Second)
		}
	}
	if newest != nil {
		t := newestAt
		f.PreviousNotBefore = &t
		if na, ok := parseInstant(newest.NotAfter); ok && na.Truncate(time.Second).After(now) {
			f.Live = &LedgerLive{Endpoint: newest.Endpoint, NotAfter: na.Truncate(time.Second)}
		}
	}
	elsewhere := f.Live != nil && f.Live.Endpoint != endpoint
	switch {
	case elsewhere && f.KnownEndpoint:
		f.Kind = LedgerMoveBack
	case elsewhere:
		f.Kind = LedgerMove
	case f.KnownEndpoint:
		f.Kind = LedgerRenew
	default:
		f.Kind = LedgerNewHost
	}
	if elsewhere && !move {
		f.Refusal = SecondHome(f.Live.Endpoint)
	}
	return f, nil
}

// Answer is the answer of CONTRACT §6.1's ledger_check.
func (f *LedgerFacts) Answer() map[string]any {
	notice := map[string]any{"kind": f.Kind}
	if (f.Kind == LedgerMove || f.Kind == LedgerMoveBack) && f.Live != nil {
		notice["from"] = f.Live.Endpoint
		notice["until"] = timeOut(f.Live.NotAfter)
	}
	var refusal, previous, live any
	if f.Refusal != "" {
		refusal = f.Refusal
	}
	if f.PreviousNotBefore != nil {
		previous = timeOut(*f.PreviousNotBefore)
	}
	if f.Live != nil {
		live = map[string]any{"endpoint": f.Live.Endpoint, "not_after": timeOut(f.Live.NotAfter)}
	}
	return map[string]any{
		"refusal": refusal, "new_host": f.NewHost, "known_endpoint": f.KnownEndpoint,
		"previous_not_before": previous, "live": live, "notice": notice,
	}
}
