package pactidentity

import (
	"testing"
	"time"
)

const (
	ledgerRoot  = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ledgerOther = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	ledgerA     = "https://agent.alina.example/mcp"
	ledgerB     = "https://alina.host.example/alina/mcp"
)

var ledgerNow = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func ledgerEntry(root, endpoint string, nb, na time.Time) LedgerEntry {
	return LedgerEntry{Root: root, Endpoint: endpoint, NotBefore: timeOut(nb), NotAfter: timeOut(na), IssuedAt: timeOut(nb)}
}

func days(n int) time.Time { return ledgerNow.Add(time.Duration(n) * 24 * time.Hour) }

func mustCheck(t *testing.T, ledger []LedgerEntry, endpoint string, move bool) *LedgerFacts {
	t.Helper()
	f, err := LedgerCheck(ledger, ledgerRoot, endpoint, ledgerNow, move)
	if err != nil {
		t.Fatalf("LedgerCheck: %v", err)
	}
	return f
}

func TestLedgerCheckNamesEachKindAndRefusesOnlyASecondHome(t *testing.T) {
	atA := []LedgerEntry{ledgerEntry(ledgerRoot, ledgerA, days(-10), days(300))}
	if f := mustCheck(t, atA, ledgerA, false); f.Kind != LedgerRenew || f.Refusal != "" || !f.KnownEndpoint || f.NewHost || !f.PreviousNotBefore.Equal(days(-10)) {
		t.Errorf("renewal: %+v", f)
	}
	if f := mustCheck(t, atA, ledgerB, false); f.Kind != LedgerMove || f.Refusal != SecondHome(ledgerA) || !f.NewHost {
		t.Errorf("a move without the flag: %+v", f)
	}
	f := mustCheck(t, atA, ledgerB, true)
	if f.Kind != LedgerMove || f.Refusal != "" {
		t.Errorf("a move: %+v", f)
	}
	if n := f.Answer()["notice"].(map[string]any); n["from"] != ledgerA || n["until"] != timeOut(days(300)) {
		t.Errorf("the move notice: %v", n)
	}
	moved := []LedgerEntry{ledgerEntry(ledgerRoot, ledgerA, days(-10), days(300)), ledgerEntry(ledgerRoot, ledgerB, days(-1), days(200))}
	if f := mustCheck(t, moved, ledgerA, false); f.Kind != LedgerMoveBack || f.Refusal != SecondHome(ledgerB) || f.Live.Endpoint != ledgerB {
		t.Errorf("back: %+v", f)
	}
	if f := mustCheck(t, moved, ledgerA, true); f.Refusal != "" {
		t.Errorf("back, chosen: %+v", f)
	}
	if f := mustCheck(t, []LedgerEntry{}, ledgerA, false); f.Kind != LedgerNewHost {
		t.Errorf("an empty ledger: %+v", f)
	}
	expired := []LedgerEntry{ledgerEntry(ledgerRoot, ledgerA, days(-400), days(-1))}
	if f := mustCheck(t, expired, ledgerB, false); f.Kind != LedgerNewHost || f.Refusal != "" || f.Live != nil {
		t.Errorf("after expiry: %+v", f)
	}
	if f := mustCheck(t, expired, ledgerA, false); f.Kind != LedgerRenew {
		t.Errorf("after expiry, the same endpoint: %+v", f)
	}
	theirs := []LedgerEntry{ledgerEntry(ledgerOther, ledgerB, days(-1), days(300))}
	if f := mustCheck(t, theirs, ledgerA, false); f.Kind != LedgerNewHost || f.Refusal != "" || !f.NewHost || f.PreviousNotBefore != nil {
		t.Errorf("another root's leaf: %+v", f)
	}
	if f := mustCheck(t, nil, ledgerA, false); f.Kind != LedgerNoLedger || !f.NewHost || f.KnownEndpoint {
		t.Errorf("no ledger: %+v", f)
	}
}

// The live leaf is the newest by notBefore, IF unexpired — never the newest of the unexpired.
func TestLedgerCheckTakesTheNewestLeafAndNotTheNewestUnexpiredOne(t *testing.T) {
	ledger := []LedgerEntry{ledgerEntry(ledgerRoot, ledgerA, days(-100), days(200)), ledgerEntry(ledgerRoot, ledgerB, days(-50), days(-1))}
	f := mustCheck(t, ledger, ledgerB, false)
	if f.Live != nil || f.Refusal != "" || f.Kind != LedgerRenew || !f.PreviousNotBefore.Equal(days(-50)) {
		t.Errorf("%+v", f)
	}
}

// An entry that does not read is refused, never skipped — whichever root it names.
func TestLedgerCheckRefusesAnEntryThatDoesNotRead(t *testing.T) {
	bad := ledgerEntry(ledgerOther, ledgerB, days(-1), days(300))
	bad.NotBefore = "soon"
	_, err := LedgerCheck([]LedgerEntry{ledgerEntry(ledgerRoot, ledgerA, days(-1), days(300)), bad}, ledgerRoot, ledgerA, ledgerNow, false)
	if err == nil || err.Error() != "the record's ledger entry 1 does not read: not_before" {
		t.Errorf("an unread entry: %v", err)
	}
	if err := ReadLedger(map[string]any{}); err == nil || err.Error() != "the record's ledger is a list" {
		t.Errorf("a ledger that is not a list: %v", err)
	}
	if _, err := LedgerCheck([]LedgerEntry{}, ledgerRoot, "http://agent.alina.example/mcp", ledgerNow, false); err == nil || err.Error() != "endpoint is not an https URL in normal form" {
		t.Errorf("an endpoint not in normal form: %v", err)
	}
}
