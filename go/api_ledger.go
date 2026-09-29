package pactidentity

// The Ledger section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name.

import "encoding/json"

func callLedgerCheck(a args) json.RawMessage {
	// In the order the function needs them (CONTRACT §0): whose ledger, where, when, whether it is a
	// move, then the ledger. `move` was judged with every other member before any was read (R32).
	root, err := a.id("root")
	if err != nil {
		return failAs(codeArgs, err)
	}
	endpoint, err := a.str("endpoint")
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	moving, err := a.boolean("move")
	if err != nil {
		return failAs(codeArgs, err)
	}
	var entries []LedgerEntry
	if raw := a.present("ledger"); raw != nil {
		// The ledger as it arrived, every member of it, before any typed decoding drops one.
		if !IsNormalHTTPS(endpoint) {
			return fail(codeArgs, "endpoint is not an https URL in normal form")
		}
		decoded, err := decodeJSON(raw)
		if err != nil {
			return fail(codeArgs, "the record's ledger is a list")
		}
		if err := ReadLedger(decoded); err != nil {
			return failErr(codeArgs, err)
		}
		// Read, so taken by hand: encoding/json here could not fail, and its `arguments do not read`
		// was a refusal nothing reached.
		entries = ledgerEntriesOf(decoded)
	}
	facts, err := LedgerCheck(entries, root, endpoint, now, moving)
	if err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	return ok(facts.Answer())
}

// ledgerEntriesOf takes the entries of a ledger ReadLedger has read: a list of objects whose members
// are strings. A value that is not a list has none (nil), and an empty list has read all of them.
func ledgerEntriesOf(v any) []LedgerEntry {
	items, isList := v.([]any)
	if !isList {
		return nil
	}
	out := make([]LedgerEntry, 0, len(items))
	for _, e := range items {
		o, _ := e.(map[string]any)
		text := func(k string) string { s, _ := o[k].(string); return s }
		out = append(out, LedgerEntry{Root: text("root"), Endpoint: text("endpoint"), NotBefore: text("not_before"), NotAfter: text("not_after"), IssuedAt: text("issued_at"), Origin: text("origin")})
	}
	return out
}
