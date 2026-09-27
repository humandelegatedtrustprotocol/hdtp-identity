package pactidentity

// The Ledger section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name.

import (
	"bytes"
	"encoding/json"
)

func callLedgerCheck(args json.RawMessage) json.RawMessage {
	var a struct {
		Ledger   json.RawMessage `json:"ledger"`
		Root     *string         `json:"root"`
		Endpoint *string         `json:"endpoint"`
		Now      *string         `json:"now"`
		Move     *bool           `json:"move"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	// In the order the function needs them (CONTRACT §0): whose ledger, where, when, then the ledger.
	root, err := needStr(a.Root, "root")
	if err == nil && root == "" {
		err = errArg("root is required")
	}
	if err != nil {
		return failErr(codeArgs, err)
	}
	endpoint, err := needStr(a.Endpoint, "endpoint")
	if err != nil {
		return failErr(codeArgs, err)
	}
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	var entries []LedgerEntry
	if raw := bytes.TrimSpace(a.Ledger); len(raw) > 0 && string(raw) != "null" {
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
		entries = []LedgerEntry{}
		if json.Unmarshal(raw, &entries) != nil {
			return fail(codeArgs, "arguments do not read")
		}
	}
	facts, err := LedgerCheck(entries, root, endpoint, now, a.Move != nil && *a.Move)
	if err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	return ok(facts.Answer())
}
