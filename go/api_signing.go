package pactidentity

// The Signing requests section of contract/contract.json: a body for each function it declares,
// which api.go's `functions` map dispatches by name.

import (
	"bytes"
	"encoding/json"
)

func callSigningRequestCheck(args json.RawMessage) json.RawMessage {
	var a struct {
		Request   json.RawMessage `json:"request"`
		Origin    *string         `json:"origin"`
		Now       *string         `json:"now"`
		RootSPKIs []B64           `json:"root_spkis"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	// The arguments are errors; the request's own faults are the answer (CONTRACT §3.1).
	var request map[string]any
	if raw := bytes.TrimSpace(a.Request); len(raw) > 0 {
		decoded, err := decodeJSON(raw)
		if err == nil {
			request, _ = decoded.(map[string]any)
		}
	}
	if request == nil {
		return fail(codeArgs, "request is required")
	}
	origin, err := needStr(a.Origin, "origin")
	if err != nil {
		return failErr(codeArgs, err)
	}
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	checked, err := SigningRequestCheck(request, origin, now, chainOf(a.RootSPKIs))
	if err != nil {
		return ok(map[string]any{"ok": false, "why": err.Error()})
	}
	return ok(map[string]any{"ok": true, "csr": checked.CSR, "redirect": checked.Redirect, "purpose": checked.Purpose, "valid_days": checked.ValidDays})
}
