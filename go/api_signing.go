package pactidentity

// The Signing requests section of contract/contract.json: a body for each function it declares,
// which api.go's `functions` map dispatches by name. Its members are read as api/signing.rs reads
// them, in the order the contract's note fixes.

import "encoding/json"

func callSigningRequestCheck(a args) json.RawMessage {
	// The arguments are errors; the request's own faults are the answer (CONTRACT §3.1).
	var request map[string]any
	if raw := a.present("request"); raw != nil {
		if decoded, err := decodeJSON(raw); err == nil {
			request, _ = decoded.(map[string]any)
		}
	}
	if request == nil {
		return fail(codeArgs, "request is required")
	}
	origin, err := a.str("origin")
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	roots, err := a.optChain("root_spkis")
	if err != nil {
		return failAs(codeArgs, err)
	}
	checked, err := SigningRequestCheck(request, origin, now, roots)
	if err != nil {
		return ok(map[string]any{"ok": false, "why": err.Error()})
	}
	return ok(map[string]any{"ok": true, "csr": checked.CSR, "redirect": checked.Redirect, "purpose": checked.Purpose, "valid_days": checked.ValidDays})
}
