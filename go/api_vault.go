package pactidentity

// The Vault section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name. Each reads its members as api/vault.rs does, in the
// order the contract's notes fix.

import "encoding/json"

func callVaultSeal(a args) json.RawMessage {
	// In the contract's order: `passphrase` (absent: `passphrase is required`; empty: `empty
	// passphrase`), `plaintext` and its generation, then `kdf`, `salt` and `nonce` — each judged
	// where it is read, never by a decoder that ran first (R32's corrected case: a `kdf` of the wrong
	// type was named before a missing passphrase).
	passphrase, err := a.str("passphrase")
	if err != nil {
		return failAs(codeArgs, err)
	}
	if passphrase == "" {
		return fail("bad_request", "empty passphrase")
	}
	raw := a.present("plaintext")
	if raw == nil {
		return fail(codeArgs, "plaintext is required")
	}
	pt, err := compactJSON(raw)
	if err != nil {
		return fail("parse", "plaintext is not JSON")
	}
	// The generation is a bad request, as the Rust core answers it; the rest is the vault's.
	if plaintextV(pt) != PlaintextV {
		return fail("bad_request", generationWhy)
	}
	var kdf *KDF
	if raw := a.present("kdf"); raw != nil {
		kdf = &KDF{}
		if err := json.Unmarshal(raw, kdf); err != nil {
			return failAs(codeArgs, err)
		}
	}
	salt, err := a.optBytes("salt")
	if err != nil {
		return failAs(codeArgs, err)
	}
	nonce, err := a.optBytes("nonce")
	if err != nil {
		return failAs(codeArgs, err)
	}
	v, err := VaultSeal(passphrase, pt, kdf, salt, nonce)
	if err != nil {
		return failErr("vault", err)
	}
	return ok(map[string]any{"vault": v})
}

func callVaultOpen(a args) json.RawMessage {
	// The document as received, every member of it: the AAD is the header as written, so a
	// member added after sealing fails to open here as it does in the Rust core. The core reads
	// `vault`, then `passphrase` (absent: `passphrase is required`, where this port opened with "").
	raw := a.present("vault")
	if raw == nil {
		return fail(codeArgs, "vault is required")
	}
	passphrase, err := a.str("passphrase")
	if err != nil {
		return failAs(codeArgs, err)
	}
	dv, err := decodeJSON(raw)
	doc, isDoc := dv.(map[string]any)
	if err != nil || !isDoc {
		return fail("vault", "not a pact-vault/1 document")
	}
	pt, err := VaultOpenDoc(passphrase, doc)
	if err != nil {
		return failErr("vault", err)
	}
	return ok(map[string]any{"plaintext": json.RawMessage(pt)})
}

func callWalletIssue(a args) json.RawMessage {
	fingerprint, err := a.str("root_fingerprint")
	if err != nil {
		return failAs(codeArgs, err)
	}
	csr, err := a.bytes("csr")
	if err != nil {
		return failAs(codeArgs, err)
	}
	now, err := a.instant("now")
	if err != nil {
		return failAs("parse", err)
	}
	days, err := a.validDays()
	if err != nil {
		return failAs(codeArgs, err)
	}
	moving, err := a.boolean("move")
	if err != nil {
		return failAs(codeArgs, err)
	}
	// After the arguments, the documents, each held to CONTRACT §6 as it arrived — before any typed
	// decoding, which would drop a member the contract does not describe and put encoding/json's
	// own words into an answer (CONTRACT §0).
	vaultPlaintext, recordPlaintext := a["vault_plaintext"], a["record_plaintext"]
	if err := CheckFile(vaultPlaintext); err != nil {
		return failErr("bad_request", err)
	}
	if err := CheckRecord(recordPlaintext); err != nil {
		return failErr("bad_request", err)
	}
	var vault VaultPlaintext
	var record RecordPlaintext
	if json.Unmarshal(vaultPlaintext, &vault) != nil || json.Unmarshal(recordPlaintext, &record) != nil {
		return fail(codeArgs, "arguments do not read")
	}
	issued, err := WalletIssue(vault, record, fingerprint, csr, now, days, moving)
	if err != nil {
		return failAs("bad_request", err)
	}
	warnings := issued.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	// The full shape of CONTRACT §6: the certificate, where and when it is good for, the ledger
	// entry to append, whether this host is new, and what a person should be told.
	return ok(map[string]any{
		"der": B64url(issued.DER), "ledger_entry": issued.Entry, "warnings": warnings, "new_host": issued.NewHost,
		"endpoint": issued.Entry.Endpoint, "not_before": issued.Entry.NotBefore, "not_after": issued.Entry.NotAfter,
	})
}
