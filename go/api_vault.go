package hdtpidentity

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
	// Written as a sealed plaintext is (inOrder) by VaultSeal, as the core's seal writes it.
	pt := []byte(raw)
	// The generation is a bad request, as the Rust core answers it; the rest is the vault's.
	if plaintextV(pt) != PlaintextV {
		return fail("bad_request", generationWhy)
	}
	// The one KDF reader, which vault_open reads a document's with (vault.go readKDF).
	var kdfValue any
	raw = a.present("kdf")
	if raw != nil {
		if kdfValue, err = decodeJSON(raw); err != nil {
			return fail(codeArgs, "kdf is required")
		}
	}
	kdf, err := kdfFromArgs(kdfValue, raw != nil)
	if err != nil {
		return failAs("vault", err)
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
		return failAs("vault", err)
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
		return fail("vault", "not a hdtp-vault/1 document")
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
	// After the arguments, the documents, each held to CONTRACT §6 as it arrived, in the core's order
	// and words. Then what the rules read is taken from them by hand: decoding them into the typed
	// structs refused a member of the wrong type anywhere, a contact's included, as `arguments do not
	// read` — encoding/json's reading, not the contract's — and read a `pkcs8` of "" as none (R31).
	file, err := fileOf(a["vault_plaintext"])
	if err != nil {
		return failErr("bad_request", err)
	}
	record, err := recordOf(a["record_plaintext"])
	if err != nil {
		return failErr("bad_request", err)
	}
	var vault VaultPlaintext
	for _, r := range file["roots"].([]any) {
		o := r.(map[string]any)
		root := VaultRoot{}
		root.Fingerprint, _ = o["fingerprint"].(string)
		root.CN, _ = o["cn"].(string)
		root.Cert, _ = o["cert"].(string)
		root.PKCS8, root.pkcs8Given = o["pkcs8"].(string)
		vault.Roots = append(vault.Roots, root)
	}
	// A record with no `ledger` has no entry to read, and one with an empty ledger has read all of
	// them: nil and empty stay apart, as the typed decode kept them.
	ledger := ledgerEntriesOf(record["ledger"])
	issued, err := WalletIssue(vault, RecordPlaintext{V: PlaintextV, Ledger: ledger}, fingerprint, csr, now, days, moving)
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
