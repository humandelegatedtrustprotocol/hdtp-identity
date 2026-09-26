package pactidentity

// The Vault section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name.

import (
	"bytes"
	"encoding/json"
)

func callVaultSeal(args json.RawMessage) json.RawMessage {
	var a struct {
		Passphrase *string         `json:"passphrase"`
		Plaintext  json.RawMessage `json:"plaintext"`
		KDF        *KDF            `json:"kdf"`
		Salt       B64             `json:"salt"`
		Nonce      B64             `json:"nonce"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	// Absent is `passphrase is required`, as the core says it; present and empty is its own refusal.
	passphrase, err := needStr(a.Passphrase, "passphrase")
	if err != nil {
		return failErr(codeArgs, err)
	}
	if passphrase == "" {
		return fail("bad_request", "empty passphrase")
	}
	if len(bytes.TrimSpace(a.Plaintext)) == 0 || string(bytes.TrimSpace(a.Plaintext)) == "null" {
		return fail(codeArgs, "plaintext is required")
	}
	pt, err := compactJSON(a.Plaintext)
	if err != nil {
		return fail("parse", "plaintext is not JSON")
	}
	salt, nonce := []byte(a.Salt), []byte(a.Nonce)
	v, err := VaultSeal(passphrase, pt, a.KDF, salt, nonce)
	if err != nil {
		// The generation is a bad request, as the Rust core answers it; the rest is the vault's.
		if plaintextV(pt) != PlaintextV {
			return failErr("bad_request", err)
		}
		return failErr("vault", err)
	}
	return ok(map[string]any{"vault": v})
}

func callVaultOpen(args json.RawMessage) json.RawMessage {
	var a struct {
		Passphrase string          `json:"passphrase"`
		Vault      json.RawMessage `json:"vault"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	// The document as received, every member of it: the AAD is the header as written, so a
	// member added after sealing fails to open here as it does in the Rust core.
	if len(bytes.TrimSpace(a.Vault)) == 0 || string(bytes.TrimSpace(a.Vault)) == "null" {
		return fail(codeArgs, "vault is required")
	}
	dv, err := decodeJSON(a.Vault)
	doc, isDoc := dv.(map[string]any)
	if err != nil || !isDoc {
		return fail("vault", "not a pact-vault/1 document")
	}
	pt, err := VaultOpenDoc(a.Passphrase, doc)
	if err != nil {
		return failErr("vault", err)
	}
	return ok(map[string]any{"plaintext": json.RawMessage(pt)})
}

func callWalletIssue(args json.RawMessage) json.RawMessage {
	var a struct {
		VaultPlaintext  json.RawMessage `json:"vault_plaintext"`
		RecordPlaintext json.RawMessage `json:"record_plaintext"`
		RootFingerprint *string         `json:"root_fingerprint"`
		CSR             B64             `json:"csr"`
		Now             *string         `json:"now"`
		ValidDays       *int            `json:"valid_days"`
		Move            bool            `json:"move"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	fingerprint, err := needStr(a.RootFingerprint, "root_fingerprint")
	if err != nil {
		return failErr(codeArgs, err)
	}
	if err := need(a.CSR, "csr"); err != nil {
		return failErr(codeArgs, err)
	}
	now, err := timeIn(a.Now, "now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	days, err := daysOr(a.ValidDays)
	if err != nil {
		return failErr("bad_request", err)
	}
	// After the arguments, the documents, each held to CONTRACT §6 as it arrived — before any typed
	// decoding, which would drop a member the contract does not describe and put encoding/json's
	// own words into an answer (CONTRACT §0).
	if err := CheckFile(a.VaultPlaintext); err != nil {
		return failErr("bad_request", err)
	}
	if err := CheckRecord(a.RecordPlaintext); err != nil {
		return failErr("bad_request", err)
	}
	var vault VaultPlaintext
	var record RecordPlaintext
	if json.Unmarshal(a.VaultPlaintext, &vault) != nil || json.Unmarshal(a.RecordPlaintext, &record) != nil {
		return fail(codeArgs, "arguments do not read")
	}
	issued, err := WalletIssue(vault, record, fingerprint, a.CSR, now, days, a.Move)
	if err != nil {
		return failErr("bad_request", err)
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
