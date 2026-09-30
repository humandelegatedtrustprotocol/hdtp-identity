package pactidentity

import "testing"

// Helpers only the tests call. They were exported (or package) API that nothing outside the
// tests reached — review N-15 — so they live beside the tests that use them.

// chainIn decodes a list of base64url members for a test holding strings rather than the
// boundary's arguments, and fails the test on one that does not read.
func chainIn(t *testing.T, chain []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(chain))
	for _, c := range chain {
		b, err := DecodeB64url(c)
		if err != nil {
			t.Fatalf("chain member %q: %v", c, err)
		}
		out = append(out, b)
	}
	return out
}

// wireIn decodes an envelope member of the vectors as it travels, and fails the test on one that is
// not in its one canonical spelling.
func wireIn(t *testing.T, s string) []byte {
	t.Helper()
	b, err := wireB64url(s)
	if err != nil {
		t.Fatalf("envelope member %q: %v", s, err)
	}
	return b
}

// Functions lists the contract's names, for a caller that wants to check coverage.
func Functions() []string {
	out := make([]string, 0, len(functions))
	for k := range functions {
		out = append(out, k)
	}
	return out
}

// Seed derives every secret in the vectors from a label, so the generator is reproducible.
func Seed(label string) []byte { return sha256Sum([]byte("pact-2.0-vectors/" + label)) }

// VaultOpen decrypts a typed document; a wrong passphrase and a tampered document are one message.
func VaultOpen(passphrase string, v Vault) ([]byte, error) {
	doc := vaultDoc(v)
	doc["ct"] = v.Ct
	return VaultOpenDoc(passphrase, doc)
}

// SerialOf is the vectors' serial: SHA-256("serial/" + label), first 8 bytes.
func SerialOf(label string) []byte { return sha256Sum([]byte("serial/" + label))[:8] }
