package pactidentity

// Helpers only the tests call. They were exported (or package) API that nothing outside the
// tests reached — review N-15 — so they live beside the tests that use them.

// chainIn decodes a list of base64url members the way the wire does, for a test or a caller holding
// strings rather than the boundary's arguments. The boundary itself decodes strictly (b64.go).
func chainIn(chain []string) [][]byte {
	out := make([][]byte, 0, len(chain))
	for _, c := range chain {
		out = append(out, FromB64url(c))
	}
	return out
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
