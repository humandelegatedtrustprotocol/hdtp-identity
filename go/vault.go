package pactidentity

// The vault of §9 in the format the ceremony, the CLI and the extension share (CONTRACT §6): Argon2id
// to a key, AES-256-GCM over the plaintext, the document's own header as AAD.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

const VaultFormat = "pact-vault/1"

// KDF are the Argon2id parameters, stored in the document.
type KDF struct {
	Name string `json:"name"`
	MKiB uint32 `json:"m_kib"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
}

// DefaultKDF is 64 MiB, three passes, one lane.
var DefaultKDF = KDF{Name: "argon2id", MKiB: 65536, T: 3, P: 1}

// UnmarshalJSON fills in what a `kdf` member leaves out. Every member of it is optional: a caller
// who writes `{"m_kib": 8192, "t": 1, "p": 1}` — which is what a test or a small device writes — is
// naming argon2id with those parameters, as the Rust core reads it. This port required the name and
// refused the document as "not a pact-vault/1 document", which is a refusal about the wrong thing.
func (k *KDF) UnmarshalJSON(p []byte) error {
	raw := struct {
		Name *string `json:"name"`
		MKiB *uint32 `json:"m_kib"`
		T    *uint32 `json:"t"`
		P    *uint8  `json:"p"`
	}{}
	if err := json.Unmarshal(p, &raw); err != nil {
		return parseError{"kdf does not read"}
	}
	*k = DefaultKDF
	if raw.Name != nil {
		if *raw.Name != "argon2id" {
			return vaultError{"unknown kdf"}
		}
		k.Name = *raw.Name
	}
	if raw.MKiB != nil {
		k.MKiB = *raw.MKiB
	}
	if raw.T != nil {
		k.T = *raw.T
	}
	if raw.P != nil {
		k.P = *raw.P
	}
	return nil
}

// vaultError is a refusal about the vault itself, answered as `vault` at the boundary.
type vaultError struct{ why string }

func (e vaultError) Error() string { return e.why }

// Vault is the sealed document.
type Vault struct {
	Format string `json:"format"`
	KDF    KDF    `json:"kdf"`
	Salt   string `json:"salt"`
	Nonce  string `json:"nonce"`
	Ct     string `json:"ct"`
}

var errVault = errors.New("the passphrase is wrong or the vault is damaged")

// vaultAAD is the canonical form of the header exactly as sealed: the four members a sealer writes.
func vaultAAD(v Vault) []byte {
	return Canonical(vaultDoc(v))
}

func vaultDoc(v Vault) map[string]any {
	return map[string]any{
		"format": v.Format,
		"kdf":    map[string]any{"name": v.KDF.Name, "m_kib": int64(v.KDF.MKiB), "t": int64(v.KDF.T), "p": int64(v.KDF.P)},
		"salt":   v.Salt,
		"nonce":  v.Nonce,
	}
}

func vaultKey(passphrase string, v Vault) ([]byte, error) {
	if v.Format != VaultFormat || v.KDF.Name != "argon2id" || v.KDF.MKiB < 8 || v.KDF.T < 1 || v.KDF.P < 1 {
		return nil, errors.New("not a pact-vault/1 document")
	}
	salt := FromB64url(v.Salt)
	if len(salt) < 8 {
		return nil, errors.New("not a pact-vault/1 document")
	}
	return argon2.IDKey([]byte(passphrase), salt, v.KDF.T, v.KDF.MKiB, v.KDF.P, 32), nil
}

// VaultSeal encrypts plaintext under the passphrase. salt and nonce are drawn when nil (tests pass them).
func VaultSeal(passphrase string, plaintext []byte, kdf *KDF, salt, nonce []byte) (*Vault, error) {
	if kdf == nil {
		k := DefaultKDF
		kdf = &k
	}
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	if len(nonce) != 12 {
		return nil, errors.New("nonce is 12 bytes")
	}
	v := Vault{Format: VaultFormat, KDF: *kdf, Salt: B64url(salt), Nonce: B64url(nonce)}
	key, err := vaultKey(passphrase, v)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	v.Ct = B64url(gcm.Seal(nil, nonce, plaintext, vaultAAD(v)))
	return &v, nil
}

// VaultOpen decrypts a typed document; a wrong passphrase and a tampered document are one message.
func VaultOpen(passphrase string, v Vault) ([]byte, error) {
	doc := vaultDoc(v)
	doc["ct"] = v.Ct
	return VaultOpenDoc(passphrase, doc)
}

// VaultOpenDoc decrypts the document as received: the AAD is every member but ct, canonicalised,
// so a member added after sealing — or one changed — fails to open, exactly as in the Rust core.
func VaultOpenDoc(passphrase string, doc map[string]any) ([]byte, error) {
	var v Vault
	v.Format, _ = doc["format"].(string)
	v.Salt, _ = doc["salt"].(string)
	v.Nonce, _ = doc["nonce"].(string)
	v.Ct, _ = doc["ct"].(string)
	if kdf, ok := doc["kdf"].(map[string]any); ok {
		v.KDF.Name, _ = kdf["name"].(string)
		if m, ok := numberOf(kdf["m_kib"]); ok {
			v.KDF.MKiB = uint32(m)
		}
		if t, ok := numberOf(kdf["t"]); ok {
			v.KDF.T = uint32(t)
		}
		if p, ok := numberOf(kdf["p"]); ok {
			v.KDF.P = uint8(p)
		}
	}
	key, err := vaultKey(passphrase, v)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := FromB64url(v.Nonce)
	if len(nonce) != 12 {
		return nil, errVault
	}
	header := make(map[string]any, len(doc))
	for k, val := range doc {
		if k != "ct" {
			header[k] = val
		}
	}
	pt, err := gcm.Open(nil, nonce, FromB64url(v.Ct), Canonical(header))
	if err != nil {
		return nil, errVault
	}
	return pt, nil
}

// VaultRoot is one identity in the wallet.
type VaultRoot struct {
	Fingerprint string `json:"fingerprint"`
	CN          string `json:"cn"`
	PKCS8       string `json:"pkcs8"`
	Cert        string `json:"cert"`
	Created     string `json:"created"`
}

// LedgerEntry is one leaf the wallet issued.
type LedgerEntry struct {
	Root      string `json:"root"`
	Leaf      string `json:"leaf"`
	Endpoint  string `json:"endpoint"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	IssuedAt  string `json:"issued_at"`
	Origin    string `json:"origin,omitempty"`
}

// VaultContact is the wallet's own copy of one contact.
type VaultContact struct {
	Root     string `json:"root"`
	Endpoint string `json:"endpoint"`
	Name     string `json:"name"`
	Leaf     string `json:"leaf,omitempty"`
	Added    string `json:"added"`
}

// VaultPlaintext is what the vault protects.
type VaultPlaintext struct {
	V        int            `json:"v"`
	Roots    []VaultRoot    `json:"roots"`
	Ledger   []LedgerEntry  `json:"ledger"`
	Contacts []VaultContact `json:"contacts"`
}

// WalletIssued is what WalletIssue returns: the leaf, the ledger entry to append, and what to show.
type WalletIssued struct {
	DER      []byte
	Entry    LedgerEntry
	Warnings []string
	NewHost  bool
}

// WalletIssue applies the wallet's rules of §9 to a request: proof of possession and the root-key
// refusal (CSRCheck with every root the wallet holds), a new host flagged, one live leaf per identity
// unless the caller says this is a move, and notBefore monotonic over the ledger.
func WalletIssue(plain VaultPlaintext, rootFingerprint string, csr []byte, now time.Time, validDays int, move bool) (*WalletIssued, error) {
	var root *VaultRoot
	rootSPKIs := make([][]byte, 0, len(plain.Roots))
	for i := range plain.Roots {
		r := &plain.Roots[i]
		if r.Fingerprint == rootFingerprint {
			root = r
		}
		if priv, err := ParsePKCS8(FromB64url(r.PKCS8)); err == nil {
			rootSPKIs = append(rootSPKIs, priv.Public.SPKI)
		}
	}
	if root == nil {
		return nil, errors.New("no such root in the vault")
	}
	rootKey, err := ParsePKCS8(FromB64url(root.PKCS8))
	if err != nil {
		return nil, errors.New("the root key does not parse")
	}
	info := CSRCheck(csr, rootSPKIs)
	if !info.OK {
		return nil, errors.New(info.Why)
	}
	host := hostOf(info.Endpoint)
	newHost := true
	var previous *time.Time
	var newest *LedgerEntry
	for i := range plain.Ledger {
		e := &plain.Ledger[i]
		if e.Root != rootFingerprint {
			continue
		}
		if hostOf(e.Endpoint) == host {
			newHost = false
		}
		if nb, ok := parseInstant(e.NotBefore); ok && (previous == nil || nb.After(*previous)) {
			t := nb
			previous = &t
			newest = e
		}
	}
	// The live leaf is the newest one issued (§14.3: a later notBefore supersedes every earlier
	// leaf the instant it is seen), if it has not expired. Earlier entries are history.
	movingFrom := ""
	if newest != nil && newest.Endpoint != info.Endpoint {
		if na, ok := parseInstant(newest.NotAfter); ok && na.After(now) {
			if !move {
				return nil, errors.New("a leaf is live for " + newest.Endpoint + ": a second endpoint is a move, not a second home")
			}
			movingFrom = newest.Endpoint
		}
	}
	issued, err := IssueFromCSR(csr, IssueOpts{RootCN: root.CN, RootKey: rootKey, RootSPKIs: rootSPKIs, Now: now, PreviousNotBefore: previous, ValidDays: validDays})
	if err != nil {
		return nil, err
	}
	out := &WalletIssued{DER: issued.DER, NewHost: newHost, Entry: LedgerEntry{
		Root: rootFingerprint, Leaf: B64url(issued.DER), Endpoint: issued.Endpoint,
		NotBefore: issued.NotBefore.UTC().Format(time.RFC3339), NotAfter: issued.NotAfter.UTC().Format(time.RFC3339),
		IssuedAt: now.UTC().Format(time.RFC3339),
	}}
	if newHost {
		out.Warnings = append(out.Warnings, "new host: this endpoint's host has never been issued to")
	}
	if movingFrom != "" {
		out.Warnings = append(out.Warnings, "move: the live leaf at the previous endpoint is superseded once contacts see this one")
	}
	return out, nil
}
