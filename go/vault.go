package pactidentity

// The vault of §9 in the format a browser wallet and the CLI share (CONTRACT §6): Argon2id
// to a key, AES-256-GCM over the plaintext, the document's own header as AAD.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"sort"
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
	// Wider than the fields, then bounded — so a value that does not fit is a KDF refusal and not a
	// JSON one. Decoding straight into `uint32` made `m_kib: 4294967304` a parse error
	// ("kdf does not read") where the Rust core says "kdf parameters out of range": the same document,
	// two different answers, which CONTRACT section 0 forbids.
	raw := struct {
		Name *string `json:"name"`
		MKiB *uint64 `json:"m_kib"`
		T    *uint64 `json:"t"`
		P    *uint64 `json:"p"`
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
		if *raw.MKiB > math.MaxUint32 {
			return vaultError{"kdf parameters out of range"}
		}
		k.MKiB = uint32(*raw.MKiB)
	}
	if raw.T != nil {
		if *raw.T > math.MaxUint32 {
			return vaultError{"kdf parameters out of range"}
		}
		k.T = uint32(*raw.T)
	}
	if raw.P != nil {
		if *raw.P > math.MaxUint8 {
			return vaultError{"kdf parameters out of range"}
		}
		k.P = uint8(*raw.P)
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

// The range a passphrase KDF may name, at BOTH ends, matching the Rust core's four numbers exactly
// (vault.rs). The parameters come out of the document and are used before the passphrase is tested,
// so forging them is free: unbounded above, `m_kib: 4294967295` asked x/crypto/argon2 for terabytes;
// unbounded below, `m_kib: 8` put the person's root behind a KDF a laptop brute-forces, and
// x/crypto's own clamp then quietly rewrote the cost so this port could write a document the Rust
// core refuses to open.
const (
	maxMKiB uint32 = 1 << 21 // 2 GiB
	minMKiB uint32 = 8 * 1024
	maxT    uint32 = 16
	maxP    uint8  = 16
)

func vaultKey(passphrase string, v Vault) ([]byte, error) {
	if v.Format != VaultFormat {
		return nil, errors.New("not a pact-vault/1 document")
	}
	// Named separately, because the Rust core names it separately: a document whose kdf is not
	// argon2id answered "not a pact-vault/1 document" here and "unknown kdf" there.
	if v.KDF.Name != "argon2id" {
		return nil, vaultError{"unknown kdf"}
	}
	if v.KDF.MKiB < minMKiB || v.KDF.MKiB > maxMKiB || v.KDF.T < 1 || v.KDF.T > maxT || v.KDF.P < 1 || v.KDF.P > maxP {
		return nil, vaultError{"kdf parameters out of range"}
	}
	salt := FromB64url(v.Salt)
	if len(salt) < 8 {
		return nil, errors.New("not a pact-vault/1 document")
	}
	return argon2.IDKey([]byte(passphrase), salt, v.KDF.T, v.KDF.MKiB, v.KDF.P, 32), nil
}

// PlaintextV is the generation both documents carry: the file (the root and nothing else) and
// the record (the ledger and the contacts). There is no earlier one to open: a `v` that is not
// this is refused at both ends, sealing and opening, and nothing converts.
const PlaintextV = 2

// plaintextV reads the generation off a plaintext, or -1 when it carries none.
func plaintextV(plaintext []byte) int64 {
	var head struct {
		V *int64 `json:"v"`
	}
	if err := json.Unmarshal(plaintext, &head); err != nil || head.V == nil {
		return -1
	}
	return *head.V
}

var errEarlierGeneration = errors.New("this vault was written by an earlier wallet and is not opened: there is no conversion")

const generationWhy = "a vault plaintext is v 2: the root, or the record"

var (
	fileMembers   = []string{"v", "roots", "prf", "passkey"}
	recordMembers = []string{"v", "roots", "ledger", "contacts", "passkey", "backup_verified_at"}
	entryRequired = []string{"root", "endpoint", "not_before", "not_after", "issued_at"}
	entryMembers  = []string{"root", "endpoint", "not_before", "not_after", "issued_at", "origin"}
	entryInstants = map[string]bool{"not_before": true, "not_after": true, "issued_at": true}
)

// stranger is the first member, in sorted order, that allowed does not name: sorted, so the two
// ports name the same one whatever order their maps iterate in.
func stranger(doc map[string]any, allowed []string) string {
	var extra []string
	for k := range doc {
		found := false
		for _, a := range allowed {
			if a == k {
				found = true
			}
		}
		if !found {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	if len(extra) == 0 {
		return ""
	}
	return extra[0]
}

// CheckFile holds the file's plaintext to CONTRACT §6, as the Rust core's check_file does, in the
// same order and the same words. Held where the rules read it, not at seal and open, which carry the
// documents a live wallet already keeps.
func CheckFile(raw json.RawMessage) error {
	v, err := decodeJSON(raw)
	doc, isDoc := v.(map[string]any)
	if len(raw) == 0 || err != nil || !isDoc {
		return errors.New("vault_plaintext is required: the root lives there")
	}
	_, ledger := doc["ledger"]
	_, contacts := doc["contacts"]
	if ledger || contacts {
		return errors.New("a vault holds the root and nothing else: its ledger and contacts belong in the record")
	}
	if plaintextV(raw) != PlaintextV {
		return errors.New(generationWhy)
	}
	if k := stranger(doc, fileMembers); k != "" {
		return errors.New("vault_plaintext holds v, roots, prf and passkey, and nothing else: " + k)
	}
	return nil
}

// CheckRecord holds the record's plaintext to CONTRACT §6, every ledger entry included. An entry
// that does not read is refused, never skipped: skipped, it could be the live leaf, and one live leaf
// per identity would fail open. Every entry is read, not only one root's.
func CheckRecord(raw json.RawMessage) error {
	v, err := decodeJSON(raw)
	doc, isDoc := v.(map[string]any)
	if len(raw) == 0 || err != nil || !isDoc {
		return errors.New("record_plaintext is required: the ledger lives there")
	}
	if plaintextV(raw) != PlaintextV {
		return errors.New(generationWhy)
	}
	if k := stranger(doc, recordMembers); k != "" {
		return errors.New("record_plaintext holds v, roots, ledger, contacts, passkey and backup_verified_at, and nothing else: " + k)
	}
	ledger, has := doc["ledger"]
	if !has {
		return nil
	}
	return ReadLedger(ledger)
}

// VaultSeal encrypts plaintext under the passphrase. salt and nonce are drawn when nil (tests pass them).
func VaultSeal(passphrase string, plaintext []byte, kdf *KDF, salt, nonce []byte) (*Vault, error) {
	if plaintextV(plaintext) != PlaintextV {
		return nil, errors.New("a vault plaintext is v 2: the root, or the record")
	}
	return vaultSealAny(passphrase, plaintext, kdf, salt, nonce)
}

// vaultSealAny is the sealing itself, with no opinion about the plaintext: VaultSeal holds the
// generation, and the test of VaultOpen's refusal needs a document VaultSeal would not write.
func vaultSealAny(passphrase string, plaintext []byte, kdf *KDF, salt, nonce []byte) (*Vault, error) {
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
	// A plaintext that is not JSON is damage, as the Rust core has it — not an earlier wallet's.
	if !json.Valid(pt) {
		return nil, errVault
	}
	if plaintextV(pt) != PlaintextV {
		return nil, errEarlierGeneration
	}
	return pt, nil
}

// VaultRoot is one identity in the wallet.
type VaultRoot struct {
	Fingerprint string `json:"fingerprint"`
	CN          string `json:"cn"`
	Alg         string `json:"alg,omitempty"`
	// PKCS8 is the root's key, absent for a root generated on a card; Holder names the card, and an
	// entry may carry both (a key imported to a card and kept).
	PKCS8   string          `json:"pkcs8,omitempty"`
	Holder  json.RawMessage `json:"holder,omitempty"`
	Cert    string          `json:"cert"`
	Created string          `json:"created"`
	// ReboundAt marks a root re-bound to a new credential after the first was lost (SPEC §9): the
	// record then keeps this entry's key, and no other's.
	ReboundAt int64 `json:"rebound_at,omitempty"`
}

// LedgerEntry is one leaf the wallet issued: the endpoint and the dates, which is what every rule
// reads. Never the leaf itself, which is the host's to serve and grants nothing (SPEC §9).
type LedgerEntry struct {
	Root      string `json:"root"`
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
	Name     string `json:"name,omitempty"`
	Leaf     string `json:"leaf,omitempty"`
	RootCert string `json:"root_cert,omitempty"`
	Added    string `json:"added,omitempty"`
}

// VaultPasskey names the credential a derived root belongs to (SPEC §2.1); not secret.
type VaultPasskey struct {
	CredentialID string `json:"credential_id"`
}

// VaultPlaintext is what the FILE protects: the root and nothing else (SPEC §9). `PRF` is the
// §2.1 secret a derived root's record is opened with, for the wallet that has lost its credential.
type VaultPlaintext struct {
	V       int           `json:"v"`
	Roots   []VaultRoot   `json:"roots"`
	PRF     string        `json:"prf,omitempty"`
	Passkey *VaultPasskey `json:"passkey,omitempty"`
}

// RecordPlaintext is what the RECORD protects: the ledger and the contact book, and the roots
// without their keys — or with one, once a root has been re-bound (SPEC §9).
type RecordPlaintext struct {
	V                int            `json:"v"`
	Roots            []VaultRoot    `json:"roots,omitempty"`
	Ledger           []LedgerEntry  `json:"ledger"`
	Contacts         []VaultContact `json:"contacts"`
	Passkey          *VaultPasskey  `json:"passkey,omitempty"`
	BackupVerifiedAt int64          `json:"backup_verified_at,omitempty"`
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
// unless the caller says this is a move, and notBefore monotonic over the ledger. Two documents, as
// §9 keeps them: the vault is the root and nothing else, and the record holds the ledger this
// reads and the entry this answers is appended to.
func WalletIssue(plain VaultPlaintext, record RecordPlaintext, rootFingerprint string, csr []byte, now time.Time, validDays int, move bool) (*WalletIssued, error) {
	var root *VaultRoot
	rootSPKIs := make([][]byte, 0, len(plain.Roots))
	for i := range plain.Roots {
		r := &plain.Roots[i]
		if r.Fingerprint == rootFingerprint {
			root = r
		}
		// EVERY root this vault holds, and a root is held as its certificate: a software root has a
		// `pkcs8` beside it and a card-held one has not. Reading `pkcs8` alone left a card-held
		// sibling out of "a request whose key is a root" (§9), and such a request was given a leaf.
		if cert, err := Parse(FromB64url(r.Cert)); err == nil {
			rootSPKIs = append(rootSPKIs, cert.SPKI)
		}
		if priv, err := ParsePKCS8(FromB64url(r.PKCS8)); err == nil {
			rootSPKIs = append(rootSPKIs, priv.Public().SPKI)
		}
	}
	if root == nil {
		return nil, errors.New("no such root in the vault")
	}
	if root.PKCS8 == "" {
		return nil, errors.New("this root is held on a card: wallet_issue signs only with a key the vault holds")
	}
	rootKey, err := ParsePKCS8(FromB64url(root.PKCS8))
	if err != nil {
		return nil, errors.New("the root key does not parse")
	}
	info := CSRCheck(csr, rootSPKIs)
	if !info.OK {
		return nil, errors.New(info.Why)
	}
	// The ledger's rules, in the one place they are written (ledger.go).
	facts, err := LedgerCheck(record.Ledger, rootFingerprint, info.Endpoint, now, move)
	if err != nil {
		return nil, err
	}
	if facts.Refusal != "" {
		return nil, errors.New(facts.Refusal)
	}
	newHost, previous := facts.NewHost, facts.PreviousNotBefore
	moving := facts.Kind == LedgerMove || facts.Kind == LedgerMoveBack
	issued, err := IssueFromCSR(csr, IssueOpts{RootCN: root.CN, RootKey: rootKey, RootSPKIs: rootSPKIs, Now: now, PreviousNotBefore: previous, ValidDays: validDays})
	if err != nil {
		return nil, err
	}
	out := &WalletIssued{DER: issued.DER, NewHost: newHost, Entry: LedgerEntry{
		Root: rootFingerprint, Endpoint: issued.Endpoint,
		NotBefore: issued.NotBefore.UTC().Format(time.RFC3339), NotAfter: issued.NotAfter.UTC().Format(time.RFC3339),
		IssuedAt: now.UTC().Format(time.RFC3339),
	}}
	if newHost {
		out.Warnings = append(out.Warnings, "new host: this endpoint's host has never been issued to")
	}
	if moving {
		out.Warnings = append(out.Warnings, "move: the live leaf at the previous endpoint is superseded once contacts see this one")
	}
	return out, nil
}
