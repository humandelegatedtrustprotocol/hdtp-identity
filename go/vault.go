package hdtpidentity

// The vault of §9 in the format a browser wallet and the CLI share (CONTRACT §6): Argon2id
// to a key, AES-256-GCM over the plaintext, the document's own header as AAD.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"golang.org/x/crypto/argon2"
)

const VaultFormat = "hdtp-vault/1"

// KDF are the Argon2id parameters, stored in the document.
type KDF struct {
	Name string `json:"name"`
	MKiB uint32 `json:"m_kib"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
}

// DefaultKDF is 64 MiB, three passes, one lane.
var DefaultKDF = KDF{Name: "argon2id", MKiB: 65536, T: 3, P: 1}

// readKDF is the one reader of a KDF, for a document's and for a caller's (S5; CONTRACT §6), as the
// Rust core's Kdf::read is. A document's `Kdf` names all four members; a caller's `KdfArgs` may leave
// any out, and it takes the default. `name` is `argon2id`, and anything else — another name, one that
// is not a string, or, in a document, none — is `unknown kdf`. Each parameter is a whole number
// written as one that fits in 32 bits, and inside its range; anything else, a parameter a document
// lacks included, is `kdf parameters out of range`, and nothing is narrowed before it is bounded.
//
// It replaces two: KDF.UnmarshalJSON, which read a caller's `kdf` before the passphrase and the
// plaintext and answered `parse` `kdf does not read` for a number of the wrong spelling, and matched
// member names in any case (`M_KIB` was `m_kib`); and VaultOpenDoc's own read of a document's, which
// read a `kdf` with no `name` as unknown where the core opened it under the default (R28, C4, T12, F17).
func readKDF(o map[string]any, document bool) (KDF, error) {
	name, present := o["name"]
	switch {
	case name == "argon2id":
	case !document && (!present || name == nil):
	default:
		return KDF{}, vaultError{"unknown kdf"}
	}
	outOfRange := vaultError{"kdf parameters out of range"}
	param := func(k string, dflt uint32) (uint32, error) {
		v, present := o[k]
		if !document && (!present || v == nil) {
			return dflt, nil
		}
		if !present {
			return 0, outOfRange
		}
		n, whole := kdfNumber(v)
		if !whole || n > math.MaxUint32 {
			return 0, outOfRange
		}
		return uint32(n), nil
	}
	m, err := param("m_kib", DefaultKDF.MKiB)
	if err != nil {
		return KDF{}, err
	}
	t, err := param("t", DefaultKDF.T)
	if err != nil {
		return KDF{}, err
	}
	p, err := param("p", uint32(DefaultKDF.P))
	if err != nil {
		return KDF{}, err
	}
	if err := kdfInRange(m, t, p); err != nil {
		return KDF{}, err
	}
	// Members by their exact names, and no others (`Kdf`, `KdfArgs`: additionalProperties false).
	if k := stranger(o, []string{"name", "m_kib", "t", "p"}); k != "" {
		return KDF{}, vaultError{"kdf holds name, m_kib, t and p, and nothing else: " + k}
	}
	return KDF{Name: "argon2id", MKiB: m, T: t, P: uint8(p)}, nil
}

// kdfInRange is the range every derivation is held to, at both ends and on both paths.
func kdfInRange(m, t, p uint32) error {
	if m < minMKiB || m > maxMKiB || t < 1 || t > maxT || p < 1 || p > uint32(maxP) {
		return vaultError{"kdf parameters out of range"}
	}
	return nil
}

// kdfFromArgs is vault_seal's `kdf` argument: absent or null is the default, an object is read by the
// one reader, and anything else is `kdf is required` (CONTRACT §0: a member of the wrong type is
// refused in the words its absence gets, and never read as absent).
func kdfFromArgs(v any, present bool) (*KDF, error) {
	if !present || v == nil {
		return nil, nil
	}
	o, isObject := v.(map[string]any)
	if !isObject {
		return nil, errArg("kdf is required")
	}
	k, err := readKDF(o, false)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// kdfOfDocument is a document's `kdf`: an object with all four members. One that is not an object
// names no KDF.
func kdfOfDocument(v any) (KDF, error) {
	o, isObject := v.(map[string]any)
	if !isObject {
		return KDF{}, vaultError{"unknown kdf"}
	}
	return readKDF(o, true)
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

// The range a passphrase KDF may name, at BOTH ends: contract/contract.json's `Kdf`, which
// constants_test.go holds these to (and vault.rs's tests the Rust core's). The parameters come out of the document and are used before the passphrase is tested,
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

// minSalt is the shortest salt either end takes, in bytes: contract/contract.json's `VaultSaltMin`,
// which constants_test.go holds this to (and vault.rs's tests the core's). x/crypto's argon2 takes a
// salt of any length; this port refused one under 8 bytes as `not an hdtp-vault/1 document`, and the
// core passed Argon2id's own words (`salt is too short`) into `why` (R29, C6).
const minSalt = 8

// deriveKey is Argon2id after the one range and the salt floor, as the core's `derive` is: no
// caller, typed or JSON, sealing or opening, reaches it with parameters the other end refuses.
func deriveKey(passphrase string, salt []byte, kdf KDF) ([]byte, error) {
	if err := kdfInRange(kdf.MKiB, kdf.T, uint32(kdf.P)); err != nil {
		return nil, err
	}
	if len(salt) < minSalt {
		return nil, vaultError{"salt is at least 8 bytes"}
	}
	return argon2.IDKey([]byte(passphrase), salt, kdf.T, kdf.MKiB, kdf.P, 32), nil
}

// PlaintextV is the generation both documents carry: the file (the root and nothing else) and
// the record (the ledger and the contacts). There is no other one to open: a `v` that is not
// this is refused at both ends, sealing and opening, and nothing converts.
const PlaintextV = 1

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

var errOtherGeneration = errors.New("this vault is of another generation and is not opened: there is no conversion")

const generationWhy = "a vault plaintext is v 1: the root, or the record"

var (
	fileMembers   = []string{"v", "roots", "prf", "passkey"}
	recordMembers = []string{"v", "roots", "ledger", "contacts", "passkey", "backup_verified_at"}
	entryRequired = []string{"root", "endpoint", "not_before", "not_after", "issued_at"}
	entryMembers  = []string{"root", "endpoint", "not_before", "not_after", "issued_at", "origin"}
	entryInstants = map[string]bool{"not_before": true, "not_after": true, "issued_at": true}
)

// stranger is the first member, in sorted order, that allowed does not name: sorted, so the two
// ports name the same one whatever order their maps iterate in.
func stranger[V any](doc map[string]V, allowed []string) string {
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

// member is a member a document declares, read as CONTRACT §0 reads every member: the JSON literal
// null is absent, as the core's `member` reads it. These readers took a null member for one of the
// wrong type (836d080), so a root's `pkcs8: null` was `does not read: pkcs8` where its absence is a
// card-held root. A member a document does not declare is refused whatever it holds, null too
// (stranger), as a function's arguments are.
func member(o map[string]any, k string) (any, bool) {
	v, has := o[k]
	return v, has && v != nil
}

// CheckFile holds the file's plaintext to CONTRACT §6, as the Rust core's check_file does, in the
// same order and the same words. Held where the rules read it, not at seal and open, which carry the
// documents a live wallet already keeps.
func CheckFile(raw json.RawMessage) error {
	_, err := fileOf(raw)
	return err
}

// fileOf is CheckFile, answering the document it read.
func fileOf(raw json.RawMessage) (map[string]any, error) {
	// Absent or null is `<name> is required`, as CONTRACT §0 has every absent member (S1-2).
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errArg("vault_plaintext is required")
	}
	v, err := decodeJSON(raw)
	doc, isDoc := v.(map[string]any)
	if err != nil || !isDoc {
		return nil, errors.New("vault_plaintext is required: the root lives there")
	}
	_, ledger := doc["ledger"]
	_, contacts := doc["contacts"]
	if ledger || contacts {
		return nil, errors.New("a vault holds the root and nothing else: its ledger and contacts belong in the record")
	}
	if plaintextV(raw) != PlaintextV {
		return nil, errors.New(generationWhy)
	}
	if k := stranger(doc, fileMembers); k != "" {
		return nil, errors.New("vault_plaintext holds v, roots, prf and passkey, and nothing else: " + k)
	}
	// Then each member, as CONTRACT §6 types it, in the order VaultPlaintext lists them. This port
	// decoded the documents into typed structs, so a member of the wrong type anywhere in them was
	// `arguments do not read`, where the core read it as absent, skipped it, or carried it (F18, R31).
	roots, has := member(doc, "roots")
	if err := readRoots(roots, has, "vault", true); err != nil {
		return nil, err
	}
	if prf, has := member(doc, "prf"); has {
		text, isText := prf.(string)
		b, err := DecodeB64url(text)
		if !isText || err != nil || len(b) != 32 {
			return nil, errors.New("the vault's prf does not read")
		}
	}
	passkey, has := member(doc, "passkey")
	return doc, readPasskey(passkey, has, "vault")
}

var (
	rootRequired = []string{"fingerprint", "cn", "cert", "created"}
	rootMembers  = []string{"fingerprint", "cn", "alg", "cert", "created", "pkcs8", "holder", "rebound_at"}
)

// readRoots is a document's `roots`, each entry read as CONTRACT §6's VaultRoot, as the core's
// read_roots reads them: a list, each entry an object whose `fingerprint` is a fingerprint, `cn` and
// `cert` strings and `created` an instant, whose `alg`, `pkcs8`, `holder` and `rebound_at` are of
// their types where present, and that holds nothing else. The first that does not read is named by
// its index and member, as a ledger entry is. The file must have `roots`; the record may leave it out.
func readRoots(roots any, present bool, whose string, required bool) error {
	if !present && !required {
		return nil
	}
	entries, isList := roots.([]any)
	if !present || !isList {
		return fmt.Errorf("the %s's roots is a list", whose)
	}
	for i, r := range entries {
		o, isObject := r.(map[string]any)
		if !isObject {
			return fmt.Errorf("the %s's root %d does not read", whose, i)
		}
		unread := func(m string) error { return fmt.Errorf("the %s's root %d does not read: %s", whose, i, m) }
		for _, m := range rootRequired {
			text, isText := o[m].(string)
			wrong := !isText
			switch m {
			case "fingerprint":
				wrong = wrong || !IsFingerprint(text)
			case "created":
				_, reads := parseInstant(text)
				wrong = wrong || !reads
			}
			if wrong {
				return unread(m)
			}
		}
		for _, c := range []struct {
			m     string
			reads func(any) bool
		}{
			{"alg", func(v any) bool { return v == "ed25519" || v == "p256" }},
			{"pkcs8", func(v any) bool { _, isText := v.(string); return isText }},
			{"holder", func(v any) bool { _, isObject := v.(map[string]any); return isObject }},
			{"rebound_at", func(v any) bool { _, whole := asU64(v); return whole }},
		} {
			if v, has := member(o, c.m); has && !c.reads(v) {
				return unread(c.m)
			}
		}
		if k := stranger(o, rootMembers); k != "" {
			return unread(k)
		}
	}
	return nil
}

var (
	contactRequired = []string{"root", "endpoint"}
	contactMembers  = []string{"root", "endpoint", "name", "leaf", "root_cert", "added"}
)

// readContacts is the record's `contacts`, each entry read as CONTRACT §6's VaultContact, as the
// core's read_contacts reads them: a list, each entry an object whose `root` is a fingerprint and
// `endpoint` a string, whose `name`, `leaf`, `root_cert` and `added` are strings where present, `added`
// an instant, and that holds nothing else.
func readContacts(contacts any) error {
	entries, isList := contacts.([]any)
	if !isList {
		return errors.New("the record's contacts is a list")
	}
	for i, c := range entries {
		o, isObject := c.(map[string]any)
		if !isObject {
			return fmt.Errorf("the record's contact %d does not read", i)
		}
		unread := func(m string) error { return fmt.Errorf("the record's contact %d does not read: %s", i, m) }
		for _, m := range contactRequired {
			text, isText := o[m].(string)
			if !isText || (m == "root" && !IsFingerprint(text)) {
				return unread(m)
			}
		}
		for _, m := range []string{"name", "leaf", "root_cert", "added"} {
			v, has := member(o, m)
			if !has {
				continue
			}
			text, isText := v.(string)
			if _, reads := parseInstant(text); !isText || (m == "added" && !reads) {
				return unread(m)
			}
		}
		if k := stranger(o, contactMembers); k != "" {
			return unread(k)
		}
	}
	return nil
}

// readPasskey is `passkey`, where a document carries one: an object naming its credential and nothing
// else.
func readPasskey(passkey any, present bool, whose string) error {
	if !present {
		return nil
	}
	o, isObject := passkey.(map[string]any)
	if isObject {
		if _, isText := o["credential_id"].(string); isText && stranger(o, []string{"credential_id"}) == "" {
			return nil
		}
	}
	return fmt.Errorf("the %s's passkey does not read", whose)
}

// CheckRecord holds the record's plaintext to CONTRACT §6, every ledger entry included. An entry
// that does not read is refused, never skipped: skipped, it could be the live leaf, and one live leaf
// per identity would fail open. Every entry is read, not only one root's.
func CheckRecord(raw json.RawMessage) error {
	_, err := recordOf(raw)
	return err
}

// recordOf is CheckRecord, answering the document it read.
func recordOf(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errArg("record_plaintext is required")
	}
	v, err := decodeJSON(raw)
	doc, isDoc := v.(map[string]any)
	if err != nil || !isDoc {
		return nil, errors.New("record_plaintext is required: the ledger lives there")
	}
	if plaintextV(raw) != PlaintextV {
		return nil, errors.New(generationWhy)
	}
	if k := stranger(doc, recordMembers); k != "" {
		return nil, errors.New("record_plaintext holds v, roots, ledger, contacts, passkey and backup_verified_at, and nothing else: " + k)
	}
	// Then each member, in the order RecordPlaintext lists them.
	roots, has := member(doc, "roots")
	if err := readRoots(roots, has, "record", false); err != nil {
		return nil, err
	}
	if ledger, has := member(doc, "ledger"); has {
		if err := ReadLedger(ledger); err != nil {
			return nil, err
		}
	}
	if contacts, has := member(doc, "contacts"); has {
		if err := readContacts(contacts); err != nil {
			return nil, err
		}
	}
	passkey, has := member(doc, "passkey")
	if err := readPasskey(passkey, has, "record"); err != nil {
		return nil, err
	}
	if b, has := member(doc, "backup_verified_at"); has {
		if _, whole := asU64(b); !whole {
			return nil, errors.New("the record's backup_verified_at does not read")
		}
	}
	return doc, nil
}

// VaultSeal encrypts plaintext under the passphrase. salt and nonce are drawn when nil (tests pass them).
// An empty passphrase is refused, as the core's typed `seal` refuses it: only this port's JSON
// boundary did (T19's mirror).
func VaultSeal(passphrase string, plaintext []byte, kdf *KDF, salt, nonce []byte) (*Vault, error) {
	if passphrase == "" {
		return nil, errArg("empty passphrase")
	}
	// Written as a sealed plaintext is (inOrder), as the core's seal writes the value it is handed, so
	// the two ports seal one document alike.
	pt, err := inOrder(plaintext)
	if err != nil {
		return nil, parseError{"plaintext is not JSON"}
	}
	if plaintextV(pt) != PlaintextV {
		return nil, errors.New("a vault plaintext is v 1: the root, or the record")
	}
	return vaultSealAny(passphrase, pt, kdf, salt, nonce)
}

// vaultSealAny is the sealing itself, with no opinion about the plaintext: VaultSeal writes it
// (inOrder) and holds the generation, and the tests of VaultOpen's refusals need documents VaultSeal
// would not write.
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
	if kdf.Name != "argon2id" {
		return nil, vaultError{"unknown kdf"}
	}
	key, err := deriveKey(passphrase, salt, *kdf)
	if err != nil {
		return nil, err
	}
	v := Vault{Format: VaultFormat, KDF: *kdf, Salt: B64url(salt), Nonce: B64url(nonce)}
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

// kdfNumber is a KDF parameter of a document as the core reads one (`as_u64`): a json.Number, as the
// boundary decodes the document, written as a whole number — `1.0` is not one. A float64 is a Go
// caller's own decoding, which kept no spelling: it counts when it is whole. Past 2^32 it is out of
// every parameter's range, which is what the caller is told.
func kdfNumber(v any) (uint64, bool) {
	if f, isFloat := v.(float64); isFloat {
		if f < 0 || f != math.Trunc(f) || f > math.MaxUint32 {
			return 0, false
		}
		return uint64(f), true
	}
	return asU64(v)
}

// VaultOpenDoc decrypts the document as received: the AAD is every member but ct, canonicalised,
// so a member added after sealing — or one changed — fails to open, exactly as in the Rust core. The
// header is read first, in its members' order, as the core reads it: `format`, then `kdf` by the one
// reader, then `salt`, `nonce` and `ct`, of which one that does not read is damage. This derived the
// key before it read the nonce and ct, so a short salt beside a damaged nonce was named for the salt
// here and was damage there.
func VaultOpenDoc(passphrase string, doc map[string]any) ([]byte, error) {
	if format, _ := doc["format"].(string); format != VaultFormat {
		return nil, vaultError{"not an hdtp-vault/1 document"}
	}
	kdf, err := kdfOfDocument(doc["kdf"])
	if err != nil {
		return nil, err
	}
	// Read strictly, as the core reads them: this port skipped a stray character in `ct`, so a
	// document the core refuses as damaged opened here (C8). One that is absent or not a string is
	// no bytes, as the core reads it.
	var parts [3][]byte
	for i, k := range []string{"salt", "nonce", "ct"} {
		text, _ := doc[k].(string)
		if parts[i], err = DecodeB64url(text); err != nil {
			return nil, errVault
		}
	}
	salt, nonce, ct := parts[0], parts[1], parts[2]
	if len(nonce) != 12 {
		return nil, errVault
	}
	key, err := deriveKey(passphrase, salt, kdf)
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
	header := make(map[string]any, len(doc))
	for k, val := range doc {
		if k != "ct" {
			header[k] = val
		}
	}
	pt, err := gcm.Open(nil, nonce, ct, Canonical(header))
	if err != nil {
		return nil, errVault
	}
	// A plaintext that is not JSON is damage, as the Rust core has it — not another generation's. JSON
	// is what the core's parser reads (decodeJSON): one that is not UTF-8, holds half a surrogate
	// pair, holds a number infinite as a double, or is nested past its limit, is damage there too.
	if _, err := decodeJSON(pt); err != nil {
		return nil, errVault
	}
	if plaintextV(pt) != PlaintextV {
		return nil, errOtherGeneration
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
	// pkcs8Given is the JSON boundary's: a `pkcs8` member given as "" is a key that does not read,
	// where the typed "" means none (a card-held root), as the core tells them apart.
	pkcs8Given bool
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
// rootProof is SPEC §2.2's challenge: `HDTP root proof v1` and a newline, before 32 random bytes, so
// that proving possession of the root key can never be made to sign a certificate.
const rootProof = "HDTP root proof v1\n"

// proveRoot is SPEC §2.2, before any certificate is issued: the vault's root key is the root the
// identity is known by; the root certificate parses and is that key's; and the key signs a challenge
// that verifies under the certificate's key. WalletIssue signed with whatever key sat beside the
// fingerprint, and a vault entry holding another key's PKCS #8 got a leaf that failed chain rule 3, in
// both ports (TC-8). Answers the root certificate, for the chain WalletIssue validates before it
// returns one. As the core's prove_root, in its words.
func proveRoot(root *VaultRoot, key *PrivateKey, fingerprint string) (*Cert, error) {
	pub := key.Public()
	if Fingerprint(pub.SPKI) != fingerprint {
		return nil, errArg("the vault's root key is not the root it is filed under")
	}
	der, err := DecodeB64url(root.Cert)
	if err != nil {
		return nil, err
	}
	cert, err := Parse(der)
	if err != nil {
		return nil, classed(err)
	}
	if !bytes.Equal(cert.SPKI, pub.SPKI) {
		return nil, errArg("the vault's root certificate is not its key's")
	}
	challenge := make([]byte, len(rootProof)+32)
	copy(challenge, rootProof)
	if _, err := rand.Read(challenge[len(rootProof):]); err != nil {
		return nil, err
	}
	sig, err := SignDetached(key, challenge)
	if err != nil || !VerifyDetached(cert.PublicKey, challenge, sig) {
		return nil, errArg("the vault's root key does not sign for its certificate")
	}
	return cert, nil
}

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
		if der, err := DecodeB64url(r.Cert); err == nil {
			if cert, err := Parse(der); err == nil {
				rootSPKIs = append(rootSPKIs, cert.SPKI)
			}
		}
		if der, err := DecodeB64url(r.PKCS8); err == nil {
			if priv, err := ParsePKCS8(der); err == nil {
				rootSPKIs = append(rootSPKIs, priv.Public().SPKI)
			}
		}
	}
	if root == nil {
		return nil, errors.New("no such root in the vault")
	}
	if root.PKCS8 == "" && !root.pkcs8Given {
		return nil, errors.New("this root is held on a card: wallet_issue signs only with a key the vault holds")
	}
	// A key that does not read is refused in its reader's class, as the core's `?` has it: `parse`,
	// or `unsupported` for a key outside the profile. This said `bad_request` `the root key does not
	// parse` for both (F18, R31).
	rootDER, err := DecodeB64url(root.PKCS8)
	if err != nil {
		return nil, err
	}
	rootKey, err := ParsePKCS8(rootDER)
	if err != nil {
		return nil, classed(err)
	}
	rootCert, err := proveRoot(root, rootKey, rootFingerprint)
	if err != nil {
		return nil, err
	}
	info := CSRCheck(csr, rootSPKIs)
	if !info.OK {
		// With its class, as the core's `csr::check` propagates it: a key outside the profile is
		// `unsupported` and bytes that do not read are `parse`, where this said `bad_request` for both.
		return nil, info.err
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
	// §2.2: a chain the wallet assembled is validated against the expected root and endpoint before it
	// is returned — a chain that fails is the wallet's defect, and returned it would be the host's to find.
	vr := ValidateChain([][]byte{issued.DER, rootCert.DER}, ChainOpts{Now: now, ExpectedRoot: rootFingerprint, ExpectedEndpoint: issued.Endpoint, rootGiven: true, endpointGiven: true})
	if !vr.OK {
		return nil, errArg(fmt.Sprintf("the chain it issued does not validate: chain rule %d: %s", vr.Rule, vr.Reason))
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
