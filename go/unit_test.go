package pactidentity

// The parts the vectors do not reach: the address guard, the normal form, the CSR round trip, the vault,
// and a wallet issuing under its rules.

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestIsNormalHTTPS(t *testing.T) {
	good := []string{"https://agent.alina.example/mcp", "https://alina.host.example/alina/mcp", "https://a.example/x/y-z_1.2~", "https://a.example/%2F", "https://192.0.2.1/mcp", "https://[2001:db8::1]/mcp"}
	bad := []string{"http://agent.alina.example/mcp", "https://agent.alina.example/", "https://agent.alina.example", "https://Agent.Alina.example/mcp", "https://agent.alina.example@mallory.example/mcp", "https://agent.alina.example:443/mcp", "https://agent.alina.example/mcp/", "https://agent.alina.example/mcp?x=1", "https://agent.alina.example/mcp#f", "https://agent.alina.example/mcp/../admin", "https://agent.alina.example/./mcp", "https://a.example/%2f", "https://a.example/%41", "https://a.example/a b", "https://a.example/a\\b", "https://a.example/ü", "https://a.example/%zz", "https://.a.example/mcp", "https://a..example/mcp", "https://01.2.3.4/mcp", "https://[2001:DB8::1]/mcp", "https://[::ffff:1.2.3.4]/mcp"}
	for _, u := range good {
		if !IsNormalHTTPS(u) {
			t.Errorf("should be normal: %s", u)
		}
	}
	for _, u := range bad {
		if IsNormalHTTPS(u) {
			t.Errorf("should not be normal: %s", u)
		}
	}
}

func TestAddressGuard(t *testing.T) {
	refused := []string{"https://255.255.255.255/mcp", "https://localhost/mcp", "https://alina.localhost/mcp", "https://127.0.0.1/mcp", "https://10.1.2.3/mcp", "https://172.16.0.9/mcp", "https://192.168.1.1/mcp", "https://169.254.1.1/mcp", "https://100.64.0.1/mcp", "https://0.0.0.0/mcp", "https://[::1]/mcp", "https://[::]/mcp", "https://[fd00::1]/mcp", "https://[fe80::1]/mcp", "https://[::ffff:10.0.0.1]/mcp"}
	for _, u := range refused {
		if ok, _ := AddressGuard(u, "", false); ok {
			t.Errorf("should be refused: %s", u)
		}
	}
	for _, u := range []string{"https://agent.alina.example/mcp", "https://192.0.2.1/mcp", "https://[2001:db8::1]/mcp"} {
		if ok, why := AddressGuard(u, "", false); !ok {
			t.Errorf("should pass: %s (%s)", u, why)
		}
	}
	if ok, _ := AddressGuard(endpointB, endpointB, true); ok {
		t.Error("a guest at the receiver's own endpoint should be refused")
	}
	if ok, _ := AddressGuard(endpointB, endpointB, false); !ok {
		t.Error("a contact may name the receiver's endpoint (the guard is for guests)")
	}
	for ip, want := range map[string]bool{"255.255.255.255": true, "127.0.0.1": true, "8.8.8.8": false, "::1": true, "2001:db8::1": false, "::ffff:192.168.0.1": true, "not an ip": false} {
		if IPIsPrivate(ip) != want {
			t.Errorf("ip_is_private(%s) should be %v", ip, want)
		}
	}
}

func TestCSRRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	root, _ := GenerateKey(AlgEd25519)
	host, _ := GenerateKey(AlgP256)
	other, _ := GenerateKey(AlgEd25519)
	rootDer, _ := BuildRoot(RootOpts{CN: "Alina Rao", Key: root, NotBefore: now})
	csr, err := CSRNew("Alina Rao", host, endpointA, "agent.alina.example")
	if err != nil {
		t.Fatal(err)
	}
	info := CSRCheck(csr, [][]byte{root.Public().SPKI})
	if !info.OK || info.Endpoint != endpointA || info.DNSName != "agent.alina.example" || info.Alg != AlgP256 {
		t.Fatalf("csr_check: %+v", info)
	}
	issued, err := IssueFromCSR(csr, IssueOpts{RootCN: "Alina Rao", RootKey: root, RootSPKIs: [][]byte{root.Public().SPKI}, Now: now, ValidDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	r := ValidateChain([][]byte{issued.DER, rootDer}, ChainOpts{Now: now, ExpectedRoot: Fingerprint(root.Public().SPKI), ExpectedEndpoint: endpointA})
	if !r.OK {
		t.Fatalf("issued leaf does not validate: rule %d %s", r.Rule, r.Reason)
	}
	if !issued.NotBefore.Equal(now.Add(-time.Hour)) || !issued.NotAfter.Equal(now.Add(-time.Hour).Add(365*24*time.Hour)) {
		t.Errorf("dates: %v %v", issued.NotBefore, issued.NotAfter)
	}
	prev := now.Add(time.Hour)
	later, err := IssueFromCSR(csr, IssueOpts{RootCN: "Alina Rao", RootKey: root, Now: now, PreviousNotBefore: &prev, ValidDays: 30})
	if err != nil || !later.NotBefore.Equal(prev.Add(time.Second)) {
		t.Errorf("monotonic rule: %v %v", err, later.NotBefore)
	}
	if _, err := IssueFromCSR(csr, IssueOpts{RootCN: "Alina Rao", RootKey: root, Now: now, ValidDays: 399}); err == nil {
		t.Error("399 days should be refused")
	}
	// Proof of possession: a request signed by another key.
	infoBytes := csrInfo("Alina Rao", host.Public(), endpointA, "")
	sig, _ := SignDetached(other, infoBytes)
	forged := seq(infoBytes, sigAlgFor(host.Alg), bitstr(sig, 0))
	if r := CSRCheck(forged, nil); r.OK || !strings.Contains(r.Why, "proof of possession") {
		t.Errorf("forged CSR: %+v", r)
	}
	// The root-key refusal.
	rootCSR, _ := CSRNew("Alina Rao", root, endpointA, "")
	if r := CSRCheck(rootCSR, [][]byte{root.Public().SPKI}); r.OK || !strings.Contains(r.Why, "root") {
		t.Errorf("root-key CSR: %+v", r)
	}
	// A private address and a non-normal endpoint.
	for _, e := range []string{"https://10.0.0.1/mcp", "https://Agent.example/mcp"} {
		c, _ := CSRNew("x", host, e, "")
		if r := CSRCheck(c, nil); r.OK {
			t.Errorf("endpoint %s should be refused", e)
		}
	}
	// The seam: issue the TBS, sign it outside, assemble.
	plan, err := IssueTBSFromCSR(csr, IssueOpts{RootCN: "Alina Rao", RootPub: root.Public(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	outside, _ := SignDetached(root, plan.TBS)
	der := Assemble(plan.TBS, plan.Alg, outside)
	if r := ValidateChain([][]byte{der, rootDer}, ChainOpts{Now: now}); !r.OK {
		t.Errorf("assembled leaf: rule %d %s", r.Rule, r.Reason)
	}
	out := Call("assemble_leaf", mustJSON(map[string]any{"tbs": B64url(plan.TBS), "sig": B64url(outside), "sig_alg": B64url(plan.Alg)}))
	if !bytes.Contains(out, []byte(`"der"`)) {
		t.Errorf("assemble_leaf: %s", out)
	}
}

func TestVault(t *testing.T) {
	kdf := KDF{Name: "argon2id", MKiB: 8192, T: 1, P: 1}
	plain := []byte(`{"v":2,"roots":[]}`)
	v, err := VaultSeal("correct horse", plain, &kdf, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VaultOpen("correct horse", *v)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := VaultOpen("wrong", *v); err == nil || err.Error() != errVault.Error() {
		t.Errorf("wrong passphrase: %v", err)
	}
	tampered := *v
	tampered.Salt = B64url([]byte("0123456789abcdef"))
	if _, err := VaultOpen("correct horse", tampered); err == nil {
		t.Error("a changed header should not open")
	}
	out := Call("vault_seal", mustJSON(map[string]any{"passphrase": "p", "plaintext": json.RawMessage(plain), "kdf": kdf}))
	var sealed struct{ Vault Vault }
	if err := json.Unmarshal(out, &sealed); err != nil || sealed.Vault.Ct == "" {
		t.Fatalf("vault_seal: %s", out)
	}
	out = Call("vault_open", mustJSON(map[string]any{"passphrase": "p", "vault": sealed.Vault}))
	if !bytes.Contains(out, []byte(`"plaintext":{"v":2`)) {
		t.Errorf("vault_open: %s", out)
	}
	out = Call("vault_open", mustJSON(map[string]any{"passphrase": "q", "vault": sealed.Vault}))
	if !bytes.Contains(out, []byte(`"error":"vault"`)) {
		t.Errorf("vault_open wrong passphrase: %s", out)
	}
	// An earlier generation is refused at both ends, and nothing converts: sealing it is a bad
	// request; a document an earlier wallet wrote decrypts and is still not opened.
	if _, err := VaultSeal("correct horse", []byte(`{"v":1,"roots":[],"ledger":[]}`), &kdf, nil, nil); err == nil || err.Error() != "a vault plaintext is v 2: the root, or the record" {
		t.Errorf("sealing v 1: %v", err)
	}
	out = Call("vault_seal", mustJSON(map[string]any{"passphrase": "p", "plaintext": json.RawMessage(`{"roots":[]}`), "kdf": kdf}))
	if !bytes.Contains(out, []byte(`"error":"bad_request"`)) {
		t.Errorf("vault_seal without v: %s", out)
	}
	old, err := vaultSealAny("correct horse", []byte(`{"v":1,"roots":[],"ledger":[],"contacts":[]}`), &kdf, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VaultOpen("correct horse", *old); err == nil || err.Error() != errEarlierGeneration.Error() {
		t.Errorf("opening v 1: %v", err)
	}
	// The control: a wrong passphrase on that same document is still the one message.
	if _, err := VaultOpen("wrong", *old); err == nil || err.Error() != errVault.Error() {
		t.Errorf("wrong passphrase on v 1: %v", err)
	}
}

func TestWalletIssue(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	root, _ := GenerateKey(AlgEd25519)
	rootDer, _ := BuildRoot(RootOpts{CN: "Alina Rao", Key: root, NotBefore: now})
	pkcs8, _ := root.PKCS8()
	fp := Fingerprint(root.Public().SPKI)
	plain := VaultPlaintext{V: 2, Roots: []VaultRoot{{Fingerprint: fp, CN: "Alina Rao", PKCS8: B64url(pkcs8), Cert: B64url(rootDer), Created: now.Format(time.RFC3339)}}}
	record := RecordPlaintext{V: 2}
	host, _ := GenerateKey(AlgEd25519)
	csr, _ := CSRNew("Alina Rao", host, endpointA, "")
	first, err := WalletIssue(plain, record, fp, csr, now, 365, false)
	if err != nil || !first.NewHost || len(first.Warnings) != 1 {
		t.Fatalf("first issue: %v %+v", err, first)
	}
	// The entry is the endpoint and the dates: no leaf in it.
	if entry, _ := json.Marshal(first.Entry); bytes.Contains(entry, []byte(`"leaf"`)) {
		t.Errorf("the ledger entry carries a leaf: %s", entry)
	}
	record.Ledger = append(record.Ledger, first.Entry)
	// A renewal for the same endpoint: allowed, monotonic, no longer a new host.
	host2, _ := GenerateKey(AlgEd25519)
	csr2, _ := CSRNew("Alina Rao", host2, endpointA, "")
	renewal, err := WalletIssue(plain, record, fp, csr2, now.Add(time.Minute), 365, false)
	if err != nil || renewal.NewHost {
		t.Fatalf("renewal: %v", err)
	}
	if cmp, _ := CompareLeaves(first.DER, renewal.DER); cmp != "newer" {
		t.Errorf("renewal should be newer, got %s", cmp)
	}
	// A second endpoint while a leaf is live is a move, refused without move: true.
	csr3, _ := CSRNew("Alina Rao", host2, "https://alina.host.example/alina/mcp", "")
	if _, err := WalletIssue(plain, record, fp, csr3, now, 365, false); err == nil || !strings.Contains(err.Error(), "move") {
		t.Errorf("second endpoint: %v", err)
	}
	moved, err := WalletIssue(plain, record, fp, csr3, now, 365, true)
	if err != nil || !moved.NewHost {
		t.Errorf("move: %v", err)
	}
	// After the move the new address is the live one: a renewal there is not a second home, and
	// a leaf for the old address now is the move back, refused without the flag.
	record.Ledger = append(record.Ledger, moved.Entry)
	host3, _ := GenerateKey("ed25519")
	csr4, _ := CSRNew("Alina Rao", host3, "https://alina.host.example/alina/mcp", "")
	if renewed, err := WalletIssue(plain, record, fp, csr4, now.Add(2*time.Minute), 365, false); err != nil || renewed.NewHost {
		t.Errorf("renewal after a move: %v", err)
	}
	if _, err := WalletIssue(plain, record, fp, csr, now.Add(2*time.Minute), 365, false); err == nil {
		t.Error("the old address after a move is a move back")
	}
	// The root's own key in a CSR is refused by the wallet too.
	rootCSR, _ := CSRNew("Alina Rao", root, endpointA, "")
	if _, err := WalletIssue(plain, record, fp, rootCSR, now, 365, false); err == nil {
		t.Error("root key as a leaf should be refused")
	}
}

func TestNormalFormPorts(t *testing.T) {
	for _, good := range []string{"https://[2001:db8::1]:8443/mcp", "https://203.0.113.9:8080/mcp"} {
		if !IsNormalHTTPS(good) {
			t.Errorf("%s should be normal", good)
		}
	}
	for _, bad := range []string{"https://agent.alina.example:443/mcp", "https://agent.alina.example:0/mcp", "https://agent.alina.example:08443/mcp", "https://agent.alina.example:65536/mcp", "https://agent.alina.example:/mcp", "https://[2001:db8::1]8443/mcp", "https://a.example:8443:1/mcp"} {
		if IsNormalHTTPS(bad) {
			t.Errorf("%s should not be normal", bad)
		}
	}
}

// The fold threshold is UTF-16 code units, as the seed counts them (CONTRACT §0) — not octets,
// which is what this port counted until the 2026-09-15 review.
func TestCardFoldsOnUTF16CodeUnits(t *testing.T) {
	short := "FN:" + strings.Repeat("é", 40) // 43 code units, 83 octets
	if got := fold(short); got != short {
		t.Errorf("43 code units must stay one line, got %d lines", len(strings.Split(got, "\r\n")))
	}
	long := "FN:" + strings.Repeat("é", 80) // 83 code units
	lines := strings.Split(fold(long), "\r\n")
	if len(lines) != 2 {
		t.Fatalf("83 code units folds once, got %d lines", len(lines))
	}
	if n := len(utf16.Encode([]rune(lines[0]))); n != 75 {
		t.Errorf("first line is %d code units, want 75", n)
	}
	if n := len(utf16.Encode([]rune(lines[1]))); n != 9 {
		t.Errorf("second line is %d code units, want 9 (a space and 8)", n)
	}
	// A break inside a surrogate pair moves one unit earlier; nothing is lost.
	astral := "FN:" + strings.Repeat("a", 74) + strings.Repeat("\U0001F600", 3)
	f := fold(astral)
	if strings.ContainsRune(f, 0xFFFD) {
		t.Errorf("a surrogate pair was split: %q", f)
	}
	if got := unfoldRE.ReplaceAllString(f, ""); got != astral {
		t.Errorf("unfold round trip: %q", got)
	}
}

func TestCardRoundTrip(t *testing.T) {
	v := loadVectors(t)
	leaf := hexBytes(t, v.Certificates["leaf_a"].DerHex)
	card, err := EncodeCard("Alina Rao", leaf, "required", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(card, "\r\n") {
		if len(line) > 75 {
			t.Errorf("line over 75 octets: %d", len(line))
		}
	}
	c, err := DecodeCard(card, mustTime(t, v.Now))
	if err != nil || c.Endpoint != endpointA || c.Seal != "required" || !bytes.Equal(c.Cert, leaf) || c.Expired {
		t.Fatalf("decode: %v %+v", err, c)
	}
	if _, err := DecodeCard(strings.Replace(card, "X-PACT-VERSION:2", "X-PACT-VERSION:3", 1), mustTime(t, v.Now)); err == nil || err.Error() != "version not implemented" {
		t.Errorf("version: %v", err)
	}
	if _, err := DecodeCard("BEGIN:VCARD\r\nEND:VCARD\r\n", mustTime(t, v.Now)); err == nil || err.Error() != "no X-PACT-VERSION" {
		t.Errorf("no version: %v", err)
	}
	expired := hexBytes(t, v.Certificates["leaf_a_expired"].DerHex)
	expiredCard, err := EncodeCard("Alina Rao", expired, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err = DecodeCard(expiredCard, mustTime(t, v.Now))
	if err != nil || !c.Expired || c.Seal != "none" {
		t.Errorf("expired card: %v %+v", err, c)
	}
}

func TestSealAndOpenResult(t *testing.T) {
	v := loadVectors(t)
	c := theCast(t)
	der := func(n string) []byte { return hexBytes(t, v.Certificates[n].DerHex) }
	now := mustTime(t, v.Now)
	leafA, _ := Parse(der("leaf_a"))
	// Bharat answers Alina: sealed to leaf_a's key, with his chain.
	env, err := SealResult(SealOpts{RecipientKey: leafA.PublicKey, Sender: c.leafB, Form: "chain", SenderChain: [][]byte{der("leaf_b"), der("root_b")}, Result: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`), MsgID: "m-1", TS: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	rootB, _ := Parse(der("root_b"))
	opened, err := OpenResult(*env, OpenOpts{Recipient: c.leafA, RecipientPublic: c.leafA.Public(), MsgID: "m-1", Now: now, ExpectedRoot: FingerprintOf(rootB), ExpectedEndpoint: endpointB})
	if err != nil || opened.Form != "chain" || opened.Root != FingerprintOf(rootB) || !bytes.Contains(opened.Result, []byte("ok")) {
		t.Fatalf("open result: %v %+v", err, opened)
	}
	if _, err := OpenResult(*env, OpenOpts{Recipient: c.leafA, RecipientPublic: c.leafA.Public(), MsgID: "m-2", Now: now}); err == nil {
		t.Error("a wrong msg_id should not correlate")
	}
	// The small form back, against a pin of leaf_b.
	env, _ = SealResult(SealOpts{RecipientKey: leafA.PublicKey, Sender: c.leafB, Form: "leaf", Error: json.RawMessage(`{"code":"permission_denied","message":"no"}`), MsgID: "m-3", TS: now.Unix()})
	pins := []Pin{{Root: FingerprintOf(rootB), Endpoint: endpointB, Leaf: B64url(der("leaf_b")), State: "active"}}
	opened, err = OpenResult(*env, OpenOpts{Recipient: c.leafA, RecipientPublic: c.leafA.Public(), MsgID: "m-3", Now: now, Pins: pins})
	if err != nil || opened.Form != "leaf" || opened.Error == nil {
		t.Fatalf("open small-form error result: %v %+v", err, opened)
	}
	if _, err := OpenResult(*env, OpenOpts{Recipient: c.leafA, RecipientPublic: c.leafA.Public(), MsgID: "m-3", Now: now}); err == nil {
		t.Error("an unheld leaf should not verify")
	}
	// A request sealed through Call, decided by Bharat.
	out := Call("seal_request", mustJSON(map[string]any{
		"recipient_leaf": B64url(der("leaf_b")), "sender_pkcs8": B64url(hexBytes(t, v.LeafKeys["leaf_a"])), "form": "leaf",
		"params": json.RawMessage(`{"name":"send_message","arguments":{"msg_id":"x","text":"hi"}}`), "msg_id": "m-4", "ts": now.Unix(),
	}))
	var e Envelope
	if err := json.Unmarshal(out, &e); err != nil || e.Ct == "" {
		t.Fatalf("seal_request: %s", out)
	}
	rootA, _ := Parse(der("root_a"))
	d := decided(t, now, e, bharatNode(t, v, []Pin{{Root: FingerprintOf(rootA), Endpoint: endpointA, Leaf: B64url(der("leaf_a")), State: "active"}}))
	if d.Result["code"] != "ok" || d.Result["tier"] != "contact" {
		t.Errorf("decide on a sealed request: %v", d.Result)
	}
	// A seed fixes the ephemeral so the same call lands on the same bytes twice — the property the
	// vector checker leans on when it re-seals a vector and compares. This port used to refuse the
	// seed, so that check could not run here at all.
	sealArgs := map[string]any{"recipient_leaf": B64url(der("leaf_b")), "sender_pkcs8": B64url(hexBytes(t, v.LeafKeys["leaf_a"])), "form": "leaf", "params": json.RawMessage(`{}`), "msg_id": "m", "ts": 1, "ephemeral_seed": B64url(make([]byte, 32))}
	first, second := Call("seal_request", mustJSON(sealArgs)), Call("seal_request", mustJSON(sealArgs))
	if !bytes.Equal(first, second) || bytes.Contains(first, []byte(`"error"`)) {
		t.Errorf("seal_request from a seed should repeat exactly: %s / %s", first, second)
	}
	sealArgs["ephemeral_seed"] = B64url(make([]byte, 8))
	if !bytes.Contains(Call("seal_request", mustJSON(sealArgs)), []byte("32 bytes")) {
		t.Error("seal_request should refuse a seed that is not 32 bytes")
	}
}

// Arguments that are not an object, including the literal `null`, are one answer in both ports.
// `js/parity.mjs` cannot reach this: its shim turns a null into `{}` before either port sees it.
func TestArgsMustBeAnObject(t *testing.T) {
	for _, args := range []string{`null`, `[]`, `3`, `"x"`, `true`} {
		if out := Call("key_info", json.RawMessage(args)); !bytes.Contains(out, []byte("args is a JSON object")) {
			t.Errorf("key_info(%s): %s", args, out)
		}
	}
	// An absent `args` is not the same thing, and still reaches the function.
	if out := Call("key_info", nil); !bytes.Contains(out, []byte("spki is required")) {
		t.Errorf("key_info with no args: %s", out)
	}
}

func TestCallNeverPanics(t *testing.T) {
	for _, name := range Functions() {
		for _, args := range []string{``, `{}`, `[]`, `{"der":"!!","chain":["x"],"vcard":1,"now":"nope","envelope":{"protected":"e30"},"node":{}}`} {
			out := Call(name, json.RawMessage(args))
			var v map[string]any
			if err := json.Unmarshal(out, &v); err != nil {
				t.Errorf("%s(%s): not a JSON object: %s", name, args, out)
			}
		}
	}
	if !bytes.Contains(Call("no_such", nil), []byte(`"unsupported"`)) {
		t.Error("unknown function")
	}
}

// decided is Decide for a test whose node state is readable: an error here is the test's own setup.
func decided(t *testing.T, now time.Time, env Envelope, node NodeState) Decision {
	t.Helper()
	d, err := Decide(now, env, node)
	if err != nil {
		t.Fatalf("Decide: the node's own state would not read: %v", err)
	}
	return d
}

// A plaintext that decrypts and is not JSON is damage, as the Rust core answers it (its open reads
// the bytes as JSON and says "the passphrase is wrong or the vault is damaged"), not a document an
// earlier wallet wrote. This port said the second (the review of PR #29, C11).
func TestAPlaintextThatIsNotJSONIsDamageNotAnEarlierWallet(t *testing.T) {
	sealed, err := vaultSealAny("a passphrase", []byte("not json"), &KDF{Name: "argon2id", MKiB: 8192, T: 1, P: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sealed)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, err := VaultOpenDoc("a passphrase", doc); err != errVault {
		t.Fatalf("a plaintext that is not JSON opened as %v, want %v", err, errVault)
	}
	// The control: JSON with no generation is still an earlier wallet's, in both ports.
	old, _ := vaultSealAny("a passphrase", []byte(`{"roots":[]}`), &KDF{Name: "argon2id", MKiB: 8192, T: 1, P: 1}, nil, nil)
	raw, _ = json.Marshal(old)
	_ = json.Unmarshal(raw, &doc)
	if _, err := VaultOpenDoc("a passphrase", doc); err != errEarlierGeneration {
		t.Fatalf("a plaintext with no generation opened as %v, want %v", err, errEarlierGeneration)
	}
}

// The public key an open is handed is the host's word for its own (hpke.go decap): a wrong one, of
// the same algorithm or the other, refuses, and never yields a plaintext. The right one is the control.
func TestOpenWithAPublicKeyThatIsNotTheRecipientsOpensNothing(t *testing.T) {
	for _, tc := range []struct{ alg, suite, other string }{{AlgEd25519, SuiteX25519, AlgP256}, {AlgP256, SuiteP256, AlgEd25519}} {
		r, err := KeyFromSeed(tc.alg, Seed("t/r"))
		if err != nil {
			t.Fatal(err)
		}
		enc, ct, err := Seal(tc.suite, r.Public(), []byte(InfoV2), []byte("aad"), []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		sameAlg, _ := KeyFromSeed(tc.alg, Seed("t/other"))
		otherAlg, _ := KeyFromSeed(tc.other, Seed("t/r"))
		for _, wrong := range []*PrivateKey{sameAlg, otherAlg} {
			pt, err := Open(tc.suite, r, wrong.Public(), []byte(InfoV2), []byte("aad"), enc, ct)
			if err == nil || err.Error() != "does not open" || pt != nil {
				t.Fatalf("%s with a %s public key: %q, %v", tc.alg, wrong.Alg, pt, err)
			}
		}
		if pt, err := Open(tc.suite, r, r.Public(), []byte(InfoV2), []byte("aad"), enc, ct); err != nil || string(pt) != "hello" {
			t.Fatalf("%s: the right public key: %q, %v", tc.alg, pt, err)
		}
	}
}

// A missing key is a named refusal, never a panic (0.4.0 dereferenced nil): Open and OpenResult,
// each argument alone, with the right keys as the control.
func TestAnOpenWithAMissingKeyIsRefusedByName(t *testing.T) {
	r, _ := KeyFromSeed(AlgEd25519, Seed("t/r"))
	pub := r.Public()
	enc, ct, err := Seal(SuiteX25519, pub, []byte(InfoV2), nil, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		priv *PrivateKey
		pub  *PublicKey
		why  string
	}{{nil, pub, "the recipient's key is required"}, {r, nil, "the recipient's public key is required"}} {
		pt, err := Open(SuiteX25519, tc.priv, tc.pub, []byte(InfoV2), nil, enc, ct)
		if err == nil || err.Error() != tc.why || codeFor(err, "") != codeArgs || pt != nil {
			t.Fatalf("Open: %q, %v; want %q", pt, err, tc.why)
		}
		_, err = OpenResult(Envelope{}, OpenOpts{Recipient: tc.priv, RecipientPublic: tc.pub, MsgID: "m"})
		if err == nil || err.Error() != tc.why || codeFor(err, "") != codeArgs {
			t.Fatalf("OpenResult: %v; want %q", err, tc.why)
		}
	}
	if pt, err := Open(SuiteX25519, r, pub, []byte(InfoV2), nil, enc, ct); err != nil || string(pt) != "hi" {
		t.Fatalf("the control: %q, %v", pt, err)
	}
}

// A P-256 scalar outside [1, n-1] is refused at parse as it was when ecdsa.ParseRawPrivateKey did it,
// now without the multiplication; n-1 is the control that reads.
func TestAP256ScalarOutsideTheGroupIsRefused(t *testing.T) {
	pkcs8 := func(d []byte) []byte {
		return seq(derIntN(0), seq(oidBytes(oidEcPublicKey), oidBytes(oidPrime256v1)), octet(seq(derIntN(1), octet(d))))
	}
	nMinus1 := new(big.Int).Sub(p256N, big.NewInt(1)).FillBytes(make([]byte, 32))
	for name, d := range map[string][]byte{"zero": make([]byte, 32), "n": p256N.FillBytes(make([]byte, 32)), "n+1": new(big.Int).Add(p256N, big.NewInt(1)).FillBytes(make([]byte, 32))} {
		if _, err := ParsePKCS8(pkcs8(d)); err == nil || err.Error() != "P-256 scalar out of range" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	k, err := ParsePKCS8(pkcs8(nMinus1))
	if err != nil {
		t.Fatalf("n-1: %v", err)
	}
	if k.Public() == nil || k.Public().EC == nil {
		t.Fatal("n-1 has no public key")
	}
}
