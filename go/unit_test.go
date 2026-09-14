package pactidentity

// The parts the vectors do not reach: the address guard, the normal form, the CSR round trip, the vault,
// and a wallet issuing under its rules.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestIsNormalHTTPS(t *testing.T) {
	good := []string{"https://agent.alina.example/mcp", "https://alina.pact.contact/alina/mcp", "https://a.example/x/y-z_1.2~", "https://a.example/%2F", "https://192.0.2.1/mcp", "https://[2001:db8::1]/mcp"}
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
	refused := []string{"https://localhost/mcp", "https://alina.localhost/mcp", "https://127.0.0.1/mcp", "https://10.1.2.3/mcp", "https://172.16.0.9/mcp", "https://192.168.1.1/mcp", "https://169.254.1.1/mcp", "https://100.64.0.1/mcp", "https://0.0.0.0/mcp", "https://[::1]/mcp", "https://[::]/mcp", "https://[fd00::1]/mcp", "https://[fe80::1]/mcp", "https://[::ffff:10.0.0.1]/mcp"}
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
	for ip, want := range map[string]bool{"127.0.0.1": true, "8.8.8.8": false, "::1": true, "2001:db8::1": false, "::ffff:192.168.0.1": true, "not an ip": false} {
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
	info := CSRCheck(csr, [][]byte{root.Public.SPKI})
	if !info.OK || info.Endpoint != endpointA || info.DNSName != "agent.alina.example" || info.Alg != AlgP256 {
		t.Fatalf("csr_check: %+v", info)
	}
	issued, err := IssueFromCSR(csr, IssueOpts{RootCN: "Alina Rao", RootKey: root, RootSPKIs: [][]byte{root.Public.SPKI}, Now: now, ValidDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	r := ValidateChain([][]byte{issued.DER, rootDer}, ChainOpts{Now: now, ExpectedRoot: Fingerprint(root.Public.SPKI), ExpectedEndpoint: endpointA})
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
	infoBytes := csrInfo("Alina Rao", host.Public, endpointA, "")
	sig, _ := SignDetached(other, infoBytes)
	forged := seq(infoBytes, sigAlgFor(host.Alg), bitstr(sig, 0))
	if r := CSRCheck(forged, nil); r.OK || !strings.Contains(r.Why, "proof of possession") {
		t.Errorf("forged CSR: %+v", r)
	}
	// The root-key refusal.
	rootCSR, _ := CSRNew("Alina Rao", root, endpointA, "")
	if r := CSRCheck(rootCSR, [][]byte{root.Public.SPKI}); r.OK || !strings.Contains(r.Why, "root") {
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
	plan, err := IssueTBSFromCSR(csr, IssueOpts{RootCN: "Alina Rao", RootPub: root.Public, Now: now})
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
	plain := []byte(`{"v":1,"roots":[],"ledger":[],"contacts":[]}`)
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
	if !bytes.Contains(out, []byte(`"plaintext":{"v":1`)) {
		t.Errorf("vault_open: %s", out)
	}
	out = Call("vault_open", mustJSON(map[string]any{"passphrase": "q", "vault": sealed.Vault}))
	if !bytes.Contains(out, []byte(`"error":"vault"`)) {
		t.Errorf("vault_open wrong passphrase: %s", out)
	}
}

func TestWalletIssue(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	root, _ := GenerateKey(AlgEd25519)
	rootDer, _ := BuildRoot(RootOpts{CN: "Alina Rao", Key: root, NotBefore: now})
	pkcs8, _ := root.PKCS8()
	fp := Fingerprint(root.Public.SPKI)
	plain := VaultPlaintext{V: 1, Roots: []VaultRoot{{Fingerprint: fp, CN: "Alina Rao", PKCS8: B64url(pkcs8), Cert: B64url(rootDer), Created: now.Format(time.RFC3339)}}}
	host, _ := GenerateKey(AlgEd25519)
	csr, _ := CSRNew("Alina Rao", host, endpointA, "")
	first, err := WalletIssue(plain, fp, csr, now, 365, false)
	if err != nil || !first.NewHost || len(first.Warnings) != 1 {
		t.Fatalf("first issue: %v %+v", err, first)
	}
	plain.Ledger = append(plain.Ledger, first.Entry)
	// A renewal for the same endpoint: allowed, monotonic, no longer a new host.
	host2, _ := GenerateKey(AlgEd25519)
	csr2, _ := CSRNew("Alina Rao", host2, endpointA, "")
	renewal, err := WalletIssue(plain, fp, csr2, now.Add(time.Minute), 365, false)
	if err != nil || renewal.NewHost {
		t.Fatalf("renewal: %v", err)
	}
	if cmp, _ := CompareLeaves(first.DER, renewal.DER); cmp != "newer" {
		t.Errorf("renewal should be newer, got %s", cmp)
	}
	// A second endpoint while a leaf is live is a move, refused without move: true.
	csr3, _ := CSRNew("Alina Rao", host2, "https://alina.pact.contact/alina/mcp", "")
	if _, err := WalletIssue(plain, fp, csr3, now, 365, false); err == nil || !strings.Contains(err.Error(), "move") {
		t.Errorf("second endpoint: %v", err)
	}
	moved, err := WalletIssue(plain, fp, csr3, now, 365, true)
	if err != nil || !moved.NewHost {
		t.Errorf("move: %v", err)
	}
	// After the move the new address is the live one: a renewal there is not a second home, and
	// a leaf for the old address now is the move back, refused without the flag.
	plain.Ledger = append(plain.Ledger, moved.Entry)
	host3, _ := GenerateKey("ed25519")
	csr4, _ := CSRNew("Alina Rao", host3, "https://alina.pact.contact/alina/mcp", "")
	if renewed, err := WalletIssue(plain, fp, csr4, now.Add(2*time.Minute), 365, false); err != nil || renewed.NewHost {
		t.Errorf("renewal after a move: %v", err)
	}
	if _, err := WalletIssue(plain, fp, csr, now.Add(2*time.Minute), 365, false); err == nil {
		t.Error("the old address after a move is a move back")
	}
	// The root's own key in a CSR is refused by the wallet too.
	rootCSR, _ := CSRNew("Alina Rao", root, endpointA, "")
	if _, err := WalletIssue(plain, fp, rootCSR, now, 365, false); err == nil {
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
	v, _ := loadVectors(t)
	leaf := hexBytes(t, v.Certificates["leaf_a"].DerHex)
	card := EncodeCard("Alina Rao", leaf, "required", nil)
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
	c, err = DecodeCard(EncodeCard("Alina Rao", expired, "", nil), mustTime(t, v.Now))
	if err != nil || !c.Expired || c.Seal != "none" {
		t.Errorf("expired card: %v %+v", err, c)
	}
	compat, err := EncodeCompatCard("Alina Rao", leaf, "optional")
	if err != nil || !strings.Contains(compat, "X-PACT-VERSION:1\r\n") || !strings.Contains(compat, "X-PACT-ENDPOINT:"+endpointA) {
		t.Errorf("compat: %v %s", err, compat)
	}
}

func TestSealAndOpenResult(t *testing.T) {
	v, _ := loadVectors(t)
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
	opened, err := OpenResult(*env, OpenOpts{Recipient: c.leafA, MsgID: "m-1", Now: now, ExpectedRoot: FingerprintOf(rootB), ExpectedEndpoint: endpointB})
	if err != nil || opened.Form != "chain" || opened.Root != FingerprintOf(rootB) || !bytes.Contains(opened.Result, []byte("ok")) {
		t.Fatalf("open result: %v %+v", err, opened)
	}
	if _, err := OpenResult(*env, OpenOpts{Recipient: c.leafA, MsgID: "m-2", Now: now}); err == nil {
		t.Error("a wrong msg_id should not correlate")
	}
	// The small form back, against a pin of leaf_b.
	env, _ = SealResult(SealOpts{RecipientKey: leafA.PublicKey, Sender: c.leafB, Form: "leaf", Error: json.RawMessage(`{"code":"permission_denied","message":"no"}`), MsgID: "m-3", TS: now.Unix()})
	pins := []Pin{{Root: FingerprintOf(rootB), Endpoint: endpointB, Leaf: B64url(der("leaf_b")), State: "active"}}
	opened, err = OpenResult(*env, OpenOpts{Recipient: c.leafA, MsgID: "m-3", Now: now, Pins: pins})
	if err != nil || opened.Form != "leaf" || opened.Error == nil {
		t.Fatalf("open small-form error result: %v %+v", err, opened)
	}
	if _, err := OpenResult(*env, OpenOpts{Recipient: c.leafA, MsgID: "m-3", Now: now}); err == nil {
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
	d := Decide(now, e, bharatNode(t, v, []Pin{{Root: FingerprintOf(rootA), Endpoint: endpointA, Leaf: B64url(der("leaf_a")), State: "active"}}))
	if d.Result["code"] != "ok" || d.Result["tier"] != "contact" {
		t.Errorf("decide on a sealed request: %v", d.Result)
	}
	if !bytes.Contains(Call("seal_request", mustJSON(map[string]any{"recipient_leaf": B64url(der("leaf_b")), "sender_pkcs8": B64url(hexBytes(t, v.LeafKeys["leaf_a"])), "form": "leaf", "params": json.RawMessage(`{}`), "msg_id": "m", "ts": 1, "ephemeral_seed": B64url(make([]byte, 32))})), []byte("refused")) {
		t.Error("seal_request should refuse a seed")
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
