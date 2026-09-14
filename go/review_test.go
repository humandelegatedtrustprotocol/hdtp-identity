package pactidentity

// The cryptography review of 2026-09-14, as tests: each finding it made against this port is a
// case that failed before the fix and passes after it, mirroring crates/pact-identity/tests/review.rs.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const reviewEndpoint = "https://agent.alina.example/mcp"

type reviewPair struct {
	rootKey, leafKey *PrivateKey
	root, leaf       []byte
	rootFP           string
}

func reviewIdentity(t *testing.T, alg, endpoint string) reviewPair {
	t.Helper()
	rootKey, _ := GenerateKey(alg)
	root, err := BuildRoot(RootOpts{CN: "Alina Rao", Key: rootKey, NotBefore: mustTime(t, "2026-09-01T00:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := GenerateKey(alg)
	leaf, err := BuildLeaf(LeafOpts{CN: "Alina Rao", RootCN: "Alina Rao", RootKey: rootKey, HostPub: leafKey.Public, Endpoint: endpoint, NotBefore: mustTime(t, "2026-09-01T00:00:00Z"), NotAfter: mustTime(t, "2027-09-01T00:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	return reviewPair{rootKey: rootKey, leafKey: leafKey, root: root, leaf: leaf, rootFP: Fingerprint(rootKey.Public.SPKI)}
}

// withField rebuilds a certificate's TBS with one of its eight fields replaced, re-signs it, and
// assembles it with the algorithm the TBS declares — so only the deviation under test differs.
func withField(t *testing.T, der []byte, index int, field []byte, signer *PrivateKey) []byte {
	t.Helper()
	c, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	node, _ := derRead(c.TBS, 0)
	kids, _ := derChildren(node)
	fields := make([][]byte, len(kids))
	for i, k := range kids {
		fields[i] = k.raw
	}
	fields[index] = field
	tbs := seq(fields...)
	tn, _ := derRead(tbs, 0)
	tf, _ := derChildren(tn)
	sig, err := SignDetached(signer, tbs)
	if err != nil {
		t.Fatal(err)
	}
	return Assemble(tbs, tf[2].raw, sig)
}

func pkcs8Of(t *testing.T, k *PrivateKey) []byte {
	t.Helper()
	b, err := k.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func extOf(oid string, critical bool, value []byte) []byte {
	parts := [][]byte{oidBytes(oid)}
	if critical {
		parts = append(parts, derBool(true))
	}
	parts = append(parts, octet(value))
	return seq(parts...)
}

func rootExtensions(id, basic, usage []byte) []byte {
	return explicit(3, seq(extOf(OIDBasicConstraints, true, basic), extOf(OIDKeyUsage, true, usage), extOf(OIDSubjectKeyID, false, octet(id))))
}

func reason(t *testing.T, chain [][]byte) string {
	t.Helper()
	vr := ValidateChain(chain, ChainOpts{Now: mustTime(t, "2026-09-13T12:00:00Z")})
	if vr.OK {
		t.Fatal("accepted")
	}
	if vr.Rule != 1 {
		t.Fatalf("rule %d: %s", vr.Rule, vr.Reason)
	}
	return vr.Reason
}

// MEDIUM 4: one algorithm inside the TBS, another outside.
func TestInnerAndOuterAlgorithmMustAgree(t *testing.T) {
	p := reviewIdentity(t, "ed25519", reviewEndpoint)
	c, _ := Parse(p.leaf)
	mismatched := Assemble(c.TBS, seq(oidBytes(OIDEcdsaSHA256)), c.Sig)
	if got := reason(t, [][]byte{mismatched, p.root}); got != "signature algorithm inside and outside differ" {
		t.Errorf("got %q", got)
	}
	// With parameters inside and out, it is not the profile's AlgorithmIdentifier either.
	withParams := seq(oidBytes(OIDEd25519), tlv(0x05, nil))
	cert := withField(t, p.leaf, 2, withParams, p.rootKey)
	if vr := ValidateChain([][]byte{cert, p.root}, ChainOpts{Now: mustTime(t, "2026-09-13T12:00:00Z")}); vr.OK || vr.Rule != 1 {
		t.Errorf("parameters accepted: %+v", vr)
	}
}

// LOW 7: DER strictness the exact profile relies on.
func TestDERDeviationsAreRefused(t *testing.T) {
	p := reviewIdentity(t, "ed25519", reviewEndpoint)
	root, _ := Parse(p.root)
	id := root.KeyID
	cases := []struct {
		name  string
		index int
		field []byte
		want  string
	}{
		{"an explicit BOOLEAN FALSE as cA", 7, rootExtensions(id, seq(derBool(false), derIntN(0)), bitstr([]byte{0x04}, 2)), "BOOLEAN not in the DER form"},
		{"TRUE encoded as 0x01 as the critical flag", 7, explicit(3, seq(seq(oidBytes(OIDBasicConstraints), tlv(0x01, []byte{0x01}), octet(seq(derBool(true), derIntN(0)))), extOf(OIDKeyUsage, true, bitstr([]byte{0x04}, 2)), extOf(OIDSubjectKeyID, false, octet(id)))), "BOOLEAN not in the DER form"},
		{"a serial with a needless leading zero", 1, tlv(0x02, []byte{0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}), "INTEGER not minimal"},
		{"pathLenConstraint 128 read in full", 7, rootExtensions(id, seq(derBool(true), derIntN(128)), bitstr([]byte{0x04}, 2)), "root basicConstraints"},
		{"keyUsage with a second byte", 7, rootExtensions(id, seq(derBool(true), derIntN(0)), bitstr([]byte{0x04, 0x80}, 7)), "root keyUsage is not keyCertSign alone"},
		{"unused bits that are not zero", 7, rootExtensions(id, seq(derBool(true), derIntN(0)), bitstr([]byte{0x05}, 2)), "BIT STRING not in the DER form"},
		{"an extension value with a trailing byte", 7, rootExtensions(id, append(seq(derBool(true), derIntN(0)), 0x00), bitstr([]byte{0x04}, 2)), "extension value has trailing bytes"},
		{"the version INTEGER written non-minimally", 0, explicit(0, tlv(0x02, []byte{0x00, 0x02})), "not a v3 certificate with extensions"},
	}
	for _, c := range cases {
		cert := withField(t, p.root, c.index, c.field, p.rootKey)
		if got := reason(t, [][]byte{p.leaf, cert}); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// A validity with three times.
	node, _ := derRead(root.TBS, 0)
	f, _ := derChildren(node)
	vn, _ := derRead(f[4].raw, 0)
	vk, _ := derChildren(vn)
	cert := withField(t, p.root, 4, seq(vk[0].raw, vk[1].raw, vk[1].raw), p.rootKey)
	if got := reason(t, [][]byte{p.leaf, cert}); got != "time not in the DER form" {
		t.Errorf("three times: got %q", got)
	}
	if vr := ValidateChain([][]byte{p.leaf, p.root}, ChainOpts{Now: mustTime(t, "2026-09-13T12:00:00Z"), ExpectedRoot: p.rootFP, ExpectedEndpoint: reviewEndpoint}); !vr.OK {
		t.Fatalf("the untouched pair must validate: %+v", vr)
	}
}

// MEDIUM 3: every other spelling of a loopback address is refused by the guard and the normal form.
func TestAddressGuardRefusesEverySpellingOfLoopback(t *testing.T) {
	for _, bad := range []string{"https://127.1/mcp", "https://2130706433/mcp", "https://0x7f000001/mcp", "https://0177.0.0.1/mcp", "https://localhost./mcp", "https://LOCALHOST/mcp", "https://[::1]/mcp"} {
		if ok, _ := AddressGuard(bad, "", true); ok {
			t.Errorf("%s accepted", bad)
		}
		if strings.HasPrefix(bad, "https://0x") || strings.HasPrefix(bad, "https://127.1") || strings.HasPrefix(bad, "https://2130") || strings.HasPrefix(bad, "https://0177") {
			if IsNormalHTTPS(bad) {
				t.Errorf("%s read as the normal form", bad)
			}
		}
	}
	if ok, why := AddressGuard(reviewEndpoint, "", true); !ok {
		t.Error(why)
	}
}

// LOW 10/11: a small-order Ed25519 point is not a key, and an SPKI's BIT STRING has no unused bits.
func TestSmallOrderPointsAndSPKIBits(t *testing.T) {
	k, _ := GenerateKey("ed25519")
	sig, _ := SignDetached(k, []byte("data"))
	if !VerifyDetached(k.Public, []byte("data"), sig) {
		t.Fatal("a real signature verifies")
	}
	identity := make([]byte, 32)
	identity[0] = 1 // the identity element: y = 1
	small := &PublicKey{Alg: AlgEd25519, Ed: identity}
	if VerifyDetached(small, []byte("data"), sig) {
		t.Error("a small-order public key verified")
	}
	bad := append(append([]byte{}, identity...), sig[32:]...)
	if VerifyDetached(k.Public, []byte("data"), bad) {
		t.Error("a small-order R verified")
	}
	if ed25519PointOK(identity) {
		t.Error("the identity element is a point of small order")
	}
	// The SPKI's BIT STRING unused-bits byte must be zero.
	spki := append([]byte{}, k.Public.SPKI...)
	spki[len(spki)-33] = 1 // the unused-bits byte before the 32 key bytes
	if _, err := ParseSPKI(spki); err == nil {
		t.Error("an SPKI with unused bits parsed")
	}
}

// HIGH 1 (this port's half) and LOW 13: the vault's rules, and its message.
func TestVaultRulesMirrorTheCore(t *testing.T) {
	kdf := KDF{Name: "argon2id", MKiB: 8192, T: 1, P: 1}
	r := Call("vault_seal", json.RawMessage(`{"passphrase":"","plaintext":{"v":1,"roots":[],"ledger":[],"contacts":[]}}`))
	var fail struct {
		Error, Why string
	}
	_ = json.Unmarshal(r, &fail)
	if fail.Error != "bad_request" || fail.Why != "empty passphrase" {
		t.Errorf("empty passphrase: %s", r)
	}
	v, err := VaultSeal("correct horse", []byte(`{"v":1}`), &kdf, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VaultOpen("wrong", *v); err == nil || err.Error() != "the passphrase is wrong or the vault is damaged" {
		t.Errorf("the message is the core's: %v", err)
	}
	// A member added after sealing is part of the AAD as received, so the document no longer opens.
	doc := vaultDoc(*v)
	doc["ct"] = v.Ct
	if _, err := VaultOpenDoc("correct horse", doc); err != nil {
		t.Fatalf("the document as sealed opens: %v", err)
	}
	doc["note"] = "added later"
	if _, err := VaultOpenDoc("correct horse", doc); err == nil {
		t.Error("a member added after sealing still opened")
	}
	raw, _ := json.Marshal(doc)
	out := Call("vault_open", json.RawMessage(`{"passphrase":"correct horse","vault":`+string(raw)+`}`))
	if !bytes.Contains(out, []byte(`"error"`)) {
		t.Errorf("through Call: %s", out)
	}
}

// LOW 8 and MEDIUM 5: exp − ts is bounded; a result is checked for skew and for the endpoint in question.
func TestLifetimeAndCallerSideChecks(t *testing.T) {
	alina := reviewIdentity(t, "ed25519", reviewEndpoint)
	bharat := reviewIdentity(t, "ed25519", "https://agent.bharat.example/mcp")
	now := mustTime(t, "2026-09-13T12:00:00Z")
	ts := now.Unix()
	seal := func(exp int64, msgID string) *Envelope {
		env, err := SealRequest(SealOpts{RecipientKey: bharat.leafKey.Public, Sender: alina.leafKey, Form: "chain", SenderChain: [][]byte{alina.leaf, alina.root}, Method: "tools/call", Params: json.RawMessage(`{"name":"send_message","arguments":{"msg_id":"m","text":"hello"}}`), MsgID: msgID, TS: ts, Exp: exp})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	node := NodeState{
		Endpoint: "https://agent.bharat.example/mcp", AcceptNewHosts: "auto",
		Chain: []string{B64url(bharat.leaf), B64url(bharat.root)},
		Keys:  []HeldKey{{Kid: Fingerprint(bharat.leafKey.Public.SPKI), Leaf: B64url(bharat.leaf), PKCS8: B64url(pkcs8Of(t, bharat.leafKey)), Current: true}},
		Pins:  []Pin{{Root: alina.rootFP, Endpoint: reviewEndpoint, Leaf: B64url(alina.leaf), State: "active"}},
	}
	if d := Decide(now, *seal(ts+600, "m-1"), node); d.Result["code"] != "ok" || d.Result["tier"] != "contact" {
		t.Fatalf("a fresh envelope: %v", d.Result)
	}
	if d := Decide(now, *seal(ts+365*86400, "m-2"), node); d.Result["code"] != "envelope_invalid" || d.Result["why"] != "exp too far from ts" {
		t.Errorf("a year-long envelope: %v", d.Result)
	}
	if d := Decide(now, *seal(ts+30*86400, "m-3"), node); d.Result["code"] != "ok" {
		t.Errorf("exactly thirty days: %v", d.Result)
	}

	// A result sealed twenty minutes ago is outside the window even before its exp.
	sealResult := func(tsAt, exp int64, form string) []byte {
		args := map[string]any{"recipient_spki": B64url(alina.leafKey.Public.SPKI), "sender_pkcs8": B64url(pkcs8Of(t, bharat.leafKey)), "form": form, "sender_chain": []string{B64url(bharat.leaf), B64url(bharat.root)}, "result": map[string]any{"ok": true}, "msg_id": "m-1", "ts": tsAt, "exp": exp}
		raw, _ := json.Marshal(args)
		return Call("seal_result", raw)
	}
	open := func(env []byte, expectedEndpoint string) map[string]any {
		var e map[string]any
		_ = json.Unmarshal(env, &e)
		args := map[string]any{"envelope": e, "my_pkcs8": B64url(pkcs8Of(t, alina.leafKey)), "msg_id": "m-1", "now": "2026-09-13T12:00:00Z",
			"pins": []map[string]any{{"root": bharat.rootFP, "endpoint": "https://agent.bharat.example/mcp", "leaf": B64url(bharat.leaf), "state": "active"}}}
		if expectedEndpoint != "" {
			args["expected_endpoint"] = expectedEndpoint
		}
		raw, _ := json.Marshal(args)
		var out map[string]any
		_ = json.Unmarshal(Call("open_result", raw), &out)
		return out
	}
	if out := open(sealResult(ts-1200, ts+600, "chain"), ""); out["error"] != "envelope_invalid" || out["why"] != "outside the time window" {
		t.Errorf("a stale result: %v", out)
	}
	if out := open(sealResult(ts, ts+600, "leaf"), "https://elsewhere.example/mcp"); out["why"] != "endpoint differs from the one in question" {
		t.Errorf("the small form ignores the endpoint in question: %v", out)
	}
	if out := open(sealResult(ts, ts+600, "leaf"), "https://agent.bharat.example/mcp"); out["ok"] != true {
		t.Errorf("a good small-form result: %v", out)
	}

	// FollowRenewed: equal notBefore, different bytes, is a conflict and is not followed.
	twin, err := BuildLeaf(LeafOpts{CN: "Alina Rao", RootCN: "Alina Rao", RootKey: bharat.rootKey, HostPub: bharat.leafKey.Public, Endpoint: "https://agent.bharat.example/mcp", NotBefore: mustTime(t, "2026-09-01T00:00:00Z"), NotAfter: mustTime(t, "2027-09-01T00:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	if follow, why, _ := FollowRenewed([][]byte{twin, bharat.root}, bharat.rootFP, bharat.leaf, "https://agent.bharat.example/mcp", now); follow || why != "a different leaf with the same notBefore" {
		t.Errorf("a conflicting chain was followed: %v %q", follow, why)
	}
	_ = time.Second
}
