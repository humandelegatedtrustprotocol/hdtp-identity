package pactidentity

// The cryptography review of 2026-09-14, as tests: each finding it made against this port is a
// case that failed before the fix and passes after it, mirroring crates/pact-identity/tests/review.rs.
// P-21 of the 2026-09-23 review is held here the same way, at the end, mirroring
// crates/pact-identity/tests/findings.rs instead.

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
		// An empty attribute in a Name. `nameOf` indexed `parts[0]` one line ABOVE the `len(parts) < 2`
		// that would have made it safe, so these six bytes panicked the parser — reachable with no
		// credential through `Decide` -> `ValidateChain` -> `Parse`, before any signature is verified.
		// Rust put the length first in a short-circuiting `||`, so only this port could be reached.
		{"an empty attribute in the Name", 5, seq(tlv(0x31, seq())), "name is not a UTF-8 commonName"},
		// An X25519 key. `AlgorithmOf` errors only on an EMPTY Alg, and `ParseSPKI` names X25519, so
		// this leaf was inside the profile here and outside it in Rust — a chain this port validated
		// and the wallet refused.
		{"a key algorithm outside the profile", 6, seq(seq(oidBytes(oidX25519)), bitstr(make([]byte, 32), 0)), "key algorithm not in the profile"},
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
	if d := decided(t, now, *seal(ts+600, "m-1"), node); d.Result["code"] != "ok" || d.Result["tier"] != "contact" {
		t.Fatalf("a fresh envelope: %v", d.Result)
	}
	if d := decided(t, now, *seal(ts+365*86400, "m-2"), node); d.Result["code"] != "envelope_invalid" || d.Result["why"] != "exp too far from ts" {
		t.Errorf("a year-long envelope: %v", d.Result)
	}
	if d := decided(t, now, *seal(ts+30*86400, "m-3"), node); d.Result["code"] != "ok" {
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

// The 1-in-256 bug the strict reader surfaced: eight random bytes beginning 0x00 used to encode as a
// non-minimal INTEGER, and ParseCertificate then refused a certificate this port had just issued.
// Both halves are asserted, because either alone passes: the encoder produces minimal bytes, and the
// serial generator never hands it a value that would shrink under 64 bits.
func TestIntegersAreMinimalAndSerialsStaySixtyFourBits(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want []byte
	}{
		{[]byte{0x00, 0x11, 0x22}, []byte{0x02, 0x02, 0x11, 0x22}},
		{[]byte{0x00, 0x00, 0x01}, []byte{0x02, 0x01, 0x01}},
		{[]byte{0x80, 0x11}, []byte{0x02, 0x03, 0x00, 0x80, 0x11}},
		{[]byte{0x00, 0x80, 0x11}, []byte{0x02, 0x03, 0x00, 0x80, 0x11}},
		{[]byte{0x00}, []byte{0x02, 0x01, 0x00}},
		// The empty slice means zero and encodes as one byte. This port already did the right
		// thing while the seed and the Rust port wrote `02 00`, which is not a DER INTEGER at
		// all — a three-way disagreement no gate could see, because nothing passes empty.
		{[]byte{}, []byte{0x02, 0x01, 0x00}},
	} {
		if got := derInt(c.in); !bytes.Equal(got, c.want) {
			t.Errorf("derInt(%x) = %x, want %x", c.in, got, c.want)
		}
		node, err := derRead(derInt(c.in), 0)
		if err != nil || !derIntMinimal(node.content) {
			t.Errorf("derInt(%x) does not read back as minimal", c.in)
		}
	}
	for i := 0; i < 512; i++ {
		s, err := randomSerial()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != 8 || s[0] == 0 {
			t.Fatalf("randomSerial gave %x, which the profile would refuse once encoded", s)
		}
		node, err := derRead(derInt(s), 0)
		if err != nil || !derIntMinimal(node.content) || len(node.content) < 8 {
			t.Fatalf("serial %x encoded to %d non-minimal bytes", s, len(node.content))
		}
	}
}

// crypto/ecdsa returns either twin of a signature; this port returns the low-S one, every time
// (SPEC 14.1). Half of these were high before the rule, so forty in a row is not luck.
func TestEveryP256SignatureIsTheLowSTwin(t *testing.T) {
	priv, err := GenerateKey(AlgP256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		sig, err := SignDetached(priv, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if low, isSig := EcdsaIsLowS(sig); !isSig || !low {
			t.Fatalf("signature %d: low=%v isSig=%v", i, low, isSig)
		}
		if !VerifyDetached(priv.Public, []byte{byte(i)}, sig) {
			t.Fatalf("signature %d does not verify", i)
		}
	}
	if _, isSig := EcdsaIsLowS([]byte{1, 2, 3}); isSig {
		t.Error("bytes that are not an ECDSA value were judged as one")
	}
}

// RFC 8785 prints a number as ECMAScript's Number does. The first ten rows are `canonical.rs`'s own
// table, so the two ports are held to one list; the rest are where this port used to differ from it
// and from the seed — Go's `%g` writes a two-digit exponent and turns to one at 1e-5, negative zero
// printed as `-0`, and an integer past 2^53 kept digits a double does not have.
func TestNumbersAsECMAScriptPrintsThem(t *testing.T) {
	for _, c := range [][2]string{
		{"1e21", "1e+21"},
		{"1.5e300", "1.5e+300"},
		{"1e-7", "1e-7"},
		{"0.000001", "0.000001"},
		{"100.0", "100"},
		{"9223372036854775808.0", "9223372036854776000"},
		{"1e20", "100000000000000000000"},
		{"0.1", "0.1"},
		{"-0.0", "0"},
		{"42", "42"},
		{"1e-5", "0.00001"},
		{"0.0000001", "1e-7"},
		{"1.25e-9", "1.25e-9"},
		{"-1e-7", "-1e-7"},
		{"1e100", "1e+100"},
		{"9007199254740992", "9007199254740992"},
		{"9007199254740993", "9007199254740992"},
		{"-9007199254740993", "-9007199254740992"},
		{"12345678901234567890", "12345678901234567000"},
	} {
		v, err := decodeJSON([]byte(c[0]))
		if err != nil {
			t.Fatalf("%s: %v", c[0], err)
		}
		if got := Canonical(v); string(got) != c[1] {
			t.Errorf("%s canonicalises to %s, and ECMAScript prints %s", c[0], got, c[1])
		}
	}
}

// A four-octet DER length reaches 2^32-1. Folded into a 32-bit `int` it wrapped negative, `at+l`
// stayed inside the buffer, and the slice panicked — from six bytes of anybody's certificate. This
// runs on any word size; the 32-bit one is where the old reader fell over, and it is cross-compiled
// and run under linux/386 to show so (see the review-findings plan, B8).
func TestAFourOctetLengthIsRefusedOnAnyWordSize(t *testing.T) {
	for _, in := range [][]byte{
		{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 0x01, 0x02},
		{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFE, 0x00},
		// The one that PANICKED a 32-bit build: a length that stays positive, so it passed the
		// "not minimal" test, and `at+l` wrapped instead — a negative slice bound.
		{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF},
		{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFA, 0x01, 0x02, 0x03},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%x panicked the reader: %v", in, r)
				}
			}()
			if _, err := derRead(in, 0); err == nil || err.Error() != "DER length overruns the buffer" {
				t.Errorf("%x: %v", in, err)
				return
			}
			if _, err := Parse(in); err == nil {
				t.Errorf("%x parsed as a certificate", in)
			}
		}()
	}
}

// §3 (2.1.3): a writer puts no control character into a card. A card is LINES: a line break in a name,
// the seal policy or an extra line writes a property of the writer's choosing, and the decoder reads
// the FIRST of a name, so this card required sealing and said it did not.
func TestNothingThatGoesIntoACardMayCarryALineBreak(t *testing.T) {
	leaf := []byte{0x30, 0x00}
	for what, in := range map[string][3]any{
		"a name with CR LF":        {"x\r\nX-PACT-SEAL:none", "required", []string(nil)},
		"a name with a bare LF":    {"x\nX-PACT-SEAL:none", "", []string(nil)},
		"a name with a NUL":        {"x\x00y", "", []string(nil)},
		"a seal with CR LF":        {"x", "required\r\nX-PACT-VERSION:3", []string(nil)},
		"an extra line with CR LF": {"x", "", []string{"X-A:1\r\nX-PACT-SEAL:none"}},
	} {
		if card, err := EncodeCard(in[0].(string), leaf, in[1].(string), in[2].([]string)); err == nil {
			t.Errorf("%s was written into a card:\n%s", what, card)
		}
	}
	card, err := EncodeCard("Rao, Alina; of Pune", leaf, "required", []string{"X-PACT-FUTURE:1"})
	if err != nil || !strings.Contains(card, "FN:Rao, Alina; of Pune\r\n") || !strings.Contains(card, "X-PACT-SEAL:required\r\n") {
		t.Fatalf("an honest card: %v\n%s", err, card)
	}
}

// P-21 (review of 2026-09-23) — a contact I asked, still `pending_out`, lists my tools: `tools/list`
// returns what the caller's tier may use (§6) and a sealed call is dispatched in the tier the proven
// identity earns (§13.2). A listing names no tool, so it never matched `contact_accepted` or
// `contact_rejected` and was answered `pending_approval` — in the small form, in the chain form, and
// on the path where the pin moves on the way through. The controls are the calls that must still
// wait. Mirrors a_pending_contacts_sealed_listing_answers_at_the_pending_tier in tests/findings.rs.
func TestAPendingContactsSealedListingAnswersAtThePendingTier(t *testing.T) {
	const movedEndpoint = "https://alina.pact.contact/alina/mcp"
	v := loadVectors(t)
	c := theCast(t)
	now := mustTime(t, v.Now)
	der := func(n string) []byte { return hexBytes(t, v.Certificates[n].DerHex) }
	rootA, _ := Parse(der("root_a"))
	// Alina's next host: the same root, a newer leaf, another address (§5.3 under `auto`).
	moved, err := BuildLeaf(LeafOpts{CN: "Alina Rao", RootCN: "Alina Rao", RootKey: c.rootA, HostPub: c.leafANext.Public, Endpoint: movedEndpoint, NotBefore: mustTime(t, "2026-09-10T00:00:00Z"), NotAfter: mustTime(t, "2027-09-10T00:00:00Z"), Serial: SerialOf("p21/moved")})
	if err != nil {
		t.Fatal(err)
	}
	node := bharatNode(t, v, []Pin{{Root: FingerprintOf(rootA), Endpoint: endpointA, Leaf: B64url(der("leaf_a")), State: "pending_out"}})
	decide := func(senderLeaf []byte, senderKey, method, params string) Decision {
		args := map[string]any{"recipient_leaf": B64url(der("leaf_b")), "sender_pkcs8": B64url(hexBytes(t, v.LeafKeys[senderKey])), "form": "leaf",
			"method": method, "params": json.RawMessage(params), "msg_id": "p21", "ts": now.Unix()}
		if senderLeaf != nil {
			args["form"] = "chain"
			args["sender_chain"] = []string{B64url(senderLeaf), B64url(der("root_a"))}
		}
		var e Envelope
		if out := Call("seal_request", mustJSON(args)); json.Unmarshal(out, &e) != nil || e.Ct == "" {
			t.Fatalf("seal_request: %s", out)
		}
		return decided(t, now, e, node)
	}
	for _, s := range []struct {
		what, key, endpoint string
		leaf                []byte
	}{
		{"small form", "leaf_a", endpointA, nil},
		{"chain form", "leaf_a", endpointA, der("leaf_a")},
		{"chain form, moved", "leaf_a_next", movedEndpoint, moved},
	} {
		d := decide(s.leaf, s.key, "tools/list", `{}`)
		if d.Result["code"] != "ok" || d.Result["tier"] != "pending" || d.Result["endpoint"] != s.endpoint {
			t.Errorf("%s, tools/list: %v", s.what, d.Result)
		}
		if d = decide(s.leaf, s.key, "tools/call", `{"name":"contact_accepted"}`); d.Result["code"] != "ok" || d.Result["tier"] != "pending" {
			t.Errorf("%s, contact_accepted: %v", s.what, d.Result)
		}
		// The controls: what the pending tier does not have still waits.
		if d = decide(s.leaf, s.key, "tools/call", `{"name":"send_message"}`); d.Result["code"] != "pending_approval" {
			t.Errorf("%s, send_message: %v", s.what, d.Result)
		}
		if d = decide(s.leaf, s.key, "tools/call", `{}`); d.Result["code"] != "pending_approval" {
			t.Errorf("%s, a call that names no tool: %v", s.what, d.Result)
		}
	}
}
