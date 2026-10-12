package hdtpidentity

// Proves this port against Appendix B: the certificates rebuilt (byte for byte where the issuer is
// Ed25519; the TBS, and the vector's signature verified, where it is P-256), the ones marked refused
// refused, every chain, newest-leaf, certificate_renewed and envelope case, the envelopes
// reproduced from their ephemeral seeds, decide on them, and the derivation vectors.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Now          string `json:"now"`
	Certificates map[string]struct {
		DerHex string `json:"der_hex"`
		// Refused marks a certificate that exists to be refused (SPEC 14.1): it is not one the
		// generator rebuilds, and it must not come out of Parse and the profile check clean.
		Refused bool `json:"refused"`
	} `json:"certificates"`
	LeafKeys   map[string]string `json:"leaf_keys_pkcs8_hex"`
	ChainCases []struct {
		Name             string   `json:"name"`
		Chain            []string `json:"chain"`
		ExpectedRoot     string   `json:"expected_root"`
		ExpectedEndpoint string   `json:"expected_endpoint"`
		Now              string   `json:"now"`
		Expect           string   `json:"expect"`
		Rule             int      `json:"rule"`
		Reason           string   `json:"reason"`
	} `json:"chain_cases"`
	NewestLeafCases []struct {
		Pinned, Presented, Expect string
	} `json:"newest_leaf_cases"`
	Derivation []struct {
		Label, Info, Alg, Prf, Salt, Seed, Spki, Fingerprint string
	} `json:"derivation"`
	RenewedCases []struct {
		Name       string `json:"name"`
		PinnedLeaf string `json:"pinned_leaf"`
		Dialed     string `json:"dialed"`
		Now        string `json:"now"`
		Answer     struct {
			Code string `json:"code"`
			Data struct {
				Chain []string `json:"chain"`
			} `json:"data"`
		} `json:"answer"`
		Expect string `json:"expect"`
	} `json:"certificate_renewed_cases"`
	Envelopes []struct {
		Name           string   `json:"name"`
		Form           string   `json:"form"`
		Suite          string   `json:"suite"`
		SenderChain    []string `json:"sender_chain"`
		RecipientChain []string `json:"recipient_chain"`
		PlaintextHex   string   `json:"plaintext_hex"`
		Protected      string   `json:"protected"`
		Enc            string   `json:"enc"`
		Ct             string   `json:"ct"`
		Sig            string   `json:"sig"`
	} `json:"envelopes"`
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// readSpec is the newest released version of hdtp-spec's specification as one document: its
// index.md followed by the pages its table of contents links, in that order, as hdtp-spec's
// site/spec-source.mjs reads it. HDTP_SPEC names a version directory instead.
func readSpec() (string, error) {
	dir := os.Getenv("HDTP_SPEC")
	if dir == "" {
		base := "../../hdtp-spec/docs/specification"
		entries, err := os.ReadDir(base)
		if err != nil {
			return "", err
		}
		best := [2]int{-1, -1}
		for _, e := range entries {
			var x, y int
			if n, _ := fmt.Sscanf(e.Name(), "%d.%d", &x, &y); n == 2 && fmt.Sprintf("%d.%d", x, y) == e.Name() && (x > best[0] || x == best[0] && y > best[1]) {
				best, dir = [2]int{x, y}, base+"/"+e.Name()
			}
		}
		if dir == "" {
			return "", errors.New("no released version under " + base)
		}
	}
	index, err := os.ReadFile(dir + "/index.md")
	if err != nil {
		return "", err
	}
	at := strings.Index(string(index), "\n## Table of contents")
	if at < 0 {
		return "", errors.New(dir + "/index.md has no table of contents")
	}
	out := string(index)
	for _, part := range strings.Split(string(index)[at:], "](")[1:] {
		if end := strings.Index(part, ".md)"); end >= 0 {
			page, err := os.ReadFile(dir + "/" + part[:end+3])
			if err != nil {
				return "", err
			}
			out += string(page)
		}
	}
	return out, nil
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(envOr("HDTP_VECTORS", "../../hdtp-spec/vectors/hdtp-1.0-vectors.json"))
	if err != nil {
		t.Skip("vectors not found: " + err.Error())
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	spec, err := readSpec()
	if err != nil {
		t.Skip("the specification is not found: " + err.Error())
	}
	blocks, err := appendixB(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) < 1 {
		t.Fatal("Appendix B lacks its vector block")
	}
	var inSpec, inFile any
	_ = json.Unmarshal(blocks[0], &inSpec)
	_ = json.Unmarshal(raw, &inFile)
	a, _ := json.Marshal(inSpec)
	b, _ := json.Marshal(inFile)
	if !bytes.Equal(a, b) {
		t.Error("the specification does not carry the generated vectors unchanged")
	}
	return v
}

// appendixB is the JSON blocks of a specification's Appendix B: everything fenced as ```json between
// the heading `## Appendix B` and the first `*End of HDTP` after it. Both markers must be there,
// every fence must close and every block must be JSON — the rule js/seed.mjs `appendixB`, the CLI's
// `appendix_b` (crates/hdtp/src/vectors/check.rs) and the core tests' read by, each held to
// js/appendix-b-reader.json's cases, refusals word for word (TestAppendixBIsReadAsTheSharedCasesSay).
// It sliced with two bare strings.Index calls, which panicked on a missing marker, took an end marker
// from before the heading, and silently dropped a block whose fence never closed.
func appendixB(spec string) ([]json.RawMessage, error) {
	start := strings.Index(spec, "## Appendix B")
	if start < 0 {
		return nil, errors.New("the document has no Appendix B")
	}
	end := strings.Index(spec[start:], "*End of HDTP")
	if end < 0 {
		return nil, errors.New("Appendix B has no end marker (*End of HDTP)")
	}
	b := spec[start : start+end]
	var out []json.RawMessage
	for {
		i := strings.Index(b, "```json\n")
		if i < 0 {
			return out, nil
		}
		after := b[i+8:]
		j := strings.Index(after, "\n```")
		if j < 0 {
			return nil, errors.New("an unterminated json fence in Appendix B")
		}
		block := json.RawMessage(after[:j])
		if !json.Valid(block) {
			return nil, fmt.Errorf("Appendix B block %d is not JSON", len(out)+1)
		}
		out = append(out, block)
		b = after[j+4:]
	}
}

// js/appendix-b-reader.json: the cases all four Appendix B readers of this repository are held to.
// (This port's list used to hold two cases the other readers' did not: an end marker quoted before
// the heading, and a block that is not JSON. They are in the one list now.)
func TestAppendixBIsReadAsTheSharedCasesSay(t *testing.T) {
	raw, err := os.ReadFile("../js/appendix-b-reader.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Doc, Refused string
			Blocks             []json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 10 {
		t.Fatalf("%d cases", len(fixture.Cases))
	}
	for _, c := range fixture.Cases {
		blocks, err := appendixB(c.Doc)
		if c.Refused != "" {
			if err == nil || err.Error() != c.Refused {
				t.Errorf("%s: got %v, want the refusal %q", c.Name, err, c.Refused)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		got, _ := json.Marshal(canonicalBlocks(t, blocks))
		want, _ := json.Marshal(canonicalBlocks(t, c.Blocks))
		if !bytes.Equal(got, want) {
			t.Errorf("%s: read %s, want %s", c.Name, got, want)
		}
	}
}

// canonicalBlocks decodes each block, so two spellings of one JSON value compare equal.
func canonicalBlocks(t *testing.T, blocks []json.RawMessage) []any {
	t.Helper()
	out := []any{}
	for _, b := range blocks {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	endpointA = "https://agent.alina.example/mcp"
	endpointB = "https://agent.bharat.example/mcp"
	endpointC = "https://agent.chandra.example/mcp"
	rootCEnds = "2028-01-01T00:00:00Z"
)

type cast struct {
	rootA, rootB, rootC, leafA, leafANext, leafB, leafC *PrivateKey
}

func theCast(t *testing.T) cast {
	t.Helper()
	k := func(alg, label string) *PrivateKey {
		p, err := KeyFromSeed(alg, Seed(label))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return cast{
		rootA: k(AlgEd25519, "root/alina"), rootB: k(AlgP256, "root/bharat"), rootC: k(AlgEd25519, "root/chandra"),
		leafA: k(AlgEd25519, "host/alina/2026"), leafANext: k(AlgEd25519, "host/alina/2027"), leafB: k(AlgP256, "host/bharat/2026"),
		leafC: k(AlgEd25519, "host/chandra/2026"),
	}
}

func rebuild(t *testing.T, c cast) map[string][]byte {
	t.Helper()
	at := func(s string) time.Time { return mustTime(t, s) }
	leafA := func(label string, host *PrivateKey, dns, nb, na string) []byte {
		der, err := BuildLeaf(LeafOpts{CN: "Alina Rao", RootCN: "Alina Rao", RootKey: c.rootA, HostPub: host.Public(), Endpoint: endpointA, DNSName: dns, NotBefore: at(nb), NotAfter: at(na), Serial: SerialOf(label)})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	rootA, err := BuildRoot(RootOpts{CN: "Alina Rao", Key: c.rootA, NotBefore: at("2026-09-01T00:00:00Z"), Serial: SerialOf("root_a")})
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := BuildRoot(RootOpts{CN: "Bharat Mehta", Key: c.rootB, NotBefore: at("2026-09-01T00:00:00Z"), Serial: SerialOf("root_b")})
	if err != nil {
		t.Fatal(err)
	}
	leafB, err := BuildLeaf(LeafOpts{CN: "Bharat Mehta", RootCN: "Bharat Mehta", RootKey: c.rootB, HostPub: c.leafB.Public(), Endpoint: endpointB, NotBefore: at("2026-09-01T00:00:00Z"), NotAfter: at("2027-09-01T00:00:00Z"), Serial: SerialOf("leaf_b")})
	if err != nil {
		t.Fatal(err)
	}
	rootC, err := BuildRoot(RootOpts{CN: "Chandra Iyer", Key: c.rootC, NotBefore: at("2026-09-01T00:00:00Z"), NotAfter: at(rootCEnds), Serial: SerialOf("root_c")})
	if err != nil {
		t.Fatal(err)
	}
	leafC := func(label, nb, na string) []byte {
		der, err := BuildLeaf(LeafOpts{CN: "Chandra Iyer", RootCN: "Chandra Iyer", RootKey: c.rootC, HostPub: c.leafC.Public(), Endpoint: endpointC, NotBefore: at(nb), NotAfter: at(na), Serial: SerialOf(label)})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	return map[string][]byte{
		"root_a": rootA, "root_b": rootB, "leaf_b": leafB, "root_c": rootC,
		"leaf_c":          leafC("leaf_c", "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z"),
		"leaf_c_last":     leafC("leaf_c_last", "2027-01-01T00:00:00Z", rootCEnds),
		"leaf_c_outlives": leafC("leaf_c_outlives", "2027-06-01T00:00:00Z", "2028-06-01T00:00:00Z"),
		"leaf_a":          leafA("leaf_a", c.leafA, "agent.alina.example", "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z"),
		"leaf_a_expired":  leafA("leaf_a_expired", c.leafA, "", "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z"),
		"leaf_a_long":     leafA("leaf_a_long", c.leafA, "", "2026-09-01T00:00:00Z", "2027-10-10T00:00:00Z"),
		"leaf_a_next":     leafA("leaf_a_next", c.leafANext, "", "2027-08-02T00:00:00Z", "2028-08-01T00:00:00Z"),
	}
}

func TestCertificatesReproduce(t *testing.T) {
	v := loadVectors(t)
	c := theCast(t)
	built := rebuild(t, c)
	for name, cert := range v.Certificates {
		want := hexBytes(t, cert.DerHex)
		if cert.Refused {
			why := ""
			if parsed, err := Parse(want); err != nil {
				why = err.Error()
			} else if strings.HasPrefix(name, "root") {
				why = ProfileError(parsed, "root")
			} else {
				why = ProfileError(parsed, "leaf")
			}
			if why == "" {
				t.Errorf("%s: marked refused, and Parse + the profile let it through", name)
			}
			continue
		}
		got, ok := built[name]
		if !ok {
			t.Errorf("%s: not rebuilt", name)
			continue
		}
		wc, err := Parse(want)
		if err != nil {
			t.Fatalf("%s: vector does not parse: %v", name, err)
		}
		gc, err := Parse(got)
		if err != nil {
			t.Fatalf("%s: rebuilt does not parse: %v", name, err)
		}
		if !bytes.Equal(wc.TBS, gc.TBS) {
			t.Errorf("%s: TBS differs", name)
		}
		issuer := c.rootA.Public()
		switch strings.Split(name, "_")[1] {
		case "b":
			issuer = c.rootB.Public()
		case "c":
			issuer = c.rootC.Public()
		}
		if !verifyCert(wc, issuer) {
			t.Errorf("%s: the vector's signature does not verify under its issuer", name)
		}
		if issuer.Alg == AlgEd25519 && !bytes.Equal(want, got) {
			t.Errorf("%s: bytes differ", name)
		}
		if len(want) > MaxCertBytes {
			t.Errorf("%s: over 4 KiB", name)
		}
		kind := "leaf"
		if strings.HasPrefix(name, "root") {
			kind = "root"
		}
		if e := ProfileError(wc, kind); e != "" {
			t.Errorf("%s: profile: %s", name, e)
		}
	}
	for name, hexKey := range v.LeafKeys {
		priv, err := ParsePKCS8(hexBytes(t, hexKey))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		again, err := priv.PKCS8()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, hexBytes(t, hexKey)) {
			t.Errorf("%s: PKCS #8 does not round-trip", name)
		}
		leaf, _ := Parse(hexBytes(t, v.Certificates[name].DerHex))
		if !bytes.Equal(leaf.SPKI, priv.Public().SPKI) {
			t.Errorf("%s: the key is not the leaf's", name)
		}
	}
}

func TestChainCases(t *testing.T) {
	v := loadVectors(t)
	der := func(n string) []byte { return hexBytes(t, v.Certificates[n].DerHex) }
	for _, c := range v.ChainCases {
		chain := make([][]byte, 0, len(c.Chain))
		for _, n := range c.Chain {
			chain = append(chain, der(n))
		}
		r := ValidateChain(chain, ChainOpts{Now: mustTime(t, c.Now), ExpectedRoot: c.ExpectedRoot, ExpectedEndpoint: c.ExpectedEndpoint})
		if c.Expect == "accept" && !r.OK {
			t.Errorf("%s: expected accept, got rule %d (%s)", c.Name, r.Rule, r.Reason)
		}
		if c.Expect == "refuse" && (r.OK || r.Rule != c.Rule) {
			t.Errorf("%s: expected rule %d, got ok=%v rule %d (%s)", c.Name, c.Rule, r.OK, r.Rule, r.Reason)
		}
		// A case that names its reason is held to it: rule 4 refuses for four reasons, and a guard
		// that went missing would still refuse by rule 4 for another one.
		if c.Reason != "" && (r.OK || r.Reason != c.Reason) {
			t.Errorf("%s: expected the reason %q, got ok=%v %q", c.Name, c.Reason, r.OK, r.Reason)
		}
	}
	for _, c := range v.NewestLeafCases {
		got, err := CompareLeaves(der(c.Pinned), der(c.Presented))
		if err != nil || got != c.Expect {
			t.Errorf("%s vs %s: expected %s, got %s (%v)", c.Pinned, c.Presented, c.Expect, got, err)
		}
	}
	for _, c := range v.RenewedCases {
		pinned, err := Parse(der(c.PinnedLeaf))
		if err != nil {
			t.Fatal(err)
		}
		follow, why, _ := FollowRenewed(chainIn(t, c.Answer.Data.Chain), "sha256:"+B64url(pinned.AKI), der(c.PinnedLeaf), c.Dialed, mustTime(t, c.Now))
		if follow != (c.Expect == "follow") {
			t.Errorf("%s: expected %s (%s)", c.Name, c.Expect, why)
		}
		out := Call("follow_renewed", mustJSON(map[string]any{"answer": c.Answer, "pinned_root": "sha256:" + B64url(pinned.AKI), "pinned_leaf": B64url(der(c.PinnedLeaf)), "dialed": c.Dialed, "now": c.Now}))
		var r struct{ Follow bool }
		_ = json.Unmarshal(out, &r)
		if r.Follow != follow {
			t.Errorf("%s: Call disagrees: %s", c.Name, out)
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestEnvelopesOpenAndReproduce(t *testing.T) {
	v := loadVectors(t)
	der := func(n string) []byte { return hexBytes(t, v.Certificates[n].DerHex) }
	now := mustTime(t, v.Now)
	for _, e := range v.Envelopes {
		recipientLeaf, err := Parse(der(e.RecipientChain[0]))
		if err != nil {
			t.Fatal(err)
		}
		recipient, err := ParsePKCS8(hexBytes(t, v.LeafKeys[e.RecipientChain[0]]))
		if err != nil {
			t.Fatal(err)
		}
		aad, enc, ct := wireIn(t, e.Protected), wireIn(t, e.Enc), wireIn(t, e.Ct)
		hv, err := decodeJSON(aad)
		if err != nil {
			t.Fatal(err)
		}
		header := hv.(map[string]any)
		if sortedKeys(header) != HeaderMembers {
			t.Errorf("%s: header members %s", e.Name, sortedKeys(header))
		}
		vv, _ := numberOf(header["v"])
		suite, _ := SuiteForKey(recipientLeaf.PublicKey)
		if vv != 1 || header["suite"] != e.Suite || e.Suite != suite {
			t.Errorf("%s: version and suite", e.Name)
		}
		if header["kid"] != Fingerprint(recipientLeaf.SPKI) {
			t.Errorf("%s: kid is not the recipient leaf key", e.Name)
		}
		if !bytes.Equal(recipient.Public().SPKI, recipientLeaf.SPKI) {
			t.Errorf("%s: the recipient key is not the leaf's", e.Name)
		}
		pt, err := Open(e.Suite, recipient, recipientLeaf.PublicKey, []byte(Info), aad, enc, ct)
		if err != nil {
			t.Errorf("%s: open: %v", e.Name, err)
			continue
		}
		if hex.EncodeToString(pt) != e.PlaintextHex {
			t.Errorf("%s: plaintext differs", e.Name)
		}
		bv, _ := decodeJSON(pt)
		body := bv.(map[string]any)
		senderLeaf, _ := Parse(der(e.SenderChain[0]))
		signed := concat(aad, enc, ct)
		if e.Form == "leaf" {
			if sortedKeys(body) != "leaf,method,params" {
				t.Errorf("%s: small form members", e.Name)
			}
			if body["leaf"] != Fingerprint(senderLeaf.SPKI) {
				t.Errorf("%s: leaf names the sender's held leaf", e.Name)
			}
			if !VerifyDetached(senderLeaf.PublicKey, signed, wireIn(t, e.Sig)) {
				t.Errorf("%s: signature under the held leaf's key", e.Name)
			}
			if len(ct) >= 400 {
				t.Errorf("%s: small form is %d bytes sealed", e.Name, len(ct))
			}
		} else {
			if sortedKeys(body) != "chain,method,params" {
				t.Errorf("%s: full form members", e.Name)
			}
			var chain [][]byte
			for _, c := range body["chain"].([]any) {
				chain = append(chain, chainIn(t, []string{c.(string)})[0])
			}
			r := ValidateChain(chain, ChainOpts{Now: now})
			if !r.OK {
				t.Errorf("%s: chain inside: rule %d %s", e.Name, r.Rule, r.Reason)
				continue
			}
			if !bytes.Equal(chain[0], der(e.SenderChain[0])) {
				t.Errorf("%s: chain inside is not the sender's", e.Name)
			}
			if !VerifyDetached(r.LeafKey, signed, wireIn(t, e.Sig)) {
				t.Errorf("%s: signature under the chain's leaf key", e.Name)
			}
		}
		// Reproduce enc and ct from the ephemeral seed.
		enc2, ct2, err := sealWith(e.Suite, recipientLeaf.PublicKey, []byte(Info), aad, pt, Seed("ephemeral/"+e.Name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(enc2, enc) || !bytes.Equal(ct2, ct) {
			t.Errorf("%s: enc/ct do not reproduce from the seed", e.Name)
		}
	}
}

func bharatNode(t *testing.T, v vectorFile, pins []Pin) NodeState {
	t.Helper()
	der := func(n string) string { return B64url(hexBytes(t, v.Certificates[n].DerHex)) }
	leafB, _ := Parse(hexBytes(t, v.Certificates["leaf_b"].DerHex))
	return NodeState{
		Endpoint: endpointB, AcceptNewHosts: "auto", Chain: []string{der("leaf_b"), der("root_b")},
		Keys: []HeldKey{{Kid: Fingerprint(leafB.SPKI), Leaf: der("leaf_b"), PKCS8: B64url(hexBytes(t, v.LeafKeys["leaf_b"])), Current: true}},
		Pins: pins,
	}
}

func TestDecideOnVectors(t *testing.T) {
	v := loadVectors(t)
	now := mustTime(t, v.Now)
	rootA, _ := Parse(hexBytes(t, v.Certificates["root_a"].DerHex))
	pinA := Pin{Root: FingerprintOf(rootA), Endpoint: endpointA, Leaf: B64url(hexBytes(t, v.Certificates["leaf_a"].DerHex)), State: "active"}
	envOf := func(name string) Envelope {
		for _, e := range v.Envelopes {
			if e.Name == name {
				return Envelope{Protected: e.Protected, Enc: e.Enc, Ct: e.Ct, Sig: e.Sig}
			}
		}
		t.Fatal("no envelope " + name)
		return Envelope{}
	}
	d := decided(t, now, envOf("alina-to-bharat"), bharatNode(t, v, nil))
	if d.Result["code"] != "envelope_invalid" || d.Result["why"] != "guest may only redeem or request" {
		t.Errorf("first contact with send_message: %v", d.Result)
	}
	d = decided(t, now, envOf("alina-to-bharat"), bharatNode(t, v, []Pin{pinA}))
	if d.Result["code"] != "ok" || d.Result["tier"] != "contact" || d.Result["form"] != "chain" || d.Result["tool"] != "send_message" {
		t.Errorf("pinned sender: %v", d.Result)
	}
	if len(d.Effects) != 1 || d.Effects[0]["op"] != "seen" {
		t.Errorf("effects: %v", d.Effects)
	}
	d = decided(t, now, envOf("alina-to-bharat-by-reference"), bharatNode(t, v, []Pin{pinA}))
	if d.Result["code"] != "ok" || d.Result["tier"] != "contact" || d.Result["form"] != "leaf" {
		t.Errorf("small form against the pinned leaf: %v", d.Result)
	}
	d = decided(t, now, envOf("alina-to-bharat-by-reference"), bharatNode(t, v, nil))
	if d.Result["code"] != "chain_required" {
		t.Errorf("small form against no pins: %v", d.Result)
	}
	// The same through Call.
	node := bharatNode(t, v, []Pin{pinA})
	node.Seen = []string{"vec-v1-alina-to-bharat"}
	out := Call("decide", mustJSON(map[string]any{"now": v.Now, "envelope": envOf("alina-to-bharat"), "node": node}))
	var r Decision
	_ = json.Unmarshal(out, &r)
	if r.Result["code"] != "ok" || r.Result["replayed"] != true {
		t.Errorf("replay through Call: %s", out)
	}
}

// A `sig` not in the one spelling (§13.1) is `envelope_invalid` before the form decides anything.
// The small form from a pinned contact answered `chain_required` to every one of them, while the
// chain form refused them: the same envelope, two answers, by form alone. An empty `sig` is the one
// spelling of zero bytes and fails as a signature (§13.3 step 7). Absent or null never becomes one: an
// Envelope is read from JSON by envelopeOf (UnmarshalJSON), which refuses both (§13.1).
func TestASigNotInTheOneSpellingIsRefusedInEitherForm(t *testing.T) {
	v := loadVectors(t)
	now := mustTime(t, v.Now)
	rootA, _ := Parse(hexBytes(t, v.Certificates["root_a"].DerHex))
	pinA := Pin{Root: FingerprintOf(rootA), Endpoint: endpointA, Leaf: B64url(hexBytes(t, v.Certificates["leaf_a"].DerHex)), State: "active"}
	envOf := func(name string) Envelope {
		for _, e := range v.Envelopes {
			if e.Name == name {
				return Envelope{Protected: e.Protected, Enc: e.Enc, Ct: e.Ct, Sig: e.Sig}
			}
		}
		t.Fatal("no envelope " + name)
		return Envelope{}
	}
	const a64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, form := range []struct{ name, envelope string }{{"chain", "alina-to-bharat"}, {"small", "alina-to-bharat-by-reference"}} {
		e := envOf(form.envelope)
		good := e.Sig
		if len(good)%4 != 2 {
			t.Fatalf("%s: a 64-byte signature leaves four spare bits in its last character", form.name)
		}
		last := strings.IndexByte(a64, good[len(good)-1])
		standard := strings.NewReplacer("-", "+", "_", "/").Replace(good)
		if standard == good {
			standard = good[:len(good)-1] + "+"
		}
		for _, c := range []struct {
			what string
			env  Envelope
			why  string
		}{
			{"not base64url at all", Envelope{e.Protected, e.Enc, e.Ct, "!!!"}, "sig is not base64url"},
			{"padded", Envelope{e.Protected, e.Enc, e.Ct, good + "=="}, "sig is not base64url"},
			{"in the standard alphabet", Envelope{e.Protected, e.Enc, e.Ct, standard}, "sig is not base64url"},
			{"with a line break", Envelope{e.Protected, e.Enc, e.Ct, good[:8] + "\n" + good[8:]}, "sig is not base64url"},
			{"with its spare bits set", Envelope{e.Protected, e.Enc, e.Ct, good[:len(good)-1] + string(a64[last|1])}, "sig is not base64url"},
		} {
			for _, whom := range []struct {
				name string
				pins []Pin
			}{{"a pinned contact", []Pin{pinA}}, {"a stranger", nil}} {
				d := decided(t, now, c.env, bharatNode(t, v, whom.pins))
				if d.Result["code"] != "envelope_invalid" || d.Result["why"] != c.why || len(d.Result) != 2 || len(d.Effects) != 0 {
					t.Errorf("%s form from %s, sig %s: %v %v", form.name, whom.name, c.what, d.Result, d.Effects)
				}
			}
		}
	}
	// Empty: a signature that does not verify, answered as the form answers one (§13.2), never a
	// refusal of the spelling. Absent or null does not read as an Envelope at all.
	for _, form := range []struct{ name, envelope, code, why string }{
		{"chain", "alina-to-bharat", "envelope_invalid", "signature is not the chain's leaf key"},
		{"small", "alina-to-bharat-by-reference", "chain_required", ""},
	} {
		e := envOf(form.envelope)
		for _, raw := range []struct{ what, json, why string }{
			{"absent", fmt.Sprintf(`{"protected":%q,"enc":%q,"ct":%q}`, e.Protected, e.Enc, e.Ct), "envelope members"},
			{"null", fmt.Sprintf(`{"protected":%q,"enc":%q,"ct":%q,"sig":null}`, e.Protected, e.Enc, e.Ct), "envelope member types"},
		} {
			var read Envelope
			if err := json.Unmarshal([]byte(raw.json), &read); err == nil || err.Error() != raw.why {
				t.Errorf("%s form, sig %s, read as an Envelope: %v, want %s", form.name, raw.what, err, raw.why)
			}
		}
		for _, raw := range []struct{ what, json string }{
			{"empty", fmt.Sprintf(`{"protected":%q,"enc":%q,"ct":%q,"sig":""}`, e.Protected, e.Enc, e.Ct)},
		} {
			var read Envelope
			if err := json.Unmarshal([]byte(raw.json), &read); err != nil {
				t.Fatal(err)
			}
			for _, whom := range []struct {
				name string
				pins []Pin
			}{{"a pinned contact", []Pin{pinA}}, {"a stranger", nil}} {
				d := decided(t, now, read, bharatNode(t, v, whom.pins))
				want := map[string]any{"code": form.code}
				if form.why != "" {
					want["why"] = form.why
				}
				if fmt.Sprint(d.Result) != fmt.Sprint(want) || len(d.Effects) != 0 {
					t.Errorf("%s form from %s, sig %s: %v %v", form.name, whom.name, raw.what, d.Result, d.Effects)
				}
			}
		}
	}
	// The controls: the vector's own signature passes in both forms, and a signature in the one
	// spelling that is not the leaf's is still the small form's `chain_required` (§13.2).
	if d := decided(t, now, envOf("alina-to-bharat"), bharatNode(t, v, []Pin{pinA})); d.Result["code"] != "ok" || d.Result["form"] != "chain" {
		t.Errorf("chain form, its own sig: %v", d.Result)
	}
	if d := decided(t, now, envOf("alina-to-bharat-by-reference"), bharatNode(t, v, []Pin{pinA})); d.Result["code"] != "ok" || d.Result["form"] != "leaf" {
		t.Errorf("small form, its own sig: %v", d.Result)
	}
	wrong := B64url(make([]byte, 64))
	small := envOf("alina-to-bharat-by-reference")
	small.Sig = wrong
	if d := decided(t, now, small, bharatNode(t, v, []Pin{pinA})); d.Result["code"] != "chain_required" || len(d.Result) != 1 {
		t.Errorf("small form, a sig that is not the leaf's: %v", d.Result)
	}
	full := envOf("alina-to-bharat")
	full.Sig = wrong
	if d := decided(t, now, full, bharatNode(t, v, []Pin{pinA})); d.Result["code"] != "envelope_invalid" || d.Result["why"] != "signature is not the chain's leaf key" {
		t.Errorf("chain form, a sig that is not the leaf's: %v", d.Result)
	}
}

// §2.1, recomputed from the published prf alone — so what passes is what a third implementation
// reading Appendix B would have to reproduce, not what this port happened to write.
func TestDerivationVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Derivation) < 3 {
		t.Fatal("Appendix B should cover all three derivation info strings")
	}
	seen := map[string]string{}
	for _, d := range v.Derivation {
		if got := B64url(PrfSalt()); got != d.Salt {
			t.Errorf("%s: salt is SHA-256(\"hdtp/vault/1\"): got %s want %s", d.Info, got, d.Salt)
		}
		prf, err := DecodeB64url(d.Prf)
		if err != nil {
			t.Fatal(err)
		}
		seed, err := DeriveSeed(prf, d.Info)
		if err != nil {
			t.Fatalf("%s: %v", d.Info, err)
		}
		if got := B64url(seed); got != d.Seed {
			t.Errorf("%s: HKDF-SHA256 over an empty salt: got %s want %s", d.Info, got, d.Seed)
		}
		if d.Alg != "" {
			if d.Alg != "ed25519" {
				t.Errorf("a derived root is Ed25519, not %s", d.Alg)
			}
			k, err := KeyFromSeed(d.Alg, seed)
			if err != nil {
				t.Fatal(err)
			}
			if got := B64url(k.Public().SPKI); got != d.Spki {
				t.Errorf("%s: the key the seed makes: got %s want %s", d.Info, got, d.Spki)
			}
			if got := Fingerprint(k.Public().SPKI); got != d.Fingerprint {
				t.Errorf("%s: the identity that key is: got %s want %s", d.Info, got, d.Fingerprint)
			}
		}
		// The property the info strings exist for: one credential, three unrelated secrets. A port
		// that dropped info from the expand step passes everything above and fails here.
		if prev, dup := seen[B64url(seed)]; dup {
			t.Errorf("%s and %s derive the same seed", d.Info, prev)
		}
		seen[B64url(seed)] = d.Info
	}
}

// The two refusals §2.1 leans on. A mistyped domain separator would otherwise return 32 perfectly
// good bytes belonging to nobody, which is this design's whole failure mode.
func TestDerivationRefusesWhatWouldSilentlyDiffer(t *testing.T) {
	prf := bytes.Repeat([]byte{7}, 32)
	for _, c := range []struct {
		why  string
		prf  []byte
		info string
	}{
		{"an info string that is not one of the three", prf, "hdtp/root/2"},
		{"case matters in a domain separator", prf, "hdtp/Root/1"},
		{"a prf output is 32 bytes", prf[:31], "hdtp/root/1"},
	} {
		if _, err := DeriveSeed(c.prf, c.info); err == nil {
			t.Errorf("expected a refusal: %s", c.why)
		}
	}
	if _, err := DeriveSeed(prf, "hdtp/root/1"); err != nil {
		t.Errorf("the ordinary case must work: %v", err)
	}
}

// SpecVersion is a claim about a document, and it read "2.0.0-draft" for days after that draft
// shipped as 2.0.0 and then as 2.1.0, because a constant has nothing to fail against. The
// specification is already read here for the vectors; its own version line is what the constant
// must equal.
func TestSpecVersionIsTheDocumentsOwn(t *testing.T) {
	spec, err := readSpec()
	if err != nil {
		t.Skip("the specification is not found: " + err.Error())
	}
	for _, line := range strings.Split(spec, "\n") {
		if rest, ok := strings.CutPrefix(line, "**Version "); ok {
			if got := strings.Fields(rest)[0]; got != SpecVersion {
				t.Fatalf("this port says it implements %s and the specification is %s", SpecVersion, got)
			}
			return
		}
	}
	t.Fatal("the specification has no version line")
}

// sigText is an envelope's four members as JSON text, `sig` written as each of sigs in turn: text,
// because a decoded value cannot hold a member written twice.
func sigText(protected, enc, ct string, sigs ...string) string {
	members := make([]string, 0, len(sigs))
	for _, s := range sigs {
		members = append(members, `"sig":`+s)
	}
	return fmt.Sprintf(`{"protected":%q,"enc":%q,"ct":%q,%s}`, protected, enc, ct, strings.Join(members, ","))
}

// callWithEnvelope is Call's answer to fn with envelope spliced into rest as it is written.
func callWithEnvelope(t *testing.T, fn string, rest map[string]any, envelope string) map[string]any {
	t.Helper()
	r := string(mustJSON(rest))
	var out map[string]any
	if err := json.Unmarshal(Call(fn, json.RawMessage(`{"envelope":`+envelope+`,`+r[1:])), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// withMember is e's four members with k set to x (x nil removes it), as JSON text.
func withMember(e Envelope, k string, x any, remove bool) string {
	o := map[string]any{"protected": e.Protected, "enc": e.Enc, "ct": e.Ct, "sig": e.Sig}
	if remove {
		delete(o, k)
	} else {
		o[k] = x
	}
	return string(mustJSON(o))
}

// A member written twice reaches this port's readers at its last occurrence, and is never refused:
// encoding/json's decode into a map keeps the last. What envelopeOf relies on for §13.1, measured so
// it cannot move under it.
func TestARepeatedMemberIsReadAtItsLastOccurrence(t *testing.T) {
	v, err := decodeJSON([]byte(`{"sig":5,"sig":"real"}`))
	if err != nil || fmt.Sprint(v) != "map[sig:real]" {
		t.Errorf("%v %v", v, err)
	}
	var e Envelope
	if err := json.Unmarshal([]byte(`{"protected":"p","enc":"e","ct":"c","sig":null,"sig":"real"}`), &e); err != nil || e.Sig != "real" {
		t.Errorf("%+v %v", e, err)
	}
	// Names byte for byte: a struct decode would have read SIG as sig.
	if err := json.Unmarshal([]byte(`{"protected":"p","enc":"e","ct":"c","SIG":"real"}`), &e); err == nil || err.Error() != "envelope members" {
		t.Errorf("SIG read as an Envelope: %v", err)
	}
}

// §13.1 of the draft (SEP-0005), through Call as a host hands an envelope over: exactly four members,
// each a string, names byte for byte, a repeated member read at its last occurrence, and step 1 of
// §13.3 reading all four spellings before the key is resolved. The answers are the seed's
// (vectors/lib/envelope.mjs receive, vectors/lib/invalid-envelopes.mjs); the core's twin is
// decide_reads_an_envelope_of_exactly_four_string_members.
func TestDecideReadsAnEnvelopeOfExactlyFourStringMembers(t *testing.T) {
	v := loadVectors(t)
	rootA, _ := Parse(hexBytes(t, v.Certificates["root_a"].DerHex))
	pinA := Pin{Root: FingerprintOf(rootA), Endpoint: endpointA, Leaf: B64url(hexBytes(t, v.Certificates["leaf_a"].DerHex)), State: "active"}
	envOf := func(name string) Envelope {
		for _, e := range v.Envelopes {
			if e.Name == name {
				return Envelope{Protected: e.Protected, Enc: e.Enc, Ct: e.Ct, Sig: e.Sig}
			}
		}
		t.Fatal("no envelope " + name)
		return Envelope{}
	}
	full, small := envOf("alina-to-bharat"), envOf("alina-to-bharat-by-reference")
	node := bharatNode(t, v, []Pin{pinA})
	decide := func(text string) map[string]any {
		return callWithEnvelope(t, "decide", map[string]any{"now": v.Now, "node": node}, text)
	}
	q := func(s string) string { return fmt.Sprintf("%q", s) }
	notJSON := full
	notJSON.Protected = B64url([]byte("nope"))
	for _, c := range []struct{ what, text, why string }{
		{"a fifth member", withMember(full, "note", "x", false), "envelope members"},
		{"sig spelled SIG", fmt.Sprintf(`{"protected":%q,"enc":%q,"ct":%q,"SIG":%q}`, full.Protected, full.Enc, full.Ct, full.Sig), "envelope members"},
		{"Protected beside protected", withMember(full, "Protected", full.Protected, false), "envelope members"},
		{"sig absent, in the small form", withMember(small, "sig", nil, true), "envelope members"},
		{"an array in place of the object", string(mustJSON([]string{full.Protected, full.Enc, full.Ct, full.Sig})), "envelope members"},
		{"a string in place of the object", `"x"`, "envelope members"},
		{"sig null, in the small form", withMember(small, "sig", nil, false), "envelope member types"},
		{"sig a number", withMember(full, "sig", 5, false), "envelope member types"},
		{"enc an object", withMember(full, "enc", map[string]any{}, false), "envelope member types"},
		{"sig not base64url, in the small form", withMember(small, "sig", "!!!!", false), "sig is not base64url"},
		{"sig twice, the real one then AAAA", sigText(full.Protected, full.Enc, full.Ct, q(full.Sig), `"AAAA"`), "signature is not the chain's leaf key"},
		{"protected not JSON and sig not base64url", withMember(notJSON, "sig", "!!!!", false), "sig is not base64url"},
	} {
		got := decide(c.text)
		want := map[string]any{"result": map[string]any{"code": "envelope_invalid", "why": c.why}, "effects": []any{}}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %v", c.what, got)
		}
	}
	for _, c := range []struct{ what, text, form string }{
		{"each member once", sigText(full.Protected, full.Enc, full.Ct, q(full.Sig)), "chain"},
		{"sig twice, AAAA then the real one", sigText(full.Protected, full.Enc, full.Ct, `"AAAA"`, q(full.Sig)), "chain"},
		{"sig twice, 5 then the real one", sigText(full.Protected, full.Enc, full.Ct, `5`, q(full.Sig)), "chain"},
		{"sig twice in the small form, null then the real one", sigText(small.Protected, small.Enc, small.Ct, `null`, q(small.Sig)), "leaf"},
	} {
		r, _ := decide(c.text)["result"].(map[string]any)
		if r["code"] != "ok" || r["tier"] != "contact" || r["form"] != c.form {
			t.Errorf("%s: %v", c.what, r)
		}
	}
	if got := callWithEnvelope(t, "decide", map[string]any{"now": v.Now, "node": node}, "null"); fmt.Sprint(got) != fmt.Sprint(map[string]any{"error": "bad_request", "why": "envelope is required"}) {
		t.Errorf("a null envelope: %v", got)
	}
	if got := callWithEnvelope(t, "decide", map[string]any{"now": "yesterday", "node": node}, withMember(full, "note", "x", false)); got["error"] != "parse" {
		t.Errorf("a fifth member and a now that does not read: %v", got)
	}
}

// Step 1 comes before the key is resolved (§13.3): an envelope to a key this endpoint once held is
// certificate_renewed, and the same envelope with a sig that does not read is envelope_invalid.
func TestAMisspelledMemberToAFormerKeyIsRefusedBeforeTheKeyIsResolved(t *testing.T) {
	v := loadVectors(t)
	var full Envelope
	for _, e := range v.Envelopes {
		if e.Name == "alina-to-bharat" {
			full = Envelope{Protected: e.Protected, Enc: e.Enc, Ct: e.Ct, Sig: e.Sig}
		}
	}
	node := bharatNode(t, v, nil)
	node.Former, node.Keys = []string{node.Keys[0].Kid}, nil
	decide := func(text string) map[string]any {
		return callWithEnvelope(t, "decide", map[string]any{"now": v.Now, "node": node}, text)
	}
	if r, _ := decide(sigText(full.Protected, full.Enc, full.Ct, fmt.Sprintf("%q", full.Sig)))["result"].(map[string]any); r["code"] != "certificate_renewed" {
		t.Errorf("the real envelope to a former key: %v", r)
	}
	for _, c := range []struct{ sig, why string }{{`"!!!!"`, "sig is not base64url"}, {`null`, "envelope member types"}} {
		r, _ := decide(sigText(full.Protected, full.Enc, full.Ct, c.sig))["result"].(map[string]any)
		if r["code"] != "envelope_invalid" || r["why"] != c.why {
			t.Errorf("sig %s to a former key: %v", c.sig, r)
		}
	}
}

// open_result reads a result envelope as decide reads a request (§13.2, §13.1): envelopeOf, then
// readMembers, in the same words, as {error: envelope_invalid}.
func TestOpenResultReadsAnEnvelopeOfExactlyFourStringMembers(t *testing.T) {
	v := loadVectors(t)
	der := func(n string) string { return B64url(hexBytes(t, v.Certificates[n].DerHex)) }
	leafA, _ := Parse(hexBytes(t, v.Certificates["leaf_a"].DerHex))
	ts := mustTime(t, v.Now).Unix()
	var e Envelope
	if err := json.Unmarshal(Call("seal_result", mustJSON(map[string]any{
		"recipient_spki": B64url(leafA.SPKI), "sender_pkcs8": B64url(hexBytes(t, v.LeafKeys["leaf_b"])), "form": "chain",
		"sender_chain": []string{der("leaf_b"), der("root_b")}, "result": map[string]any{"ok": 1}, "msg_id": "m-1", "ts": ts,
	})), &e); err != nil {
		t.Fatal(err)
	}
	rest := map[string]any{"my_pkcs8": B64url(hexBytes(t, v.LeafKeys["leaf_a"])), "my_spki": B64url(leafA.SPKI), "msg_id": "m-1", "now": v.Now}
	open := func(text string) map[string]any { return callWithEnvelope(t, "open_result", rest, text) }
	q := fmt.Sprintf("%q", e.Sig)
	for _, c := range []struct{ what, text, why string }{
		{"a fifth member", withMember(e, "note", "x", false), "envelope members"},
		{"CT beside ct", withMember(e, "CT", e.Ct, false), "envelope members"},
		{"ct absent", withMember(e, "ct", nil, true), "envelope members"},
		{"a string in place of the object", `"x"`, "envelope members"},
		{"sig null", withMember(e, "sig", nil, false), "envelope member types"},
		{"sig not base64url", withMember(e, "sig", "!!!!", false), "sig is not base64url"},
		{"sig twice, the real one then AAAA", sigText(e.Protected, e.Enc, e.Ct, q, `"AAAA"`), "signature is not the chain's leaf key"},
	} {
		if got := open(c.text); fmt.Sprint(got) != fmt.Sprint(map[string]any{"error": "envelope_invalid", "why": c.why}) {
			t.Errorf("%s: %v", c.what, got)
		}
	}
	for _, c := range []struct{ what, text string }{
		{"each member once", sigText(e.Protected, e.Enc, e.Ct, q)},
		{"sig twice, 5 then the real one", sigText(e.Protected, e.Enc, e.Ct, `5`, q)},
	} {
		if got := open(c.text); got["ok"] != true || fmt.Sprint(got["result"]) != "map[ok:1]" {
			t.Errorf("%s: %v", c.what, got)
		}
	}
}
