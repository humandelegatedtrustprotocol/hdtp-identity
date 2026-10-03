package hdtpidentity

// Proves this port against Appendix B: the certificates rebuilt (byte for byte where the issuer is
// Ed25519; the TBS, and the vector's signature verified, where it is P-256), the ones marked refused
// refused, every chain, newest-leaf, certificate_renewed and v2 envelope case, the envelopes
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
)

type cast struct {
	rootA, rootB, leafA, leafANext, leafB *PrivateKey
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
		rootA: k(AlgEd25519, "root/alina"), rootB: k(AlgP256, "root/bharat"),
		leafA: k(AlgEd25519, "host/alina/2026"), leafANext: k(AlgEd25519, "host/alina/2027"), leafB: k(AlgP256, "host/bharat/2026"),
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
	return map[string][]byte{
		"root_a": rootA, "root_b": rootB, "leaf_b": leafB,
		"leaf_a":         leafA("leaf_a", c.leafA, "agent.alina.example", "2026-09-01T00:00:00Z", "2027-09-01T00:00:00Z"),
		"leaf_a_expired": leafA("leaf_a_expired", c.leafA, "", "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z"),
		"leaf_a_long":    leafA("leaf_a_long", c.leafA, "", "2026-09-01T00:00:00Z", "2027-10-10T00:00:00Z"),
		"leaf_a_next":    leafA("leaf_a_next", c.leafANext, "", "2027-08-02T00:00:00Z", "2028-08-01T00:00:00Z"),
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
		if name == "root_b" || name == "leaf_b" {
			issuer = c.rootB.Public()
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

func TestV2Envelopes(t *testing.T) {
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
